use crate::{
    akash::{
        build_phase_a_vars, build_phase_b_vars, build_phase_c_vars, build_phase_rly_vars,
        endpoint_hostname, fetch_statesync_trust_params, inject_p2p_nodeport, node_refresh_vars,
    },
    cli::prompt_continue,
    crypto::{
        push_pre_start_files, push_scripts_sftp, verify_files_and_signal_start, FileSource,
        PreStartFile,
    },
    deployer::OLineDeployer,
    dns::cloudflare::{cloudflare_update_accept_domains, cloudflare_update_p2p_domains},
    nodes::register_phase_nodes,
    workflow::context::PhaseResult,
    workflow::step::{DeployPhase, NodeTarget, OLineStep, PeerTarget},
    workflow::{OLineWorkflow, StepResult},
    MAX_RETRIES,
};
use akash_deploy_rs::{
    broadcast_multi_signer, build_create_lease_msg, AkashBackend, AkashClient, Bid, BidId,
    DeployError, DeploymentRecord, DeploymentState, DeploymentStore, DeploymentWorkflow,
    ProviderAuth, ServiceEndpoint, SignerEntry, Step,
};
use std::{
    env::var,
    io::{BufRead, Lines},
    path::Path,
};

/// Parallel deployment path: all phases deployed before snapshot sync wait.
///
/// The key improvement over the sequential path is that phases B (Tackles) and
/// C (Forwards) are deployed *before* the snapshot node finishes syncing.
/// In production, snapshot sync takes ~30 min; by deploying B+C first and
/// using `SNAPSHOT_MODE=sftp`, their nodes wait for the deployer to push the
/// snapshot archive, saving ~60 min of total wall-clock time.
///
/// Step sequence: FundChildAccounts → DeployAllUnits (per-phase DNS updates) → SelectAllProviders →
///   UpdateAllDns → WaitSnapshotReady → DistributeSnapshot → SignalAllNodes →
///   InjectPeers → WaitAllPeers → Summary
use crate::{
    accounts::{child_address, derive_child_signer},
    providers::TrustedProviderStore,
    sessions::{AccountEntry, DeploymentEntry, FundingMethod},
    snapshots::{fetch_genesis_from_node, fetch_snapshot_from_node, push_snapshot_to_node},
    workflow::context::UnitState,
};
use std::{collections::HashMap, path::PathBuf};

// Unit index mapping (for documentation / future Vec<UnitState> expansion):
//   0 = Special Teams (snapshot + seed + minio)
//   1 = Tackles (left + right)
//   2 = Forwards (left + right)
//   3 = Relayer (optional)

// ─────────────────────────────────────────────────────────────────────────────
// Step 1: FundChildAccounts
// ─────────────────────────────────────────────────────────────────────────────

/// Prepare deployment accounts based on the configured funding strategy.
///
/// - `FundingMethod::Master`: single master account (backward compatible).
/// - `FundingMethod::Direct`: all phases deploy from master — no child accounts.
/// - `FundingMethod::HdDerived`: derive N child accounts and fund each from master.
pub async fn fund_child_accounts(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Parallel: preparing deployment units ──");
    tracing::info!("  Master address: {}", w.ctx.deployer.client.address());

    let method = w.ctx.session.funding.clone();
    match method {
        FundingMethod::Master | FundingMethod::Direct => {
            let label = if method == FundingMethod::Direct {
                "direct (single-signer batch)"
            } else {
                "master account (single signer)"
            };
            tracing::info!("  Funding: {}", label);
            w.ctx.session.accounts.push(AccountEntry {
                hd_index: 0,
                address: w.ctx.deployer.client.address().to_string(),
                funded: true,
                funded_amount: 0,
                act_funded_amount: 0,
                assigned_to: None,
            });
            // No child deployers — deploy_all_units will use the master deployer
            // for all phases via single-signer multi-msg batch.
        }
        FundingMethod::HdDerived {
            count,
            amount_per_child,
            act_amount_per_child,
        } => {
            tracing::info!(
                "  Funding: HD-derived ({} children, {} uakt + {} uact each)",
                count,
                amount_per_child,
                act_amount_per_child
            );

            // Check master ACT balance and mint if needed
            let total_act_needed = act_amount_per_child as u128 * count as u128;
            let master_addr = w.ctx.deployer.client.address().to_string();
            let act_balance = w
                .ctx
                .deployer
                .client
                .query_balance(&master_addr, "uact")
                .await
                .unwrap_or(0);

            if act_balance < total_act_needed {
                const MIN_MINT_UACT: u128 = 25_000_000; // 25 ACT minimum mint
                let shortfall = (total_act_needed - act_balance).max(MIN_MINT_UACT);
                tracing::info!(
                    "  Master needs {} uact, has {} — minting {} uakt → uact",
                    total_act_needed,
                    act_balance,
                    shortfall
                );
                let tx = w
                    .ctx
                    .deployer
                    .client
                    .broadcast_mint_act(&w.ctx.deployer.signer, &master_addr, shortfall as u64)
                    .await
                    .map_err(|e| DeployError::InvalidState(format!("Failed to mint ACT: {}", e)))?;
                if !tx.is_success() {
                    return Err(DeployError::InvalidState(format!(
                        "Mint ACT tx failed: {}",
                        tx.raw_log
                    )));
                }
                tracing::info!("  Minted ACT: tx={}", tx.hash);
            }

            // Phase 1: Derive all child addresses, then fund them in a single batch tx.
            let mut recipients: Vec<(String, u128, &str)> = Vec::with_capacity(count as usize * 2);
            for i in 0..count {
                let signer = derive_child_signer(&w.ctx.deployer.config.mnemonic, i)?;
                let addr = child_address(&signer, "akash");
                // AKT for gas
                recipients.push((addr.clone(), amount_per_child as u128, "uakt"));
                // ACT for deployment deposit
                recipients.push((addr.clone(), act_amount_per_child as u128, "uact"));
                w.ctx.session.accounts.push(AccountEntry {
                    hd_index: i,
                    address: addr,
                    funded: true,
                    funded_amount: amount_per_child,
                    act_funded_amount: act_amount_per_child,
                    assigned_to: None,
                });
            }

            // Single batch tx: N MsgSend messages, one gas estimation, one confirmation.
            let batch_recipients: Vec<(&str, u128, &str)> = recipients
                .iter()
                .map(|(addr, amt, denom)| (addr.as_str(), *amt, *denom))
                .collect();
            w.ctx
                .deployer
                .client
                .bank_send_batch(&batch_recipients)
                .await
                .map_err(|e| {
                    DeployError::InvalidState(format!("Failed to batch-fund children: {}", e))
                })?;

            for (addr, _, _) in &recipients {
                tracing::info!("  Funded child: {}", addr);
            }

            // Phase 2: Create child deployers for each funded account.
            let phase_names: &[&'static str] = &["special-teams", "tackles", "forwards", "relayer"];
            for i in 0..count {
                let child_deployer = OLineDeployer::new_child(
                    w.ctx.deployer.config.clone(),
                    w.ctx.deployer.password.clone(),
                    i,
                )
                .await?;

                let name = phase_names.get(i as usize).copied().unwrap_or("extra");
                tracing::info!(
                    "  Child deployer {}: {} ({})",
                    i,
                    child_deployer.client.address(),
                    name
                );

                w.ctx.units.push(UnitState {
                    name,
                    hd_index: i,
                    deployer: child_deployer,
                    vars: HashMap::new(),
                    endpoints: Vec::new(),
                });

                // Mark account assignment in session.
                if let Some(acct) = w.ctx.session.accounts.last_mut() {
                    acct.assigned_to = Some(name.into());
                }
            }
        }
    }

    w.ctx.session.touch();
    w.ctx
        .session_store
        .save(&w.ctx.session)
        .map_err(|e| DeployError::InvalidState(format!("Session save failed: {}", e)))?;

    w.step = OLineStep::DeployAllUnits;
    Ok(StepResult::Continue)
}

// ── Provider selection helpers ───────────────────────────────────────────────

/// Find the bid from a specific provider in a list of bids.
fn find_bid_for_provider(bids: &[Bid], provider: &str) -> Result<Bid, DeployError> {
    bids.iter()
        .find(|b| b.provider == provider)
        .cloned()
        .ok_or_else(|| DeployError::InvalidState(format!("no bid from provider {}", provider)))
}

/// Select a provider for one phase of a parallel deployment.
///
/// Priority:
///   1. Trusted provider bidding → auto-select (cheapest among trusted)
///   2. Non-interactive mode → auto-select cheapest overall
///   3. Interactive mode → show prompt and let operator choose
///
/// In interactive mode, the operator sees one prompt per phase in sequence
/// ("queued"), allowing quick selection before all lease creation proceeds
/// in parallel.
/// Result of provider selection for one phase.
enum ProviderChoice {
    /// Provider was selected (trusted, pre-selected, or interactive).
    Selected(String),
    /// Non-interactive mode, no trusted/pre-selected provider — needs manual selection.
    /// Contains the phase label for structured output.
    NeedsSelection,
}

async fn select_provider_for_phase(
    deployer: &OLineDeployer,
    bids: &[Bid],
    label: &str,
    lines: &mut Lines<impl BufRead>,
    trusted_store: &TrustedProviderStore,
    non_interactive: bool,
    pre_selected: Option<&str>,
) -> Result<ProviderChoice, DeployError> {
    // 1. Check pre-selected provider (from --select flag).
    if let Some(provider) = pre_selected {
        // Verify this provider actually bid
        if bids.iter().any(|b| b.provider == provider) {
            tracing::info!("  [{}] Using pre-selected provider: {}", label, provider);
            return Ok(ProviderChoice::Selected(provider.to_string()));
        } else {
            return Err(DeployError::InvalidState(format!(
                "[{}] Pre-selected provider {} did not bid on this phase.",
                label, provider
            )));
        }
    }

    // 2. Try trusted list.
    if let Some(provider) = trusted_store.select_from_bids(bids) {
        return Ok(ProviderChoice::Selected(provider));
    }

    // 3. Non-interactive: signal that this phase needs manual selection.
    if non_interactive {
        return Ok(ProviderChoice::NeedsSelection);
    }

    // 4. Interactive: show prompt.
    tracing::info!(
        "  [{}] No trusted provider bidding — select interactively:",
        label
    );
    let provider = deployer
        .interactive_select_provider(bids, lines)
        .await
        .map_err(|e| DeployError::InvalidState(format!("Provider selection failed: {}", e)))?;
    Ok(ProviderChoice::Selected(provider))
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2: DeployAllUnits — types and helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Per-phase deployment metadata used to drive the data-driven deployment loop.
///
/// Instead of repeating A/B/C/E blocks, each active phase is described by a
/// `PhaseSlot` that carries its SDL, vars, deployer index, labels, and service
/// registration info. The deploy pipeline iterates over a `Vec<PhaseSlot>`.
struct PhaseSlot {
    /// Which workflow phase this slot represents.
    phase: DeployPhase,
    /// Short key for CLI `--select` flag (e.g. "a", "b", "c", "e").
    select_key: &'static str,
    /// Akash deployment label (e.g. "oline-phase-a").
    label: &'static str,
    /// Rendered SDL after variable substitution.
    rendered_sdl: String,
    /// SDL template variables.
    vars: HashMap<String, String>,
    /// Index into `OLineContext::units` for the deployer (0..3).
    /// Falls back to master deployer when units are empty (direct mode).
    unit_index: usize,
    /// Session phase name (e.g. "special-teams", "tackles").
    session_phase: &'static str,
    /// Service names + labels for node registration.
    /// Phase E derives these dynamically from endpoints, so this can be empty.
    node_services: Vec<(&'static str, &'static str)>,
    /// Phase letter for node registration (e.g. "A", "B", "C", "E").
    phase_letter: &'static str,
}

/// Intermediate result after bid collection and provider selection.
struct PhaseWithBids {
    slot: PhaseSlot,
    state: DeploymentState,
    bids: Vec<Bid>,
    provider_choice: ProviderChoice,
}

/// Fully leased phase ready for manifest send and endpoint collection.
struct LeasedPhase {
    slot: PhaseSlot,
    state: DeploymentState,
}

// ── Phase selection prompts ─────────────────────────────────────────────────

/// Prompt the operator for which phases to deploy. Phase A is required;
/// B, C, E are optional. Returns `None` if the operator aborts, or
/// `Some((run_b, run_c, run_e))` with the selection flags.
fn prompt_phase_selection(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
) -> Result<Option<(bool, bool, bool)>, DeployError> {
    if !prompt_continue(lines, "Deploy Phase A (Special Teams)?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?
    {
        tracing::info!("Aborted.");
        w.step = OLineStep::Complete;
        return Ok(None);
    }
    let run_b = prompt_continue(lines, "Deploy Phase B (Tackles)?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;
    let run_c = prompt_continue(lines, "Deploy Phase C (Forwards)?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;
    let relayer_chain = w.ctx.deployer.config.val("RLY_REMOTE_CHAIN_ID");
    let run_e = !relayer_chain.is_empty()
        && prompt_continue(lines, "Deploy Phase E (Relayer)?")
            .map_err(|e| DeployError::InvalidState(e.to_string()))?;

    if !run_b {
        w.ctx
            .set_phase_result(DeployPhase::Tackles, PhaseResult::Skipped);
    }
    if !run_c {
        w.ctx
            .set_phase_result(DeployPhase::Forwards, PhaseResult::Skipped);
    }
    if !run_e {
        w.ctx
            .set_phase_result(DeployPhase::Relayer, PhaseResult::Skipped);
    }
    Ok(Some((run_b, run_c, run_e)))
}

// ── SDL var building + SSH key extraction ───────────────────────────────────

/// Build SDL template variables for all phases and extract the shared SSH key.
///
/// Phase A generates the SSH keypair; B and C share the public key.
/// Phase E generates its own key inside `build_phase_rly_vars`.
async fn build_all_sdl_vars(
    w: &mut OLineWorkflow,
    run_b: bool,
    run_c: bool,
    run_e: bool,
) -> Result<
    (
        HashMap<String, String>,
        HashMap<String, String>,
        HashMap<String, String>,
        HashMap<String, String>,
    ),
    DeployError,
> {
    let session_key_path = w.ctx.session.ssh_key_path_buf();
    let a_vars = build_phase_a_vars(
        &w.ctx.deployer.config,
        &session_key_path,
        &w.ctx.deployer.password,
    )
    .await
    .map_err(|e| DeployError::InvalidState(format!("build_phase_a_vars: {}", e)))?;

    // Extract and store SSH key from Phase A.
    let ssh_privkey_pem = a_vars
        .get("SSH_PRIVKEY")
        .ok_or_else(|| DeployError::InvalidState("SSH_PRIVKEY missing from phase-A vars".into()))?
        .clone();
    // Use session-derived key path (already written by build_phase_a_vars).
    w.ctx.ssh_key_path = session_key_path;
    w.ctx.ssh_privkey_pem = ssh_privkey_pem;
    w.ctx.a_vars = a_vars.clone();

    let ssh_pubkey = a_vars.get("SSH_PUBKEY").cloned().unwrap_or_default();

    let b_vars = if run_b {
        let mut v = build_phase_b_vars(&w.ctx.deployer.config);
        v.insert("SSH_PUBKEY".into(), ssh_pubkey.clone());
        v
    } else {
        HashMap::new()
    };

    let c_vars = if run_c {
        let mut v = build_phase_c_vars(&w.ctx.deployer.config);
        v.insert("SSH_PUBKEY".into(), ssh_pubkey.clone());
        v
    } else {
        HashMap::new()
    };

    let e_vars = if run_e {
        build_phase_rly_vars(&w.ctx.deployer.config)
    } else {
        HashMap::new()
    };

    Ok((a_vars, b_vars, c_vars, e_vars))
}

// ── SDL loading + rendering ─────────────────────────────────────────────────

/// Build `PhaseSlot` entries for all active phases by loading SDL templates
/// and rendering them with the corresponding vars.
///
/// Phase A is required; B/C/E are optional and marked as failed on SDL errors.
fn build_phase_slots(
    w: &mut OLineWorkflow,
    run_b: bool,
    run_c: bool,
    run_e: bool,
    a_vars: HashMap<String, String>,
    b_vars: HashMap<String, String>,
    c_vars: HashMap<String, String>,
    e_vars: HashMap<String, String>,
) -> Result<Vec<PhaseSlot>, DeployError> {
    let mut slots = Vec::with_capacity(4);

    // Phase A — required.
    let sdl_a = w
        .ctx
        .deployer
        .config
        .load_sdl("a.yml")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;
    let rendered_a = akash_deploy_rs::substitute_partial(&sdl_a, &a_vars);
    slots.push(PhaseSlot {
        phase: DeployPhase::SpecialTeams,
        select_key: "a",
        label: "oline-phase-a",
        rendered_sdl: rendered_a,
        vars: a_vars,
        unit_index: 0,
        session_phase: "special-teams",
        node_services: vec![
            ("oline-a-snapshot", "Phase A - Snapshot"),
            ("oline-a-seed", "Phase A - Seed"),
            ("oline-a-minio-ipfs", "Phase A - MinIO"),
        ],
        phase_letter: "A",
    });

    // Helper: try loading an optional phase SDL.
    let mut try_load_optional = |run: bool,
                                 file: &str,
                                 phase: DeployPhase,
                                 vars: HashMap<String, String>,
                                 select_key: &'static str,
                                 label: &'static str,
                                 unit_index: usize,
                                 session_phase: &'static str,
                                 node_services: Vec<(&'static str, &'static str)>,
                                 phase_letter: &'static str| {
        if !run {
            return;
        }
        match w.ctx.deployer.config.load_sdl(file) {
            Ok(sdl) => {
                let rendered = akash_deploy_rs::substitute_partial(&sdl, &vars);
                slots.push(PhaseSlot {
                    phase,
                    select_key,
                    label,
                    rendered_sdl: rendered,
                    vars,
                    unit_index,
                    session_phase,
                    node_services,
                    phase_letter,
                });
            }
            Err(e) => {
                tracing::warn!("  Phase {} SDL error: {} — skipping.", phase_letter, e);
                w.ctx
                    .set_phase_result(phase, PhaseResult::Failed(e.to_string()));
            }
        }
    };

    try_load_optional(
        run_b,
        "b.yml",
        DeployPhase::Tackles,
        b_vars,
        "b",
        "oline-phase-b",
        1,
        "tackles",
        vec![
            ("oline-b-left-node", "Phase B - Left Tackle"),
            ("oline-b-right-node", "Phase B - Right Tackle"),
        ],
        "B",
    );
    try_load_optional(
        run_c,
        "c.yml",
        DeployPhase::Forwards,
        c_vars,
        "c",
        "oline-phase-c",
        2,
        "forwards",
        vec![
            ("oline-c-left-node", "Phase C - Left Forward"),
            ("oline-c-right-node", "Phase C - Right Forward"),
        ],
        "C",
    );
    try_load_optional(
        run_e,
        "e.yml",
        DeployPhase::Relayer,
        e_vars,
        "e",
        "oline-phase-e",
        3,
        "relayer",
        vec![], // Phase E derives service names dynamically from endpoints
        "E",
    );

    Ok(slots)
}

// ── Deployer ref resolution ─────────────────────────────────────────────────

/// Resolve the deployer for a given unit index. Falls back to master when
/// no child deployers exist (direct mode).
fn deployer_for_index<'a>(
    ctx: &'a crate::workflow::context::OLineContext,
    idx: usize,
) -> &'a OLineDeployer {
    ctx.units
        .get(idx)
        .map(|u| &u.deployer)
        .unwrap_or(&ctx.deployer)
}

// ── ACT balance + mint ──────────────────────────────────────────────────────

/// Ensure the master account has enough ACT for `num_deploys` deployment deposits.
///
/// BME mints ACT in the end-blocker, so the mint tx must confirm and the balance
/// must be polled until sufficient. This is the one place where a >3s sleep is
/// acceptable — we are waiting for blockchain block production (~6s/block).
async fn ensure_act_for_deposits(
    deployer: &OLineDeployer,
    signer: &akash_deploy_rs::KeySigner,
    deposit_amount: u64,
    num_deploys: u64,
) -> Result<(), DeployError> {
    let total_act_needed = deposit_amount as u128 * num_deploys as u128;
    let master_addr = deployer.client.address().to_string();
    let act_balance = deployer
        .client
        .query_balance(&master_addr, "uact")
        .await
        .unwrap_or(0);

    if act_balance >= total_act_needed {
        return Ok(());
    }

    const MIN_MINT_UAKT: u128 = 25_000_000; // BME minimum mint = 25 ACT
    let shortfall = (total_act_needed - act_balance).max(MIN_MINT_UAKT);
    tracing::info!(
        total_act_needed,
        act_balance,
        shortfall,
        "  Minting ACT (burn {} uakt -> uact) before deploy batch...",
        shortfall
    );
    let mint_tx = deployer
        .client
        .broadcast_mint_act(signer, &master_addr, shortfall as u64)
        .await
        .map_err(|e| DeployError::InvalidState(format!("MsgMintACT failed: {}", e)))?;
    if !mint_tx.is_success() {
        return Err(DeployError::InvalidState(format!(
            "MsgMintACT tx failed: {}",
            mint_tx.raw_log
        )));
    }
    tracing::info!(tx_hash = %mint_tx.hash, "  MsgMintACT confirmed, waiting for end-blocker...");

    // Poll until ACT balance covers the deposits.
    // BME end-blocker processes mints — can take several blocks (~6s each).
    let poll_start = std::time::Instant::now();
    let poll_timeout = std::time::Duration::from_secs(120);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        let new_balance = deployer
            .client
            .query_balance(&master_addr, "uact")
            .await
            .unwrap_or(0);
        if new_balance >= total_act_needed {
            tracing::info!(new_balance, total_act_needed, "  ACT balance sufficient");
            return Ok(());
        }
        let elapsed = poll_start.elapsed().as_secs();
        if poll_start.elapsed() > poll_timeout {
            return Err(DeployError::InvalidState(format!(
                "Timed out waiting for ACT mint after {}s: balance {} < needed {}",
                elapsed, new_balance, total_act_needed,
            )));
        }
        tracing::info!(
            new_balance,
            total_act_needed,
            elapsed,
            "  Waiting for ACT mint (end-blocker)..."
        );
    }
}

// ── Batch MsgCreateDeployment broadcast ─────────────────────────────────────

/// Build MsgCreateDeployment messages for each slot, broadcast them atomically,
/// and return the assigned dseq for each slot.
///
/// In direct mode (no child accounts): all messages go in a single tx with the
/// master signer, each getting a unique dseq (dseq, dseq+1, ...).
/// In HD mode: each child signer signs its own message, all combined atomically.
async fn broadcast_create_deployments(
    w: &OLineWorkflow,
    slots: &[PhaseSlot],
    base_dseq: u64,
    deposit_amount: u64,
    deposit_denom: &str,
    is_direct: bool,
) -> Result<Vec<u64>, DeployError> {
    // Build messages and assign dseqs.
    let dseqs = assign_dseqs(base_dseq, slots.len(), is_direct);
    let mut messages = Vec::with_capacity(slots.len());
    for (slot, &assigned_dseq) in slots.iter().zip(dseqs.iter()) {
        let d = deployer_for_index(&w.ctx, slot.unit_index);
        let msg = d.client.build_create_deployment_msg(
            &d.client.address(),
            &slot.rendered_sdl,
            deposit_amount,
            deposit_denom,
            assigned_dseq,
        )?;
        messages.push(msg);
    }

    let d0 = deployer_for_index(&w.ctx, 0);
    let querier = &d0.client.signing_client().querier;
    let chain_id = querier.chain_config.chain_id.as_str();

    if is_direct {
        // Single signer (master) — all MsgCreateDeployment in one tx.
        let acct = querier
            .base_account(d0.client.address_ref())
            .await
            .map_err(|e| DeployError::Query(format!("base_account master: {}", e)))?;

        tracing::info!(
            msgs = messages.len(),
            chain_id,
            "  Broadcasting single-signer MsgCreateDeployment batch..."
        );

        let signer_entries = vec![SignerEntry {
            signer: &w.ctx.deployer.signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages,
        }];

        let multi_tx = broadcast_multi_signer(
            querier,
            chain_id,
            signer_entries,
            1.5,
            std::time::Duration::from_secs(60),
        )
        .await?;

        tracing::info!(
            tx_hash = %multi_tx.hash, height = multi_tx.height,
            "  Single-signer batch confirmed"
        );
    } else {
        // HD mode: one SignerEntry per child signer.
        let mnemonic = &w.ctx.deployer.config.mnemonic;
        let mut accounts = Vec::with_capacity(slots.len());
        let mut signers = Vec::with_capacity(slots.len());
        for (i, slot) in slots.iter().enumerate() {
            let d = deployer_for_index(&w.ctx, slot.unit_index);
            let acct = querier
                .base_account(d.client.address_ref())
                .await
                .map_err(|e| {
                    DeployError::Query(format!("base_account d{} for deploy: {}", i, e))
                })?;
            let hd_index = w
                .ctx
                .units
                .get(slot.unit_index)
                .map(|u| u.hd_index)
                .unwrap_or(slot.unit_index as u32);
            let signer = derive_child_signer(mnemonic, hd_index)?;
            accounts.push(acct);
            signers.push(signer);
        }

        let signer_entries: Vec<SignerEntry<'_>> = signers
            .iter()
            .zip(accounts.iter())
            .zip(messages.into_iter())
            .map(|((signer, acct), msg)| SignerEntry {
                signer,
                account_number: acct.account_number,
                sequence: acct.sequence,
                messages: vec![msg],
            })
            .collect();

        tracing::info!(
            signers = signer_entries.len(),
            chain_id,
            "  Broadcasting multi-signer MsgCreateDeployment batch..."
        );

        let multi_tx = broadcast_multi_signer(
            querier,
            chain_id,
            signer_entries,
            1.5,
            std::time::Duration::from_secs(60),
        )
        .await?;

        tracing::info!(
            tx_hash = %multi_tx.hash, height = multi_tx.height,
            "  Multi-signer batch confirmed"
        );
    }

    Ok(dseqs)
}

// ── DeploymentState creation ────────────────────────────────────────────────

/// Create a `DeploymentState` for each phase slot with the assigned dseq.
fn create_deployment_states(
    slots: &[PhaseSlot],
    ctx: &crate::workflow::context::OLineContext,
    dseqs: &[u64],
) -> Vec<DeploymentState> {
    slots
        .iter()
        .zip(dseqs.iter())
        .map(|(slot, &assigned_dseq)| {
            let d = deployer_for_index(ctx, slot.unit_index);
            let mut state = DeploymentState::new(slot.label, d.client.address())
                .with_sdl(&slot.rendered_sdl)
                .with_label(slot.label);
            state.dseq = Some(assigned_dseq);
            state
        })
        .collect()
}

// ── Bid waiting ─────────────────────────────────────────────────────────────

/// Wait for bids on all phases. Phase A (index 0) is required — its failure
/// is fatal. Optional phases that fail to receive bids are silently dropped.
async fn wait_for_all_bids(
    ctx: &crate::workflow::context::OLineContext,
    slots: Vec<PhaseSlot>,
    states: &mut [DeploymentState],
) -> Result<Vec<(PhaseSlot, DeploymentState, Vec<Bid>)>, DeployError> {
    // Bid-waiting runs sequentially here because the futures are !Send (they
    // hold references into the workflow context). The original code used
    // tokio::join! which also runs on a single task — same concurrency model.
    let mut results: Vec<Option<Result<Vec<Bid>, DeployError>>> =
        slots.iter().map(|_| None).collect();

    for i in 0..slots.len() {
        let d = deployer_for_index(ctx, slots[i].unit_index);
        results[i] = Some(d.wait_for_bids(&mut states[i], slots[i].label).await);
    }

    // Phase A is required — propagate its error.
    let bids_a = results[0].take().unwrap()?;

    let mut collected = Vec::with_capacity(slots.len());
    let mut slot_iter = slots.into_iter().enumerate();

    // Phase A
    let (_, slot_a) = slot_iter.next().unwrap();
    let state_a = std::mem::replace(&mut states[0], DeploymentState::new("placeholder", ""));
    collected.push((slot_a, state_a, bids_a));

    // Optional phases
    for (idx, slot) in slot_iter {
        match results[idx].take().unwrap() {
            Ok(bids) => {
                let state =
                    std::mem::replace(&mut states[idx], DeploymentState::new("placeholder", ""));
                collected.push((slot, state, bids));
            }
            Err(e) => {
                tracing::warn!(
                    "  Phase {} bid wait failed: {} — skipping.",
                    slot.phase_letter,
                    e
                );
            }
        }
    }

    Ok(collected)
}

// ── Provider selection ──────────────────────────────────────────────────────

/// Print structured bid output for one phase (used in two-step non-interactive flow).
async fn print_phase_bids_output(
    deployer: &OLineDeployer,
    phase: &str,
    dseq: u64,
    bids: &[Bid],
    auto_selected: Option<&str>,
) {
    println!(
        "PHASE_{} DSEQ={} BIDS={}",
        phase.to_uppercase(),
        dseq,
        bids.len()
    );
    for (i, bid) in bids.iter().enumerate() {
        let price_akt = bid.price as f64 / 1_000_000.0;
        let info = deployer
            .client
            .query_provider_info(&bid.provider)
            .await
            .ok()
            .flatten();
        let host = info
            .as_ref()
            .map(|i| i.host_uri.as_str())
            .unwrap_or("unknown");
        let email = info.as_ref().map(|i| i.email.as_str()).unwrap_or("");
        let website = info.as_ref().map(|i| i.website.as_str()).unwrap_or("");
        println!(
            "  BID[{}] provider={} price={} price_akt={:.6} host={} email={} website={}",
            i, bid.provider, bid.price, price_akt, host, email, website
        );
    }
    if let Some(addr) = auto_selected {
        println!("  AUTO_SELECTED={} (trusted)", addr);
    } else {
        println!("  NEEDS_SELECTION=true");
    }
}

/// Select providers for all phases. Returns the phases with their chosen providers,
/// or prints bids and returns `None` if any phase needs manual selection (two-step flow).
async fn select_providers_for_all(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
    phases: Vec<(PhaseSlot, DeploymentState, Vec<Bid>)>,
) -> Result<Option<Vec<PhaseWithBids>>, DeployError> {
    tracing::info!("  -- Provider selection --");
    let trusted_store = TrustedProviderStore::open(TrustedProviderStore::default_path());
    let non_interactive = std::env::var("OLINE_NON_INTERACTIVE").is_ok()
        || std::env::var("OLINE_AUTO_SELECT").is_ok();
    let selections = &w.ctx.provider_selections;

    let mut with_choices: Vec<PhaseWithBids> = Vec::with_capacity(phases.len());
    let mut any_needs_selection = false;

    for (slot, state, bids) in phases {
        let choice = select_provider_for_phase(
            &w.ctx.deployer,
            &bids,
            slot.label,
            lines,
            &trusted_store,
            non_interactive,
            selections.get(slot.select_key).map(|s| s.as_str()),
        )
        .await?;

        if matches!(&choice, ProviderChoice::NeedsSelection) {
            any_needs_selection = true;
        }

        with_choices.push(PhaseWithBids {
            slot,
            state,
            bids,
            provider_choice: choice,
        });
    }

    if !any_needs_selection {
        return Ok(Some(with_choices));
    }

    // Two-step flow: print all bids and exit with --select instructions.
    tracing::info!("  Some phases need manual provider selection. Printing bids...");
    println!();

    let mut select_parts: Vec<String> = Vec::new();
    for phase in &with_choices {
        let auto = match &phase.provider_choice {
            ProviderChoice::Selected(p) => Some(p.as_str()),
            ProviderChoice::NeedsSelection => None,
        };
        print_phase_bids_output(
            &w.ctx.deployer,
            phase.slot.select_key,
            phase.state.dseq.unwrap_or(0),
            &phase.bids,
            auto,
        )
        .await;
        if matches!(&phase.provider_choice, ProviderChoice::NeedsSelection) {
            select_parts.push(format!("{}=<PROVIDER>", phase.slot.select_key));
        }
    }

    println!();
    println!("To complete deployment, run:");
    println!(
        "  oline deploy --parallel --select {}",
        select_parts.join(" ")
    );
    println!();
    println!("WAITING_FOR_SELECTION=true");

    w.step = OLineStep::Complete;
    Ok(None)
}

// ── Batch CreateLease ───────────────────────────────────────────────────────

/// Apply provider selections to states, build MsgCreateLease for each phase,
/// and broadcast them in a single transaction. Returns leased phases.
async fn create_leases_batch(
    w: &OLineWorkflow,
    phases: Vec<PhaseWithBids>,
    is_direct: bool,
) -> Result<Vec<LeasedPhase>, DeployError> {
    // Apply provider selections and build bid IDs.
    let mut selected: Vec<(PhaseSlot, DeploymentState, BidId)> = Vec::with_capacity(phases.len());

    for mut phase in phases {
        let provider = match phase.provider_choice {
            ProviderChoice::Selected(p) => p,
            ProviderChoice::NeedsSelection => {
                unreachable!("all phases have providers at this point")
            }
        };
        DeploymentWorkflow::<AkashClient>::select_provider(&mut phase.state, &provider)?;

        let bid =
            find_bid_for_provider(&phase.bids, phase.state.selected_provider.as_ref().unwrap())?;
        let bid_id = BidId::from_bid(
            &phase.state.owner,
            phase.state.dseq.unwrap(),
            phase.state.gseq,
            phase.state.oseq,
            &bid,
        );
        selected.push((phase.slot, phase.state, bid_id));
    }

    let lease_msgs: Vec<_> = selected
        .iter()
        .map(|(_, _, bid_id)| build_create_lease_msg(bid_id))
        .collect();

    tracing::info!(
        msgs = lease_msgs.len(),
        "  Batch CreateLease: broadcasting {} MsgCreateLease in 1 tx...",
        lease_msgs.len()
    );

    let d0 = deployer_for_index(&w.ctx, 0);
    let querier = &d0.client.signing_client().querier;
    let chain_id = querier.chain_config.chain_id.as_str();

    if is_direct {
        let acct = querier
            .base_account(d0.client.address_ref())
            .await
            .map_err(|e| DeployError::Query(format!("base_account master for lease: {}", e)))?;

        let signer_entries = vec![SignerEntry {
            signer: &w.ctx.deployer.signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages: lease_msgs,
        }];

        let batch_tx = broadcast_multi_signer(
            querier,
            chain_id,
            signer_entries,
            1.5,
            std::time::Duration::from_secs(60),
        )
        .await?;

        tracing::info!(
            tx_hash = %batch_tx.hash, height = batch_tx.height,
            "  Batch lease tx confirmed (direct mode)"
        );

        Ok(selected
            .into_iter()
            .map(|(slot, mut state, bid_id)| {
                state.record_tx(&batch_tx.hash);
                state.lease_id = Some(bid_id.into());
                state.transition(Step::SendManifest);
                LeasedPhase { slot, state }
            })
            .collect())
    } else {
        // HD mode: one SignerEntry per child signer.
        let mnemonic = &w.ctx.deployer.config.mnemonic;
        let mut accounts = Vec::with_capacity(selected.len());
        let mut signers = Vec::with_capacity(selected.len());

        for (i, (slot, _, _)) in selected.iter().enumerate() {
            let d = deployer_for_index(&w.ctx, slot.unit_index);
            let acct = querier
                .base_account(d.client.address_ref())
                .await
                .map_err(|e| DeployError::Query(format!("base_account d{} for lease: {}", i, e)))?;
            let hd_index = w
                .ctx
                .units
                .get(slot.unit_index)
                .map(|u| u.hd_index)
                .unwrap_or(slot.unit_index as u32);
            let signer = derive_child_signer(mnemonic, hd_index)?;
            accounts.push(acct);
            signers.push(signer);
        }

        let signer_entries: Vec<SignerEntry<'_>> = signers
            .iter()
            .zip(accounts.iter())
            .zip(selected.iter().map(|(_, _, bid_id)| bid_id))
            .map(|((signer, acct), bid_id)| SignerEntry {
                signer,
                account_number: acct.account_number,
                sequence: acct.sequence,
                messages: vec![build_create_lease_msg(bid_id)],
            })
            .collect();

        let batch_tx = broadcast_multi_signer(
            querier,
            chain_id,
            signer_entries,
            1.5,
            std::time::Duration::from_secs(60),
        )
        .await?;

        tracing::info!(
            tx_hash = %batch_tx.hash, height = batch_tx.height,
            "  Batch lease tx confirmed (HD mode)"
        );

        Ok(selected
            .into_iter()
            .map(|(slot, mut state, bid_id)| {
                state.record_tx(&batch_tx.hash);
                state.lease_id = Some(bid_id.into());
                state.transition(Step::SendManifest);
                LeasedPhase { slot, state }
            })
            .collect())
    }
}

// ── JWT + SendManifest + WaitForEndpoints ───────────────────────────────────

/// Generate a JWT and complete deployment (SendManifest + WaitForEndpoints)
/// for all leased phases. Returns each phase index paired with its endpoint result.
async fn complete_manifests(
    w: &OLineWorkflow,
    phases: &mut [LeasedPhase],
    is_direct: bool,
) -> Result<Vec<(usize, Result<Vec<ServiceEndpoint>, DeployError>)>, DeployError> {
    let jwt_token = w
        .ctx
        .deployer
        .client
        .generate_jwt(&w.ctx.deployer.client.address())
        .await
        .map_err(|e| DeployError::InvalidState(format!("JWT generation failed: {}", e)))?;

    for phase in phases.iter_mut() {
        phase.state.jwt_token = Some(jwt_token.clone());
    }

    let mut results: Vec<(usize, Result<Vec<ServiceEndpoint>, DeployError>)> =
        Vec::with_capacity(phases.len());

    if is_direct {
        tracing::info!("  Completing deployments sequentially (SendManifest + endpoints)...");
        let d = &w.ctx.deployer;
        for (i, phase) in phases.iter_mut().enumerate() {
            let res = d
                .deploy_phase_complete(&mut phase.state, phase.slot.label)
                .await;
            results.push((i, res));
        }
    } else {
        tracing::info!("  Completing deployments in parallel (SendManifest + endpoints)...");
        for (i, phase) in phases.iter_mut().enumerate() {
            let d = deployer_for_index(&w.ctx, phase.slot.unit_index);
            let res = d
                .deploy_phase_complete(&mut phase.state, phase.slot.label)
                .await;
            results.push((i, res));
        }
    }

    Ok(results)
}

// ── Phase result recording ──────────────────────────────────────────────────

/// Extract unique service names from endpoints (preserving insertion order).
fn unique_services(endpoints: &[ServiceEndpoint]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    endpoints
        .iter()
        .filter_map(|e| {
            if seen.insert(e.service.clone()) {
                Some(e.service.clone())
            } else {
                None
            }
        })
        .collect()
}

/// Record a successfully deployed phase into session state, deployment store,
/// and node registry. Handles Phase E's special SSH key separately.
async fn record_deployed_phase(
    w: &mut OLineWorkflow,
    slot: &PhaseSlot,
    state: &DeploymentState,
    endpoints: &[ServiceEndpoint],
    key_name: &str,
    password: &str,
    ssh_port_internal: u16,
) -> Result<(), DeployError> {
    let dseq = state.dseq.unwrap_or(0);
    tracing::info!("  [Phase {}] Deployed. DSEQ: {}", slot.phase_letter, dseq);

    w.ctx
        .deployer
        .deployment_store
        .save(
            &DeploymentRecord::from_state(state, &w.ctx.deployer.password)
                .map_err(|e| DeployError::InvalidState(e.to_string()))?,
        )
        .await
        .ok();

    // Node registration — Phase E has dynamic service names.
    if slot.phase == DeployPhase::Relayer {
        register_phase_e_nodes(w, &slot.vars, state, endpoints, password, ssh_port_internal);
    } else {
        register_phase_nodes(
            endpoints,
            dseq,
            &slot.node_services,
            key_name,
            slot.phase_letter,
            password,
            ssh_port_internal,
        );
    }

    let account_index = w
        .ctx
        .units
        .get(slot.unit_index)
        .map(|u| u.hd_index)
        .unwrap_or(0);

    w.ctx.session.deployments.push(DeploymentEntry {
        phase: slot.session_phase.into(),
        dseq,
        account_index,
        label: slot.label.into(),
        provider: state.selected_provider.clone(),
        endpoints: endpoints
            .iter()
            .map(|e| format!("{}:{}", e.service, e.port))
            .collect(),
        gseq: state.gseq,
        oseq: state.oseq,
        services: unique_services(endpoints),
    });

    w.ctx
        .set_phase_result(slot.phase.clone(), PhaseResult::Deployed);
    w.ctx.session_store.save(&w.ctx.session).ok();
    Ok(())
}

/// Handle Phase E's special SSH key and dynamic service registration.
fn register_phase_e_nodes(
    w: &OLineWorkflow,
    e_vars: &HashMap<String, String>,
    state: &DeploymentState,
    endpoints: &[ServiceEndpoint],
    password: &str,
    ssh_port_internal: u16,
) {
    let Some(privkey_pem) = e_vars.get("SSH_PRIVKEY") else {
        return;
    };
    let session = &w.ctx.session;
    let session_key_name = format!("{}/ssh-key", session.id);
    let session_key_path_buf = session.ssh_key_path_buf();
    match ssh_key::PrivateKey::from_openssh(privkey_pem.as_bytes()) {
        Ok(k) => {
            if let Err(e) =
                crate::crypto::save_ssh_key_encrypted(&k, &session_key_path_buf, password)
            {
                tracing::warn!("  [Phase E] Failed to save SSH key: {}", e);
                return;
            }
            let e_services: Vec<String> = endpoints
                .iter()
                .filter(|ep| ep.internal_port == ssh_port_internal)
                .map(|ep| ep.service.clone())
                .collect();
            let e_svc_pairs: Vec<(&str, String)> = e_services
                .iter()
                .map(|svc| (svc.as_str(), format!("Phase E - {}", svc)))
                .collect();
            let e_svc_refs: Vec<(&str, &str)> =
                e_svc_pairs.iter().map(|(s, l)| (*s, l.as_str())).collect();
            register_phase_nodes(
                endpoints,
                state.dseq.unwrap_or(0),
                &e_svc_refs,
                &session_key_name,
                "E",
                password,
                ssh_port_internal,
            );
        }
        Err(e) => tracing::warn!("  [Phase E] Invalid SSH key: {}", e),
    }
}

// ── Statesync RPC extraction ────────────────────────────────────────────────

/// Extract statesync RPC addresses from Phase A endpoints (snapshot + seed).
fn extract_statesync_rpc(endpoints: &[ServiceEndpoint]) -> String {
    let snap_rpc =
        OLineDeployer::find_endpoint_by_internal_port(endpoints, "oline-a-snapshot", 26657)
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port))
            .unwrap_or_default();
    let seed_rpc = OLineDeployer::find_endpoint_by_internal_port(endpoints, "oline-a-seed", 26657)
        .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port))
        .unwrap_or_default();
    match (snap_rpc.is_empty(), seed_rpc.is_empty()) {
        (false, false) => format!("{},{}", snap_rpc, seed_rpc),
        (false, true) => snap_rpc,
        (true, false) => seed_rpc,
        (true, true) => String::new(),
    }
}

// ── DNS updates ─────────────────────────────────────────────────────────────

/// Update Cloudflare DNS for all deployed phases (accept domains + P2P domains).
async fn update_dns_after_deploy(w: &OLineWorkflow) {
    let cf_token = w.ctx.deployer.config.val("OLINE_CF_API_TOKEN");
    let cf_zone = w.ctx.deployer.config.val("OLINE_CF_ZONE_ID");
    if cf_token.is_empty() || cf_zone.is_empty() {
        return;
    }

    // HTTP/HTTPS accept domains (proxied through Cloudflare).
    for phase in DeployPhase::ALL {
        if let Some(state) = w.ctx.state(phase.clone()) {
            if let Some(ref sdl) = state.sdl_content {
                let eps = w.ctx.endpoints(phase).to_vec();
                if !eps.is_empty() {
                    cloudflare_update_accept_domains(sdl, &eps, &cf_token, &cf_zone).await;
                }
            }
        }
    }

    // P2P domains: DNS-only A records (NOT proxied — raw TCP for CometBFT P2P).
    let cfg = &w.ctx.deployer.config;
    let val = |k: &str| {
        let v = cfg.val(k);
        if v.is_empty() {
            String::new()
        } else {
            v
        }
    };

    let a_eps = w.ctx.endpoints(DeployPhase::SpecialTeams).to_vec();
    if !a_eps.is_empty() {
        let snap_p2p: u16 = val("P2P_P_SNAP").parse().unwrap_or(26656);
        let seed_p2p: u16 = val("P2P_P_SEED").parse().unwrap_or(26656);
        let d_snap = val("P2P_D_SNAP");
        let d_seed = val("P2P_D_SEED");
        let entries = [
            (d_snap.as_str(), snap_p2p, "oline-a-snapshot"),
            (d_seed.as_str(), seed_p2p, "oline-a-seed"),
        ];
        cloudflare_update_p2p_domains(&entries, &a_eps, &cf_token, &cf_zone).await;
    }

    let b_eps = w.ctx.endpoints(DeployPhase::Tackles).to_vec();
    if !b_eps.is_empty() {
        let tl_p2p: u16 = val("P2P_P_TL").parse().unwrap_or(26656);
        let tr_p2p: u16 = val("P2P_P_TR").parse().unwrap_or(26656);
        let d_tl = val("P2P_D_TL");
        let d_tr = val("P2P_D_TR");
        let entries = [
            (d_tl.as_str(), tl_p2p, "oline-b-left-tackle"),
            (d_tr.as_str(), tr_p2p, "oline-b-right-tackle"),
        ];
        cloudflare_update_p2p_domains(&entries, &b_eps, &cf_token, &cf_zone).await;
    }

    let c_eps = w.ctx.endpoints(DeployPhase::Forwards).to_vec();
    if !c_eps.is_empty() {
        let fl_p2p: u16 = val("P2P_P_FL").parse().unwrap_or(26656);
        let fr_p2p: u16 = val("P2P_P_FR").parse().unwrap_or(26656);
        let d_fl = val("P2P_D_FL");
        let d_fr = val("P2P_D_FR");
        let entries = [
            (d_fl.as_str(), fl_p2p, "oline-c-left-forward"),
            (d_fr.as_str(), fr_p2p, "oline-c-right-forward"),
        ];
        cloudflare_update_p2p_domains(&entries, &c_eps, &cf_token, &cf_zone).await;
    }
}

// ── SSH init: push scripts and signal Phase A ───────────────────────────────

/// Push scripts to the snapshot node with retry, then signal it to start syncing.
/// Returns `true` if the signal succeeded (snapshot is bootstrapping).
async fn push_and_signal_snapshot(w: &OLineWorkflow, scripts_path: &str, nginx_path: &str) -> bool {
    let snapshot_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-snapshot");
    if snapshot_eps.is_empty() {
        return false;
    }

    tracing::info!("  [init] Pushing scripts to snapshot node...");
    let mut attempt = 0u32;
    let pushed = loop {
        match push_scripts_sftp(
            "init-snapshot",
            &snapshot_eps,
            &w.ctx.ssh_key_path,
            scripts_path,
            Some(nginx_path),
        )
        .await
        {
            Ok(_) => break true,
            Err(e) => {
                attempt += 1;
                if attempt >= MAX_RETRIES as u32 {
                    tracing::warn!(
                        "  [init] Script push to snapshot failed after {}: {}",
                        attempt,
                        e
                    );
                    break false;
                }
                tracing::info!(
                    "  [init] SSH not ready yet ({}/{}): {} — retrying in 5s",
                    attempt,
                    MAX_RETRIES,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    };

    if !pushed {
        return false;
    }

    let mut snap_refresh = node_refresh_vars(&w.ctx.a_vars, "SNAP");
    inject_p2p_nodeport(&mut snap_refresh, &snapshot_eps, "oline-a-snapshot");
    match verify_files_and_signal_start(
        "init-snapshot",
        &snapshot_eps,
        &w.ctx.ssh_key_path,
        &[],
        &snap_refresh,
    )
    .await
    {
        Ok(_) => {
            tracing::info!("  [init] Snapshot signaled — sync started.");
            true
        }
        Err(e) => {
            tracing::warn!(
                "  [init] Snapshot signal failed: {} — will retry in WaitSnapshotReady.",
                e
            );
            false
        }
    }
}

/// Push scripts to seed and minio nodes (Phase A), and sentry nodes (B/C).
async fn push_scripts_to_remaining_nodes(w: &OLineWorkflow, scripts_path: &str, nginx_path: &str) {
    // Phase A: seed node
    let seed_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-seed");
    if !seed_eps.is_empty() {
        tracing::info!("  [init] Pushing scripts to seed node...");
        let _ = push_scripts_sftp(
            "init-seed",
            &seed_eps,
            &w.ctx.ssh_key_path,
            scripts_path,
            Some(nginx_path),
        )
        .await;
        let mut seed_refresh = node_refresh_vars(&w.ctx.a_vars, "SEED");
        inject_p2p_nodeport(&mut seed_refresh, &seed_eps, "oline-a-seed");
        let _ = verify_files_and_signal_start(
            "init-seed",
            &seed_eps,
            &w.ctx.ssh_key_path,
            &[],
            &seed_refresh,
        )
        .await;
    }

    // Phase A: minio node
    let minio_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-minio-ipfs");
    if !minio_eps.is_empty() {
        tracing::info!("  [init] Pushing scripts to minio node...");
        let _ = push_scripts_sftp(
            "init-minio",
            &minio_eps,
            &w.ctx.ssh_key_path,
            scripts_path,
            None,
        )
        .await;
    }

    // Phase B: tackle nodes (push only; signal comes in SignalAllNodes)
    push_scripts_to_sentry_services(w, DeployPhase::Tackles, scripts_path).await;

    // Phase C: forward nodes (push only; signal + peers come in InjectPeers)
    push_scripts_to_sentry_services(w, DeployPhase::Forwards, scripts_path).await;
}

/// Push scripts to all sentry services in a phase (no signal — just file delivery).
async fn push_scripts_to_sentry_services(
    w: &OLineWorkflow,
    phase: DeployPhase,
    scripts_path: &str,
) {
    let services: &[&str] = match phase {
        DeployPhase::Tackles => &["oline-b-left-node", "oline-b-right-node"],
        DeployPhase::Forwards => &["oline-c-left-node", "oline-c-right-node"],
        _ => return,
    };
    let all_eps = w.ctx.endpoints(phase).to_vec();
    for svc in services {
        let eps: Vec<_> = all_eps
            .iter()
            .filter(|e| e.service == *svc)
            .cloned()
            .collect();
        if !eps.is_empty() {
            tracing::info!("  [init] Pushing scripts to {}...", svc);
            let _ = push_scripts_sftp(svc, &eps, &w.ctx.ssh_key_path, scripts_path, None).await;
        }
    }
}

/// Detect whether a pre-start snapshot exists (for testing).
fn has_pre_start_snapshot() -> bool {
    let snap_env =
        std::env::var("E2E_SNAP_PATH").or_else(|_| std::env::var("OLINE_PRE_START_SNAP"));
    tracing::info!("  [debug] OLINE_PRE_START_SNAP env = {:?}", snap_env);
    if let Ok(ref p) = snap_env {
        tracing::info!(
            "  [debug] file exists? {}",
            std::path::Path::new(p).exists()
        );
    }
    std::env::var("E2E_SNAP_PATH")
        .or_else(|_| std::env::var("OLINE_PRE_START_SNAP"))
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists())
        .is_some()
}

/// Push scripts to all nodes and signal Phase A to start syncing.
async fn ssh_init_all_nodes(w: &mut OLineWorkflow) {
    let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());
    let nginx_path = var("OLINE_NGINX_PATH").unwrap_or_else(|_| "plays/flea-flicker/nginx".into());

    if !has_pre_start_snapshot() {
        if push_and_signal_snapshot(w, &scripts_path, &nginx_path).await {
            w.ctx.phase_a_bootstrapped = true;
        }
        push_scripts_to_remaining_nodes(w, &scripts_path, &nginx_path).await;
    } else {
        tracing::info!(
            "  [init] Pre-start snapshot detected — deferring Phase A signal to WaitSnapshotReady."
        );
        // Still push scripts to B/C sentry nodes.
        push_scripts_to_sentry_services(w, DeployPhase::Tackles, &scripts_path).await;
        push_scripts_to_sentry_services(w, DeployPhase::Forwards, &scripts_path).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2: DeployAllUnits — orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Deploy all phases, storing state + endpoints before snapshot sync.
///
/// Phases B and C are deployed with empty peer/statesync vars (`SNAPSHOT_MODE=sftp`).
/// The entrypoint will wait for the deployer to push the snapshot archive before
/// starting the chain process. Peer injection happens in `inject_peers` after
/// snapshot sync.
pub async fn deploy_all_units(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n-- Parallel: deploy all units (concurrent MsgCreateDeployment) --");

    // 1. Phase selection prompts.
    let (run_b, run_c, run_e) = match prompt_phase_selection(w, lines)? {
        Some(flags) => flags,
        None => return Ok(StepResult::Complete),
    };

    // 2. Build SDL template variables for all active phases.
    let (a_vars, b_vars, c_vars, e_vars) = build_all_sdl_vars(w, run_b, run_c, run_e).await?;

    // 3. Load SDL templates, render with vars, and build PhaseSlot descriptors.
    let slots = build_phase_slots(
        w,
        run_b,
        run_c,
        run_e,
        a_vars,
        b_vars,
        c_vars,
        e_vars.clone(),
    )?;

    // 4. Build and broadcast MsgCreateDeployment batch.
    tracing::info!("  Building multi-signer batch (1 tx for all MsgCreateDeployment)...");
    let is_direct = w.ctx.units.is_empty();
    let d0 = deployer_for_index(&w.ctx, 0);
    let querier = &d0.client.signing_client().querier;
    let base_dseq: u64 = querier
        .block_height()
        .await
        .map_err(|e| DeployError::Query(format!("block_height for dseq: {}", e)))?;
    let deposit_amount: u64 = 5_000_000; // 0.5 ACT
    let deposit_denom = "uact";
    tracing::info!(base_dseq, "  Base dseq for deployments");

    if is_direct {
        ensure_act_for_deposits(
            &w.ctx.deployer,
            &w.ctx.deployer.signer,
            deposit_amount,
            slots.len() as u64,
        )
        .await?;
    }

    let dseqs = broadcast_create_deployments(
        w,
        &slots,
        base_dseq,
        deposit_amount,
        deposit_denom,
        is_direct,
    )
    .await?;

    // 5. Create DeploymentState objects with assigned dseqs.
    let mut states = create_deployment_states(&slots, &w.ctx, &dseqs);

    // 6. Wait for bids on all active phases.
    let phases_with_bids = wait_for_all_bids(&w.ctx, slots, &mut states).await?;

    // 7. Provider selection (interactive or two-step non-interactive flow).
    let phases_selected = match select_providers_for_all(w, lines, phases_with_bids).await? {
        Some(p) => p,
        None => return Ok(StepResult::Continue), // two-step: waiting for --select
    };

    // 8. Batch CreateLease for all phases in one transaction.
    let mut leased_phases = create_leases_batch(w, phases_selected, is_direct).await?;

    // 9. JWT + SendManifest + WaitForEndpoints for all phases.
    let manifest_results = complete_manifests(w, &mut leased_phases, is_direct).await?;

    // 10. Record results, register nodes, update session state.
    let ssh_port_internal: u16 = var("SSH_P")
        .unwrap_or_else(|_| "22".into())
        .parse()
        .unwrap_or(22);
    let session_key_name = format!("{}/ssh-key", w.ctx.session.id);
    let key_name = w
        .ctx
        .ssh_key_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or(session_key_name);
    let password = w.ctx.deployer.password.clone();

    for (idx, result) in manifest_results {
        let phase = &leased_phases[idx];
        match result {
            Ok(endpoints) => {
                // Build a slot reference with the correct vars (Phase E needs its own).
                let slot_ref = PhaseSlot {
                    phase: phase.slot.phase.clone(),
                    select_key: phase.slot.select_key,
                    label: phase.slot.label,
                    rendered_sdl: String::new(), // not needed for recording
                    vars: if phase.slot.phase == DeployPhase::Relayer {
                        e_vars.clone()
                    } else {
                        phase.slot.vars.clone()
                    },
                    unit_index: phase.slot.unit_index,
                    session_phase: phase.slot.session_phase,
                    node_services: phase.slot.node_services.clone(),
                    phase_letter: phase.slot.phase_letter,
                };

                record_deployed_phase(
                    w,
                    &slot_ref,
                    &phase.state,
                    &endpoints,
                    &key_name,
                    &password,
                    ssh_port_internal,
                )
                .await?;

                if phase.slot.phase == DeployPhase::SpecialTeams {
                    w.ctx.statesync_rpc = extract_statesync_rpc(&endpoints);
                }

                w.ctx.set_endpoints(phase.slot.phase.clone(), endpoints);
                w.ctx
                    .set_state(phase.slot.phase.clone(), phase.state.clone());
            }
            Err(e) => {
                if phase.slot.phase == DeployPhase::SpecialTeams {
                    return Err(e); // Phase A is required
                }
                tracing::warn!(
                    "  Phase {} completion failed: {} — skipping.",
                    phase.slot.phase_letter,
                    e
                );
                w.ctx
                    .set_phase_result(phase.slot.phase.clone(), PhaseResult::Failed(e.to_string()));
            }
        }
    }

    // 11. DNS updates for all deployed phases.
    update_dns_after_deploy(w).await;

    // 12. SSH init — push scripts to all nodes; signal Phase A.
    ssh_init_all_nodes(w).await;

    w.step = OLineStep::SelectAllProviders;
    Ok(StepResult::Continue)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 3: SelectAllProviders
// ─────────────────────────────────────────────────────────────────────────────

/// Provider selection is handled inside `deploy_phase_with_selection`.
/// This step is a named checkpoint for observability; it transitions straight
/// to `UpdateAllDns`. (DNS also updated per-phase during DeployAllUnits for
/// earlier propagation.)
pub async fn select_all_providers(
    w: &mut OLineWorkflow,
    _lines: &mut Lines<impl BufRead>,
) -> Result<StepResult, DeployError> {
    tracing::info!("  [parallel] All providers selected — proceeding to DNS update.");
    w.step = OLineStep::UpdateAllDns;
    Ok(StepResult::Continue)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 4: UpdateAllDns
// ─────────────────────────────────────────────────────────────────────────────

/// Update Cloudflare DNS for all phases that have SDL content + endpoints.
pub async fn update_all_dns(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let cf_token = w.ctx.deployer.config.val("OLINE_CF_API_TOKEN");
    let cf_zone = w.ctx.deployer.config.val("OLINE_CF_ZONE_ID");

    // Test/CI mode: stop here after verifying deployments were created.
    // Set OLINE_TEST_STOP_AFTER_DEPLOY=1 to prevent the workflow from
    // attempting SSH cert delivery / snapshot sync against real containers.
    if var("OLINE_TEST_STOP_AFTER_DEPLOY").is_ok() {
        tracing::info!(
            "  [test] OLINE_TEST_STOP_AFTER_DEPLOY set — stopping after deploy verification."
        );
        tracing::info!(
            "  Phase A DSEQ: {}",
            w.ctx
                .state(DeployPhase::SpecialTeams)
                .and_then(|s| s.dseq)
                .unwrap_or(0)
        );
        tracing::info!(
            "  Phase B DSEQ: {}",
            w.ctx
                .state(DeployPhase::Tackles)
                .and_then(|s| s.dseq)
                .unwrap_or(0)
        );
        tracing::info!(
            "  Phase C DSEQ: {}",
            w.ctx
                .state(DeployPhase::Forwards)
                .and_then(|s| s.dseq)
                .unwrap_or(0)
        );
        w.step = OLineStep::Summary;
        return Ok(StepResult::Continue);
    }

    if cf_token.is_empty() || cf_zone.is_empty() {
        tracing::info!(
            "  Note: Cloudflare DNS not configured — update CNAMEs for accept domains manually."
        );
        w.step = OLineStep::WaitSnapshotReady {
            timeout_secs: var("OLINE_SNAP_SYNC_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
        };
        return Ok(StepResult::Continue);
    }

    tracing::info!("  Updating Cloudflare DNS for all phases...");

    // HTTP/HTTPS accept domains (proxied through Cloudflare)
    for phase in [
        DeployPhase::SpecialTeams,
        DeployPhase::Tackles,
        DeployPhase::Forwards,
        DeployPhase::Relayer,
    ] {
        if let Some(state) = w.ctx.state(phase.clone()) {
            if let Some(ref sdl) = state.sdl_content {
                let eps = w.ctx.endpoints(phase).to_vec();
                if !eps.is_empty() {
                    cloudflare_update_accept_domains(sdl, &eps, &cf_token, &cf_zone).await;
                }
            }
        }
    }

    // P2P domains: DNS-only A records (NOT proxied — raw TCP for CometBFT P2P)
    {
        let cfg = &w.ctx.deployer.config;
        let val = |k: &str| {
            let v = cfg.val(k);
            if v.is_empty() {
                String::new()
            } else {
                v
            }
        };

        let a_eps = w.ctx.endpoints(DeployPhase::SpecialTeams).to_vec();
        if !a_eps.is_empty() {
            let snap_p2p: u16 = val("P2P_P_SNAP").parse().unwrap_or(26656);
            let seed_p2p: u16 = val("P2P_P_SEED").parse().unwrap_or(26656);
            let d_snap = val("P2P_D_SNAP");
            let d_seed = val("P2P_D_SEED");
            let entries = [
                (d_snap.as_str(), snap_p2p, "oline-a-snapshot"),
                (d_seed.as_str(), seed_p2p, "oline-a-seed"),
            ];
            cloudflare_update_p2p_domains(&entries, &a_eps, &cf_token, &cf_zone).await;
        }

        let b_eps = w.ctx.endpoints(DeployPhase::Tackles).to_vec();
        if !b_eps.is_empty() {
            let tl_p2p: u16 = val("P2P_P_TL").parse().unwrap_or(26656);
            let tr_p2p: u16 = val("P2P_P_TR").parse().unwrap_or(26656);
            let d_tl = val("P2P_D_TL");
            let d_tr = val("P2P_D_TR");
            let entries = [
                (d_tl.as_str(), tl_p2p, "oline-b-left-tackle"),
                (d_tr.as_str(), tr_p2p, "oline-b-right-tackle"),
            ];
            cloudflare_update_p2p_domains(&entries, &b_eps, &cf_token, &cf_zone).await;
        }

        let c_eps = w.ctx.endpoints(DeployPhase::Forwards).to_vec();
        if !c_eps.is_empty() {
            let fl_p2p: u16 = val("P2P_P_FL").parse().unwrap_or(26656);
            let fr_p2p: u16 = val("P2P_P_FR").parse().unwrap_or(26656);
            let d_fl = val("P2P_D_FL");
            let d_fr = val("P2P_D_FR");
            let entries = [
                (d_fl.as_str(), fl_p2p, "oline-c-left-forward"),
                (d_fr.as_str(), fr_p2p, "oline-c-right-forward"),
            ];
            cloudflare_update_p2p_domains(&entries, &c_eps, &cf_token, &cf_zone).await;
        }
    }

    let timeout_secs: u64 = var("OLINE_SNAP_SYNC_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);

    w.step = OLineStep::WaitSnapshotReady { timeout_secs };
    Ok(StepResult::Continue)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 5: WaitSnapshotReady
// ─────────────────────────────────────────────────────────────────────────────

/// Wait for the snapshot node's RPC to come up and its peer ID to become available.
///
/// If Phase A nodes were not yet signaled during `deploy_all_units` (i.e.,
/// `phase_a_bootstrapped == false`), this step also pushes scripts and signals
/// them now.  When early bootstrap succeeded, the signal is skipped here to
/// avoid launching a second process on the snapshot node.
pub async fn wait_snapshot_ready(
    w: &mut OLineWorkflow,
    timeout_secs: u64,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Parallel: signal Phase A + wait for snapshot sync ──");

    let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());
    let nginx_path = var("OLINE_NGINX_PATH").unwrap_or_else(|_| "plays/flea-flicker/nginx".into());

    // Build pre-start files (snapshot archive if available for testing).
    let pre_start_files: Vec<PreStartFile> = {
        let snapshot_path = std::env::var("E2E_SNAP_PATH")
            .or_else(|_| std::env::var("OLINE_PRE_START_SNAP"))
            .ok()
            .map(std::path::PathBuf::from)
            .filter(|p| p.exists());
        let remote_path =
            std::env::var("SNAPSHOT_SFTP_PATH").unwrap_or_else(|_| "/tmp/snapshot.tar.lz4".into());
        match snapshot_path {
            Some(p) => vec![PreStartFile {
                source: FileSource::Path(p),
                remote_path,
            }],
            None => vec![],
        }
    };
    w.ctx.pre_start_files = pre_start_files;

    // Push scripts + signal snapshot start (skip if already done in deploy_all_units).
    let snapshot_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-snapshot");
    if !snapshot_eps.is_empty() {
        // Always push pre-start files (snapshot archive) if present — idempotent.
        push_pre_start_files(
            "parallel-snapshot",
            &snapshot_eps,
            &w.ctx.ssh_key_path,
            &w.ctx.pre_start_files,
            MAX_RETRIES,
        )
        .await
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;

        if w.ctx.phase_a_bootstrapped {
            tracing::info!(
                "  [Phase A] Snapshot already signaled during deploy — skipping re-signal."
            );
        } else {
            let _ = push_scripts_sftp(
                "parallel-snapshot",
                &snapshot_eps,
                &w.ctx.ssh_key_path,
                &scripts_path,
                Some(&nginx_path),
            )
            .await;

            let remote_paths: Vec<String> = w
                .ctx
                .pre_start_files
                .iter()
                .map(|f| f.remote_path.clone())
                .collect();
            let mut snap_refresh = node_refresh_vars(&w.ctx.a_vars, "SNAP");
            inject_p2p_nodeport(&mut snap_refresh, &snapshot_eps, "oline-a-snapshot");
            verify_files_and_signal_start(
                "parallel-snapshot",
                &snapshot_eps,
                &w.ctx.ssh_key_path,
                &remote_paths,
                &snap_refresh,
            )
            .await
            .map_err(|e| DeployError::InvalidState(e.to_string()))?;
        }
    }

    // Push scripts + signal seed start (skip if already done in deploy_all_units).
    let seed_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-seed");
    if !seed_eps.is_empty() {
        if w.ctx.phase_a_bootstrapped {
            tracing::info!("  [Phase A] Seed already signaled during deploy — skipping re-signal.");
        } else {
            let _ = push_scripts_sftp(
                "parallel-seed",
                &seed_eps,
                &w.ctx.ssh_key_path,
                &scripts_path,
                Some(&nginx_path),
            )
            .await;
            let mut seed_refresh = node_refresh_vars(&w.ctx.a_vars, "SEED");
            inject_p2p_nodeport(&mut seed_refresh, &seed_eps, "oline-a-seed");
            let _ = verify_files_and_signal_start(
                "parallel-seed",
                &seed_eps,
                &w.ctx.ssh_key_path,
                &[],
                &seed_refresh,
            )
            .await;
        }
    }

    // Push scripts to minio (no signal needed; minio starts automatically).
    // Idempotent: safe to push again even if done early in deploy_all_units.
    let minio_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-minio-ipfs");
    if !minio_eps.is_empty() {
        if !w.ctx.phase_a_bootstrapped {
            let _ = push_scripts_sftp(
                "parallel-minio",
                &minio_eps,
                &w.ctx.ssh_key_path,
                &scripts_path,
                None,
            )
            .await;
        } else {
            tracing::info!("  [Phase A] Minio scripts already pushed during deploy — skipping.");
        }
    }

    // Wait for snapshot RPC to come up and resolve the snapshot peer ID.
    let a_eps = w.ctx.endpoints(DeployPhase::SpecialTeams);
    let snap_rpc = OLineDeployer::find_endpoint_by_internal_port(a_eps, "oline-a-snapshot", 26657)
        .map(|e| format!("http://{}:{}", endpoint_hostname(&e.uri), e.port));
    let snap_p2p = OLineDeployer::find_endpoint_by_internal_port(a_eps, "oline-a-snapshot", 26656)
        .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    if let (Some(rpc), Some(p2p)) = (snap_rpc, snap_p2p) {
        tracing::info!(
            "  Waiting up to {}m for snapshot node to sync (catching_up = false)...",
            timeout_secs / 60
        );

        // ── Background log stream: show container output during wait ──
        // Spawn a task that streams provider container logs so the operator
        // can see bootstrap progress, snapshot extraction, sync status, etc.
        // instead of just "Peer ID fetch attempt N/120" polling messages.
        let log_abort = {
            use akash_deploy_rs::logs::ws::WsLogStream;
            use akash_deploy_rs::{LogStreamConfig, ProviderAuth};
            use futures_util::StreamExt;

            let phase_a_state = w.ctx.state(DeployPhase::SpecialTeams);
            let provider_addr = phase_a_state.and_then(|s| s.selected_provider.clone());
            let host_uri = provider_addr
                .as_ref()
                .and_then(|addr| w.ctx.provider_hosts.get(addr).cloned());
            let lease_id = phase_a_state.and_then(|s| s.lease_id.clone());

            if let (Some(host), Some(lease)) = (host_uri, lease_id) {
                let jwt = w.ctx.deployer.client.generate_jwt(&lease.owner).await.ok();
                if let Some(jwt) = jwt {
                    let config = LogStreamConfig::new()
                        .with_follow(true)
                        .with_tail(20)
                        .with_service("oline-a-snapshot");
                    let auth = ProviderAuth::Jwt { token: jwt };
                    let handle = tokio::spawn(async move {
                        match WsLogStream::connect(&host, &lease, &auth, &config).await {
                            Ok(mut stream) => {
                                while let Some(line) = stream.next().await {
                                    match line {
                                        Ok(msg) => {
                                            // Prefix with [oline] for clarity
                                            let trimmed = msg.message.trim();
                                            if !trimmed.is_empty() {
                                                tracing::info!("  [oline] {}", trimmed);
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::debug!("  [log-stream] Could not connect: {}", e);
                            }
                        }
                    });
                    Some(handle)
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Use a generous initial wait since snapshot sync takes ~30 min in production.
        let boot_wait = var("OLINE_RPC_INITIAL_WAIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120u64);
        let max_retries = (timeout_secs / 30).min(120) as u32;

        match OLineDeployer::extract_peer_id_with_boot_wait(&rpc, &p2p, boot_wait, max_retries, 30)
            .await
        {
            Some(peer) => {
                tracing::info!("  [snapshot] Peer: {}", peer);
                w.ctx.set_peer(PeerTarget::Snapshot, peer);
            }
            None => {
                tracing::info!("  Warning: snapshot peer ID not resolved within timeout.");
            }
        }

        // Stop background log stream
        if let Some(handle) = log_abort {
            handle.abort();
        }
    }

    w.step = OLineStep::DistributeSnapshot;
    Ok(StepResult::Continue)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 6: DistributeSnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// SSH-stream the snapshot data directory from the snapshot node to all waiting
/// nodes (seed, left/right tackles, left/right forwards) concurrently.
pub async fn distribute_snapshot(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Parallel: distribute snapshot ──");

    let snapshot_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-snapshot");
    if snapshot_eps.is_empty() {
        tracing::info!("  Warning: no snapshot endpoints — skipping snapshot distribution.");
        w.step = OLineStep::SignalAllNodes;
        return Ok(StepResult::Continue);
    }

    let format = var("OLINE_SNAP_SAVE_FORMAT").unwrap_or_else(|_| "tar.lz4".into());
    let remote_data_dir =
        var("OLINE_SNAP_REMOTE_DATA_DIR").unwrap_or_else(|_| "/root/.terpd/data".into());
    let secrets_path = var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
    let local_path: PathBuf = format!("{}/oline-parallel-snapshot.{}", secrets_path, format).into();
    let remote_snapshot_path =
        var("SNAPSHOT_SFTP_PATH").unwrap_or_else(|_| "/tmp/snapshot.tar.lz4".into());

    // Fetch from snapshot node (cached on disk if already present).
    fetch_snapshot_from_node(
        "parallel-snapshot",
        &snapshot_eps,
        &w.ctx.ssh_key_path,
        &remote_data_dir,
        &local_path,
        &format,
    )
    .await
    .map_err(|e| DeployError::InvalidState(format!("Snapshot fetch failed: {}", e)))?;

    // Fetch genesis.json from the snapshot node (not in the snapshot — lives in config/).
    let genesis_local: PathBuf = format!("{}/oline-parallel-genesis.json", secrets_path).into();
    let remote_genesis = format!(
        "{}/config/genesis.json",
        remote_data_dir.trim_end_matches("/data")
    );
    fetch_genesis_from_node(
        "parallel-snapshot",
        &snapshot_eps,
        &w.ctx.ssh_key_path,
        &remote_genesis,
        &genesis_local,
    )
    .await
    .map_err(|e| DeployError::InvalidState(format!("Genesis fetch failed: {}", e)))?;
    let genesis_bytes = std::fs::read(&genesis_local)
        .map_err(|e| DeployError::InvalidState(format!("Cannot read genesis: {}", e)))?;

    // Collect all target endpoint sets.
    let seed_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-seed");
    let lt_eps = w
        .ctx
        .service_endpoints(DeployPhase::Tackles, "oline-b-left-node");
    let rt_eps = w
        .ctx
        .service_endpoints(DeployPhase::Tackles, "oline-b-right-node");
    let lf_eps = w
        .ctx
        .service_endpoints(DeployPhase::Forwards, "oline-c-left-node");
    let rf_eps = w
        .ctx
        .service_endpoints(DeployPhase::Forwards, "oline-c-right-node");

    let key = &w.ctx.ssh_key_path;
    let rp = &remote_snapshot_path;

    // Push snapshot + genesis to all waiting nodes in parallel.
    // Each target gets its own SSH process so they transfer concurrently.
    // tokio::join! runs all futures on the current task (no Send required).
    tracing::info!("  Distributing snapshot to all nodes in parallel...");

    /// Push snapshot (+ genesis for B/C) to a single target node.
    async fn push_one(
        label: &str,
        eps: &[akash_deploy_rs::ServiceEndpoint],
        key: &std::path::PathBuf,
        local_path: &std::path::Path,
        rp: &str,
        genesis: Option<&[u8]>,
    ) {
        if eps.is_empty() {
            return;
        }
        if let Err(e) = push_snapshot_to_node(label, eps, key, local_path, rp).await {
            tracing::info!("  Warning: snapshot push to {} failed: {}", label, e);
            return;
        }
        if let Some(genesis_bytes) = genesis {
            if let Err(e) = push_pre_start_files(
                label,
                eps,
                key,
                &[PreStartFile {
                    source: FileSource::Bytes(genesis_bytes.to_vec()),
                    remote_path: "/tmp/genesis.json".into(),
                }],
                MAX_RETRIES,
            )
            .await
            {
                tracing::info!("  Warning: genesis push to {} failed: {}", label, e);
            }
        }
    }

    let gen = genesis_bytes.as_slice();
    let sync_method = w.ctx.deployer.config.val("OLINE_SYNC_METHOD");
    let skip_bc = sync_method == "statesync";
    if skip_bc {
        tracing::info!(
            "  OLINE_SYNC_METHOD=statesync — skipping B/C snapshot push (they will statesync)"
        );
    }

    tokio::join!(
        push_one("parallel-seed", &seed_eps, key, &local_path, rp, None),
        async {
            if !skip_bc {
                push_one(
                    "parallel-left-tackle",
                    &lt_eps,
                    key,
                    &local_path,
                    rp,
                    Some(gen),
                )
                .await
            }
        },
        async {
            if !skip_bc {
                push_one(
                    "parallel-right-tackle",
                    &rt_eps,
                    key,
                    &local_path,
                    rp,
                    Some(gen),
                )
                .await
            }
        },
        async {
            if !skip_bc {
                push_one(
                    "parallel-left-forward",
                    &lf_eps,
                    key,
                    &local_path,
                    rp,
                    Some(gen),
                )
                .await
            }
        },
        async {
            if !skip_bc {
                push_one(
                    "parallel-right-forward",
                    &rf_eps,
                    key,
                    &local_path,
                    rp,
                    Some(gen),
                )
                .await
            }
        },
    );

    w.step = OLineStep::SignalAllNodes;
    Ok(StepResult::Continue)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 7: SignalAllNodes
// ─────────────────────────────────────────────────────────────────────────────

/// Signal Phase B (tackles) and Phase C (forwards) to start.
///
/// Phase A was already signalled in `wait_snapshot_ready`.
pub async fn signal_all_nodes(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Parallel: signal Phase B + C ──");

    let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());
    let boot_wait: u64 = var("OLINE_RPC_INITIAL_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);

    // Auto-fetch statesync trust params from Phase A RPC if not manually set.
    let sync_method = w.ctx.deployer.config.val("OLINE_SYNC_METHOD");
    if sync_method == "statesync" {
        let has_height = !w
            .ctx
            .deployer
            .config
            .val("STATESYNC_TRUST_HEIGHT")
            .is_empty();
        if !has_height {
            let rpc = if w.ctx.statesync_rpc.is_empty() {
                w.ctx.deployer.config.val("STATESYNC_RPC_SERVERS")
            } else {
                w.ctx.statesync_rpc.clone()
            };
            tracing::info!("  Fetching statesync trust params from {}...", rpc);
            match fetch_statesync_trust_params(&rpc).await {
                Ok((height, hash)) => {
                    tracing::info!("  trust_height={} trust_hash={}", height, hash);
                    w.ctx
                        .deployer
                        .config
                        .set_value("STATESYNC_TRUST_HEIGHT", height);
                    w.ctx
                        .deployer
                        .config
                        .set_value("STATESYNC_TRUST_HASH", hash);
                }
                Err(e) => {
                    tracing::warn!("  Failed to fetch trust params: {} — nodes will auto-fetch from entrypoint", e);
                }
            }
        }
    }

    let mut config = w.ctx.deployer.config.clone();
    //    w.ctx.peer(PeerTarget::Snapshot),
    //     &w.ctx.statesync_rpc,
    let b_vars = build_phase_b_vars(&config);

    // Signal left tackle.
    let lt_eps = w
        .ctx
        .service_endpoints(DeployPhase::Tackles, "oline-b-left-node");
    if !lt_eps.is_empty() {
        let _ = push_scripts_sftp(
            "parallel-left-tackle",
            &lt_eps,
            &w.ctx.ssh_key_path,
            &scripts_path,
            None,
        )
        .await;
        let mut lt_refresh = node_refresh_vars(&b_vars, "TL");
        inject_p2p_nodeport(&mut lt_refresh, &lt_eps, "oline-b-left-tackle");
        let _ = verify_files_and_signal_start(
            "parallel-left-tackle",
            &lt_eps,
            &w.ctx.ssh_key_path,
            &["/tmp/genesis.json".to_string()],
            &lt_refresh,
        )
        .await;
    }

    // Signal right tackle.
    let rt_eps = w
        .ctx
        .service_endpoints(DeployPhase::Tackles, "oline-b-right-node");
    if !rt_eps.is_empty() {
        let _ = push_scripts_sftp(
            "parallel-right-tackle",
            &rt_eps,
            &w.ctx.ssh_key_path,
            &scripts_path,
            None,
        )
        .await;
        let mut rt_refresh = node_refresh_vars(&b_vars, "TR");
        inject_p2p_nodeport(&mut rt_refresh, &rt_eps, "oline-b-right-tackle");
        let _ = verify_files_and_signal_start(
            "parallel-right-tackle",
            &rt_eps,
            &w.ctx.ssh_key_path,
            &["/tmp/genesis.json".to_string()],
            &rt_refresh,
        )
        .await;
    }

    w.step = OLineStep::InjectPeers;
    let _ = boot_wait;
    Ok(StepResult::Continue)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 8: InjectPeers
// ─────────────────────────────────────────────────────────────────────────────

/// Wait for tackle peer IDs, then inject peers into Phase C (forwards).
///
/// Tackles bootstrap from the snapshot peer.  Once they're up and we have their
/// peer IDs, we push updated env vars to the forwards so they can connect.
pub async fn inject_peers(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Parallel: wait tackle peers + inject into forwards ──");

    let b_eps = w.ctx.endpoints(DeployPhase::Tackles).to_vec();

    // Wait for left tackle peer ID.
    let lt_rpc = OLineDeployer::find_endpoint_by_internal_port(&b_eps, "oline-b-left-node", 26657)
        .map(|e| format!("http://{}:{}", endpoint_hostname(&e.uri), e.port));
    let lt_p2p = OLineDeployer::find_endpoint_by_internal_port(&b_eps, "oline-b-left-node", 26656)
        .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    if let (Some(rpc), Some(p2p)) = (lt_rpc, lt_p2p) {
        let boot_wait: u64 = var("OLINE_RPC_INITIAL_WAIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        if let Some(peer) =
            OLineDeployer::extract_peer_id_with_boot_wait(&rpc, &p2p, boot_wait, 20, 60).await
        {
            tracing::info!("  [left-tackle] Peer: {}", peer);
            w.ctx.set_peer(PeerTarget::LeftTackle, peer);
        }
    }

    // Wait for right tackle peer ID (no extra boot wait — should be ready by now).
    let rt_rpc = OLineDeployer::find_endpoint_by_internal_port(&b_eps, "oline-b-right-node", 26657)
        .map(|e| format!("http://{}:{}", endpoint_hostname(&e.uri), e.port));
    let rt_p2p = OLineDeployer::find_endpoint_by_internal_port(&b_eps, "oline-b-right-node", 26656)
        .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    if let (Some(rpc), Some(p2p)) = (rt_rpc, rt_p2p) {
        if let Some(peer) =
            OLineDeployer::extract_peer_id_with_boot_wait(&rpc, &p2p, 0, 20, 60).await
        {
            tracing::info!("  [right-tackle] Peer: {}", peer);
            w.ctx.set_peer(PeerTarget::RightTackle, peer);
        }
    }

    // Signal Phase C (forwards) if not already done, injecting tackle peers.
    let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());

    let mut config = w.ctx.deployer.config.clone();
    // w.ctx.peer(PeerTarget::Seed),
    //     w.ctx.peer(PeerTarget::Snapshot),
    //     w.ctx.peer(PeerTarget::LeftTackle),
    //     w.ctx.peer(PeerTarget::RightTackle),
    //     &w.ctx.statesync_rpc.clone(),
    let c_vars = build_phase_c_vars(&w.ctx.deployer.config);

    let lf_eps = w
        .ctx
        .service_endpoints(DeployPhase::Forwards, "oline-c-left-node");
    if !lf_eps.is_empty() {
        let _ = push_scripts_sftp(
            "parallel-left-forward",
            &lf_eps,
            &w.ctx.ssh_key_path,
            &scripts_path,
            None,
        )
        .await;
        let mut lf_refresh = node_refresh_vars(&c_vars, "FL");
        inject_p2p_nodeport(&mut lf_refresh, &lf_eps, "oline-c-left-forward");
        let _ = verify_files_and_signal_start(
            "parallel-left-forward",
            &lf_eps,
            &w.ctx.ssh_key_path,
            &["/tmp/genesis.json".to_string()],
            &lf_refresh,
        )
        .await;
    }

    let rf_eps = w
        .ctx
        .service_endpoints(DeployPhase::Forwards, "oline-c-right-node");
    if !rf_eps.is_empty() {
        let _ = push_scripts_sftp(
            "parallel-right-forward",
            &rf_eps,
            &w.ctx.ssh_key_path,
            &scripts_path,
            None,
        )
        .await;
        let mut rf_refresh = node_refresh_vars(&c_vars, "FR");
        inject_p2p_nodeport(&mut rf_refresh, &rf_eps, "oline-c-right-forward");
        let _ = verify_files_and_signal_start(
            "parallel-right-forward",
            &rf_eps,
            &w.ctx.ssh_key_path,
            &["/tmp/genesis.json".to_string()],
            &rf_refresh,
        )
        .await;
    }

    let boot_wait: u64 = var("OLINE_RPC_INITIAL_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);

    w.step = OLineStep::WaitAllPeers {
        boot_wait_secs: boot_wait,
    };
    Ok(StepResult::Continue)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 9: WaitAllPeers
// ─────────────────────────────────────────────────────────────────────────────

/// Wait for all node peer IDs concurrently.
///
/// Seed peer ID is resolved here (snapshot was already resolved in WaitSnapshotReady).
/// Tackle peer IDs were resolved in InjectPeers.
pub async fn wait_all_peers(
    w: &mut OLineWorkflow,
    _boot_wait_secs: u64,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Parallel: wait for all peer connections ──");

    // Resolve seed peer if not already set.
    if w.ctx.peer(PeerTarget::Seed).is_empty() {
        let a_eps = w.ctx.endpoints(DeployPhase::SpecialTeams).to_vec();
        let seed_rpc = OLineDeployer::find_endpoint_by_internal_port(&a_eps, "oline-a-seed", 26657)
            .map(|e| format!("http://{}:{}", endpoint_hostname(&e.uri), e.port));
        let seed_p2p = OLineDeployer::find_endpoint_by_internal_port(&a_eps, "oline-a-seed", 26656)
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

        if let (Some(rpc), Some(p2p)) = (seed_rpc, seed_p2p) {
            if let Some(peer) =
                OLineDeployer::extract_peer_id_with_boot_wait(&rpc, &p2p, 0, 20, 60).await
            {
                tracing::info!("  [seed] Peer: {}", peer);
                w.ctx.set_peer(PeerTarget::Seed, peer);
            }
        }
    }

    tracing::info!("  Peer summary:");
    for target in PeerTarget::ALL {
        let id = w.ctx.peer(target.clone());
        if !id.is_empty() {
            tracing::info!("    {}: {}", target.key(), id);
        } else {
            tracing::info!("    {}: (not resolved)", target.key());
        }
    }

    w.step = OLineStep::Summary;
    Ok(StepResult::Continue)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure dseq assignment logic (extracted for testability)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the dseq to assign to each slot.
///
/// - Direct mode (`is_direct = true`): each slot gets a unique dseq starting at
///   `base_dseq` and incrementing by 1. All deployments share one Akash account,
///   so unique dseqs are required to avoid conflicts.
/// - HD mode (`is_direct = false`): all slots get the same `base_dseq` because
///   each slot deploys from a distinct child account — dseq namespaces are
///   per-owner, so reuse is safe.
///
/// Returns a `Vec<u64>` of length `num_slots`.
fn assign_dseqs(base_dseq: u64, num_slots: usize, is_direct: bool) -> Vec<u64> {
    (0..num_slots)
        .map(|i| {
            if is_direct {
                base_dseq + i as u64
            } else {
                base_dseq
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::assign_dseqs;

    #[test]
    fn test_dseq_assignment_direct_mode() {
        // 4 phases in direct mode — each should get base, base+1, base+2, base+3.
        let base: u64 = 1_000;
        let dseqs = assign_dseqs(base, 4, true);
        assert_eq!(dseqs, vec![1_000, 1_001, 1_002, 1_003]);
    }

    #[test]
    fn test_dseq_assignment_hd_mode() {
        // 4 phases in HD mode — all should share the same base dseq.
        let base: u64 = 5_500;
        let dseqs = assign_dseqs(base, 4, false);
        assert_eq!(dseqs, vec![5_500, 5_500, 5_500, 5_500]);
    }

    #[test]
    fn test_dseq_assignment_partial_phases() {
        // Only 2 phases active (A + B) in direct mode.
        let base: u64 = 42;
        let dseqs = assign_dseqs(base, 2, true);
        assert_eq!(dseqs, vec![42, 43]);
    }

    #[test]
    fn test_dseq_assignment_single_phase_direct() {
        // Single phase — offset never increments, result is just base.
        let base: u64 = 9_999;
        let dseqs = assign_dseqs(base, 1, true);
        assert_eq!(dseqs, vec![9_999]);
    }

    #[test]
    fn test_dseq_assignment_single_phase_hd() {
        // Single phase HD — same behaviour as direct for 1 slot.
        let base: u64 = 9_999;
        let dseqs = assign_dseqs(base, 1, false);
        assert_eq!(dseqs, vec![9_999]);
    }

    #[test]
    fn test_dseq_assignment_zero_slots() {
        // Edge case: no slots — should return empty vec.
        let dseqs = assign_dseqs(100, 0, true);
        assert!(dseqs.is_empty());
    }
}

pub async fn deploy_special_teams(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Phase 1: Deploy Snapshot + Seed nodes ──");
    if !prompt_continue(lines, "Deploy Kickoff (Special Teams)?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?
    {
        tracing::info!("Aborted.");
        w.step = OLineStep::Complete;
        return Ok(StepResult::Complete);
    }

    let secrets_path = crate::config::oline_config_dir()
        .to_string_lossy()
        .into_owned();
    let a_vars = build_phase_a_vars(
        &w.ctx.deployer.config,
        &Path::new(&secrets_path),
        &w.ctx.deployer.password,
    )
    .await
    .map_err(|e| DeployError::InvalidState(format!("build_phase_a_vars: {}", e)))?;
    tracing::info!("  Deploying...");
    let sdl = w
        .ctx
        .deployer
        .config
        .load_sdl("a.yml")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;

    let (a_state, mut a_api) = w
        .ctx
        .deployer
        .deploy_phase_with_selection(&sdl, &a_vars, "oline-phase-a", lines)
        .await?;

    tracing::info!("Deployed! DSEQ: {}", a_state.dseq.unwrap());

    {
        let needs_ingress = |svc: &str| -> bool {
            !a_api.iter().any(|e| {
                e.service == svc && e.internal_port == 0 && (e.port == 443 || e.port == 80)
            })
        };
        let missing: Vec<&str> = ["oline-a-snapshot", "oline-a-seed", "oline-a-minio-ipfs"]
            .iter()
            .copied()
            .filter(|svc| !a_api.iter().any(|e| e.service.as_str() == *svc) || needs_ingress(svc))
            .collect();

        if !missing.is_empty() {
            tracing::info!(
                "  [endpoints] {} service(s) missing from initial query: {} — refreshing from provider API",
                missing.len(),
                missing.join(", ")
            );
            if let (Some(provider_addr), Some(lease_id), Some(jwt)) = (
                a_state.selected_provider.as_deref(),
                a_state.lease_id.as_ref(),
                a_state.jwt_token.as_deref(),
            ) {
                match w
                    .ctx
                    .deployer
                    .client
                    .query_provider_info(provider_addr)
                    .await
                {
                    Ok(Some(info)) => {
                        let auth = ProviderAuth::Jwt {
                            token: jwt.to_string(),
                        };
                        match w
                            .ctx
                            .deployer
                            .client
                            .query_provider_status(&info.host_uri, lease_id, &auth)
                            .await
                        {
                            Ok(status) => {
                                let before = a_api.len();
                                for ep in status.endpoints {
                                    let dup = a_api.iter().any(|e| {
                                        e.service == ep.service
                                            && e.internal_port == ep.internal_port
                                    });
                                    if !dup {
                                        //TODO: create function for service ednpoint to define endport
                                        tracing::info!(
                                            "  [endpoints] {} :{} → NodePort {} ({})",
                                            ep.service,
                                            ep.internal_port,
                                            ep.port,
                                            ep.uri
                                        );
                                        a_api.push(ep);
                                    }
                                }
                                tracing::info!(
                                    "  [endpoints] refreshed: {} → {} total",
                                    before,
                                    a_api.len()
                                );
                            }
                            Err(e) => {
                                tracing::info!("  Warning: provider status query failed: {}", e)
                            }
                        }
                    }
                    Ok(None) => {
                        tracing::info!("  Warning: provider '{}' not found", provider_addr)
                    }
                    Err(e) => tracing::info!("  Warning: could not query provider info: {}", e),
                }
            } else {
                tracing::info!(
                    "  Warning: deployment state missing provider/lease/jwt — cannot refresh endpoints"
                );
            }
        }
    }

    w.ctx
        .deployer
        .deployment_store
        .save(
            &DeploymentRecord::from_state(&a_state, &w.ctx.deployer.password)
                .map_err(|e| DeployError::InvalidState(e.to_string()))?,
        )
        .await
        .ok();

    {
        let ssh_port_internal: u16 = var("SSH_P")
            .unwrap_or_else(|_| "22".into())
            .parse()
            .unwrap_or(22);
        let key_name = format!("{}", a_state.dseq.unwrap());
        register_phase_nodes(
            &a_api,
            a_state.dseq.unwrap_or(0),
            &[
                ("oline-a-snapshot", "Phase A - Snapshot"),
                ("oline-a-seed", "Phase A - Seed"),
                ("oline-a-minio-ipfs", "Phase A - MinIO"),
            ],
            &key_name,
            "A",
            &w.ctx.deployer.password,
            ssh_port_internal,
        );
    }

    let ssh_key_path = crate::config::oline_config_dir().join(a_state.dseq.unwrap().to_string());
    let ssh_privkey_pem = a_vars
        .get("SSH_PRIVKEY")
        .ok_or_else(|| DeployError::InvalidState("SSH_PRIVKEY missing from phase-A vars".into()))?
        .clone();

    // Save SSH key encrypted to disk for subsequent SFTP/SSH steps.
    {
        use crate::crypto::save_ssh_key_encrypted;
        use ssh_key::PrivateKey;
        let k = PrivateKey::from_openssh(ssh_privkey_pem.as_bytes())
            .map_err(|e| DeployError::InvalidState(format!("Invalid SSH key: {}", e)))?;
        save_ssh_key_encrypted(&k, &ssh_key_path, &w.ctx.deployer.password)
            .map_err(|e| DeployError::InvalidState(format!("save SSH key: {}", e)))?;
    }

    // Build pre_start_files from env: if a local snapshot archive exists, deliver
    // it to each node before signaling bootstrap start.  In production, nodes
    // self-download; the list is empty so push_pre_start_files is a no-op.
    let pre_start_files: Vec<PreStartFile> = {
        let snapshot_path = std::env::var("E2E_SNAP_PATH")
            .or_else(|_| std::env::var("OLINE_PRE_START_SNAP"))
            .ok()
            .map(std::path::PathBuf::from)
            .filter(|p| p.exists());
        let remote_path =
            std::env::var("SNAPSHOT_SFTP_PATH").unwrap_or_else(|_| "/tmp/snapshot.tar.lz4".into());
        match snapshot_path {
            Some(p) => {
                tracing::info!("  [phase-a] Pre-start snapshot: {:?} → {}", p, remote_path);
                vec![PreStartFile {
                    source: FileSource::Path(p),
                    remote_path,
                }]
            }
            None => {
                tracing::info!("  [phase-a] No local snapshot — nodes will self-download.");
                vec![]
            }
        }
    };

    // Build statesync RPC string for Phase B (cosmos format: "host:port,host:port")
    let snap_rpc_ep =
        OLineDeployer::find_endpoint_by_internal_port(&a_api, "oline-a-snapshot", 26657);
    let seed_rpc_ep = OLineDeployer::find_endpoint_by_internal_port(&a_api, "oline-a-seed", 26657);
    let statesync_rpc = {
        let s = snap_rpc_ep
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port))
            .unwrap_or_default();
        let sd = seed_rpc_ep
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port))
            .unwrap_or_default();
        match (s.is_empty(), sd.is_empty()) {
            (false, false) => format!("{},{}", s, sd),
            (false, true) => s,
            (true, false) => sd,
            (true, true) => String::new(),
        }
    };

    // Print Phase A public endpoints
    {
        let get = |k: &str| a_vars.get(k).map(|s| s.as_str()).unwrap_or("");
        tracing::info!(
            "\n  ┌── Phase A Public Endpoints ──────────────────────────────────────────"
        );
        for (label, rpc, api, grpc, p2p, p2p_port) in [
            (
                "Snapshot",
                "RPC_D_SNAP",
                "API_D_SNAP",
                "GRPC_D_SNAP",
                "P2P_D_SNAP",
                "P2P_P_SNAP",
            ),
            (
                "Seed    ",
                "RPC_D_SEED",
                "API_D_SEED",
                "GRPC_D_SEED",
                "P2P_D_SEED",
                "P2P_P_SEED",
            ),
        ] {
            let (rpc_d, api_d, grpc_d, p2p_d, p2p_p) =
                (get(rpc), get(api), get(grpc), get(p2p), get(p2p_port));
            if !rpc_d.is_empty() {
                tracing::info!("  │  {} RPC:   https://{}", label, rpc_d);
            }
            if !api_d.is_empty() {
                tracing::info!("  │  {} API:   https://{}", label, api_d);
            }
            if !grpc_d.is_empty() {
                tracing::info!("  │  {} gRPC:  {}", label, grpc_d);
            }
            if !p2p_d.is_empty() {
                tracing::info!("  │  {} P2P:   {}:{}", label, p2p_d, p2p_p);
            }
        }
        let metadata_url = get("SNAPSHOT_METADATA_URL");
        let dl_domain = get("SNAPSHOT_DOWNLOAD_DOMAIN");
        if !metadata_url.is_empty() {
            tracing::info!("  │");
            tracing::info!("  │  Snapshot metadata: {}", metadata_url);
        }
        if !dl_domain.is_empty() {
            tracing::info!("  │  MinIO download:    https://{}", dl_domain);
        }
        tracing::info!(
            "  └──────────────────────────────────────────────────────────────────────\n"
        );
    }

    // Populate context
    w.ctx.ssh_key_path = ssh_key_path;
    w.ctx.ssh_privkey_pem = ssh_privkey_pem;
    w.ctx.pre_start_files = pre_start_files;
    w.ctx.a_vars = a_vars;
    w.ctx.statesync_rpc = statesync_rpc;
    w.ctx.set_endpoints(DeployPhase::SpecialTeams, a_api);
    w.ctx.set_state(DeployPhase::SpecialTeams, a_state);
    w.ctx.set_phase_result(
        DeployPhase::SpecialTeams,
        crate::workflow::context::PhaseResult::Deployed,
    );
    w.step = OLineStep::UpdateDns(DeployPhase::SpecialTeams);
    Ok(StepResult::Continue)
}

pub async fn update_dns(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let cf_token = w.ctx.deployer.config.val("OLINE_CF_API_TOKEN");
    let cf_zone = w.ctx.deployer.config.val("OLINE_CF_ZONE_ID");
    if !cf_token.is_empty() && !cf_zone.is_empty() {
        let eps = w.ctx.endpoints(DeployPhase::SpecialTeams).to_vec();

        // HTTP/HTTPS accept domains (proxied through Cloudflare)
        tracing::info!("  Updating Cloudflare DNS for accept domains...");
        let sdl = w
            .ctx
            .state(DeployPhase::SpecialTeams)
            .and_then(|s| s.sdl_content.clone());
        if let Some(sdl) = sdl {
            cloudflare_update_accept_domains(&sdl, &eps, &cf_token, &cf_zone).await;
        }

        // P2P domains: DNS-only A records (NOT proxied — raw TCP for CometBFT P2P)
        let vars = &w.ctx.a_vars;
        let get = |k: &str| vars.get(k).map(|s| s.as_str()).unwrap_or("");
        let snap_p2p: u16 = get("P2P_P_SNAP").parse().unwrap_or(26656);
        let seed_p2p: u16 = get("P2P_P_SEED").parse().unwrap_or(26656);
        let p2p_entries = [
            (get("P2P_D_SNAP"), snap_p2p, "oline-a-snapshot"),
            (get("P2P_D_SEED"), seed_p2p, "oline-a-seed"),
        ];
        cloudflare_update_p2p_domains(&p2p_entries, &eps, &cf_token, &cf_zone).await;
    } else {
        tracing::info!(
            "  Note: Cloudflare DNS not configured — update CNAMEs for accept domains manually."
        );
    }

    w.step = OLineStep::PushFiles(NodeTarget::Snapshot);
    Ok(StepResult::Continue)
}

pub async fn push_files_snapshot(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());
    let nginx_path = var("OLINE_NGINX_PATH").unwrap_or_else(|_| "plays/flea-flicker/nginx".into());

    let snapshot_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-snapshot");
    if snapshot_eps.is_empty() {
        tracing::info!(
            "  Warning: no endpoints found for oline-a-snapshot — skipping file delivery"
        );
    } else {
        tracing::info!("  Delivering pre-start files to snapshot node...");
        push_pre_start_files(
            "phase-a-snapshot",
            &snapshot_eps,
            &w.ctx.ssh_key_path,
            &w.ctx.pre_start_files,
            MAX_RETRIES,
        )
        .await
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;

        if let Err(e) = push_scripts_sftp(
            "phase-a-snapshot",
            &snapshot_eps,
            &w.ctx.ssh_key_path,
            &scripts_path,
            Some(&nginx_path),
        )
        .await
        {
            tracing::info!("  Warning: script upload to snapshot failed: {}", e);
        }
    }

    w.step = OLineStep::SignalStart(NodeTarget::Snapshot);
    Ok(StepResult::Continue)
}

pub async fn signal_snapshot_start(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let snapshot_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-snapshot");
    if snapshot_eps.is_empty() {
        tracing::info!(
            "  Warning: no endpoints found for oline-a-snapshot — skipping verify+start"
        );
    } else {
        let remote_paths: Vec<String> = w
            .ctx
            .pre_start_files
            .iter()
            .map(|f| f.remote_path.clone())
            .collect();
        let mut snapshot_refresh = node_refresh_vars(&w.ctx.a_vars, "SNAP");
        inject_p2p_nodeport(&mut snapshot_refresh, &snapshot_eps, "oline-a-snapshot");
        verify_files_and_signal_start(
            "phase-a-snapshot",
            &snapshot_eps,
            &w.ctx.ssh_key_path,
            &remote_paths,
            &snapshot_refresh,
        )
        .await
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;
    }

    // Print SSH access for all phase-A nodes before the boot wait
    {
        let ssh_port: u16 = var("SSH_P")
            .unwrap_or_else(|_| "22".into())
            .parse()
            .unwrap_or(22);
        tracing::info!("  Phase-A node access (use during boot wait):");
        for (label, service) in [
            ("snapshot", "oline-a-snapshot"),
            ("seed    ", "oline-a-seed"),
            ("minio   ", "oline-a-minio-ipfs"),
        ] {
            if let Some(ep) = w
                .ctx
                .endpoints(DeployPhase::SpecialTeams)
                .iter()
                .find(|e| e.service == service && e.internal_port == ssh_port)
            {
                tracing::info!(
                    "    [{}]  ssh -i {} -o StrictHostKeyChecking=no -p {} root@{}",
                    label,
                    w.ctx.ssh_key_path.display(),
                    ep.port,
                    endpoint_hostname(&ep.uri),
                );
            }
        }
    }

    let boot_wait = var("OLINE_RPC_INITIAL_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120u64);

    w.step = OLineStep::WaitPeer {
        target: PeerTarget::Snapshot,
        boot_wait_secs: boot_wait,
    };
    Ok(StepResult::Continue)
}

pub async fn wait_snapshot_peer(
    w: &mut OLineWorkflow,
    boot_wait_secs: u64,
) -> Result<StepResult, DeployError> {
    let a_eps = w.ctx.endpoints(DeployPhase::SpecialTeams);
    let snap_rpc_url =
        OLineDeployer::find_endpoint_by_internal_port(a_eps, "oline-a-snapshot", 26657)
            .map(|e| format!("http://{}:{}", endpoint_hostname(&e.uri), e.port));
    let snap_p2p_addr =
        OLineDeployer::find_endpoint_by_internal_port(a_eps, "oline-a-snapshot", 26656)
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    let snapshot_peer = match (snap_rpc_url.as_deref(), snap_p2p_addr.as_deref()) {
        (Some(rpc), Some(p2p)) => {
            OLineDeployer::extract_peer_id_with_boot_wait(rpc, p2p, boot_wait_secs, 10, 30)
                .await
                .unwrap_or_else(|| {
                    tracing::info!(
                        "  Warning: no RPC/P2P NodePort for snapshot — seed will start without private peer"
                    );
                    String::new()
                })
        }
        _ => {
            tracing::info!(
                "  Warning: no RPC/P2P NodePort for snapshot — seed will start without private peer"
            );
            String::new()
        }
    };
    if !snapshot_peer.is_empty() {
        tracing::info!("  [snapshot] Private peer: {}", snapshot_peer);
    }
    w.ctx.set_peer(PeerTarget::Snapshot, snapshot_peer);

    w.step = OLineStep::PushFiles(NodeTarget::Seed);
    Ok(StepResult::Continue)
}

pub async fn push_files_seed(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());
    let nginx_path = var("OLINE_NGINX_PATH").unwrap_or_else(|_| "plays/flea-flicker/nginx".into());

    let seed_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-seed");
    if seed_eps.is_empty() {
        tracing::info!("  Warning: no endpoints found for oline-a-seed — skipping file delivery");
    } else {
        tracing::info!("  Delivering pre-start files to seed node...");
        push_pre_start_files(
            "phase-a-seed",
            &seed_eps,
            &w.ctx.ssh_key_path,
            &w.ctx.pre_start_files,
            MAX_RETRIES,
        )
        .await
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;

        if let Err(e) = push_scripts_sftp(
            "phase-a-seed",
            &seed_eps,
            &w.ctx.ssh_key_path,
            &scripts_path,
            Some(&nginx_path),
        )
        .await
        {
            tracing::info!("  Warning: script upload to seed failed: {}", e);
        }
    }

    w.step = OLineStep::SignalStart(NodeTarget::Seed);
    Ok(StepResult::Continue)
}

pub async fn signal_seed_start(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let seed_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-seed");
    if !seed_eps.is_empty() {
        let snapshot_peer = w.ctx.peer(PeerTarget::Snapshot).to_string();
        let mut seed_refresh = node_refresh_vars(&w.ctx.a_vars, "SEED");
        inject_p2p_nodeport(&mut seed_refresh, &seed_eps, "oline-a-seed");
        if !snapshot_peer.is_empty() {
            // Private peer: don't gossip this ID to the network.
            seed_refresh.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), snapshot_peer.clone());
            // Persistent peer: always maintain a connection to the snapshot node.
            seed_refresh.insert("TERPD_P2P_PERSISTENT_PEERS".into(), snapshot_peer.clone());
            tracing::info!(
                "  [seed] Injecting snapshot peer (private+persistent): {}",
                snapshot_peer
            );
        }
        let remote_paths: Vec<String> = w
            .ctx
            .pre_start_files
            .iter()
            .map(|f| f.remote_path.clone())
            .collect();
        verify_files_and_signal_start(
            "phase-a-seed",
            &seed_eps,
            &w.ctx.ssh_key_path,
            &remote_paths,
            &seed_refresh,
        )
        .await
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;
    }

    w.step = OLineStep::PushFiles(NodeTarget::Minio);
    Ok(StepResult::Continue)
}

pub async fn push_files_minio(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    // init-nginx on the minio node only installs+starts sshd when
    // SNAPSHOT_DOWNLOAD_DOMAIN is non-empty. Mirror that guard here.
    let snapshot_dl_domain = w
        .ctx
        .a_vars
        .get("OLINE_SNAP_DOWNLOAD_DOMAIN")
        .map(|s| s.as_str())
        .unwrap_or_default();

    if snapshot_dl_domain.is_empty() {
        tracing::info!(
            "  Note: OLINE_SNAP_DOWNLOAD_DOMAIN not set — skipping minio pre-start file delivery."
        );
    } else {
        let minio_endpoints = w
            .ctx
            .service_endpoints(DeployPhase::SpecialTeams, "oline-a-minio-ipfs");
        if minio_endpoints.is_empty() {
            tracing::info!(
                "  Warning: no endpoints found for oline-a-minio-ipfs — skipping file delivery"
            );
        } else {
            tracing::info!("  Delivering pre-start files to minio-ipfs node...");
            let minio_retries: u16 = var("MINIO_SFTP_RETRIES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60);
            push_pre_start_files(
                "phase-a-minio",
                &minio_endpoints,
                &w.ctx.ssh_key_path,
                &w.ctx.pre_start_files,
                minio_retries,
            )
            .await
            .map_err(|e| DeployError::InvalidState(e.to_string()))?;
        }
    }

    let boot_wait = var("OLINE_RPC_INITIAL_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300u64);

    w.step = OLineStep::WaitPeer {
        target: PeerTarget::Seed,
        boot_wait_secs: boot_wait,
    };
    Ok(StepResult::Continue)
}

pub async fn wait_seed_peer(
    w: &mut OLineWorkflow,
    boot_wait_secs: u64,
) -> Result<StepResult, DeployError> {
    let a_eps = w.ctx.endpoints(DeployPhase::SpecialTeams);
    let seed_rpc_url = OLineDeployer::find_endpoint_by_internal_port(a_eps, "oline-a-seed", 26657)
        .map(|e| format!("http://{}:{}", endpoint_hostname(&e.uri), e.port));
    let seed_p2p_addr = OLineDeployer::find_endpoint_by_internal_port(a_eps, "oline-a-seed", 26656)
        .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    let seed_peer = match (seed_rpc_url.as_deref(), seed_p2p_addr.as_deref()) {
        (Some(rpc), Some(p2p)) => {
            OLineDeployer::extract_peer_id_with_boot_wait(rpc, p2p, boot_wait_secs, 20, 60)
                .await
                .unwrap_or_else(|| {
                    tracing::info!(
                        "  Warning: could not fetch seed peer ID — Phase B will use empty peer."
                    );
                    String::new()
                })
        }
        _ => {
            tracing::info!(
                "  Warning: no RPC/P2P endpoints found for oline-a-seed — skipping peer ID"
            );
            String::new()
        }
    };

    tracing::info!("    snapshot_peer: {}", w.ctx.peer(PeerTarget::Snapshot));
    tracing::info!("    seed_peer:     {}", seed_peer);
    w.ctx.set_peer(PeerTarget::Seed, seed_peer);

    w.step = OLineStep::Deploy(DeployPhase::Tackles);
    Ok(StepResult::Continue)
}

pub async fn deploy_tackles(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Phase 2: Deploy Left & Right Tackles ──");
    if !prompt_continue(lines, "Deploy b.yml?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?
    {
        tracing::info!("  Skipping Phase B.");
        w.ctx
            .set_phase_result(DeployPhase::Tackles, PhaseResult::Skipped);
        w.step = OLineStep::Deploy(DeployPhase::Forwards);
        return Ok(StepResult::Continue);
    }

    let mut config = w.ctx.deployer.config.clone();
    let peer = w.ctx.peer(PeerTarget::Snapshot);
    let state_sync_rpc = &w.ctx.statesync_rpc;
    config.set_value("TERPD_P2P_PERSISTENT_PEERS", peer.to_string());
    config.set_value("STATESYNC_RPC_SERVERS", state_sync_rpc.into());
    let b_vars = build_phase_b_vars(&config);

    let sdl = match w.ctx.deployer.config.load_sdl("b.yml") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("  Phase B SDL error: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Tackles, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Deploy(DeployPhase::Forwards);
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deploying...");
    let (b_state, b_endpoints) = match w
        .ctx
        .deployer
        .deploy_phase_with_selection(&sdl, &b_vars, "oline-phase-b", lines)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("  Phase B deploy failed: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Tackles, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Deploy(DeployPhase::Forwards);
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deployed! DSEQ: {}", b_state.dseq.unwrap_or(0));
    w.ctx
        .deployer
        .deployment_store
        .save(
            &DeploymentRecord::from_state(&b_state, &w.ctx.deployer.password)
                .map_err(|e| DeployError::InvalidState(e.to_string()))?,
        )
        .await
        .ok();

    {
        let ssh_port_internal: u16 = std::env::var("SSH_P")
            .unwrap_or_else(|_| "22".into())
            .parse()
            .unwrap_or(22);
        let key_name = w
            .ctx
            .ssh_key_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "oline-ssh-key".into());
        register_phase_nodes(
            &b_endpoints,
            b_state.dseq.unwrap_or(0),
            &[
                ("oline-b-left-node", "Phase B - Left Tackle"),
                ("oline-b-right-node", "Phase B - Right Tackle"),
            ],
            &key_name,
            "B",
            &w.ctx.deployer.password,
            ssh_port_internal,
        );
    }

    w.ctx.set_endpoints(DeployPhase::Tackles, b_endpoints);
    w.ctx.set_state(DeployPhase::Tackles, b_state);
    w.ctx
        .set_phase_result(DeployPhase::Tackles, PhaseResult::Deployed);

    let boot_wait = std::env::var("OLINE_RPC_INITIAL_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300u64);

    w.step = OLineStep::WaitPeer {
        target: PeerTarget::LeftTackle,
        boot_wait_secs: boot_wait,
    };
    Ok(StepResult::Continue)
}

pub async fn wait_left_tackle(
    w: &mut OLineWorkflow,
    boot_wait_secs: u64,
) -> Result<StepResult, DeployError> {
    if !w.ctx.phase_deployed(&DeployPhase::Tackles) {
        w.step = OLineStep::WaitPeer {
            target: PeerTarget::RightTackle,
            boot_wait_secs: 0,
        };
        return Ok(StepResult::Continue);
    }
    let b_eps = w.ctx.endpoints(DeployPhase::Tackles);
    let left_rpc_url =
        OLineDeployer::find_endpoint_by_internal_port(b_eps, "oline-b-left-node", 26657)
            .map(|e| e.uri.clone());
    let left_p2p_addr =
        OLineDeployer::find_endpoint_by_internal_port(b_eps, "oline-b-left-node", 26656)
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    let left_tackle_peer = match (left_rpc_url.as_deref(), left_p2p_addr.as_deref()) {
        (Some(rpc), Some(p2p)) => {
            OLineDeployer::extract_peer_id_with_boot_wait(rpc, p2p, boot_wait_secs, 20, 60)
                .await
                .unwrap_or_else(|| {
                    tracing::info!("  Warning: could not fetch left-tackle peer ID.");
                    String::new()
                })
        }
        _ => {
            tracing::info!("  Warning: no endpoints for oline-b-left-node");
            String::new()
        }
    };
    w.ctx.set_peer(PeerTarget::LeftTackle, left_tackle_peer);

    w.step = OLineStep::WaitPeer {
        target: PeerTarget::RightTackle,
        boot_wait_secs: 0,
    };
    Ok(StepResult::Continue)
}

pub async fn wait_right_tackle(
    w: &mut OLineWorkflow,
    _boot_wait_secs: u64,
) -> Result<StepResult, DeployError> {
    if !w.ctx.phase_deployed(&DeployPhase::Tackles) {
        w.step = OLineStep::Deploy(DeployPhase::Forwards);
        return Ok(StepResult::Continue);
    }
    let b_eps = w.ctx.endpoints(DeployPhase::Tackles);
    let right_rpc_url =
        OLineDeployer::find_endpoint_by_internal_port(b_eps, "oline-b-right-node", 26657)
            .map(|e| e.uri.clone());
    let right_p2p_addr =
        OLineDeployer::find_endpoint_by_internal_port(b_eps, "oline-b-right-node", 26656)
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    let right_tackle_peer = match (right_rpc_url.as_deref(), right_p2p_addr.as_deref()) {
        (Some(rpc), Some(p2p)) => {
            // Right tackle waits 0s — it syncs in parallel with left; left already
            // burned the boot wait, so right is usually ready by the time we query.
            OLineDeployer::extract_peer_id_with_boot_wait(rpc, p2p, 0, 20, 60)
                .await
                .unwrap_or_else(|| {
                    tracing::info!("  Warning: could not fetch right-tackle peer ID.");
                    String::new()
                })
        }
        _ => {
            tracing::info!("  Warning: no endpoints for oline-b-right-node");
            String::new()
        }
    };
    w.ctx.set_peer(PeerTarget::RightTackle, right_tackle_peer);

    tracing::info!("    left_tackle:  {}", w.ctx.peer(PeerTarget::LeftTackle));
    tracing::info!("    right_tackle: {}", w.ctx.peer(PeerTarget::RightTackle));

    w.step = OLineStep::Deploy(DeployPhase::Forwards);
    Ok(StepResult::Continue)
}

pub async fn deploy_forwards(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Phase 3: Deploy Left & Right Forwards ──");

    if !w.ctx.phase_deployed(&DeployPhase::Tackles) {
        tracing::warn!("  Note: Phase B was not deployed — forwards will lack tackle peers.");
    }

    if !prompt_continue(lines, "Deploy c.yml?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?
    {
        tracing::info!("  Skipping Phase C.");
        w.ctx
            .set_phase_result(DeployPhase::Forwards, PhaseResult::Skipped);
        w.step = OLineStep::Deploy(DeployPhase::Relayer);
        return Ok(StepResult::Continue);
    }

    let mut config = w.ctx.deployer.config.clone();
    //  w.ctx.peer(PeerTarget::Seed),
    // w.ctx.peer(PeerTarget::Snapshot),
    // w.ctx.peer(PeerTarget::LeftTackle),
    // w.ctx.peer(PeerTarget::RightTackle),
    // &w.ctx.statesync_rpc,
    let c_vars = build_phase_c_vars(&config);

    let sdl = match w.ctx.deployer.config.load_sdl("c.yml") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("  Phase C SDL error: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Forwards, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Deploy(DeployPhase::Relayer);
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deploying...");
    let (c_state, c_endpoints) = match w
        .ctx
        .deployer
        .deploy_phase_with_selection(&sdl, &c_vars, "oline-phase-c", lines)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("  Phase C deploy failed: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Forwards, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Deploy(DeployPhase::Relayer);
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deployed! DSEQ: {}", c_state.dseq.unwrap_or(0));
    w.ctx
        .deployer
        .deployment_store
        .save(
            &DeploymentRecord::from_state(&c_state, &w.ctx.deployer.password)
                .map_err(|e| DeployError::InvalidState(e.to_string()))?,
        )
        .await
        .ok();

    {
        let ssh_port_internal: u16 = std::env::var("SSH_P")
            .unwrap_or_else(|_| "22".into())
            .parse()
            .unwrap_or(22);
        let key_name = w
            .ctx
            .ssh_key_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "oline-ssh-key".into());
        register_phase_nodes(
            &c_endpoints,
            c_state.dseq.unwrap_or(0),
            &[
                ("oline-c-left-node", "Phase C - Left Forward"),
                ("oline-c-right-node", "Phase C - Right Forward"),
            ],
            &key_name,
            "C",
            &w.ctx.deployer.password,
            ssh_port_internal,
        );
    }

    w.ctx.set_state(DeployPhase::Forwards, c_state);
    w.ctx
        .set_phase_result(DeployPhase::Forwards, PhaseResult::Deployed);

    w.step = OLineStep::Deploy(DeployPhase::Relayer);
    Ok(StepResult::Continue)
}

pub async fn deploy_relayer(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Phase 5: Deploy IBC Relayer ──");
    if !prompt_continue(lines, "Deploy e.yml?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?
    {
        tracing::info!("  Skipped.");
        w.ctx
            .set_phase_result(DeployPhase::Relayer, PhaseResult::Skipped);
        w.step = OLineStep::Summary;
        return Ok(StepResult::Continue);
    }

    let e_vars = build_phase_rly_vars(&w.ctx.deployer.config);

    let sdl = match w.ctx.deployer.config.load_sdl("e.yml") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("  Phase E SDL error: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Relayer, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Summary;
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deploying...");
    let (e_state, e_endpoints) = match w
        .ctx
        .deployer
        .deploy_phase_with_selection(&sdl, &e_vars, "oline-phase-e", lines)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("  Phase E deploy failed: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Relayer, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Summary;
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deployed! DSEQ: {}", e_state.dseq.unwrap_or(0));
    w.ctx
        .deployer
        .deployment_store
        .save(
            &DeploymentRecord::from_state(&e_state, &w.ctx.deployer.password)
                .map_err(|e| DeployError::InvalidState(e.to_string()))?,
        )
        .await
        .ok();

    // Phase E has its own SSH key — save to disk and register nodes.
    if let Some(privkey_pem) = e_vars.get("SSH_PRIVKEY") {
        let ssh_port_internal: u16 = std::env::var("SSH_P")
            .unwrap_or_else(|_| "22".into())
            .parse()
            .unwrap_or(22);
        let e_key_name = format!("oline-phase-e-key-{}", e_state.dseq.unwrap_or(0));
        let e_key_path = crate::config::oline_config_dir().join(&e_key_name);
        match ssh_key::PrivateKey::from_openssh(privkey_pem.as_bytes()) {
            Ok(k) => {
                if let Err(e) =
                    crate::crypto::save_ssh_key_encrypted(&k, &e_key_path, &w.ctx.deployer.password)
                {
                    tracing::warn!("  [Phase E] Failed to save SSH key: {}", e);
                } else {
                    let e_services: Vec<String> = e_endpoints
                        .iter()
                        .filter(|ep| ep.internal_port == ssh_port_internal)
                        .map(|ep| ep.service.clone())
                        .collect();
                    let e_svc_pairs: Vec<(&str, String)> = e_services
                        .iter()
                        .map(|svc| (svc.as_str(), format!("Phase E - {}", svc)))
                        .collect();
                    let e_svc_refs: Vec<(&str, &str)> =
                        e_svc_pairs.iter().map(|(s, l)| (*s, l.as_str())).collect();
                    register_phase_nodes(
                        &e_endpoints,
                        e_state.dseq.unwrap_or(0),
                        &e_svc_refs,
                        &e_key_name,
                        "E",
                        &w.ctx.deployer.password,
                        ssh_port_internal,
                    );
                }
            }
            Err(e) => tracing::warn!("  [Phase E] Invalid SSH key: {}", e),
        }
    }

    w.ctx.set_endpoints(DeployPhase::Relayer, e_endpoints);
    w.ctx.set_state(DeployPhase::Relayer, e_state);
    w.ctx
        .set_phase_result(DeployPhase::Relayer, PhaseResult::Deployed);

    w.step = OLineStep::UpdateDns(DeployPhase::Relayer);
    Ok(StepResult::Continue)
}

pub async fn update_dns_relayer(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    if !w.ctx.phase_deployed(&DeployPhase::Relayer) {
        w.step = OLineStep::Summary;
        return Ok(StepResult::Continue);
    }

    let cf_token = w.ctx.deployer.config.val("OLINE_CF_API_TOKEN");
    let cf_zone = w.ctx.deployer.config.val("OLINE_CF_ZONE_ID");

    if !cf_token.is_empty() && !cf_zone.is_empty() {
        let sdl = w
            .ctx
            .state(DeployPhase::Relayer)
            .and_then(|s| s.sdl_content.clone());
        if let Some(sdl) = sdl {
            let e_endpoints = w.ctx.endpoints(DeployPhase::Relayer).to_vec();
            cloudflare_update_accept_domains(&sdl, &e_endpoints, &cf_token, &cf_zone).await;
        }
    }

    w.step = OLineStep::Summary;
    Ok(StepResult::Continue)
}
