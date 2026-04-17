use crate::config::substitute_template_raw;
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
    providers::TrustedProviderStore,
    sessions::{AccountEntry, DeploymentEntry, FundingMethod},
    snapshots::{fetch_genesis_from_node, fetch_snapshot_from_node, push_snapshot_to_node},
    workflow::{
        context::{PhaseResult, UnitState},
        step::{DeployPhase, OLineStep, PeerTarget},
        OLineWorkflow, StepResult,
    },
    MAX_RETRIES,
};
use akash_deploy_rs::{
    broadcast_multi_signer, build_create_lease_msg, AkashBackend, AkashClient, Bid, BidId,
    DeployError, DeploymentRecord, DeploymentState, DeploymentStore, DeploymentWorkflow,
    ServiceEndpoint, SignerEntry, Step,
};
use std::{
    collections::HashMap,
    env::var,
    io::{BufRead, Lines},
    path::PathBuf,
};

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
async fn select_provider_for_phase(
    deployer: &OLineDeployer,
    bids: &[Bid],
    label: &str,
    lines: &mut Lines<impl BufRead>,
    trusted_store: &TrustedProviderStore,
    non_interactive: bool,
) -> Result<String, DeployError> {
    // Try trusted list first.
    if let Some(provider) = trusted_store.select_from_bids(bids) {
        return Ok(provider);
    }

    // No trusted provider bidding.
    if non_interactive {
        let cheapest = bids
            .iter()
            .min_by_key(|b| b.price)
            .ok_or_else(|| DeployError::InvalidState(format!("[{}] No bids received", label)))?;
        tracing::info!(
            "  [{}] No trusted provider — auto-selecting cheapest: {} ({} uakt/block)",
            label,
            cheapest.provider,
            cheapest.price
        );
        return Ok(cheapest.provider.clone());
    }

    // Interactive: show prompt.
    tracing::info!(
        "  [{}] No trusted provider bidding — select interactively:",
        label
    );
    deployer
        .interactive_select_provider(bids, lines)
        .await
        .map_err(|e| DeployError::InvalidState(format!("Provider selection failed: {}", e)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2: DeployAllUnits
// ─────────────────────────────────────────────────────────────────────────────

/// Deploy all phases sequentially, storing state + endpoints before snapshot sync.
///
/// Phases B and C are deployed with empty peer/statesync vars (`SNAPSHOT_MODE=sftp`).
/// The entrypoint will wait for the deployer to push the snapshot archive before
/// starting the chain process.  Peer injection happens in `inject_peers` after
/// snapshot sync.
pub async fn deploy_all_units(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Parallel: deploy all units (concurrent MsgCreateDeployment) ──");

    // ── 1. Phase selection prompts (sequential stdin — must complete before parallel deploy) ──
    if !prompt_continue(lines, "Deploy Phase A (Special Teams)?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?
    {
        tracing::info!("Aborted.");
        w.step = OLineStep::Complete;
        return Ok(StepResult::Complete);
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

    // ── 2. Build all SDL vars (sequential — Phase A is async: SSH keygen) ─────
    let secrets_path = var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
    let a_vars = build_phase_a_vars(&w.ctx.deployer.config, &secrets_path)
        .await
        .map_err(|e| DeployError::InvalidState(format!("build_phase_a_vars: {}", e)))?;

    // SSH key was saved by ensure_ssh_key inside build_phase_a_vars.
    {
        let ssh_privkey_pem = a_vars
            .get("SSH_PRIVKEY")
            .ok_or_else(|| {
                DeployError::InvalidState("SSH_PRIVKEY missing from phase-A vars".into())
            })?
            .clone();
        let key_path: PathBuf = a_vars
            .get("SSH_KEY_PATH")
            .map(|p| PathBuf::from(p))
            .unwrap_or_else(|| format!("{}/oline-parallel-key", secrets_path).into());
        w.ctx.ssh_key_path = key_path;
        w.ctx.ssh_privkey_pem = ssh_privkey_pem;
        w.ctx.a_vars = a_vars.clone();
    }

    // Share SSH pubkey from Phase A so the same key works across all units.
    let ssh_pubkey = a_vars.get("SSH_PUBKEY").cloned().unwrap_or_default();

    let mut b_vars = build_phase_b_vars(&w.ctx.deployer.config, "", "");
    b_vars.insert("SSH_PUBKEY".into(), ssh_pubkey.clone());

    let mut c_vars = build_phase_c_vars(&w.ctx.deployer.config, "", "", "", "", "");
    c_vars.insert("SSH_PUBKEY".into(), ssh_pubkey.clone());

    let e_vars = build_phase_rly_vars(&w.ctx.deployer.config);

    // ── 3. Load SDL templates ─────────────────────────────────────────────────
    let sdl_a = w
        .ctx
        .deployer
        .config
        .load_sdl("a.yml")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;

    let sdl_b: Option<String> = if run_b {
        match w.ctx.deployer.config.load_sdl("b.yml") {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!("  Phase B SDL error: {} — skipping.", e);
                w.ctx
                    .set_phase_result(DeployPhase::Tackles, PhaseResult::Failed(e.to_string()));
                None
            }
        }
    } else {
        None
    };

    let sdl_c: Option<String> = if run_c {
        match w.ctx.deployer.config.load_sdl("c.yml") {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!("  Phase C SDL error: {} — skipping.", e);
                w.ctx
                    .set_phase_result(DeployPhase::Forwards, PhaseResult::Failed(e.to_string()));
                None
            }
        }
    } else {
        None
    };

    let sdl_e: Option<String> = if run_e {
        match w.ctx.deployer.config.load_sdl("e.yml") {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!("  Phase E SDL error: {} — skipping.", e);
                w.ctx
                    .set_phase_result(DeployPhase::Relayer, PhaseResult::Failed(e.to_string()));
                None
            }
        }
    } else {
        None
    };

    // ── 4. Multi-signer batch deployment ────────────────────────────────────────
    //
    // All MsgCreateDeployment messages are assembled into a single multi-signer
    // transaction.  Each child account signs its own messages offline, then all
    // signatures are combined and broadcast atomically.  This reduces N+1 txs
    // (funding + N deployments) to exactly 2 txs (funding + batch deploy).
    tracing::info!("  Building multi-signer batch (1 tx for all MsgCreateDeployment)...");

    // Obtain deployer refs (immutable, from distinct UnitState objects).
    let d0: &_ = w
        .ctx
        .units
        .get(0)
        .map(|u| &u.deployer)
        .unwrap_or(&w.ctx.deployer);
    let d1: &_ = w
        .ctx
        .units
        .get(1)
        .map(|u| &u.deployer)
        .unwrap_or(&w.ctx.deployer);
    let d2: &_ = w
        .ctx
        .units
        .get(2)
        .map(|u| &u.deployer)
        .unwrap_or(&w.ctx.deployer);
    let d3: &_ = w
        .ctx
        .units
        .get(3)
        .map(|u| &u.deployer)
        .unwrap_or(&w.ctx.deployer);

    // 4a. Render SDL templates for each active phase.
    let rendered_a = substitute_template_raw(&sdl_a, &a_vars)
        .map_err(|e| DeployError::Template(format!("Phase A template: {}", e)))?;
    let rendered_b = sdl_b
        .as_deref()
        .map(|sdl| {
            substitute_template_raw(sdl, &b_vars)
                .map_err(|e| DeployError::Template(format!("Phase B template: {}", e)))
        })
        .transpose()?;
    let rendered_c = sdl_c
        .as_deref()
        .map(|sdl| {
            substitute_template_raw(sdl, &c_vars)
                .map_err(|e| DeployError::Template(format!("Phase C template: {}", e)))
        })
        .transpose()?;
    let rendered_e = sdl_e
        .as_deref()
        .map(|sdl| {
            substitute_template_raw(sdl, &e_vars)
                .map_err(|e| DeployError::Template(format!("Phase E template: {}", e)))
        })
        .transpose()?;

    // 4b. Get block height for shared dseq across all deployments.
    let querier = &d0.client.signing_client().querier;
    let dseq: u64 = querier
        .block_height()
        .await
        .map_err(|e| DeployError::Query(format!("block_height for dseq: {}", e)))?;
    let deposit_amount: u64 = 5_000_000; // 0.5 ACT — Akash min_deposits minimum
    let deposit_denom = "uact";

    tracing::info!(dseq, "  Base dseq for deployments");

    // 4c. Build MsgCreateDeployment for each active phase.
    // In Direct mode all deployments share the same owner, so each needs a unique
    // dseq. We use dseq, dseq+1, dseq+2, ... In HD mode each child has a different
    // owner so they can share the same dseq.
    let is_direct = w.ctx.units.is_empty();
    let mut dseq_offset: u64 = 0;
    let msg_a = d0.client.build_create_deployment_msg(
        &d0.client.address(),
        &rendered_a,
        deposit_amount,
        deposit_denom,
        dseq + dseq_offset,
    )?;
    if is_direct {
        dseq_offset += 1;
    }
    let msg_b = rendered_b
        .as_deref()
        .map(|sdl| {
            d1.client.build_create_deployment_msg(
                &d1.client.address(),
                sdl,
                deposit_amount,
                deposit_denom,
                dseq + dseq_offset,
            )
        })
        .transpose()?;
    if is_direct && msg_b.is_some() {
        dseq_offset += 1;
    }
    let msg_c = rendered_c
        .as_deref()
        .map(|sdl| {
            d2.client.build_create_deployment_msg(
                &d2.client.address(),
                sdl,
                deposit_amount,
                deposit_denom,
                dseq + dseq_offset,
            )
        })
        .transpose()?;
    if is_direct && msg_c.is_some() {
        dseq_offset += 1;
    }
    let msg_e = rendered_e
        .as_deref()
        .map(|sdl| {
            d3.client.build_create_deployment_msg(
                &d3.client.address(),
                sdl,
                deposit_amount,
                deposit_denom,
                dseq + dseq_offset,
            )
        })
        .transpose()?;

    // 4d. Build signer entries and broadcast batch.
    //
    // Direct mode (no child accounts): single master signer with all messages.
    // HD mode: one SignerEntry per child signer (existing multi-signer path).
    // Use the querier's chain_id (auto-detected from RPC /status) for tx signing.
    // The o-line config "chain.chain_id" is the deployment network name, NOT the
    // cosmos chain-id needed for SignDoc.
    let chain_id = querier.chain_config.chain_id.as_str();

    if is_direct {
        // Single signer (master) — all MsgCreateDeployment in one tx.
        // Avoids HD child derivation + uact bank_send (blocked by BME SendRestrictionFn).

        let mut all_msgs = vec![msg_a];
        if let Some(m) = msg_b {
            all_msgs.push(m);
        }
        if let Some(m) = msg_c {
            all_msgs.push(m);
        }
        if let Some(m) = msg_e {
            all_msgs.push(m);
        }

        // ── Ensure sufficient ACT for deposits ──────────────────────────────
        // BME mints ACT in the end-blocker, so the mint must be a separate tx
        // that confirms before we broadcast the deploy batch.
        let num_deploys = all_msgs.len() as u64;
        let total_act_needed = deposit_amount as u128 * num_deploys as u128;
        let master_addr = d0.client.address().to_string();
        let act_balance = d0
            .client
            .query_balance(&master_addr, "uact")
            .await
            .unwrap_or(0);

        if act_balance < total_act_needed {
            const MIN_MINT_UAKT: u128 = 25_000_000; // BME minimum mint = 25 ACT
            let shortfall = (total_act_needed - act_balance).max(MIN_MINT_UAKT);
            tracing::info!(
                total_act_needed,
                act_balance,
                shortfall,
                "  Minting ACT (burn {} uakt → uact) before deploy batch...",
                shortfall
            );
            let mint_tx = d0
                .client
                .broadcast_mint_act(&w.ctx.deployer.signer, &master_addr, shortfall as u64)
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
                let new_balance = d0
                    .client
                    .query_balance(&master_addr, "uact")
                    .await
                    .unwrap_or(0);
                if new_balance >= total_act_needed {
                    tracing::info!(new_balance, total_act_needed, "  ACT balance sufficient");
                    break;
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

        // ── Broadcast deploy batch ──────────────────────────────────────────
        // Re-query account after potential mint tx (sequence may have incremented).
        let acct = querier
            .base_account(d0.client.address_ref())
            .await
            .map_err(|e| DeployError::Query(format!("base_account master: {}", e)))?;

        tracing::info!(
            msgs = all_msgs.len(),
            chain_id,
            "  Broadcasting single-signer MsgCreateDeployment batch..."
        );

        let signer_entries = vec![SignerEntry {
            signer: &w.ctx.deployer.signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages: all_msgs,
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
        let acct_0 = querier
            .base_account(d0.client.address_ref())
            .await
            .map_err(|e| DeployError::Query(format!("base_account d0: {}", e)))?;

        let mnemonic = &w.ctx.deployer.config.mnemonic;
        let signer_0 = derive_child_signer(
            mnemonic,
            w.ctx.units.get(0).map(|u| u.hd_index).unwrap_or(0),
        )?;
        let mut signer_entries: Vec<SignerEntry<'_>> = vec![SignerEntry {
            signer: &signer_0,
            account_number: acct_0.account_number,
            sequence: acct_0.sequence,
            messages: vec![msg_a],
        }];

        let signer_1;
        let acct_1;
        if let Some(msg) = msg_b {
            acct_1 = querier
                .base_account(d1.client.address_ref())
                .await
                .map_err(|e| DeployError::Query(format!("base_account d1: {}", e)))?;
            signer_1 = derive_child_signer(
                mnemonic,
                w.ctx.units.get(1).map(|u| u.hd_index).unwrap_or(1),
            )?;
            signer_entries.push(SignerEntry {
                signer: &signer_1,
                account_number: acct_1.account_number,
                sequence: acct_1.sequence,
                messages: vec![msg],
            });
        }

        let signer_2;
        let acct_2;
        if let Some(msg) = msg_c {
            acct_2 = querier
                .base_account(d2.client.address_ref())
                .await
                .map_err(|e| DeployError::Query(format!("base_account d2: {}", e)))?;
            signer_2 = derive_child_signer(
                mnemonic,
                w.ctx.units.get(2).map(|u| u.hd_index).unwrap_or(2),
            )?;
            signer_entries.push(SignerEntry {
                signer: &signer_2,
                account_number: acct_2.account_number,
                sequence: acct_2.sequence,
                messages: vec![msg],
            });
        }

        let signer_3;
        let acct_3;
        if let Some(msg) = msg_e {
            acct_3 = querier
                .base_account(d3.client.address_ref())
                .await
                .map_err(|e| DeployError::Query(format!("base_account d3: {}", e)))?;
            signer_3 = derive_child_signer(
                mnemonic,
                w.ctx.units.get(3).map(|u| u.hd_index).unwrap_or(3),
            )?;
            signer_entries.push(SignerEntry {
                signer: &signer_3,
                account_number: acct_3.account_number,
                sequence: acct_3.sequence,
                messages: vec![msg],
            });
        }

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

    // 4f. Create DeploymentState objects with per-deployment dseq.
    // In Direct mode each deployment uses dseq, dseq+1, dseq+2, ... since they
    // share the same owner and DeploymentID = (owner, dseq) must be unique.
    let mut dseq_idx: u64 = 0;
    let mut state_a = DeploymentState::new("oline-phase-a", d0.client.address())
        .with_sdl(&rendered_a)
        .with_label("oline-phase-a");
    state_a.dseq = Some(dseq + dseq_idx);
    if is_direct {
        dseq_idx += 1;
    }

    let mut state_b_opt: Option<DeploymentState> = rendered_b.as_deref().map(|sdl| {
        let mut s = DeploymentState::new("oline-phase-b", d1.client.address())
            .with_sdl(sdl)
            .with_label("oline-phase-b");
        s.dseq = Some(dseq + dseq_idx);
        s
    });
    if is_direct && state_b_opt.is_some() {
        dseq_idx += 1;
    }

    let mut state_c_opt: Option<DeploymentState> = rendered_c.as_deref().map(|sdl| {
        let mut s = DeploymentState::new("oline-phase-c", d2.client.address())
            .with_sdl(sdl)
            .with_label("oline-phase-c");
        s.dseq = Some(dseq + dseq_idx);
        s
    });
    if is_direct && state_c_opt.is_some() {
        dseq_idx += 1;
    }

    let mut state_e_opt: Option<DeploymentState> = rendered_e.as_deref().map(|sdl| {
        let mut s = DeploymentState::new("oline-phase-e", d3.client.address())
            .with_sdl(sdl)
            .with_label("oline-phase-e");
        s.dseq = Some(dseq + dseq_idx);
        s
    });

    // Wait for bids concurrently on all active phases.
    type BidRes = Result<Vec<Bid>, DeployError>;
    type OptBidRes = Result<Option<Vec<Bid>>, DeployError>;

    let (bids_a_res, bids_b_res, bids_c_res, bids_e_res): (
        BidRes,
        OptBidRes,
        OptBidRes,
        OptBidRes,
    ) = tokio::join!(
        d0.wait_for_bids(&mut state_a, "oline-phase-a"),
        async {
            match state_b_opt.as_mut() {
                Some(s) => d1.wait_for_bids(s, "oline-phase-b").await.map(Some),
                None => Ok(None),
            }
        },
        async {
            match state_c_opt.as_mut() {
                Some(s) => d2.wait_for_bids(s, "oline-phase-c").await.map(Some),
                None => Ok(None),
            }
        },
        async {
            match state_e_opt.as_mut() {
                Some(s) => d3.wait_for_bids(s, "oline-phase-e").await.map(Some),
                None => Ok(None),
            }
        },
    );
    // d0..d3 borrows end here

    // Unpack bid results.  Phase A is required; B/C/E are non-fatal.
    let bids_a = bids_a_res?;

    let (mut state_b, bids_b) = match bids_b_res {
        Ok(Some(b)) => (state_b_opt, Some(b)),
        Ok(None) => (None, None),
        Err(e) => {
            tracing::warn!("  Phase B bid wait failed: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Tackles, PhaseResult::Failed(e.to_string()));
            (None, None)
        }
    };
    let (mut state_c, bids_c) = match bids_c_res {
        Ok(Some(b)) => (state_c_opt, Some(b)),
        Ok(None) => (None, None),
        Err(e) => {
            tracing::warn!("  Phase C bid wait failed: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Forwards, PhaseResult::Failed(e.to_string()));
            (None, None)
        }
    };
    let (mut state_e, bids_e) = match bids_e_res {
        Ok(Some(b)) => (state_e_opt, Some(b)),
        Ok(None) => (None, None),
        Err(e) => {
            tracing::warn!("  Phase E bid wait failed: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Relayer, PhaseResult::Failed(e.to_string()));
            (None, None)
        }
    };

    // ── 5. Phase 2: Sequential provider selection (queued prompts) ───────────
    //
    // For each phase that received bids:
    //   1. If a trusted provider is bidding → auto-select it
    //   2. If non-interactive mode → auto-select cheapest
    //   3. Otherwise → show interactive prompt (queued: one per phase)
    //
    // This ensures the operator sees all provider selection prompts in sequence,
    // can quickly submit each choice, and all lease creation proceeds in parallel.
    tracing::info!("  ── Provider selection (queued) ──");
    let trusted_store = TrustedProviderStore::open(TrustedProviderStore::default_path());
    let non_interactive = std::env::var("OLINE_NON_INTERACTIVE").is_ok()
        || std::env::var("OLINE_AUTO_SELECT").is_ok();

    // Phase A — required
    let choice_a = select_provider_for_phase(
        &w.ctx.deployer,
        &bids_a,
        "oline-phase-a",
        lines,
        &trusted_store,
        non_interactive,
    )
    .await?;
    DeploymentWorkflow::<AkashClient>::select_provider(&mut state_a, &choice_a)?;

    // Phase B
    if let (Some(ref bids), Some(ref mut state)) = (&bids_b, &mut state_b) {
        let choice = select_provider_for_phase(
            &w.ctx.deployer,
            bids,
            "oline-phase-b",
            lines,
            &trusted_store,
            non_interactive,
        )
        .await?;
        DeploymentWorkflow::<AkashClient>::select_provider(state, &choice)?;
    }

    // Phase C
    if let (Some(ref bids), Some(ref mut state)) = (&bids_c, &mut state_c) {
        let choice = select_provider_for_phase(
            &w.ctx.deployer,
            bids,
            "oline-phase-c",
            lines,
            &trusted_store,
            non_interactive,
        )
        .await?;
        DeploymentWorkflow::<AkashClient>::select_provider(state, &choice)?;
    }

    // Phase E
    if let (Some(ref bids), Some(ref mut state)) = (&bids_e, &mut state_e) {
        let choice = select_provider_for_phase(
            &w.ctx.deployer,
            bids,
            "oline-phase-e",
            lines,
            &trusted_store,
            non_interactive,
        )
        .await?;
        DeploymentWorkflow::<AkashClient>::select_provider(state, &choice)?;
    }

    // ── 6. Batch CreateLease (all phases in one tx) ────────────────────────

    // Build MsgCreateLease for each active phase.
    let mut lease_msgs: Vec<_> = Vec::new();

    // Phase A (required)
    let bid_a = find_bid_for_provider(&bids_a, state_a.selected_provider.as_ref().unwrap())?;
    let bid_id_a = BidId::from_bid(
        &state_a.owner,
        state_a.dseq.unwrap(),
        state_a.gseq,
        state_a.oseq,
        &bid_a,
    );
    lease_msgs.push(build_create_lease_msg(&bid_id_a));

    // Phase B (optional)
    let bid_id_b = if let (Some(ref bids), Some(ref state)) = (&bids_b, &state_b) {
        let bid = find_bid_for_provider(bids, state.selected_provider.as_ref().unwrap())?;
        let bid_id = BidId::from_bid(
            &state.owner,
            state.dseq.unwrap(),
            state.gseq,
            state.oseq,
            &bid,
        );
        lease_msgs.push(build_create_lease_msg(&bid_id));
        Some(bid_id)
    } else {
        None
    };

    // Phase C (optional)
    let bid_id_c = if let (Some(ref bids), Some(ref state)) = (&bids_c, &state_c) {
        let bid = find_bid_for_provider(bids, state.selected_provider.as_ref().unwrap())?;
        let bid_id = BidId::from_bid(
            &state.owner,
            state.dseq.unwrap(),
            state.gseq,
            state.oseq,
            &bid,
        );
        lease_msgs.push(build_create_lease_msg(&bid_id));
        Some(bid_id)
    } else {
        None
    };

    // Phase E (optional)
    let bid_id_e = if let (Some(ref bids), Some(ref state)) = (&bids_e, &state_e) {
        let bid = find_bid_for_provider(bids, state.selected_provider.as_ref().unwrap())?;
        let bid_id = BidId::from_bid(
            &state.owner,
            state.dseq.unwrap(),
            state.gseq,
            state.oseq,
            &bid,
        );
        lease_msgs.push(build_create_lease_msg(&bid_id));
        Some(bid_id)
    } else {
        None
    };

    tracing::info!(
        msgs = lease_msgs.len(),
        "  Batch CreateLease: broadcasting {} MsgCreateLease in 1 tx...",
        lease_msgs.len()
    );

    // Obtain deployer refs for signer access.
    let d0: &_ = w
        .ctx
        .units
        .get(0)
        .map(|u| &u.deployer)
        .unwrap_or(&w.ctx.deployer);
    let d1: &_ = w
        .ctx
        .units
        .get(1)
        .map(|u| &u.deployer)
        .unwrap_or(&w.ctx.deployer);
    let d2: &_ = w
        .ctx
        .units
        .get(2)
        .map(|u| &u.deployer)
        .unwrap_or(&w.ctx.deployer);
    let d3: &_ = w
        .ctx
        .units
        .get(3)
        .map(|u| &u.deployer)
        .unwrap_or(&w.ctx.deployer);

    let querier = &d0.client.signing_client().querier;
    let chain_id = querier.chain_config.chain_id.as_str();

    if is_direct {
        // Single signer (master) — all MsgCreateLease in one tx.
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

        // Record on all states and transition to SendManifest.
        state_a.record_tx(&batch_tx.hash);
        state_a.lease_id = Some(bid_id_a.into());
        state_a.transition(Step::SendManifest);

        if let (Some(bid_id), Some(ref mut s)) = (bid_id_b.as_ref(), &mut state_b) {
            s.record_tx(&batch_tx.hash);
            s.lease_id = Some(bid_id.clone().into());
            s.transition(Step::SendManifest);
        }
        if let (Some(bid_id), Some(ref mut s)) = (bid_id_c.as_ref(), &mut state_c) {
            s.record_tx(&batch_tx.hash);
            s.lease_id = Some(bid_id.clone().into());
            s.transition(Step::SendManifest);
        }
        if let (Some(bid_id), Some(ref mut s)) = (bid_id_e.as_ref(), &mut state_e) {
            s.record_tx(&batch_tx.hash);
            s.lease_id = Some(bid_id.clone().into());
            s.transition(Step::SendManifest);
        }
    } else {
        // HD mode: one SignerEntry per child signer (same pattern as CreateDeployment batch).
        let mnemonic = &w.ctx.deployer.config.mnemonic;

        let acct_0 = querier
            .base_account(d0.client.address_ref())
            .await
            .map_err(|e| DeployError::Query(format!("base_account d0 for lease: {}", e)))?;
        let signer_0 = derive_child_signer(
            mnemonic,
            w.ctx.units.get(0).map(|u| u.hd_index).unwrap_or(0),
        )?;
        let mut signer_entries: Vec<SignerEntry<'_>> = vec![SignerEntry {
            signer: &signer_0,
            account_number: acct_0.account_number,
            sequence: acct_0.sequence,
            messages: vec![build_create_lease_msg(&bid_id_a)],
        }];

        let signer_1;
        let acct_1;
        if let Some(ref bid_id) = bid_id_b {
            acct_1 = querier
                .base_account(d1.client.address_ref())
                .await
                .map_err(|e| DeployError::Query(format!("base_account d1 for lease: {}", e)))?;
            signer_1 = derive_child_signer(
                mnemonic,
                w.ctx.units.get(1).map(|u| u.hd_index).unwrap_or(1),
            )?;
            signer_entries.push(SignerEntry {
                signer: &signer_1,
                account_number: acct_1.account_number,
                sequence: acct_1.sequence,
                messages: vec![build_create_lease_msg(bid_id)],
            });
        }

        let signer_2;
        let acct_2;
        if let Some(ref bid_id) = bid_id_c {
            acct_2 = querier
                .base_account(d2.client.address_ref())
                .await
                .map_err(|e| DeployError::Query(format!("base_account d2 for lease: {}", e)))?;
            signer_2 = derive_child_signer(
                mnemonic,
                w.ctx.units.get(2).map(|u| u.hd_index).unwrap_or(2),
            )?;
            signer_entries.push(SignerEntry {
                signer: &signer_2,
                account_number: acct_2.account_number,
                sequence: acct_2.sequence,
                messages: vec![build_create_lease_msg(bid_id)],
            });
        }

        let signer_3;
        let acct_3;
        if let Some(ref bid_id) = bid_id_e {
            acct_3 = querier
                .base_account(d3.client.address_ref())
                .await
                .map_err(|e| DeployError::Query(format!("base_account d3 for lease: {}", e)))?;
            signer_3 = derive_child_signer(
                mnemonic,
                w.ctx.units.get(3).map(|u| u.hd_index).unwrap_or(3),
            )?;
            signer_entries.push(SignerEntry {
                signer: &signer_3,
                account_number: acct_3.account_number,
                sequence: acct_3.sequence,
                messages: vec![build_create_lease_msg(bid_id)],
            });
        }

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

        // Record on all states and transition to SendManifest.
        state_a.record_tx(&batch_tx.hash);
        state_a.lease_id = Some(bid_id_a.into());
        state_a.transition(Step::SendManifest);

        if let (Some(bid_id), Some(ref mut s)) = (bid_id_b, &mut state_b) {
            s.record_tx(&batch_tx.hash);
            s.lease_id = Some(bid_id.into());
            s.transition(Step::SendManifest);
        }
        if let (Some(bid_id), Some(ref mut s)) = (bid_id_c, &mut state_c) {
            s.record_tx(&batch_tx.hash);
            s.lease_id = Some(bid_id.into());
            s.transition(Step::SendManifest);
        }
        if let (Some(bid_id), Some(ref mut s)) = (bid_id_e, &mut state_e) {
            s.record_tx(&batch_tx.hash);
            s.lease_id = Some(bid_id.into());
            s.transition(Step::SendManifest);
        }
    }

    // Generate JWT for provider auth (shared across all phases).
    let jwt_token = w
        .ctx
        .deployer
        .client
        .generate_jwt(&w.ctx.deployer.client.address())
        .await
        .map_err(|e| DeployError::InvalidState(format!("JWT generation failed: {}", e)))?;
    state_a.jwt_token = Some(jwt_token.clone());
    if let Some(ref mut s) = state_b {
        s.jwt_token = Some(jwt_token.clone());
    }
    if let Some(ref mut s) = state_c {
        s.jwt_token = Some(jwt_token.clone());
    }
    if let Some(ref mut s) = state_e {
        s.jwt_token = Some(jwt_token);
    }

    // Complete remaining steps (SendManifest + WaitForEndpoints) — CreateLease already done.
    type EpsRes = Result<Vec<ServiceEndpoint>, DeployError>;
    type OptEpsRes = Result<Option<Vec<ServiceEndpoint>>, DeployError>;

    let (eps_a, eps_b, eps_c, eps_e): (EpsRes, OptEpsRes, OptEpsRes, OptEpsRes);

    if is_direct {
        tracing::info!("  Completing deployments sequentially (SendManifest + endpoints)...");
        let d = &w.ctx.deployer;
        eps_a = d.deploy_phase_complete(&mut state_a, "oline-phase-a").await;
        eps_b = match state_b.as_mut() {
            Some(s) => d.deploy_phase_complete(s, "oline-phase-b").await.map(Some),
            None => Ok(None),
        };
        eps_c = match state_c.as_mut() {
            Some(s) => d.deploy_phase_complete(s, "oline-phase-c").await.map(Some),
            None => Ok(None),
        };
        eps_e = match state_e.as_mut() {
            Some(s) => d.deploy_phase_complete(s, "oline-phase-e").await.map(Some),
            None => Ok(None),
        };
    } else {
        tracing::info!("  Completing deployments in parallel (SendManifest + endpoints)...");

        // Re-borrow deployers for manifest sends.
        let d0: &_ = w
            .ctx
            .units
            .get(0)
            .map(|u| &u.deployer)
            .unwrap_or(&w.ctx.deployer);
        let d1: &_ = w
            .ctx
            .units
            .get(1)
            .map(|u| &u.deployer)
            .unwrap_or(&w.ctx.deployer);
        let d2: &_ = w
            .ctx
            .units
            .get(2)
            .map(|u| &u.deployer)
            .unwrap_or(&w.ctx.deployer);
        let d3: &_ = w
            .ctx
            .units
            .get(3)
            .map(|u| &u.deployer)
            .unwrap_or(&w.ctx.deployer);

        (eps_a, eps_b, eps_c, eps_e) = tokio::join!(
            d0.deploy_phase_complete(&mut state_a, "oline-phase-a"),
            async {
                match state_b.as_mut() {
                    Some(s) => d1.deploy_phase_complete(s, "oline-phase-b").await.map(Some),
                    None => Ok(None),
                }
            },
            async {
                match state_c.as_mut() {
                    Some(s) => d2.deploy_phase_complete(s, "oline-phase-c").await.map(Some),
                    None => Ok(None),
                }
            },
            async {
                match state_e.as_mut() {
                    Some(s) => d3.deploy_phase_complete(s, "oline-phase-e").await.map(Some),
                    None => Ok(None),
                }
            },
        );
    }

    let a_endpoints = eps_a?;

    // ── Node registration setup ────────────────────────────────────────────
    let ssh_port_internal: u16 = var("SSH_P")
        .unwrap_or_else(|_| "22".into())
        .parse()
        .unwrap_or(22);
    let key_name = w
        .ctx
        .ssh_key_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "oline-parallel-key".into());
    let password = w.ctx.deployer.password.clone();

    // ── 7. Process Phase A result (required) ─────────────────────────────────

    tracing::info!("  [Phase A] Deployed. DSEQ: {}", state_a.dseq.unwrap_or(0));
    w.ctx
        .deployer
        .deployment_store
        .save(
            &DeploymentRecord::from_state(&state_a, &w.ctx.deployer.password)
                .map_err(|e| DeployError::InvalidState(e.to_string()))?,
        )
        .await
        .ok();

    register_phase_nodes(
        &a_endpoints,
        state_a.dseq.unwrap_or(0),
        &[
            ("oline-a-snapshot", "Phase A - Snapshot"),
            ("oline-a-seed", "Phase A - Seed"),
            ("oline-a-minio-ipfs", "Phase A - MinIO"),
        ],
        &key_name,
        "A",
        &password,
        ssh_port_internal,
    );

    let snap_rpc_ep =
        OLineDeployer::find_endpoint_by_internal_port(&a_endpoints, "oline-a-snapshot", 26657);
    let seed_rpc_ep =
        OLineDeployer::find_endpoint_by_internal_port(&a_endpoints, "oline-a-seed", 26657);
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
    w.ctx.statesync_rpc = statesync_rpc;

    let a_account_index = w.ctx.units.get(0).map(|u| u.hd_index).unwrap_or(0);
    w.ctx.session.deployments.push(DeploymentEntry {
        phase: "special-teams".into(),
        dseq: state_a.dseq.unwrap_or(0),
        account_index: a_account_index,
        label: "oline-phase-a".into(),
        provider: state_a.selected_provider.clone(),
        endpoints: a_endpoints
            .iter()
            .map(|e| format!("{}:{}", e.service, e.port))
            .collect(),
        gseq: state_a.gseq,
        oseq: state_a.oseq,
        services: {
            let mut seen = std::collections::HashSet::new();
            a_endpoints.iter().filter_map(|e| {
                if seen.insert(e.service.clone()) { Some(e.service.clone()) } else { None }
            }).collect()
        },
    });
    w.ctx.set_endpoints(DeployPhase::SpecialTeams, a_endpoints);
    w.ctx.set_state(DeployPhase::SpecialTeams, state_a);
    w.ctx
        .set_phase_result(DeployPhase::SpecialTeams, PhaseResult::Deployed);
    w.ctx.session_store.save(&w.ctx.session).ok();

    // ── 8. Process Phase B result ─────────────────────────────────────────────
    let eps_b_ok = match eps_b {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("  Phase B completion failed: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Tackles, PhaseResult::Failed(e.to_string()));
            None
        }
    };
    match (state_b, eps_b_ok) {
        (Some(b_state), Some(b_endpoints)) => {
            tracing::info!("  [Phase B] Deployed. DSEQ: {}", b_state.dseq.unwrap_or(0));
            w.ctx
                .deployer
                .deployment_store
                .save(
                    &DeploymentRecord::from_state(&b_state, &w.ctx.deployer.password)
                        .map_err(|e| DeployError::InvalidState(e.to_string()))?,
                )
                .await
                .ok();

            register_phase_nodes(
                &b_endpoints,
                b_state.dseq.unwrap_or(0),
                &[
                    ("oline-b-left-node", "Phase B - Left Tackle"),
                    ("oline-b-right-node", "Phase B - Right Tackle"),
                ],
                &key_name,
                "B",
                &password,
                ssh_port_internal,
            );

            let b_account_index = w.ctx.units.get(1).map(|u| u.hd_index).unwrap_or(0);
            w.ctx.session.deployments.push(DeploymentEntry {
                phase: "tackles".into(),
                dseq: b_state.dseq.unwrap_or(0),
                account_index: b_account_index,
                label: "oline-phase-b".into(),
                provider: b_state.selected_provider.clone(),
                endpoints: b_endpoints
                    .iter()
                    .map(|e| format!("{}:{}", e.service, e.port))
                    .collect(),
                gseq: b_state.gseq,
                oseq: b_state.oseq,
                services: {
                    let mut seen = std::collections::HashSet::new();
                    b_endpoints.iter().filter_map(|e| {
                        if seen.insert(e.service.clone()) { Some(e.service.clone()) } else { None }
                    }).collect()
                },
            });
            w.ctx.set_endpoints(DeployPhase::Tackles, b_endpoints);
            w.ctx.set_state(DeployPhase::Tackles, b_state);
            w.ctx
                .set_phase_result(DeployPhase::Tackles, PhaseResult::Deployed);
            w.ctx.session_store.save(&w.ctx.session).ok();
        }
        _ => {} // skipped or failed in bid collection
    }

    // ── 9. Process Phase C result ─────────────────────────────────────────────
    let eps_c_ok = match eps_c {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("  Phase C completion failed: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Forwards, PhaseResult::Failed(e.to_string()));
            None
        }
    };
    match (state_c, eps_c_ok) {
        (Some(c_state), Some(c_endpoints)) => {
            tracing::info!("  [Phase C] Deployed. DSEQ: {}", c_state.dseq.unwrap_or(0));
            w.ctx
                .deployer
                .deployment_store
                .save(
                    &DeploymentRecord::from_state(&c_state, &w.ctx.deployer.password)
                        .map_err(|e| DeployError::InvalidState(e.to_string()))?,
                )
                .await
                .ok();

            register_phase_nodes(
                &c_endpoints,
                c_state.dseq.unwrap_or(0),
                &[
                    ("oline-c-left-node", "Phase C - Left Forward"),
                    ("oline-c-right-node", "Phase C - Right Forward"),
                ],
                &key_name,
                "C",
                &password,
                ssh_port_internal,
            );

            let c_account_index = w.ctx.units.get(2).map(|u| u.hd_index).unwrap_or(0);
            w.ctx.session.deployments.push(DeploymentEntry {
                phase: "forwards".into(),
                dseq: c_state.dseq.unwrap_or(0),
                account_index: c_account_index,
                label: "oline-phase-c".into(),
                provider: c_state.selected_provider.clone(),
                endpoints: c_endpoints
                    .iter()
                    .map(|e| format!("{}:{}", e.service, e.port))
                    .collect(),
                gseq: c_state.gseq,
                oseq: c_state.oseq,
                services: {
                    let mut seen = std::collections::HashSet::new();
                    c_endpoints.iter().filter_map(|e| {
                        if seen.insert(e.service.clone()) { Some(e.service.clone()) } else { None }
                    }).collect()
                },
            });
            w.ctx.set_endpoints(DeployPhase::Forwards, c_endpoints);
            w.ctx.set_state(DeployPhase::Forwards, c_state);
            w.ctx
                .set_phase_result(DeployPhase::Forwards, PhaseResult::Deployed);
            w.ctx.session_store.save(&w.ctx.session).ok();
        }
        _ => {} // skipped or failed
    }

    // ── 10. Process Phase E result ────────────────────────────────────────────
    let eps_e_ok = match eps_e {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("  Phase E completion failed: {} — skipping.", e);
            w.ctx
                .set_phase_result(DeployPhase::Relayer, PhaseResult::Failed(e.to_string()));
            None
        }
    };
    match (state_e, eps_e_ok) {
        (Some(e_state), Some(e_endpoints)) => {
            tracing::info!("  [Phase E] Deployed. DSEQ: {}", e_state.dseq.unwrap_or(0));
            w.ctx
                .deployer
                .deployment_store
                .save(
                    &DeploymentRecord::from_state(&e_state, &w.ctx.deployer.password)
                        .map_err(|e| DeployError::InvalidState(e.to_string()))?,
                )
                .await
                .ok();

            // Phase E uses its own SSH key (generated in build_phase_rly_vars),
            // not the shared parallel key. Save it to disk for node registration.
            if let Some(privkey_pem) = e_vars.get("SSH_PRIVKEY") {
                let e_key_name = format!("oline-phase-e-key-{}", e_state.dseq.unwrap_or(0));
                let secrets_dir = var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
                let e_key_path = PathBuf::from(&secrets_dir).join(&e_key_name);
                match ssh_key::PrivateKey::from_openssh(privkey_pem.as_bytes()) {
                    Ok(k) => {
                        if let Err(e) = crate::crypto::save_ssh_key(&k, &e_key_path) {
                            tracing::warn!("  [Phase E] Failed to save SSH key: {}", e);
                        } else {
                            // Derive service names from endpoints (Phase E SDL varies).
                            let e_services: Vec<String> = e_endpoints
                                .iter()
                                .filter(|ep| ep.internal_port == ssh_port_internal)
                                .map(|ep| ep.service.clone())
                                .collect();
                            let e_svc_pairs: Vec<(&str, String)> = e_services
                                .iter()
                                .map(|svc| (svc.as_str(), format!("Phase E - {}", svc)))
                                .collect();
                            let e_svc_refs: Vec<(&str, &str)> = e_svc_pairs
                                .iter()
                                .map(|(s, l)| (*s, l.as_str()))
                                .collect();
                            register_phase_nodes(
                                &e_endpoints,
                                e_state.dseq.unwrap_or(0),
                                &e_svc_refs,
                                &e_key_name,
                                "E",
                                &password,
                                ssh_port_internal,
                            );
                        }
                    }
                    Err(e) => tracing::warn!("  [Phase E] Invalid SSH key: {}", e),
                }
            }

            let e_account_index = w.ctx.units.get(3).map(|u| u.hd_index).unwrap_or(0);
            w.ctx.session.deployments.push(DeploymentEntry {
                phase: "relayer".into(),
                dseq: e_state.dseq.unwrap_or(0),
                account_index: e_account_index,
                label: "oline-phase-e".into(),
                provider: e_state.selected_provider.clone(),
                endpoints: e_endpoints
                    .iter()
                    .map(|e| format!("{}:{}", e.service, e.port))
                    .collect(),
                gseq: e_state.gseq,
                oseq: e_state.oseq,
                services: {
                    let mut seen = std::collections::HashSet::new();
                    e_endpoints.iter().filter_map(|e| {
                        if seen.insert(e.service.clone()) { Some(e.service.clone()) } else { None }
                    }).collect()
                },
            });
            w.ctx.set_endpoints(DeployPhase::Relayer, e_endpoints);
            w.ctx.set_state(DeployPhase::Relayer, e_state);
            w.ctx
                .set_phase_result(DeployPhase::Relayer, PhaseResult::Deployed);
            w.ctx.session_store.save(&w.ctx.session).ok();
        }
        _ => {} // skipped or failed
    }

    // ── 11. DNS updates — all phases concurrently ─────────────────────────────
    let cf_token = w.ctx.deployer.config.val("OLINE_CF_API_TOKEN");
    let cf_zone = w.ctx.deployer.config.val("OLINE_CF_ZONE_ID");
    if !cf_token.is_empty() && !cf_zone.is_empty() {
        // HTTP/HTTPS accept domains (proxied through Cloudflare)
        macro_rules! dns_phase {
            ($phase:expr) => {{
                let sdl_opt = w.ctx.state($phase).and_then(|s| s.sdl_content.clone());
                let eps = w.ctx.endpoints($phase).to_vec();
                if let Some(sdl) = sdl_opt {
                    if !eps.is_empty() {
                        cloudflare_update_accept_domains(&sdl, &eps, &cf_token, &cf_zone).await;
                    }
                }
            }};
        }
        dns_phase!(DeployPhase::SpecialTeams);
        dns_phase!(DeployPhase::Tackles);
        dns_phase!(DeployPhase::Forwards);
        dns_phase!(DeployPhase::Relayer);

        // P2P domains: DNS-only A records (NOT proxied — raw TCP for CometBFT P2P)
        {
            let cfg = &w.ctx.deployer.config;
            let val = |k: &str| {
                let v = cfg.val(k);
                if v.is_empty() { String::new() } else { v }
            };

            // Phase A: Snapshot + Seed
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

            // Phase B: Tackles
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

            // Phase C: Forwards
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
    }

    // ── 12. Immediate SSH init — push scripts to all nodes; signal Phase A ────
    //
    // All phases are deployed and DNS is propagating. We can now SSH into every
    // node immediately. Phase A (snapshot + seed) are signaled to start syncing;
    // Phase B/C scripts are pushed so nodes have them when peers arrive.
    {
        let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());
        let nginx_path =
            var("OLINE_NGINX_PATH").unwrap_or_else(|_| "plays/flea-flicker/nginx".into());

        let has_pre_start = std::env::var("E2E_SNAP_PATH")
            .or_else(|_| std::env::var("OLINE_PRE_START_SNAP"))
            .ok()
            .map(std::path::PathBuf::from)
            .filter(|p| p.exists())
            .is_some();

        if !has_pre_start {
            // ── Phase A: snapshot node ────────────────────────────────────────
            let snapshot_eps = w
                .ctx
                .service_endpoints(DeployPhase::SpecialTeams, "oline-a-snapshot");
            if !snapshot_eps.is_empty() {
                tracing::info!("  [init] Pushing scripts to snapshot node...");
                let mut attempt = 0u32;
                let pushed = loop {
                    match push_scripts_sftp(
                        "init-snapshot",
                        &snapshot_eps,
                        &w.ctx.ssh_key_path,
                        &scripts_path,
                        Some(&nginx_path),
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
                if pushed {
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
                            w.ctx.phase_a_bootstrapped = true;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "  [init] Snapshot signal failed: {} — will retry in WaitSnapshotReady.",
                                e
                            );
                        }
                    }
                }
            }

            // ── Phase A: seed node ────────────────────────────────────────────
            let seed_eps = w
                .ctx
                .service_endpoints(DeployPhase::SpecialTeams, "oline-a-seed");
            if !seed_eps.is_empty() {
                tracing::info!("  [init] Pushing scripts to seed node...");
                let _ = push_scripts_sftp(
                    "init-seed",
                    &seed_eps,
                    &w.ctx.ssh_key_path,
                    &scripts_path,
                    Some(&nginx_path),
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

            // ── Phase A: minio node ───────────────────────────────────────────
            let minio_eps = w
                .ctx
                .service_endpoints(DeployPhase::SpecialTeams, "oline-a-minio-ipfs");
            if !minio_eps.is_empty() {
                tracing::info!("  [init] Pushing scripts to minio node...");
                let _ = push_scripts_sftp(
                    "init-minio",
                    &minio_eps,
                    &w.ctx.ssh_key_path,
                    &scripts_path,
                    None,
                )
                .await;
            }
        } else {
            tracing::info!(
                "  [init] Pre-start snapshot detected — deferring Phase A signal to WaitSnapshotReady."
            );
        }

        // ── Phase B: tackle nodes (push only; signal comes in SignalAllNodes) ─
        let b_eps = w.ctx.endpoints(DeployPhase::Tackles).to_vec();
        for svc in ["oline-b-left-node", "oline-b-right-node"] {
            let eps: Vec<_> = b_eps.iter().filter(|e| e.service == svc).cloned().collect();
            if !eps.is_empty() {
                tracing::info!("  [init] Pushing scripts to {}...", svc);
                let _ =
                    push_scripts_sftp(svc, &eps, &w.ctx.ssh_key_path, &scripts_path, None).await;
            }
        }

        // ── Phase C: forward nodes (push only; signal + peers come in InjectPeers) ─
        let c_eps = w.ctx.endpoints(DeployPhase::Forwards).to_vec();
        for svc in ["oline-c-left-node", "oline-c-right-node"] {
            let eps: Vec<_> = c_eps.iter().filter(|e| e.service == svc).cloned().collect();
            if !eps.is_empty() {
                tracing::info!("  [init] Pushing scripts to {}...", svc);
                let _ =
                    push_scripts_sftp(svc, &eps, &w.ctx.ssh_key_path, &scripts_path, None).await;
            }
        }
    }

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
            if v.is_empty() { String::new() } else { v }
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
                label, eps, key,
                &[PreStartFile {
                    source: FileSource::Bytes(genesis_bytes.to_vec()),
                    remote_path: "/tmp/genesis.json".into(),
                }],
                MAX_RETRIES,
            ).await {
                tracing::info!("  Warning: genesis push to {} failed: {}", label, e);
            }
        }
    }

    let gen = genesis_bytes.as_slice();
    let sync_method = w.ctx.deployer.config.val("OLINE_SYNC_METHOD");
    let skip_bc = sync_method == "statesync";
    if skip_bc {
        tracing::info!("  OLINE_SYNC_METHOD=statesync — skipping B/C snapshot push (they will statesync)");
    }

    tokio::join!(
        push_one("parallel-seed",          &seed_eps, key, &local_path, rp, None),
        async { if !skip_bc { push_one("parallel-left-tackle",   &lt_eps,   key, &local_path, rp, Some(gen)).await } },
        async { if !skip_bc { push_one("parallel-right-tackle",  &rt_eps,   key, &local_path, rp, Some(gen)).await } },
        async { if !skip_bc { push_one("parallel-left-forward",  &lf_eps,   key, &local_path, rp, Some(gen)).await } },
        async { if !skip_bc { push_one("parallel-right-forward", &rf_eps,   key, &local_path, rp, Some(gen)).await } },
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
        let has_height = !w.ctx.deployer.config.val("STATESYNC_TRUST_HEIGHT").is_empty();
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
                    w.ctx.deployer.config.set("STATESYNC_TRUST_HEIGHT", height);
                    w.ctx.deployer.config.set("STATESYNC_TRUST_HASH", hash);
                }
                Err(e) => {
                    tracing::warn!("  Failed to fetch trust params: {} — nodes will auto-fetch from entrypoint", e);
                }
            }
        }
    }

    let b_vars = build_phase_b_vars(
        &w.ctx.deployer.config,
        w.ctx.peer(PeerTarget::Snapshot),
        &w.ctx.statesync_rpc,
    );

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

    let c_vars = build_phase_c_vars(
        &w.ctx.deployer.config,
        w.ctx.peer(PeerTarget::Seed),
        w.ctx.peer(PeerTarget::Snapshot),
        w.ctx.peer(PeerTarget::LeftTackle),
        w.ctx.peer(PeerTarget::RightTackle),
        &w.ctx.statesync_rpc.clone(),
    );

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
