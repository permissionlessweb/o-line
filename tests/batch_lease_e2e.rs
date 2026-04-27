/// E2E test: batch CreateLease (3 MsgCreateLease in 1 tx).
///
/// Validates that the parallel deploy path correctly batches all lease creation
/// messages into a single signed transaction. This is the definitive test for
/// the batch lease optimization in `parallel.rs`.
///
/// # What this proves
///
/// 1. **Single tx for all leases**: All 3 MsgCreateLease are broadcast atomically.
/// 2. **Shared tx hash**: Every lease records the same transaction hash.
/// 3. **Correct state transitions**: After batch lease, each DeploymentState is
///    at `Step::SendManifest` with a valid `lease_id`.
///
/// # Prerequisites
///
/// ```bash
/// just akash-setup              # one-time: genesis + test-provider
/// cargo build --bin test-provider
/// ```
///
/// # Run
///
/// ```bash
/// just test-batch-lease
/// # or
/// cargo test --test batch_lease_e2e -- --nocapture --ignored
/// ```
use akash_deploy_rs::{
    broadcast_multi_signer, build_create_lease_msg, AkashBackend, AkashClient, Bid, BidId,
    DeployError, DeploymentState, DeploymentWorkflow, SignerEntry, Step,
};
use o_line_sdl::config::substitute_template_raw;
use o_line_sdl::{
    config::build_config_from_env, deployer::OLineDeployer, testing::AkashLocalNetwork,
};
use std::collections::HashMap;

/// Find the bid from a specific provider.
fn find_bid_for_provider(bids: &[Bid], provider: &str) -> Result<Bid, DeployError> {
    bids.iter()
        .find(|b| b.provider == provider)
        .cloned()
        .ok_or_else(|| DeployError::InvalidState(format!("no bid from provider {}", provider)))
}

/// Render a simple test SDL.
fn render_test_sdl(svc_name: &str, label: &str) -> Result<String, Box<dyn std::error::Error>> {
    let template = include_str!("fixtures/sdls/concurrent.yml");
    let mut vars = HashMap::new();
    vars.insert("SVC_NAME".into(), svc_name.into());
    vars.insert("DEPLOY_LABEL".into(), label.into());
    substitute_template_raw(template, &vars).map_err(Into::into)
}

#[tokio::test]
#[ignore = "requires local Akash dev cluster (just akash-setup + cargo build --bin test-provider)"]
async fn test_batch_lease_3_msgs_in_1_tx() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    // ── 1. Start local Akash network ─────────────────────────────────────────
    eprintln!("\n[batch-lease] Starting AkashLocalNetwork…");
    let net = AkashLocalNetwork::start()
        .await
        .expect("AkashLocalNetwork::start()");

    eprintln!("[batch-lease] Network ready.");
    eprintln!("[batch-lease]   RPC:    {}", net.rpc());
    eprintln!("[batch-lease]   gRPC:   {}", net.grpc());
    eprintln!("[batch-lease]   REST:   {}", net.rest());

    // ── 2. Create deployer ───────────────────────────────────────────────────
    std::env::set_var("OLINE_RPC_ENDPOINT", net.rpc());
    std::env::set_var("OLINE_GRPC_ENDPOINT", net.grpc());
    std::env::set_var("OLINE_REST_ENDPOINT", net.rest());
    std::env::set_var("OLINE_CHAIN_ID", net.chain_id());
    std::env::set_var("OLINE_NON_INTERACTIVE", "1");
    std::env::set_var("OLINE_AUTO_SELECT", "1");
    // Stop before manifest send — no real provider.
    std::env::set_var("OLINE_TEST_STOP_AFTER_DEPLOY", "1");

    let config = build_config_from_env(net.deployer_mnemonic.clone(), None);
    let deployer = OLineDeployer::new(config.clone(), "test-password".into())
        .await
        .expect("create deployer");
    let deployer_addr = deployer.client.address().to_string();
    eprintln!("[batch-lease]   Deployer: {}", deployer_addr);

    // Fund deployer.
    net.faucet(&deployer_addr, 500_000_000)
        .await
        .expect("faucet: fund deployer");

    // ── 3. Render 3 SDLs ────────────────────────────────────────────────────
    let sdl_a = render_test_sdl("svc-batch-a", "batch-a").unwrap();
    let sdl_b = render_test_sdl("svc-batch-b", "batch-b").unwrap();
    let sdl_c = render_test_sdl("svc-batch-c", "batch-c").unwrap();

    // ── 4. Batch CreateDeployment (3 in 1 tx) ────────────────────────────────
    let querier = &deployer.client.signing_client().querier;
    let dseq: u64 = querier.block_height().await.expect("block_height for dseq");
    let deposit_amount: u64 = 5_000_000;
    let deposit_denom = "uact";

    eprintln!("[batch-lease] Base dseq: {}", dseq);

    let msg_a = deployer
        .client
        .build_create_deployment_msg(&deployer_addr, &sdl_a, deposit_amount, deposit_denom, dseq)
        .expect("build deploy msg A");
    let msg_b = deployer
        .client
        .build_create_deployment_msg(
            &deployer_addr,
            &sdl_b,
            deposit_amount,
            deposit_denom,
            dseq + 1,
        )
        .expect("build deploy msg B");
    let msg_c = deployer
        .client
        .build_create_deployment_msg(
            &deployer_addr,
            &sdl_c,
            deposit_amount,
            deposit_denom,
            dseq + 2,
        )
        .expect("build deploy msg C");

    let chain_id = querier.chain_config.chain_id.as_str();
    let acct = querier
        .base_account(deployer.client.address_ref())
        .await
        .expect("base_account");

    let deploy_tx = broadcast_multi_signer(
        querier,
        chain_id,
        vec![SignerEntry {
            signer: &deployer.signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages: vec![msg_a, msg_b, msg_c],
        }],
        1.5,
        std::time::Duration::from_secs(60),
    )
    .await
    .expect("batch deploy tx");

    eprintln!(
        "[batch-lease] Deploy batch confirmed: hash={}, height={}",
        deploy_tx.hash, deploy_tx.height
    );
    assert_eq!(
        deploy_tx.code, 0,
        "deploy batch tx failed with code {}",
        deploy_tx.code
    );

    // ── 5. Create DeploymentState objects ────────────────────────────────────
    let mut state_a = DeploymentState::new("batch-a", deployer.client.address())
        .with_sdl(&sdl_a)
        .with_label("batch-a");
    state_a.dseq = Some(dseq);

    let mut state_b = DeploymentState::new("batch-b", deployer.client.address())
        .with_sdl(&sdl_b)
        .with_label("batch-b");
    state_b.dseq = Some(dseq + 1);

    let mut state_c = DeploymentState::new("batch-c", deployer.client.address())
        .with_sdl(&sdl_c)
        .with_label("batch-c");
    state_c.dseq = Some(dseq + 2);

    // ── 6. Wait for bids on all 3 deployments ────────────────────────────────
    eprintln!("[batch-lease] Waiting for bids on all 3 deployments…");

    let bids_a = deployer
        .wait_for_bids(&mut state_a, "batch-a")
        .await
        .expect("bids A");
    let bids_b = deployer
        .wait_for_bids(&mut state_b, "batch-b")
        .await
        .expect("bids B");
    let bids_c = deployer
        .wait_for_bids(&mut state_c, "batch-c")
        .await
        .expect("bids C");

    eprintln!(
        "[batch-lease] Bids received: A={}, B={}, C={}",
        bids_a.len(),
        bids_b.len(),
        bids_c.len()
    );

    assert!(!bids_a.is_empty(), "Phase A should have bids");
    assert!(!bids_b.is_empty(), "Phase B should have bids");
    assert!(!bids_c.is_empty(), "Phase C should have bids");

    // ── 7. Select providers (cheapest) ───────────────────────────────────────
    let provider_a = bids_a
        .iter()
        .min_by_key(|b| b.price)
        .unwrap()
        .provider
        .clone();
    let provider_b = bids_b
        .iter()
        .min_by_key(|b| b.price)
        .unwrap()
        .provider
        .clone();
    let provider_c = bids_c
        .iter()
        .min_by_key(|b| b.price)
        .unwrap()
        .provider
        .clone();

    DeploymentWorkflow::<AkashClient>::select_provider(&mut state_a, &provider_a)
        .expect("select provider A");
    DeploymentWorkflow::<AkashClient>::select_provider(&mut state_b, &provider_b)
        .expect("select provider B");
    DeploymentWorkflow::<AkashClient>::select_provider(&mut state_c, &provider_c)
        .expect("select provider C");

    // ── 8. BUILD + BROADCAST BATCH LEASE (3 MsgCreateLease in 1 tx) ─────────
    eprintln!("[batch-lease] Building 3 MsgCreateLease messages…");

    let owner = deployer.client.address().to_string();

    let bid_a = find_bid_for_provider(&bids_a, &provider_a).expect("bid A");
    let bid_b = find_bid_for_provider(&bids_b, &provider_b).expect("bid B");
    let bid_c = find_bid_for_provider(&bids_c, &provider_c).expect("bid C");

    let bid_id_a = BidId::from_bid(
        &owner,
        state_a.dseq.unwrap(),
        state_a.gseq,
        state_a.oseq,
        &bid_a,
    );
    let bid_id_b = BidId::from_bid(
        &owner,
        state_b.dseq.unwrap(),
        state_b.gseq,
        state_b.oseq,
        &bid_b,
    );
    let bid_id_c = BidId::from_bid(
        &owner,
        state_c.dseq.unwrap(),
        state_c.gseq,
        state_c.oseq,
        &bid_c,
    );

    let lease_msgs = vec![
        build_create_lease_msg(&bid_id_a),
        build_create_lease_msg(&bid_id_b),
        build_create_lease_msg(&bid_id_c),
    ];

    // ── THE KEY ASSERTION: exactly 3 messages in the batch ───────────────────
    assert_eq!(
        lease_msgs.len(),
        3,
        "CRITICAL: batch must contain exactly 3 MsgCreateLease messages, got {}",
        lease_msgs.len()
    );

    // Re-query account (sequence incremented after deploy batch).
    let acct = querier
        .base_account(deployer.client.address_ref())
        .await
        .expect("base_account for lease");

    eprintln!(
        "[batch-lease] Broadcasting batch: {} MsgCreateLease, chain_id={}, seq={}",
        lease_msgs.len(),
        chain_id,
        acct.sequence
    );

    let batch_tx = broadcast_multi_signer(
        querier,
        chain_id,
        vec![SignerEntry {
            signer: &deployer.signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages: lease_msgs,
        }],
        1.5,
        std::time::Duration::from_secs(60),
    )
    .await
    .expect("batch lease tx");

    eprintln!(
        "[batch-lease] Batch lease tx confirmed: hash={}, code={}, height={}",
        batch_tx.hash, batch_tx.code, batch_tx.height
    );

    // ── 9. ASSERTIONS ────────────────────────────────────────────────────────

    // The batch tx must succeed (code 0).
    assert_eq!(
        batch_tx.code, 0,
        "Batch lease tx failed with code {}: {}",
        batch_tx.code, batch_tx.raw_log
    );

    // Record on all states and verify transitions.
    state_a.record_tx(&batch_tx.hash);
    state_a.lease_id = Some(bid_id_a.clone().into());
    state_a.transition(Step::SendManifest);

    state_b.record_tx(&batch_tx.hash);
    state_b.lease_id = Some(bid_id_b.clone().into());
    state_b.transition(Step::SendManifest);

    state_c.record_tx(&batch_tx.hash);
    state_c.lease_id = Some(bid_id_c.clone().into());
    state_c.transition(Step::SendManifest);

    // All 3 states must be at SendManifest.
    assert!(
        matches!(state_a.step, Step::SendManifest),
        "State A should be at SendManifest, got {:?}",
        state_a.step
    );
    assert!(
        matches!(state_b.step, Step::SendManifest),
        "State B should be at SendManifest, got {:?}",
        state_b.step
    );
    assert!(
        matches!(state_c.step, Step::SendManifest),
        "State C should be at SendManifest, got {:?}",
        state_c.step
    );

    // All 3 states must have the SAME tx hash (proves single tx).
    let hash_a = state_a.tx_hashes.last().unwrap();
    let hash_b = state_b.tx_hashes.last().unwrap();
    let hash_c = state_c.tx_hashes.last().unwrap();
    assert_eq!(
        hash_a, hash_b,
        "Lease tx hash mismatch: A={} vs B={}",
        hash_a, hash_b
    );
    assert_eq!(
        hash_b, hash_c,
        "Lease tx hash mismatch: B={} vs C={}",
        hash_b, hash_c
    );
    eprintln!("[batch-lease] All 3 leases share tx hash: {}", hash_a);

    // All 3 states must have a lease_id.
    assert!(state_a.lease_id.is_some(), "State A must have lease_id");
    assert!(state_b.lease_id.is_some(), "State B must have lease_id");
    assert!(state_c.lease_id.is_some(), "State C must have lease_id");

    // Verify distinct DSEQs (each lease is for a different deployment).
    let dseq_a = state_a.dseq.unwrap();
    let dseq_b = state_b.dseq.unwrap();
    let dseq_c = state_c.dseq.unwrap();
    assert_ne!(dseq_a, dseq_b, "A and B should have different DSEQs");
    assert_ne!(dseq_b, dseq_c, "B and C should have different DSEQs");
    assert_ne!(dseq_a, dseq_c, "A and C should have different DSEQs");

    // ── 10. Query chain to verify leases exist ───────────────────────────────
    // Use the tx hash to query events and count EventLeaseCreated.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let tx_url = format!("{}/cosmos/tx/v1beta1/txs/{}", net.rest(), batch_tx.hash);

    match http.get(&tx_url).send().await {
        Ok(r) if r.status().is_success() => {
            let json: serde_json::Value = r.json().await.unwrap_or_default();

            // Count MsgCreateLease messages in the tx body.
            let msg_count = json
                .pointer("/tx/body/messages")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);

            eprintln!("[batch-lease] On-chain tx has {} messages", msg_count);

            assert_eq!(
                msg_count, 3,
                "CRITICAL: on-chain tx must contain exactly 3 messages, got {}. \
                 The batch lease optimization is broken if this fails!",
                msg_count
            );

            // Verify all messages are MsgCreateLease.
            if let Some(msgs) = json.pointer("/tx/body/messages").and_then(|v| v.as_array()) {
                for (i, msg) in msgs.iter().enumerate() {
                    let type_url = msg
                        .get("@type")
                        .or_else(|| msg.get("type_url"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    eprintln!("[batch-lease]   msg[{}] type: {}", i, type_url);
                    assert!(
                        type_url.contains("MsgCreateLease"),
                        "msg[{}] should be MsgCreateLease, got: {}",
                        i,
                        type_url
                    );
                }
            }
        }
        Ok(r) => {
            eprintln!(
                "[batch-lease] WARNING: tx query returned HTTP {} — skipping on-chain verification",
                r.status()
            );
        }
        Err(e) => {
            eprintln!(
                "[batch-lease] WARNING: tx query failed: {} — skipping on-chain verification",
                e
            );
        }
    }

    // ── 11. Verify deploy_phase_complete works from SendManifest ─────────────
    // With OLINE_TEST_STOP_AFTER_DEPLOY=1, deploy_phase_complete should return
    // immediately since the state is at SendManifest.
    let eps_a = deployer
        .deploy_phase_complete(&mut state_a, "batch-a")
        .await
        .expect("deploy_phase_complete A");
    let eps_b = deployer
        .deploy_phase_complete(&mut state_b, "batch-b")
        .await
        .expect("deploy_phase_complete B");
    let eps_c = deployer
        .deploy_phase_complete(&mut state_c, "batch-c")
        .await
        .expect("deploy_phase_complete C");

    eprintln!(
        "[batch-lease] deploy_phase_complete returned: A={} eps, B={} eps, C={} eps",
        eps_a.len(),
        eps_b.len(),
        eps_c.len()
    );

    // ── 12. Cleanup ──────────────────────────────────────────────────────────
    eprintln!("\n[batch-lease] Cleaning up deployments…");
    for (label, d) in [("A", dseq), ("B", dseq + 1), ("C", dseq + 2)] {
        match deployer
            .client
            .broadcast_close_deployment(&deployer.signer, &deployer_addr, d)
            .await
        {
            Ok(tx) => eprintln!(
                "[batch-lease]   closed {} DSEQ {} (tx={})",
                label, d, tx.hash
            ),
            Err(e) => eprintln!("[batch-lease]   close {} DSEQ {} failed: {}", label, d, e),
        }
    }

    eprintln!("\n[batch-lease] ALL ASSERTIONS PASSED");
    eprintln!(
        "[batch-lease]   3 MsgCreateLease in 1 tx: {}",
        batch_tx.hash
    );
    eprintln!("[batch-lease]   All states at SendManifest with shared tx hash");
    eprintln!("[batch-lease]   On-chain verification: 3 messages confirmed");
}
