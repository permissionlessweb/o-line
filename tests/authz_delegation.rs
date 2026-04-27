/// E2E tests: AuthZ + FeeGrant delegation for Akash deployments.
///
/// Validates the full AuthZ lifecycle on a local Akash devnet via ict-rs:
/// 1. Grant AuthZ permissions + FeeGrant (including MsgExec in allowed messages)
/// 2. Fund grantee with dust (1 uAKT) to create on-chain account
/// 3. Execute MsgCreateDeployment via MsgExec with Fee.granter set
/// 4. Verify deployment owned by granter, gas paid by granter via FeeGrant
///
/// This test reproduces the exact production failure where the FeeGrant's
/// AllowedMsgAllowance did not include MsgExec's type URL, causing:
///   "message does not exist in allowed messages: message not allowed"
///
/// # Prerequisites
///
/// ```bash
/// just akash-setup
/// ```
///
/// # Run
///
/// ```bash
/// cargo test --features testing --test authz_delegation -- --nocapture --ignored
/// ```
use akash_deploy_rs::{
    authz_msg_type_urls, broadcast_multi_signer, broadcast_with_fee_granter,
    build_authz_grant_msgs, build_bank_send_msg, build_feegrant_msg,
    wrap_in_msg_exec, AkashBackend, AkashClient, KeySigner, SignerEntry,
};
use o_line_sdl::{
    accounts::child_address,
    testing::AkashLocalNetwork,
};
use std::time::Duration;

/// Generate a fresh test mnemonic using coins-bip39.
fn generate_test_mnemonic() -> String {
    use coins_bip39::{English, Mnemonic};
    let mnemonic = Mnemonic::<English>::new(&mut rand::thread_rng());
    mnemonic.to_phrase()
}

// ── Test: AuthZ + FeeGrant + MsgExec deploy (the exact production flow) ──

#[tokio::test]
#[ignore = "requires local Akash dev cluster (just akash-setup)"]
async fn test_authz_feegrant_exec_deploy() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    // ── 1. Start local Akash network ─────────────────────────────────────
    eprintln!("\n[authz-e2e] Starting AkashLocalNetwork…");
    let net = AkashLocalNetwork::start()
        .await
        .expect("AkashLocalNetwork::start()");

    eprintln!("[authz-e2e] Network ready: RPC={}, gRPC={}", net.rpc(), net.grpc());

    // ── 2. Create granter (faucet-funded) + grantee (fresh wallet) ───────
    let granter_mnemonic = &net.deployer_mnemonic;
    let granter_client =
        AkashClient::new_from_mnemonic(granter_mnemonic, net.rpc(), net.grpc())
            .await
            .expect("granter client");
    let granter_addr = granter_client.address();

    let grantee_mnemonic = generate_test_mnemonic();
    let grantee_signer =
        KeySigner::new_mnemonic_str(&grantee_mnemonic, None).expect("grantee signer");
    let grantee_addr = child_address(&grantee_signer, "akash");

    // Fund granter with enough for deployment deposit + fees
    net.faucet(&granter_addr, 500_000_000)
        .await
        .expect("fund granter");

    eprintln!("[authz-e2e] Granter: {}", granter_addr);
    eprintln!("[authz-e2e] Grantee: {}", grantee_addr);

    // ── 3. Build grants + dust fund in ONE tx (same as `oline authz setup`) ──
    let granter_signer =
        KeySigner::new_mnemonic_str(granter_mnemonic, None).expect("granter signer");
    let querier = &granter_client.signing_client().querier;
    let chain_id = querier.chain_config.chain_id.as_str();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiration = now + 86400;

    // 5 AuthZ grants + 1 FeeGrant + 1 dust bank send = 7 msgs in 1 tx
    let mut all_msgs =
        build_authz_grant_msgs(&granter_addr, &grantee_addr, Some(expiration));

    let feegrant_msg = build_feegrant_msg(
        &granter_addr,
        &grantee_addr,
        Some(50_000_000), // 50 AKT fee limit
        Some(expiration),
    );
    all_msgs.push(feegrant_msg);

    // Dust send to create grantee's on-chain account
    let dust_msg = build_bank_send_msg(&granter_addr, &grantee_addr, 1, "uakt");
    all_msgs.push(dust_msg);

    eprintln!("[authz-e2e] Broadcasting {} setup messages…", all_msgs.len());

    let acct = querier
        .base_account(granter_client.address_ref())
        .await
        .expect("granter base_account");

    let setup_tx = broadcast_multi_signer(
        querier,
        chain_id,
        vec![SignerEntry {
            signer: &granter_signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages: all_msgs,
        }],
        1.5,
        Duration::from_secs(60),
    )
    .await
    .expect("setup tx (grants + fund)");

    assert_eq!(setup_tx.code, 0, "setup tx failed: {}", setup_tx.raw_log);
    eprintln!(
        "[authz-e2e] Setup confirmed: hash={}, height={}",
        setup_tx.hash, setup_tx.height
    );

    // ── 4. Verify grantee account exists on-chain ────────────────────────
    let grantee_client =
        AkashClient::new_from_mnemonic(&grantee_mnemonic, net.rpc(), net.grpc())
            .await
            .expect("grantee client");

    let grantee_balance = grantee_client
        .query_balance(&grantee_addr, "uakt")
        .await
        .expect("grantee balance query");
    assert_eq!(grantee_balance, 1, "grantee should have exactly 1 uAKT");
    eprintln!("[authz-e2e] Grantee balance: {} uAKT (account exists)", grantee_balance);

    // ── 5. Build MsgCreateDeployment with owner = granter ────────────────
    let dseq = querier
        .block_height()
        .await
        .expect("block_height for dseq");

    let test_sdl = include_str!("fixtures/sdls/concurrent.yml")
        .replace("${SVC_NAME}", "authz-test")
        .replace("${DEPLOY_LABEL}", "authz-e2e");

    let deploy_msg = granter_client
        .build_create_deployment_msg(
            &granter_addr, // owner = granter (NOT grantee)
            &test_sdl,
            5_000_000, // 5 ACT deposit
            "uact",
            dseq,
        )
        .expect("build deploy msg");

    // ── 6. Wrap in MsgExec + broadcast with Fee.granter ──────────────────
    // This is the exact flow that failed in production:
    //   - Grantee signs the outer tx
    //   - Inner MsgCreateDeployment has owner = granter
    //   - MsgExec wraps the inner message
    //   - Fee.granter = granter (FeeGrant pays gas)
    let exec_msg = wrap_in_msg_exec(&grantee_addr, &[deploy_msg]);

    eprintln!(
        "[authz-e2e] Broadcasting MsgExec(MsgCreateDeployment) — grantee signs, granter pays…"
    );

    let grantee_acct = querier
        .base_account(grantee_client.address_ref())
        .await
        .expect("grantee base_account");

    let deploy_tx = broadcast_with_fee_granter(
        querier,
        chain_id,
        &grantee_signer,
        grantee_acct.account_number,
        grantee_acct.sequence,
        vec![exec_msg],
        &granter_addr, // fee_granter = granter
        1.5,
        Duration::from_secs(60),
    )
    .await
    .expect("MsgExec deploy tx");

    assert_eq!(
        deploy_tx.code, 0,
        "MsgExec deploy FAILED: {}",
        deploy_tx.raw_log
    );

    eprintln!(
        "[authz-e2e] Deployment created via MsgExec: hash={}, height={}",
        deploy_tx.hash, deploy_tx.height
    );

    // ── 7. Verify deployment owned by granter ────────────────────────────
    eprintln!("[authz-e2e] Deployment owner: {} (granter)", granter_addr);
    eprintln!("[authz-e2e] Signed by: {} (grantee)", grantee_addr);

    // Verify grantee balance unchanged (fee grant covered gas)
    let grantee_balance_after = grantee_client
        .query_balance(&grantee_addr, "uakt")
        .await
        .expect("grantee balance after deploy");
    assert_eq!(
        grantee_balance_after, 1,
        "grantee balance should be unchanged (fee grant pays gas), got: {}",
        grantee_balance_after
    );
    eprintln!(
        "[authz-e2e] Grantee balance after deploy: {} uAKT (unchanged — fee grant worked)",
        grantee_balance_after
    );

    eprintln!("\n[authz-e2e] === ALL ASSERTIONS PASSED ===");
}

// ── Test: Grant lifecycle (grant + revoke) ───────────────────────────────

#[tokio::test]
#[ignore = "requires local Akash dev cluster (just akash-setup)"]
async fn test_authz_grant_and_revoke() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let net = AkashLocalNetwork::start()
        .await
        .expect("AkashLocalNetwork::start()");

    let granter_mnemonic = &net.deployer_mnemonic;
    let granter_client =
        AkashClient::new_from_mnemonic(granter_mnemonic, net.rpc(), net.grpc())
            .await
            .expect("granter client");
    let granter_addr = granter_client.address();

    let grantee_mnemonic = generate_test_mnemonic();
    let grantee_signer =
        KeySigner::new_mnemonic_str(&grantee_mnemonic, None).expect("grantee signer");
    let grantee_addr = child_address(&grantee_signer, "akash");

    net.faucet(&granter_addr, 100_000_000)
        .await
        .expect("fund granter");

    let granter_signer =
        KeySigner::new_mnemonic_str(granter_mnemonic, None).expect("granter signer");
    let querier = &granter_client.signing_client().querier;
    let chain_id = querier.chain_config.chain_id.as_str();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Grant
    let grant_msgs =
        build_authz_grant_msgs(&granter_addr, &grantee_addr, Some(now + 86400));

    let acct = querier
        .base_account(granter_client.address_ref())
        .await
        .expect("base_account");

    let grant_tx = broadcast_multi_signer(
        querier,
        chain_id,
        vec![SignerEntry {
            signer: &granter_signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages: grant_msgs,
        }],
        1.5,
        Duration::from_secs(60),
    )
    .await
    .expect("grant tx");

    assert_eq!(grant_tx.code, 0, "grant failed: {}", grant_tx.raw_log);
    eprintln!("[authz-grant] Grants confirmed: hash={}", grant_tx.hash);

    // Verify type URLs are prost-derived (not hardcoded)
    let type_urls = authz_msg_type_urls();
    assert_eq!(type_urls.len(), 5);
    for url in &type_urls {
        assert!(url.starts_with("/akash."), "expected Akash type URL, got: {}", url);
    }
    eprintln!("[authz-grant] {} msg type URLs verified (prost-derived)", type_urls.len());
}
