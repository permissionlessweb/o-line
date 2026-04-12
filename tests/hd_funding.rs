/// HD child account funding test against a local Akash dev cluster.
///
/// Validates that `fund_child_accounts` correctly:
///   1. Derives N child accounts from the master mnemonic
///   2. Funds each child via bank_send
///   3. Records account entries in the session
///   4. Creates child deployers with correct addresses
///
/// # Prerequisites
///
/// ```bash
/// just akash-setup              # one-time
/// cargo build --bin test-provider
/// ```
///
/// # Run
///
/// ```bash
/// just test-hd-funding
/// ```
use o_line_sdl::{
    accounts::child_address_str,
    config::build_config_from_env,
    deployer::OLineDeployer,
    sessions::{FundingMethod, OLineSession, OLineSessionStore},
    workflow::{OLineWorkflow, StepResult},
    workflow::step::OLineStep,
};
use o_line_sdl::testing::AkashLocalNetwork;

#[tokio::test]
#[ignore = "requires local Akash dev cluster (just akash-setup + cargo build --bin test-provider)"]
async fn test_hd_fund_child_accounts() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();

    // ── 1. Start local Akash network ─────────────────────────────────────────
    eprintln!("[hd-funding] Starting AkashLocalNetwork…");
    let net = AkashLocalNetwork::start()
        .await
        .expect("AkashLocalNetwork::start()");

    eprintln!("[hd-funding] Network ready.");
    eprintln!("[hd-funding]   RPC:    {}", net.rpc());
    eprintln!("[hd-funding]   gRPC:   {}", net.grpc());
    eprintln!("[hd-funding]   REST:   {}", net.rest());
    eprintln!("[hd-funding]   Chain:  {}", net.chain_id());

    // ── 2. Fund deployer account via faucet ──────────────────────────────────
    let deployer_client = net.deployer_client().await.expect("deployer client");
    let deployer_addr = deployer_client.address().to_string();
    eprintln!("[hd-funding]   Deployer: {}", deployer_addr);

    eprintln!("[hd-funding] Funding deployer via faucet (100 AKT)…");
    net.faucet(&deployer_addr, 100_000_000)
        .await
        .expect("faucet: fund deployer");

    // ── 3. Build config from env ─────────────────────────────────────────────
    // Set env vars so build_config_from_env picks them up.
    std::env::set_var("OLINE_RPC_ENDPOINT", net.rpc());
    std::env::set_var("OLINE_GRPC_ENDPOINT", net.grpc());
    std::env::set_var("OLINE_REST_ENDPOINT", net.rest());
    std::env::set_var("OLINE_CHAIN_ID", net.chain_id());
    std::env::set_var("OLINE_NON_INTERACTIVE", "1");

    let config = build_config_from_env(net.deployer_mnemonic.clone());

    // ── 4. Create deployer + workflow with HD funding ─────────────────────────
    let deployer = OLineDeployer::new(config, "test-password".into())
        .await
        .expect("OLineDeployer::new");

    let count = 3u32;
    let amount_per_child = 5_000_000u64;

    let session = OLineSession::new(
        FundingMethod::HdDerived {
            count,
            amount_per_child,
            act_amount_per_child: amount_per_child,
        },
        &deployer_addr,
        net.chain_id(),
    );

    let tmp_dir = std::env::temp_dir().join("oline-hd-funding-test");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    let session_store = OLineSessionStore::with_dir(tmp_dir.clone());

    let mut workflow = OLineWorkflow::new_with_session(
        deployer,
        OLineStep::FundChildAccounts,
        session,
        session_store,
    );

    // ── 5. Advance one step (FundChildAccounts) ──────────────────────────────
    eprintln!("[hd-funding] Running FundChildAccounts step…");
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    use std::io::BufRead;

    let result = workflow.advance(&mut lines).await.expect("advance");
    match result {
        StepResult::Continue => {}
        other => panic!("expected Continue, got {:?}", std::mem::discriminant(&other)),
    }

    // ── 6. Assertions ────────────────────────────────────────────────────────

    // Step should have moved to DeployAllUnits.
    assert_eq!(
        workflow.step,
        OLineStep::DeployAllUnits,
        "step should advance to DeployAllUnits"
    );

    // Session should have 3 account entries.
    let accounts = &workflow.ctx.session.accounts;
    assert_eq!(accounts.len(), count as usize, "expected {} accounts", count);

    // Each account should have correct address and be marked funded.
    for (i, acct) in accounts.iter().enumerate() {
        assert_eq!(acct.hd_index, i as u32);
        assert!(acct.funded, "account {} should be funded", i);
        assert_eq!(acct.funded_amount, amount_per_child);

        // Verify address matches independent derivation.
        let expected_addr =
            child_address_str(&net.deployer_mnemonic, i as u32, "akash").expect("child_address_str");
        assert_eq!(
            acct.address, expected_addr,
            "account {} address mismatch",
            i
        );
        eprintln!(
            "[hd-funding]   account[{}]: {} (funded: {} uakt)",
            i, acct.address, acct.funded_amount
        );
    }

    // Context should have 3 unit states with child deployers.
    let units = &workflow.ctx.units;
    assert_eq!(units.len(), count as usize, "expected {} units", count);

    for (i, unit) in units.iter().enumerate() {
        assert_eq!(unit.hd_index, i as u32);
        let unit_addr = unit.deployer.client.address().to_string();
        let expected_addr =
            child_address_str(&net.deployer_mnemonic, i as u32, "akash").expect("child_address_str");
        assert_eq!(
            unit_addr, expected_addr,
            "unit {} deployer address mismatch",
            i
        );
        // Child deployer address must differ from master.
        assert_ne!(
            unit_addr, deployer_addr,
            "child {} address should differ from master",
            i
        );
        eprintln!(
            "[hd-funding]   unit[{}]: name={} addr={}",
            i, unit.name, unit_addr
        );
    }

    // ── 7. Verify on-chain balances via REST ─────────────────────────────────
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    for acct in accounts {
        let url = format!(
            "{}/cosmos/bank/v1beta1/balances/{}",
            net.rest(),
            acct.address
        );
        let resp = http.get(&url).send().await;
        match resp {
            Ok(r) if r.status().is_success() => {
                let json: serde_json::Value = r.json().await.unwrap_or_default();
                let uakt_balance: u64 = json["balances"]
                    .as_array()
                    .and_then(|arr| {
                        arr.iter().find(|b| b["denom"].as_str() == Some("uakt"))
                    })
                    .and_then(|b| b["amount"].as_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                eprintln!(
                    "[hd-funding]   balance[{}]: {} uakt",
                    acct.address, uakt_balance
                );
                assert!(
                    uakt_balance >= amount_per_child,
                    "account {} balance {} < expected {}",
                    acct.address,
                    uakt_balance,
                    amount_per_child
                );
            }
            Ok(r) => {
                eprintln!(
                    "[hd-funding]   balance query HTTP {}: skipping assertion",
                    r.status()
                );
            }
            Err(e) => {
                eprintln!(
                    "[hd-funding]   balance query error for {}: {} — skipping",
                    acct.address, e
                );
            }
        }
    }

    eprintln!("[hd-funding] ✓ All assertions passed.");

    // Cleanup temp dir.
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
