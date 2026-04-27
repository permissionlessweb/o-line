/// Integration tests for `oline testnet-deploy`.
///
/// # Test functions
///
/// 1. `test_testnet_sdl_render`  — template substitution for all 3 testnet SDLs (no infra)
/// 2. `test_testnet_deploy_akash` — full deploy to local Akash devnet with localterp
///
/// # Prerequisites
///
/// SDL render test: none (runs in `just test unit`)
///
/// Akash deploy test:
/// ```bash
/// just akash-setup                    # one-time: ict-rs chain image + test-provider
/// cargo build --bin test-provider
/// # localterp image must be available:
/// docker pull ghcr.io/permissionlessweb/localterp:latest
/// # or build locally:
/// cd /path/to/terp-core && docker build --target localterp -t localterp:latest .
/// ```
///
/// # Run
///
/// ```bash
/// just test testnet render            # SDL template validation only
/// just test testnet deploy            # full Akash deploy (requires infra)
/// just test testnet all               # everything
/// ```
use o_line_sdl::config::{build_config_from_env, OLineConfig};
use std::collections::HashMap;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build a minimal OLineConfig from env + defaults for template rendering tests.
fn test_config() -> OLineConfig {
    // Set minimum required env vars for template rendering
    std::env::set_var("OMNIBUS_IMAGE", "ghcr.io/akash-network/cosmos-omnibus:test");
    std::env::set_var("SSH_P", "22");
    std::env::set_var("OLINE_BINARY", "terpd");
    std::env::set_var("OLINE_CHAIN_ID", "morocco-1");
    std::env::set_var("OLINE_CHAIN_JSON", "https://example.com/chain.json");
    build_config_from_env("test mnemonic words here".into(), None)
}

/// Build testnet Phase A vars (subset of what build_testnet_a_vars does, without SSH keygen).
fn test_a_vars(config: &OLineConfig) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();
    vars.insert("VALIDATOR_SVC".into(), "testnet-a-validator".into());
    vars.insert("SNAPSHOT_SVC".into(), "testnet-a-snapshot".into());
    vars.insert("SEED_SVC".into(), "testnet-a-seed".into());
    vars.insert("LOCALTERP_IMAGE".into(), "localterp:latest".into());
    vars.insert("TESTNET_CHAIN_ID".into(), "testnet-1".into());
    vars.insert("TESTNET_FAST_BLOCKS".into(), "true".into());
    vars.insert("SNAPSHOT_MONIKER".into(), "test-snapshot".into());
    vars.insert("SEED_MONIKER".into(), "test-seed".into());
    vars.insert("SSH_PUBKEY".into(), "ssh-ed25519 AAAA...".into());
    vars.insert(
        "SSH_PRIVKEY".into(),
        "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
    );
    vars.insert("SSH_KEY_PATH".into(), "/tmp/test-key".into());
    vars.insert("TERPD_P2P_PERSISTENT_PEERS".into(), String::new());
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), String::new());
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), String::new());
    vars.insert("SNAPSHOT_80_ACCEPTS".into(), String::new());
    vars.insert("SEED_80_ACCEPTS".into(), String::new());
    vars.insert("VALIDATOR_80_ACCEPTS".into(), String::new());
    // Port/domain vars normally from TOML config
    for suffix in ["SNAP", "SEED"] {
        vars.insert(format!("P2P_P_{}", suffix), "26656".into());
        vars.insert(format!("P2P_D_{}", suffix), "p2p.test.local".into());
        vars.insert(format!("RPC_P_{}", suffix), "26657".into());
        vars.insert(format!("RPC_D_{}", suffix), "rpc.test.local".into());
        vars.insert(format!("API_P_{}", suffix), "1317".into());
        vars.insert(format!("API_D_{}", suffix), "api.test.local".into());
        vars.insert(format!("GRPC_P_{}", suffix), "9090".into());
        vars.insert(format!("GRPC_D_{}", suffix), "grpc.test.local".into());
    }
    vars
}

/// Build testnet Phase B vars for template rendering.
fn test_b_vars(config: &OLineConfig) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();
    vars.insert("LT_SVC".into(), "oline-b-left-tackle".into());
    vars.insert("RT_SVC".into(), "oline-b-right-tackle".into());
    vars.insert("TESTNET_CHAIN_ID".into(), "testnet-1".into());
    vars.insert("LEFT_TACKLE_MONIKER".into(), "test-lt".into());
    vars.insert("RIGHT_TACKLE_MONIKER".into(), "test-rt".into());
    vars.insert("SSH_PUBKEY".into(), "ssh-ed25519 AAAA...".into());
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        "abc@1.2.3.4:26656".into(),
    );
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), "abc".into());
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), "abc".into());
    vars.insert("STATESYNC_RPC_SERVERS".into(), String::new());
    vars.insert("LT_80_ACCEPTS".into(), String::new());
    vars.insert("RT_80_ACCEPTS".into(), String::new());
    vars
}

/// Build testnet Phase C vars for template rendering.
fn test_c_vars(config: &OLineConfig) -> HashMap<String, String> {
    let mut vars = config.to_sdl_vars();
    vars.insert("LF_SVC".into(), "oline-c-left-forward".into());
    vars.insert("RF_SVC".into(), "oline-c-right-forward".into());
    vars.insert("TESTNET_CHAIN_ID".into(), "testnet-1".into());
    vars.insert("LEFT_FMONIKER".into(), "test-lf".into());
    vars.insert("RIGHT_FMONIKER".into(), "test-rf".into());
    vars.insert("SSH_PUBKEY".into(), "ssh-ed25519 AAAA...".into());
    vars.insert("TERPD_P2P_SEEDS".into(), "seed@1.2.3.4:26656".into());
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        "snap@1.2.3.4:26656".into(),
    );
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), "lt,rt,val".into());
    vars.insert(
        "TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(),
        "lt,rt,val".into(),
    );
    vars.insert("STATESYNC_RPC_SERVERS".into(), String::new());
    vars.insert("LF_80_ACCEPTS".into(), String::new());
    vars.insert("RF_80_ACCEPTS".into(), String::new());
    vars
}

// ── SDL Render Tests (no infrastructure) ─────────────────────────────────────

#[test]
fn test_testnet_sdl_render_phase_a() {
    let config = test_config();
    let vars = test_a_vars(&config);
    let sdl_template = config
        .load_sdl("testnet-a.yml")
        .expect("load testnet-a.yml");
    let rendered = akash_deploy_rs::substitute_partial(&sdl_template, &vars);

    // Validator service present with localterp image
    assert!(
        rendered.contains("testnet-a-validator"),
        "missing validator service name"
    );
    assert!(
        rendered.contains("localterp:latest"),
        "missing localterp image"
    );
    assert!(
        rendered.contains("CHAINID=testnet-1"),
        "missing CHAINID env"
    );
    assert!(
        rendered.contains("FAST_BLOCKS=true"),
        "missing FAST_BLOCKS env"
    );

    // Sentries present with OLINE_OFFLINE
    assert!(
        rendered.contains("testnet-a-snapshot"),
        "missing snapshot service"
    );
    assert!(rendered.contains("testnet-a-seed"), "missing seed service");
    assert!(
        rendered.contains("OLINE_OFFLINE=1"),
        "missing OLINE_OFFLINE"
    );

    // No SNAPSHOT_MODE=sftp (fresh chain — no snapshot to deliver)
    assert!(
        !rendered.contains("SNAPSHOT_MODE"),
        "testnet-a should not have SNAPSHOT_MODE"
    );

    // Verify YAML is parseable
    let parsed: serde_yaml::Value = serde_yaml::from_str(&rendered).expect("valid YAML");
    let services = parsed["services"].as_mapping().expect("services mapping");
    assert_eq!(
        services.len(),
        3,
        "expected 3 services (validator + snapshot + seed)"
    );

    println!(
        "testnet-a.yml rendered OK ({} bytes, {} services)",
        rendered.len(),
        services.len()
    );
}

#[test]
fn test_testnet_sdl_render_phase_b() {
    let config = test_config();
    let vars = test_b_vars(&config);
    let sdl_template = config
        .load_sdl("testnet-b.yml")
        .expect("load testnet-b.yml");
    let rendered = akash_deploy_rs::substitute_partial(&sdl_template, &vars);

    // Tackle services present
    assert!(
        rendered.contains("oline-b-left-tackle"),
        "missing left tackle service"
    );
    assert!(
        rendered.contains("oline-b-right-tackle"),
        "missing right tackle service"
    );

    // Offline mode, NO snapshot mode
    assert!(
        rendered.contains("OLINE_OFFLINE=1"),
        "missing OLINE_OFFLINE"
    );
    assert!(
        !rendered.contains("SNAPSHOT_MODE"),
        "testnet-b should not have SNAPSHOT_MODE"
    );

    // Testnet chain ID injected
    assert!(
        rendered.contains("CHAIN_ID=testnet-1"),
        "missing testnet chain ID"
    );

    // Validator as private peer
    assert!(
        rendered.contains("TERPD_P2P_PRIVATE_PEER_IDS=abc"),
        "missing private peer IDs"
    );

    let parsed: serde_yaml::Value = serde_yaml::from_str(&rendered).expect("valid YAML");
    let services = parsed["services"].as_mapping().expect("services mapping");
    assert_eq!(
        services.len(),
        2,
        "expected 2 services (left + right tackle)"
    );

    // Both tackles must have domain/port env vars for nginx/reverse-proxy
    let rt_key = serde_yaml::Value::String("oline-b-right-tackle".into());
    let rt_env = parsed["services"][&rt_key]["env"]
        .as_sequence()
        .expect("right tackle env must be a list");
    let rt_env_str: Vec<String> = rt_env
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    for required_prefix in ["RPC_DOMAIN=", "RPC_P=", "API_D=", "API_P=",
                            "P2P_D=", "P2P_P=", "GRPC_P=", "GRPC_D="] {
        assert!(
            rt_env_str.iter().any(|e| e.starts_with(required_prefix)),
            "right tackle missing env var starting with '{}'",
            required_prefix
        );
    }

    println!(
        "testnet-b.yml rendered OK ({} bytes, {} services)",
        rendered.len(),
        services.len()
    );
}

#[test]
fn test_testnet_sdl_render_phase_c() {
    let config = test_config();
    let vars = test_c_vars(&config);
    let sdl_template = config
        .load_sdl("testnet-c.yml")
        .expect("load testnet-c.yml");
    let rendered = akash_deploy_rs::substitute_partial(&sdl_template, &vars);

    // Forward services present
    assert!(
        rendered.contains("oline-c-left-forward"),
        "missing left forward service"
    );
    assert!(
        rendered.contains("oline-c-right-forward"),
        "missing right forward service"
    );

    // Offline mode, NO snapshot mode
    assert!(
        rendered.contains("OLINE_OFFLINE=1"),
        "missing OLINE_OFFLINE"
    );
    assert!(
        !rendered.contains("SNAPSHOT_MODE"),
        "testnet-c should not have SNAPSHOT_MODE"
    );

    // Seeds injected (no trailing space)
    assert!(
        rendered.contains("TERPD_P2P_SEEDS=seed@1.2.3.4:26656"),
        "missing seeds"
    );
    assert!(
        !rendered.contains("TERPD_P2P_SEEDS=seed@1.2.3.4:26656 "),
        "trailing space in seeds would poison P2P config"
    );

    let parsed: serde_yaml::Value = serde_yaml::from_str(&rendered).expect("valid YAML");
    let services = parsed["services"].as_mapping().expect("services mapping");
    assert_eq!(
        services.len(),
        2,
        "expected 2 services (left + right forward)"
    );

    println!(
        "testnet-c.yml rendered OK ({} bytes, {} services)",
        rendered.len(),
        services.len()
    );
}

// ── Akash Deploy Test (requires infrastructure) ──────────────────────────────

#[cfg(feature = "testing")]
#[tokio::test]
#[ignore = "requires local Akash dev cluster + localterp image (just test testnet deploy)"]
async fn test_testnet_deploy_akash() {
    #[cfg(feature = "testing")]
    use o_line_sdl::{
        config::build_config_from_env, deployer::OLineDeployer, testing::IctAkashNetwork,
    };

    // 1. Start local Akash network (ict-rs chain + test-provider).
    let net = IctAkashNetwork::start("testnet-deploy")
        .await
        .expect("start Akash local network");

    println!("Akash devnet running:");
    println!("  RPC:  {}", net.rpc);
    println!("  gRPC: {}", net.grpc);
    println!("  REST: {}", net.rest);

    // 2. Build config targeting local devnet.
    std::env::set_var("OLINE_RPC_ENDPOINT", &net.rpc);
    std::env::set_var("OLINE_GRPC_ENDPOINT", &net.grpc);
    std::env::set_var("OLINE_REST_ENDPOINT", &net.rest);
    std::env::set_var("OLINE_NON_INTERACTIVE", "1");
    std::env::set_var("OLINE_AUTO_SELECT", "1");
    // Stop after deploy — no real provider to send manifest to.
    std::env::set_var("OLINE_TEST_STOP_AFTER_DEPLOY", "1");

    let config = build_config_from_env(net.deployer_mnemonic.clone(), None);

    // 3. Fund deployer account.
    let deployer = OLineDeployer::new(config.clone(), "test".into())
        .await
        .expect("create deployer");
    let deployer_addr = deployer.client.address().to_string();
    println!("  Deployer: {}", deployer_addr);

    // Fund deployer via faucet.
    let faucet_client =
        akash_deploy_rs::AkashClient::new_from_mnemonic(&net.faucet_mnemonic, &net.rpc, &net.grpc)
            .await
            .expect("faucet client");

    let fund_tx = faucet_client
        .bank_send(&deployer_addr, 100_000_000, "uakt")
        .await
        .expect("fund deployer");
    assert!(fund_tx.is_success(), "fund tx failed: {}", fund_tx.raw_log);
    println!("  Funded deployer with 100M uakt (tx: {})", fund_tx.hash);

    // 4. Load and render testnet-a.yml to verify it produces a valid SDL.
    let sdl_a = config
        .load_sdl("testnet-a.yml")
        .expect("load testnet-a.yml");
    let mut vars = config.to_sdl_vars();

    // Inject the minimum vars needed for template rendering.
    vars.insert("VALIDATOR_SVC".into(), "testnet-a-validator".into());
    vars.insert("SNAPSHOT_SVC".into(), "testnet-a-snapshot".into());
    vars.insert("SEED_SVC".into(), "testnet-a-seed".into());
    vars.insert(
        "LOCALTERP_IMAGE".into(),
        "ghcr.io/permissionlessweb/localterp:latest".into(),
    );
    vars.insert("TESTNET_CHAIN_ID".into(), "testnet-1".into());
    vars.insert("TESTNET_FAST_BLOCKS".into(), "true".into());
    vars.insert("SNAPSHOT_MONIKER".into(), "test-snap".into());
    vars.insert("SEED_MONIKER".into(), "test-seed".into());
    vars.insert("SSH_PUBKEY".into(), "ssh-ed25519 AAAA_placeholder".into());
    vars.insert("TERPD_P2P_PERSISTENT_PEERS".into(), String::new());
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), String::new());
    vars.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), String::new());
    vars.insert("SNAPSHOT_80_ACCEPTS".into(), String::new());
    vars.insert("SEED_80_ACCEPTS".into(), String::new());

    let rendered = akash_deploy_rs::substitute_partial(&sdl_a, &vars);
    println!("  Rendered testnet-a.yml ({} bytes)", rendered.len());

    // 5. Deploy Phase A via the deployer (auto-select provider).
    //    OLINE_TEST_STOP_AFTER_DEPLOY stops before SendManifest.
    let (state, endpoints) = deployer
        .deploy_phase_auto(&sdl_a, &vars, "testnet-phase-a")
        .await
        .expect("deploy testnet-phase-a");

    let dseq = state.dseq.expect("Phase A must have dseq");
    println!("  Phase A deployed! DSEQ: {}", dseq);
    assert!(dseq > 0, "dseq must be > 0");

    // Endpoints may be empty in test mode (no real provider), but the deploy succeeded.
    println!(
        "  Phase A endpoints: {:?}",
        endpoints
            .iter()
            .map(|e| format!("{}:{}", e.service, e.port))
            .collect::<Vec<_>>()
    );
    println!("  Test passed: testnet Phase A deployment lifecycle OK");
}
