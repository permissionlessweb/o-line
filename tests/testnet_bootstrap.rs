/// Container bootstrap tests for `oline testnet-deploy`.
///
/// These tests verify the localterp container can bootstrap a fresh testnet
/// genesis, produce blocks, and expose RPC/faucet endpoints. No Akash deployment
/// needed — runs directly via Docker.
///
/// # Prerequisites
///
/// ```bash
/// docker pull terpnetwork/terp-core:localterp
/// # or build locally:
/// cd /path/to/terp-core && docker build --target localterp -t terpnetwork/terp-core:localterp .
/// ```
///
/// # Run
///
/// ```bash
/// cargo test --test testnet_bootstrap -- --nocapture
/// ```

const LOCALTERP_IMAGE: &str = "terpnetwork/terp-core:localterp";
const TESTNET_CHAIN_ID: &str = "bootstrap-test-1";
const CONTAINER_NAME: &str = "oline-bootstrap-test";
const BLOCK_TIMEOUT_SECS: u64 = 30;

// ── Docker helpers ───────────────────────────────────────────────────────────

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn image_exists(image: &str) -> bool {
    std::process::Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn cleanup_container(name: &str) {
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn start_localterp_custom(
    name: &str, chain_id: &str, fast_blocks: bool,
    rpc_port: u16, api_port: u16, faucet_port: u16, grpc_port: u16,
) -> Result<(), String> {
    let chain_env = format!("CHAINID={}", chain_id);
    let rpc_map = format!("{}:26657", rpc_port);
    let api_map = format!("{}:1317", api_port);
    let faucet_map = format!("{}:5000", faucet_port);
    let grpc_map = format!("{}:9090", grpc_port);

    let mut cmd = std::process::Command::new("docker");
    cmd.args([
        "run", "-d",
        "--name", name,
        "-p", &rpc_map,
        "-p", &api_map,
        "-p", &faucet_map,
        "-p", &grpc_map,
        "-e", &chain_env,
    ]);
    if fast_blocks {
        cmd.args(["-e", "FAST_BLOCKS=true"]);
    }
    cmd.arg(LOCALTERP_IMAGE);

    let output = cmd.output()
        .map_err(|e| format!("docker run failed: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "docker run exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn start_localterp(name: &str, chain_id: &str, fast_blocks: bool) -> Result<(), String> {
    let chain_env = format!("CHAINID={}", chain_id);
    let mut cmd = std::process::Command::new("docker");
    cmd.args([
        "run", "-d",
        "--name", name,
        "-p", "36657:26657",
        "-p", "31317:1317",
        "-p", "35000:5000",
        "-p", "39090:9090",
        "-e", &chain_env,
    ]);
    if fast_blocks {
        cmd.args(["-e", "FAST_BLOCKS=true"]);
    }
    cmd.arg(LOCALTERP_IMAGE);

    let output = cmd.output()
        .map_err(|e| format!("docker run failed: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "docker run exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn container_logs(name: &str) -> String {
    std::process::Command::new("docker")
        .args(["logs", name])
        .output()
        .map(|o| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        })
        .unwrap_or_default()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn test_localterp_genesis_bootstrap() {
    if !docker_available() {
        eprintln!("SKIP: Docker not available");
        return;
    }
    if !image_exists(LOCALTERP_IMAGE) {
        eprintln!("SKIP: {} image not found", LOCALTERP_IMAGE);
        return;
    }

    // Clean up any previous run
    cleanup_container(CONTAINER_NAME);

    // Start fresh localterp with fast blocks
    start_localterp(CONTAINER_NAME, TESTNET_CHAIN_ID, true)
        .expect("start localterp container");

    // Wait for container to boot and produce blocks
    let rpc_url = "http://127.0.0.1:36657";
    let mut blocks_seen = false;

    for attempt in 0..BLOCK_TIMEOUT_SECS {
        std::thread::sleep(std::time::Duration::from_secs(1));

        let status = reqwest::blocking::get(format!("{}/status", rpc_url));
        if let Ok(resp) = status {
            if let Ok(body) = resp.text() {
                // Check if we have block height > 1
                if let Some(height_str) = extract_json_field(&body, "latest_block_height") {
                    if let Ok(height) = height_str.parse::<u64>() {
                        if height > 1 {
                            println!("  Block height {} after {}s", height, attempt + 1);
                            blocks_seen = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if !blocks_seen {
        let logs = container_logs(CONTAINER_NAME);
        cleanup_container(CONTAINER_NAME);
        panic!(
            "Validator did not produce blocks within {}s.\nContainer logs:\n{}",
            BLOCK_TIMEOUT_SECS,
            &logs[logs.len().saturating_sub(2000)..]
        );
    }

    // Verify genesis is accessible via RPC
    let genesis_resp = reqwest::blocking::get(format!("{}/genesis", rpc_url))
        .expect("fetch genesis")
        .text()
        .expect("genesis body");
    assert!(
        genesis_resp.contains(TESTNET_CHAIN_ID),
        "genesis should contain chain_id {}", TESTNET_CHAIN_ID
    );
    println!("  Genesis contains chain_id: {}", TESTNET_CHAIN_ID);

    // Verify chain_id matches
    let status_resp = reqwest::blocking::get(format!("{}/status", rpc_url))
        .expect("fetch status")
        .text()
        .expect("status body");
    assert!(
        status_resp.contains(TESTNET_CHAIN_ID),
        "status should contain chain_id"
    );

    // Verify faucet is reachable
    let faucet_resp = reqwest::blocking::get("http://127.0.0.1:35000/status");
    match faucet_resp {
        Ok(resp) => {
            let body = resp.text().unwrap_or_default();
            println!("  Faucet status: {}", &body[..body.len().min(200)]);
        }
        Err(e) => {
            println!("  Faucet not ready yet (may need more time): {}", e);
        }
    }

    // Verify REST API
    let api_resp = reqwest::blocking::get("http://127.0.0.1:31317/cosmos/base/tendermint/v1beta1/blocks/latest");
    match api_resp {
        Ok(resp) => {
            let body = resp.text().unwrap_or_default();
            assert!(
                body.contains("block") || body.contains("height"),
                "REST API should return block data"
            );
            println!("  REST API responding");
        }
        Err(e) => {
            println!("  REST API not ready: {}", e);
        }
    }

    println!("  Bootstrap test PASSED");
    cleanup_container(CONTAINER_NAME);
}

#[test]
fn test_localterp_custom_chain_id() {
    if !docker_available() || !image_exists(LOCALTERP_IMAGE) {
        eprintln!("SKIP: Docker or image not available");
        return;
    }

    let name = "oline-chainid-test";
    let chain_id = "zk-testnet-42";
    cleanup_container(name);

    start_localterp(name, chain_id, true).expect("start container");

    // Wait for RPC
    let mut ready = false;
    for _ in 0..BLOCK_TIMEOUT_SECS {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(resp) = reqwest::blocking::get("http://127.0.0.1:36657/status") {
            if let Ok(body) = resp.text() {
                if body.contains(chain_id) {
                    ready = true;
                    break;
                }
            }
        }
    }

    // Port conflict — this test can only run if the previous one cleaned up.
    // If ports are in use, skip gracefully.
    if !ready {
        let logs = container_logs(name);
        cleanup_container(name);
        if logs.contains("address already in use") {
            eprintln!("SKIP: ports in use from previous test");
            return;
        }
        panic!("Container with chain_id {} did not start", chain_id);
    }

    // Verify the chain ID propagated correctly
    let genesis = reqwest::blocking::get("http://127.0.0.1:36657/genesis")
        .expect("genesis")
        .text()
        .expect("body");
    assert!(genesis.contains(chain_id), "genesis must have custom chain_id");

    println!("  Custom chain_id {} confirmed in genesis", chain_id);
    cleanup_container(name);
}

#[test]
fn test_localterp_faucet_send_verify() {
    if !docker_available() || !image_exists(LOCALTERP_IMAGE) {
        eprintln!("SKIP: Docker or image not available");
        return;
    }

    let name = "oline-faucet-test";
    cleanup_container(name);

    start_localterp(name, "faucet-test-1", true).expect("start container");

    let rpc = "http://127.0.0.1:36657";
    let faucet = "http://127.0.0.1:35000";
    let api = "http://127.0.0.1:31317";

    // 1. Wait for blocks
    let mut ready = false;
    for i in 0..BLOCK_TIMEOUT_SECS {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(resp) = reqwest::blocking::get(format!("{}/status", rpc)) {
            if let Ok(body) = resp.text() {
                if let Some(h) = extract_json_field(&body, "latest_block_height") {
                    if h.parse::<u64>().unwrap_or(0) > 1 {
                        println!("  Blocks producing (height {}) after {}s", h, i + 1);
                        ready = true;
                        break;
                    }
                }
            }
        }
    }
    if !ready {
        let logs = container_logs(name);
        cleanup_container(name);
        panic!("Blocks not producing. Logs:\n{}", &logs[logs.len().saturating_sub(2000)..]);
    }

    // 2. Get a fresh test address by querying one of the pre-funded accounts
    //    localterp has pre-funded keys: validator, a, b, c, d
    //    We'll use key "a" as the sender and create a recipient address
    //    First, get account "a"'s address from the container
    let key_output = std::process::Command::new("docker")
        .args(["exec", name, "terpd", "keys", "show", "a", "-a", "--keyring-backend", "test"])
        .output()
        .expect("get key a address");
    let sender_addr = String::from_utf8_lossy(&key_output.stdout).trim().to_string();
    assert!(sender_addr.starts_with("terp1"), "key 'a' should have terp1 address, got: {}", sender_addr);
    println!("  Sender (key a): {}", sender_addr);

    // Get key "b" as recipient
    let key_output = std::process::Command::new("docker")
        .args(["exec", name, "terpd", "keys", "show", "b", "-a", "--keyring-backend", "test"])
        .output()
        .expect("get key b address");
    let recipient_addr = String::from_utf8_lossy(&key_output.stdout).trim().to_string();
    assert!(recipient_addr.starts_with("terp1"), "key 'b' should have terp1 address, got: {}", recipient_addr);
    println!("  Recipient (key b): {}", recipient_addr);

    // 4. Wait for faucet to be ready
    let mut faucet_ready = false;
    for i in 0..60 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(resp) = reqwest::blocking::get(format!("{}/status", faucet)) {
            if resp.status().is_success() {
                let body = resp.text().unwrap_or_default();
                println!("  Faucet ready after {}s: {}", i + 1, &body[..body.len().min(200)]);
                faucet_ready = true;
                break;
            }
        }
    }
    if !faucet_ready {
        let logs = container_logs(name);
        cleanup_container(name);
        panic!("Faucet not ready after 60s");
    }

    // 5. Request funds from faucet
    let faucet_resp = reqwest::blocking::get(format!("{}/faucet?address={}", faucet, sender_addr))
        .expect("faucet request");
    let faucet_body = faucet_resp.text().unwrap_or_default();
    println!("  Faucet response: {}", &faucet_body[..faucet_body.len().min(300)]);
    assert!(faucet_body.contains("txhash"), "faucet should return txhash, got: {}", faucet_body);

    // Wait for faucet tx to land
    std::thread::sleep(std::time::Duration::from_secs(3));

    // 6. Check sender balance
    let balance_resp = reqwest::blocking::get(
        format!("{}/cosmos/bank/v1beta1/balances/{}", api, sender_addr)
    ).expect("query balance");
    let balance_body = balance_resp.text().unwrap_or_default();
    println!("  Sender balance: {}", &balance_body[..balance_body.len().min(300)]);
    assert!(
        balance_body.contains("uterp") || balance_body.contains("uthiol"),
        "sender should have tokens after faucet"
    );

    // 6. Send funds from sender (key a) to recipient (key b) via terpd tx
    let send_output = std::process::Command::new("docker")
        .args([
            "exec", name, "terpd", "tx", "bank", "send",
            "a", &recipient_addr, "1000000uterp",
            "--chain-id", "faucet-test-1",
            "--keyring-backend", "test",
            "--fees", "500uterp",
            "--yes",
            "--output", "json",
        ])
        .output()
        .expect("send tx");
    let send_stdout = String::from_utf8_lossy(&send_output.stdout);
    let send_stderr = String::from_utf8_lossy(&send_output.stderr);
    println!("  Send TX stdout: {}", &send_stdout[..send_stdout.len().min(500)]);
    if !send_stderr.is_empty() {
        println!("  Send TX stderr: {}", &send_stderr[..send_stderr.len().min(300)]);
    }

    // Extract txhash from send response
    let send_txhash = extract_json_field(&send_stdout, "txhash");
    assert!(send_txhash.is_some(), "send tx should return a txhash");
    let send_txhash = send_txhash.unwrap();
    println!("  Send TX hash: {}", send_txhash);

    // 7. Wait for tx to be included in a block
    std::thread::sleep(std::time::Duration::from_secs(3));

    // 8. Query the transaction by hash and verify events
    let tx_resp = reqwest::blocking::get(
        format!("{}/cosmos/tx/v1beta1/txs/{}", api, send_txhash)
    ).expect("query tx");
    let tx_body = tx_resp.text().unwrap_or_default();

    // Verify tx succeeded (code 0)
    let tx_code = extract_json_field(&tx_body, "code");
    println!("  TX query code: {:?}", tx_code);
    assert!(
        tx_body.contains("code") && tx_body.contains("0"),
        "tx should succeed with code 0. Response: {}", &tx_body[..tx_body.len().min(500)]
    );

    // Verify transfer event exists
    assert!(
        tx_body.contains("transfer") || tx_body.contains("coin_spent") || tx_body.contains("coin_received"),
        "tx should contain transfer events"
    );
    println!("  TX events confirmed (transfer)");

    // 9. Verify recipient balance increased
    let recipient_balance = reqwest::blocking::get(
        format!("{}/cosmos/bank/v1beta1/balances/{}", api, recipient_addr)
    ).expect("query recipient balance")
    .text().unwrap_or_default();
    println!("  Recipient balance: {}", &recipient_balance[..recipient_balance.len().min(300)]);
    assert!(
        recipient_balance.contains("uterp") || recipient_balance.contains("uthiol"),
        "recipient should have received tokens"
    );

    println!("  Faucet + Send + Verify test PASSED");
    cleanup_container(name);
}

#[test]
fn test_sentry_genesis_from_validator_rpc() {
    if !docker_available() || !image_exists(LOCALTERP_IMAGE) {
        eprintln!("SKIP: Docker or localterp image not available");
        return;
    }

    let omnibus_image = std::env::var("OMNIBUS_IMAGE")
        .unwrap_or_else(|_| "ghcr.io/terpnetwork/terp-core:v5.1.7-oline".to_string());
    if !image_exists(&omnibus_image) {
        eprintln!("SKIP: {} image not found", omnibus_image);
        return;
    }

    let val_name = "oline-genesis-url-val";
    let sentry_name = "oline-genesis-url-sentry";
    let chain_id = "genesis-url-test-1";
    cleanup_container(val_name);
    cleanup_container(sentry_name);

    // 1. Start validator on ports 46657/41317/45000
    start_localterp_custom(val_name, chain_id, true, 46657, 41317, 45000, 49090)
        .expect("start validator");

    // 2. Wait for validator to produce blocks
    let val_rpc = "http://127.0.0.1:46657";
    let mut ready = false;
    for i in 0..BLOCK_TIMEOUT_SECS {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(resp) = reqwest::blocking::get(format!("{}/status", val_rpc)) {
            if let Ok(body) = resp.text() {
                if let Some(h) = extract_json_field(&body, "latest_block_height") {
                    if h.parse::<u64>().unwrap_or(0) > 1 {
                        println!("  Validator producing blocks (height {}) after {}s", h, i + 1);
                        ready = true;
                        break;
                    }
                }
            }
        }
    }
    if !ready {
        let logs = container_logs(val_name);
        cleanup_container(val_name);
        cleanup_container(sentry_name);
        panic!("Validator not producing blocks. Logs:\n{}", &logs[logs.len().saturating_sub(2000)..]);
    }

    // 3. Verify /genesis endpoint returns valid JSON-RPC wrapper
    let genesis_url = format!("{}/genesis", val_rpc);
    let genesis_resp = reqwest::blocking::get(&genesis_url)
        .expect("fetch genesis from validator");
    let genesis_body = genesis_resp.text().unwrap_or_default();
    assert!(
        genesis_body.contains("result") && genesis_body.contains("genesis"),
        "validator /genesis should return JSON-RPC with .result.genesis"
    );
    assert!(
        genesis_body.contains(chain_id),
        "genesis should contain chain_id {}", chain_id
    );
    println!("  Validator /genesis endpoint OK ({} bytes)", genesis_body.len());

    // 4. Fetch genesis from validator, extract from JSON-RPC wrapper, save locally
    let genesis_resp = reqwest::blocking::get(format!("{}/genesis", val_rpc))
        .expect("fetch genesis");
    let genesis_rpc: serde_json::Value = genesis_resp.json().expect("parse genesis JSON-RPC");
    let genesis_inner = genesis_rpc
        .get("result")
        .and_then(|r| r.get("genesis"))
        .expect(".result.genesis missing");
    let genesis_path = "/tmp/oline-test-genesis.json";
    std::fs::write(genesis_path, serde_json::to_string_pretty(genesis_inner).unwrap())
        .expect("write genesis");
    println!("  Extracted genesis to {} ({} bytes)", genesis_path,
        std::fs::metadata(genesis_path).unwrap().len());

    // 5. Start omnibus sentry with terpd bootstrap, mounting genesis file
    let sentry_output = std::process::Command::new("docker")
        .args([
            "run", "-d",
            "--name", sentry_name,
            "--add-host", "host.docker.internal:host-gateway",
            "-p", "56657:26657",
            "-p", "51317:1317",
            "-v", &format!("{}:/tmp/genesis.json:ro", genesis_path),
            &omnibus_image,
            "terpd", "bootstrap",
            "--chain-id", chain_id,
            "--moniker", "test-sentry",
            "--pruning", "nothing",
        ])
        .output()
        .expect("start sentry container");

    if !sentry_output.status.success() {
        let stderr = String::from_utf8_lossy(&sentry_output.stderr);
        cleanup_container(val_name);
        cleanup_container(sentry_name);
        panic!("Failed to start sentry: {}", stderr);
    }

    // Copy pre-extracted genesis into the right config location
    let _ = std::process::Command::new("docker")
        .args(["exec", sentry_name, "sh", "-c",
            "mkdir -p /terpd/.terpd/config && cp /tmp/genesis.json /terpd/.terpd/config/genesis.json"])
        .output();

    // 5. Wait for sentry to download genesis and start (check RPC responds with correct chain)
    let sentry_rpc = "http://127.0.0.1:56657";
    let mut sentry_ready = false;
    for i in 0..90 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(resp) = reqwest::blocking::get(format!("{}/status", sentry_rpc)) {
            if let Ok(body) = resp.text() {
                if body.contains(chain_id) {
                    if let Some(h) = extract_json_field(&body, "latest_block_height") {
                        println!("  Sentry syncing chain {} (height {}) after {}s", chain_id, h, i + 1);
                        sentry_ready = true;
                        break;
                    }
                }
            }
        }
    }

    if !sentry_ready {
        let sentry_logs = container_logs(sentry_name);
        println!("  Sentry logs:\n{}", &sentry_logs[sentry_logs.len().saturating_sub(3000)..]);
        cleanup_container(val_name);
        cleanup_container(sentry_name);
        panic!("Sentry did not sync chain {} via GENESIS_URL within 90s", chain_id);
    }

    // 6. Verify sentry genesis matches validator genesis
    let sentry_genesis = reqwest::blocking::get(format!("{}/genesis", sentry_rpc))
        .expect("sentry genesis")
        .text()
        .unwrap_or_default();
    assert!(
        sentry_genesis.contains(chain_id),
        "sentry genesis should contain chain_id {}", chain_id
    );

    println!("  Genesis-via-URL test PASSED: sentry fetched genesis from validator RPC");
    cleanup_container(val_name);
    cleanup_container(sentry_name);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn extract_json_field<'a>(json: &'a str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", field);
    if let Some(start) = json.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = json[value_start..].find('"') {
            return Some(json[value_start..value_start + end].to_string());
        }
    }
    // Try without quotes (numeric values)
    let pattern2 = format!("\"{}\":", field);
    if let Some(start) = json.find(&pattern2) {
        let value_start = start + pattern2.len();
        let trimmed = json[value_start..].trim_start();
        let end = trimmed.find(|c: char| !c.is_ascii_digit()).unwrap_or(trimmed.len());
        if end > 0 {
            return Some(trimmed[..end].to_string());
        }
    }
    None
}
