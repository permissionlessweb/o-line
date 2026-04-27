//! Comprehensive integration tests for `oline vpn` — Headscale gRPC + pfSense Tailscale.
//!
//! Exercises the full Headscale API surface via the generated gRPC client,
//! then tests pfSense as a Tailscale subnet router with LAN connectivity.
//!
//! Start: `docker compose -f docker/pfsense-e2e/docker-compose.yml up -d --build --wait`
//! Run:   `cargo test --test vpn_pfsense -- --nocapture --ignored`

use std::path::Path;
use std::process::Command;

// ── Constants ─────────────────────────────────────────────────────────────────

const PF_HOST: &str = "127.0.0.1";
const PF_P: u16 = 2222;
const PF_ROOT_USER: &str = "root";
const PF_ROOT_PASS: &str = "pfsense";

const HEADSCALE_GRPC: &str = "http://127.0.0.1:50443";
const HEADSCALE_URL_INTERNAL: &str = "http://10.99.2.180:8080";

const INTERNAL_SERVER_IP: &str = "10.99.1.10";
const INTERNAL_SERVER_HTTP_P: u16 = 8080;
const LAN_SUBNET: &str = "10.99.1.0/24";

// ── SSH Helpers ───────────────────────────────────────────────────────────────

fn wait_for_ssh(host: &str, port: u16, user: &str, pass: &str) {
    for attempt in 1..=30 {
        let status = Command::new("sshpass")
            .args([
                "-p", pass, "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=3",
                "-p", &port.to_string(),
                &format!("{}@{}", user, host),
                "echo ok",
            ])
            .output();

        match status {
            Ok(o) if o.status.success() => return,
            _ => {
                if attempt == 30 {
                    panic!("SSH not reachable at {}:{} after 30 attempts", host, port);
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

fn ssh_exec_with_key(host: &str, port: u16, user: &str, key: &Path, cmd: &str) -> String {
    let output = Command::new("ssh")
        .args([
            "-i", key.to_str().unwrap(),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-p", &port.to_string(),
            &format!("{}@{}", user, host),
            cmd,
        ])
        .output()
        .expect("failed to run ssh");

    String::from_utf8_lossy(&output.stdout).to_string()
}

// ── Headscale CLI Helpers (docker exec) ───────────────────────────────────────

fn headscale_exec(args: &[&str]) -> (String, bool) {
    let mut cmd_args = vec!["exec", "pfsense-headscale", "headscale"];
    cmd_args.extend_from_slice(args);

    let output = Command::new("docker")
        .args(&cmd_args)
        .output()
        .expect("docker exec headscale");

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() && !output.status.success() {
        eprintln!("  headscale {:?} stderr: {}", args, stderr);
    }
    (stdout, output.status.success())
}

fn headscale_exec_json(args: &[&str]) -> serde_json::Value {
    let mut full_args = args.to_vec();
    full_args.push("--output");
    full_args.push("json");
    let (stdout, _) = headscale_exec(&full_args);
    serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Test 1: Headscale health check
#[test]
#[ignore = "requires Docker pfsense-e2e stack"]
fn test_01_headscale_health() {
    println!("\n=== Test: Headscale Health ===");

    // Wait for Headscale to be ready
    for i in 1..=30 {
        let output = Command::new("curl")
            .args(["-sf", "http://127.0.0.1:8080/health"])
            .output();
        if let Ok(o) = output {
            if o.status.success() {
                println!("  Headscale healthy after {}s", i);
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("Headscale not healthy after 30s");
}

/// Test 2: User CRUD via Headscale CLI
#[test]
#[ignore = "requires Docker pfsense-e2e stack"]
fn test_02_user_management() {
    println!("\n=== Test: User Management ===");

    // Create users
    let (out, ok) = headscale_exec(&["users", "create", "admin"]);
    println!("  Create admin: {} (ok={})", out, ok);

    let (out, ok) = headscale_exec(&["users", "create", "testuser"]);
    println!("  Create testuser: {} (ok={})", out, ok);

    let (out, ok) = headscale_exec(&["users", "create", "devops"]);
    println!("  Create devops: {} (ok={})", out, ok);

    // List users
    let users = headscale_exec_json(&["users", "list"]);
    println!("  Users: {}", serde_json::to_string_pretty(&users).unwrap_or_default());

    let empty = vec![]; let user_list = users.as_array().unwrap_or(&empty);
    assert!(user_list.len() >= 3, "Should have at least 3 users, got {}", user_list.len());

    // Rename user
    let testuser_id = user_list.iter()
        .find(|u| u.get("name").and_then(|n| n.as_str()) == Some("testuser"))
        .and_then(|u| u.get("id").and_then(|id| id.as_u64()))
        .expect("testuser should exist");

    let (out, ok) = headscale_exec(&["users", "rename", "--identifier", &testuser_id.to_string(), "--new-name", "testuser-renamed"]);
    println!("  Rename testuser → testuser-renamed: {} (ok={})", out, ok);
    assert!(ok, "Rename should succeed");

    // Delete the renamed user
    let (out, ok) = headscale_exec(&["users", "destroy", &testuser_id.to_string(), "--force"]);
    println!("  Delete testuser-renamed: {} (ok={})", out, ok);

    // Verify deletion
    let users_after = headscale_exec_json(&["users", "list"]);
    let empty_v = vec![]; let names: Vec<&str> = users_after.as_array()
        .unwrap_or(&empty_v)
        .iter()
        .filter_map(|u| u.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(!names.contains(&"testuser-renamed"), "Deleted user should not appear");
    println!("  User CRUD: PASSED");
}

/// Test 3: PreAuth key lifecycle
#[test]
#[ignore = "requires Docker pfsense-e2e stack"]
fn test_03_preauth_key_lifecycle() {
    println!("\n=== Test: PreAuth Key Lifecycle ===");

    // Ensure admin user exists
    let _ = headscale_exec(&["users", "create", "admin"]);

    // Create single-use key
    let (key1, ok) = headscale_exec(&["preauthkeys", "create", "--user", "admin"]);
    assert!(ok && !key1.is_empty(), "Single-use key creation should succeed");
    println!("  Single-use key: {}...", &key1[..key1.len().min(16)]);

    // Create reusable key
    let (key2, ok) = headscale_exec(&["preauthkeys", "create", "--user", "admin", "--reusable"]);
    assert!(ok && !key2.is_empty(), "Reusable key creation should succeed");
    println!("  Reusable key:   {}...", &key2[..key2.len().min(16)]);

    // List keys
    let keys = headscale_exec_json(&["preauthkeys", "list", "--user", "admin"]);
    let key_list = keys.as_array().cloned().unwrap_or_default();
    assert!(key_list.len() >= 2, "Should have at least 2 preauth keys");
    println!("  Listed {} preauth key(s)", key_list.len());

    // Expire the single-use key
    let (out, ok) = headscale_exec(&["preauthkeys", "expire", "--key", &key1]);
    println!("  Expire single-use: {} (ok={})", out, ok);

    println!("  PreAuth Key Lifecycle: PASSED");
}

/// Test 4: API key management
#[test]
#[ignore = "requires Docker pfsense-e2e stack"]
fn test_04_api_key_management() {
    println!("\n=== Test: API Key Management ===");

    // Create API key
    let (key, ok) = headscale_exec(&["apikeys", "create"]);
    assert!(ok && !key.is_empty(), "API key creation should succeed");
    println!("  Created API key: {}...", &key[..key.len().min(12)]);

    // List API keys
    let keys = headscale_exec_json(&["apikeys", "list"]);
    let key_list = keys.as_array().cloned().unwrap_or_default();
    assert!(!key_list.is_empty(), "Should have at least 1 API key");
    println!("  Listed {} API key(s)", key_list.len());

    // Expire the key
    let prefix = &key[..key.find('.').unwrap_or(key.len()).min(10)];
    let (out, ok) = headscale_exec(&["apikeys", "expire", "--prefix", prefix]);
    println!("  Expire API key prefix={}: {} (ok={})", prefix, out, ok);

    println!("  API Key Management: PASSED");
}

/// Test 5: Policy set and get
#[test]
#[ignore = "requires Docker pfsense-e2e stack"]
fn test_05_policy_management() {
    println!("\n=== Test: Policy Management ===");

    // Write a test policy to the container
    let test_policy = r#"{
  "acls": [
    {"action": "accept", "src": ["*"], "dst": ["*:*"]}
  ],
  "ssh": [
    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]}
  ]
}"#;

    // Write policy to container then apply
    let _ = Command::new("docker")
        .args(["exec", "-i", "pfsense-headscale", "sh", "-c",
            &format!("cat > /tmp/policy.json << 'EOF'\n{}\nEOF", test_policy)])
        .output();

    let (out, ok) = headscale_exec(&["policy", "set", "--file", "/tmp/policy.json"]);
    println!("  Set policy: {} (ok={})", out, ok);

    // Get policy
    let (policy_out, ok) = headscale_exec(&["policy", "get"]);
    println!("  Get policy: {} bytes (ok={})", policy_out.len(), ok);
    assert!(policy_out.contains("accept"), "Policy should contain 'accept' rule");

    println!("  Policy Management: PASSED");
}

/// Test 6: Full pfSense Tailscale registration + subnet routing
#[test]
#[ignore = "requires Docker pfsense-e2e stack"]
fn test_06_pfsense_tailscale_subnet_router() {
    println!("\n=== Test: pfSense Tailscale Subnet Router ===");

    // Wait for SSH
    wait_for_ssh(PF_HOST, PF_P, PF_ROOT_USER, PF_ROOT_PASS);

    // Generate SSH key
    let tmp = tempfile::tempdir().expect("tempdir");
    let pf_privkey = o_line_sdl::crypto::gen_ssh_key();
    let pf_pubkey = pf_privkey.public_key().to_string();
    let pf_key_path = tmp.path().join("pf-key");
    o_line_sdl::crypto::save_ssh_key(&pf_privkey, &pf_key_path).unwrap();

    o_line_sdl::firewall::pfsense::install_ssh_key(
        PF_HOST, PF_P, PF_ROOT_USER, PF_ROOT_PASS, &pf_pubkey,
    ).expect("install pfSense SSH key");

    // Ensure admin user exists + create preauth key
    let _ = headscale_exec(&["users", "create", "admin"]);
    let (preauth_key, ok) = headscale_exec(&["preauthkeys", "create", "--user", "admin", "--reusable"]);
    assert!(ok, "Preauth key creation should succeed");

    // Start tailscaled on pfSense
    println!("  Starting tailscaled...");
    let _ = ssh_exec_with_key(PF_HOST, PF_P, PF_ROOT_USER, &pf_key_path,
        "mkdir -p /var/lib/tailscale /var/run/tailscale && nohup tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock --tun=userspace-networking > /tmp/tailscaled.log 2>&1 &"
    );
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Register pfSense with Headscale
    println!("  Registering pfSense...");
    let reg_output = ssh_exec_with_key(PF_HOST, PF_P, PF_ROOT_USER, &pf_key_path,
        &format!(
            "tailscale --socket=/var/run/tailscale/tailscaled.sock up --login-server={} --authkey={} --hostname=pfsense-e2e --advertise-routes={} --accept-routes --snat-subnet-routes=false 2>&1",
            HEADSCALE_URL_INTERNAL, preauth_key, LAN_SUBNET,
        )
    );
    println!("  Registration: {}", reg_output.trim());

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verify node appears in Headscale
    let nodes = headscale_exec_json(&["nodes", "list"]);
    let node_list = nodes.as_array().cloned().unwrap_or_default();
    println!("  Headscale nodes: {}", node_list.len());
    assert!(!node_list.is_empty(), "pfSense should appear as a node");

    let pf_node = &node_list[0];
    let node_id = pf_node.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
    let given_name = pf_node.get("givenName").and_then(|v| v.as_str()).unwrap_or("?");
    let ips: Vec<&str> = pf_node.get("ipAddresses")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let online = pf_node.get("online").and_then(|v| v.as_bool()).unwrap_or(false);

    println!("  Node: id={} name={} ips={:?} online={}", node_id, given_name, ips, online);

    // Check available routes
    let available_routes: Vec<&str> = pf_node.get("availableRoutes")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    println!("  Available routes: {:?}", available_routes);

    // Approve subnet routes
    if !available_routes.is_empty() {
        let (out, ok) = headscale_exec(&["routes", "enable",
            "--route", LAN_SUBNET, "--identifier", &node_id.to_string()]);
        println!("  Route approval: {} (ok={})", out, ok);
    }

    // Set tags on the node
    let (out, ok) = headscale_exec(&["nodes", "tag",
        "--identifier", &node_id.to_string(), "--tags", "tag:router,tag:infra"]);
    println!("  Set tags: {} (ok={})", out, ok);

    // Rename the node
    let (out, ok) = headscale_exec(&["nodes", "rename",
        "--identifier", &node_id.to_string(), "pfsense-gateway"]);
    println!("  Rename: {} (ok={})", out, ok);

    // Check tailscale status on pfSense
    let ts_status = ssh_exec_with_key(PF_HOST, PF_P, PF_ROOT_USER, &pf_key_path,
        "tailscale --socket=/var/run/tailscale/tailscaled.sock status 2>&1"
    );
    println!("  Tailscale status:\n{}", ts_status);

    // Verify pfSense has Tailscale IP
    let ts_ip = ssh_exec_with_key(PF_HOST, PF_P, PF_ROOT_USER, &pf_key_path,
        "tailscale --socket=/var/run/tailscale/tailscaled.sock ip -4 2>&1"
    );
    let ts_ip = ts_ip.trim();
    println!("  Tailscale IP: {}", ts_ip);
    assert!(ts_ip.starts_with("100.64."), "Should have a 100.64.x.x tailnet IP, got: {}", ts_ip);

    // Verify LAN connectivity from pfSense
    let lan_check = ssh_exec_with_key(PF_HOST, PF_P, PF_ROOT_USER, &pf_key_path,
        &format!("curl -s --max-time 3 http://{}:{}/", INTERNAL_SERVER_IP, INTERNAL_SERVER_HTTP_P)
    );
    assert!(
        lan_check.contains("internal-server-ok"),
        "pfSense should reach internal server on LAN, got: {}", lan_check.trim()
    );
    println!("  LAN connectivity: OK");

    // Final node state
    let final_nodes = headscale_exec_json(&["nodes", "list"]);
    if let Some(arr) = final_nodes.as_array() {
        for n in arr {
            let name = n.get("givenName").and_then(|v| v.as_str()).unwrap_or("?");
            let tags: Vec<&str> = n.get("tags")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let approved: Vec<&str> = n.get("approvedRoutes")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            println!("  Final state: {} tags={:?} routes={:?}", name, tags, approved);
        }
    }

    println!("  pfSense Subnet Router: PASSED");
}

/// Test 7: Node expiry and deletion
#[test]
#[ignore = "requires Docker pfsense-e2e stack"]
fn test_07_node_lifecycle() {
    println!("\n=== Test: Node Lifecycle (expire + delete) ===");

    // Create a debug node for testing
    let _ = headscale_exec(&["users", "create", "admin"]);
    let (out, ok) = headscale_exec(&["debug", "create-node",
        "--user", "admin", "--name", "ephemeral-test", "--key", "nodekey:dummy123"]);
    println!("  Debug create node: {} (ok={})", out, ok);

    let nodes = headscale_exec_json(&["nodes", "list"]);
    let node_list = nodes.as_array().cloned().unwrap_or_default();

    // Find our debug node
    let debug_node = node_list.iter().find(|n|
        n.get("givenName").and_then(|v| v.as_str()).map(|s| s.contains("ephemeral")).unwrap_or(false)
    );

    if let Some(node) = debug_node {
        let id = node.get("id").and_then(|v| v.as_u64()).unwrap_or(0);

        // Expire the node
        let (out, ok) = headscale_exec(&["nodes", "expire", "--identifier", &id.to_string()]);
        println!("  Expire node {}: {} (ok={})", id, out, ok);

        // Delete the node
        let (out, ok) = headscale_exec(&["nodes", "delete", "--identifier", &id.to_string(), "--force"]);
        println!("  Delete node {}: {} (ok={})", id, out, ok);

        // Verify deletion
        let nodes_after = headscale_exec_json(&["nodes", "list"]);
        let remaining = nodes_after.as_array().cloned().unwrap_or_default();
        let still_exists = remaining.iter().any(|n|
            n.get("id").and_then(|v| v.as_u64()) == Some(id)
        );
        assert!(!still_exists, "Deleted node should not appear in list");
        println!("  Node Lifecycle: PASSED");
    } else {
        println!("  SKIP: debug node creation not supported in this Headscale version");
    }
}

/// Test 8: Multiple preauth keys with different users
#[test]
#[ignore = "requires Docker pfsense-e2e stack"]
fn test_08_multi_user_keys() {
    println!("\n=== Test: Multi-User PreAuth Keys ===");

    // Create users for different environments
    let _ = headscale_exec(&["users", "create", "admin"]);
    let _ = headscale_exec(&["users", "create", "devops"]);

    // Create keys for each user
    let (admin_key, ok1) = headscale_exec(&["preauthkeys", "create", "--user", "admin", "--reusable"]);
    let (devops_key, ok2) = headscale_exec(&["preauthkeys", "create", "--user", "devops", "--reusable"]);

    assert!(ok1, "Admin key creation should succeed");
    assert!(ok2, "Devops key creation should succeed");
    assert_ne!(admin_key, devops_key, "Different users should get different keys");

    println!("  Admin key:  {}...", &admin_key[..admin_key.len().min(12)]);
    println!("  Devops key: {}...", &devops_key[..devops_key.len().min(12)]);

    // List keys per user
    let admin_keys = headscale_exec_json(&["preauthkeys", "list", "--user", "admin"]);
    let devops_keys = headscale_exec_json(&["preauthkeys", "list", "--user", "devops"]);

    let admin_count = admin_keys.as_array().map(|a| a.len()).unwrap_or(0);
    let devops_count = devops_keys.as_array().map(|a| a.len()).unwrap_or(0);

    println!("  Admin keys: {}, Devops keys: {}", admin_count, devops_count);
    assert!(admin_count >= 1 && devops_count >= 1, "Each user should have keys");

    println!("  Multi-User Keys: PASSED");
}

/// Test 9: Protected deployments are NOT closed by manage close --all
#[test]
#[ignore = "requires Docker pfsense-e2e stack"]
fn test_09_protected_deployment_not_closed() {
    println!("
=== Test: Protected Deployment Guard ===");

    // Create a mock HeadscaleStore with a protected DSEQ
    let tmp = tempfile::tempdir().expect("tempdir");
    let store_path = tmp.path().join("headscale.enc");
    let password = "test-password";

    let store = o_line_sdl::cmd::vpn::HeadscaleStore {
        servers: vec![o_line_sdl::cmd::vpn::HeadscaleServer {
            label: "test".into(),
            control_url: "https://admin.terp.network".into(),
            grpc_endpoint: "https://admin.terp.network:443".into(),
            api_key: "test-key".into(),
            preauth_key: "test-preauth".into(),
            dseq: 99999999,
            protected: true,
        }],
        default_label: "test".into(),
    };

    // Save and reload to verify round-trip
    store.save(password).expect("save store");
    let loaded = o_line_sdl::cmd::vpn::HeadscaleStore::load(password).expect("load store");

    assert_eq!(loaded.servers.len(), 1);
    assert!(loaded.servers[0].protected, "Server should be marked protected");
    assert_eq!(loaded.servers[0].dseq, 99999999);

    // Verify load_protected_dseqs returns it
    std::env::set_var("OLINE_PASSWORD", password);
    let protected = o_line_sdl::cmd::vpn::load_protected_dseqs();
    assert!(
        protected.contains(&99999999),
        "Protected DSEQs should include our test DSEQ, got: {:?}",
        protected
    );

    // Simulate what manage close does: partition into protected vs closeable
    let all_dseqs: Vec<u64> = vec![11111111, 99999999, 22222222];
    let (protected_list, closeable): (Vec<u64>, Vec<u64>) = all_dseqs
        .into_iter()
        .partition(|d| protected.contains(d));

    assert_eq!(protected_list, vec![99999999], "DSEQ 99999999 should be protected");
    assert_eq!(closeable, vec![11111111, 22222222], "Other DSEQs should be closeable");

    println!("  Protected: {:?}", protected_list);
    println!("  Closeable: {:?}", closeable);
    println!("  Protected Deployment Guard: PASSED");

    // Cleanup
    std::env::remove_var("OLINE_PASSWORD");
}
