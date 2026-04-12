/// Unified SSH/SFTP test suite for o-line.
///
/// Merges `oline_ssh_workflow_test.rs` (sentry plumbing) and `local_phase_a.rs`
/// (Phase A cosmos-omnibus integration) into a single file with two Docker tests
/// and one unit test.
///
/// ## Test 1: `test_oline_ssh_plumbing`
/// Quick SSH plumbing against 6 cosmos-omnibus containers (SSH only, no chain).
/// Exercises push_scripts_sftp, push_pre_start_files, verify_files_and_signal_start,
/// push_snapshot_to_node, genesis distribution, APPEND behavior, and peer-ID
/// extraction stubs.
///
/// ## Test 2: `test_oline_ssh_offline_bootstrap`
/// Stub for full OLINE_OFFLINE bootstrap with ict-rs chain.
///
/// ## Unit test: `test_harness_port_constants`
/// Port-constant consistency smoke test (no Docker).
///
/// Port layout (no conflicts with other test files):
///
/// | Node           | SSH  |
/// |----------------|------|
/// | snapshot       | 2260 |
/// | seed           | 2261 |
/// | left-tackle    | 2262 |
/// | right-tackle   | 2263 |
/// | left-forward   | 2264 |
/// | right-forward  | 2265 |
use o_line_sdl::{
    akash::node_refresh_vars,
    crypto::{
        push_pre_start_files, push_scripts_sftp, verify_files_and_signal_start, FileSource,
        PreStartFile,
    },
    snapshots::push_snapshot_to_node,
    testing::docker::{
        container_exec, run_container, wait_for_tcp, ContainerHandle, ContainerPort, ContainerSpec,
    },
    testing::harness::generate_ssh_keypair,
};
use std::{collections::HashMap, fs, time::Duration};

// ── Container names ─────────────────────────────────────────────────────────

const SNAPSHOT: &str = "oline-ssh-snapshot";
const SEED: &str = "oline-ssh-seed";
const LEFT_TACKLE: &str = "oline-ssh-lt";
const RIGHT_TACKLE: &str = "oline-ssh-rt";
const LEFT_FORWARD: &str = "oline-ssh-lf";
const RIGHT_FORWARD: &str = "oline-ssh-rf";

const ALL_CONTAINERS: &[&str] = &[
    SNAPSHOT,
    SEED,
    LEFT_TACKLE,
    RIGHT_TACKLE,
    LEFT_FORWARD,
    RIGHT_FORWARD,
];

// ── Port mapping ────────────────────────────────────────────────────────────

const SNAPSHOT_SSH: u16 = 2260;
const SEED_SSH: u16 = 2261;
const LT_SSH: u16 = 2262;
const RT_SSH: u16 = 2263;
const LF_SSH: u16 = 2264;
const RF_SSH: u16 = 2265;

const ALL_PS: &[u16] = &[SNAPSHOT_SSH, SEED_SSH, LT_SSH, RT_SSH, LF_SSH, RF_SSH];

const SSH_TIMEOUT: Duration = Duration::from_secs(120);

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Load key=value pairs from a `.env` file and set them as environment
/// variables only when they are NOT already set (i.e., respect process env).
fn load_dotenv_fallback(path: &str) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            // Only set if not already in the process environment
            if std::env::var(key).is_err() && !val.is_empty() {
                // SAFETY: single-threaded at this point in the test lifecycle
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::set_var(key, val);
                }
            }
        }
    }
}

/// Resolve the cosmos-omnibus image: env override -> arch-based default.
fn resolve_omnibus_image() -> String {
    std::env::var("E2E_OMNIBUS_IMAGE")
        .or_else(|_| std::env::var("OMNIBUS_IMAGE"))
        .unwrap_or_else(|_| match std::env::consts::ARCH {
            "aarch64" => "oline-omnibus:local".to_string(),
            _ => "ghcr.io/akash-network/cosmos-omnibus:latest".to_string(),
        })
}

fn make_spec(name: &str, ssh_port: u16, ssh_pubkey: &str, omnibus_image: &str) -> ContainerSpec {
    let mut env = HashMap::new();
    env.insert("SSH_PUBKEY".into(), ssh_pubkey.into());

    let bootstrap_cmd = r#"set -e
mkdir -p /root/.ssh
echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
if ! command -v sshd >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null 2>&1 \
    || apk add --no-cache openssh >/dev/null 2>&1 || true
fi
SSHD_BIN=$(command -v sshd 2>/dev/null)
mkdir -p /run/sshd /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
printf '\nPermitRootLogin yes\nPubkeyAuthentication yes\n' >> /etc/ssh/sshd_config
mkdir -p /tmp
export -p > /tmp/oline-env.sh
exec "$SSHD_BIN" -D"#;

    ContainerSpec {
        name: name.into(),
        image: omnibus_image.into(),
        env,
        ports: vec![ContainerPort {
            internal: 22,
            host: ssh_port,
        }],
        entrypoint: Some("/bin/bash".into()),
        command: Some(bootstrap_cmd.into()),
        extra_hosts: vec![],
    }
}

fn make_endpoints(name: &str, ssh_port: u16) -> Vec<akash_deploy_rs::ServiceEndpoint> {
    vec![akash_deploy_rs::ServiceEndpoint {
        service: name.to_string(),
        uri: "http://127.0.0.1".to_string(),
        port: ssh_port,
        internal_port: 22,
    }]
}

fn make_vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ── Test 1: SSH plumbing (no chain, no Akash) ──────────────────────────────

#[tokio::test]
#[ignore = "requires Docker + OMNIBUS_IMAGE"]
async fn test_oline_ssh_plumbing() {
    // ── 0. Env ───────────────────────────────────────────────────────────────
    load_dotenv_fallback(".env");

    let omnibus_image = resolve_omnibus_image();

    // SSH_P=22 — must match internal port used by crypto functions.
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("SSH_P", "22");
    }

    println!("\n========================================");
    println!("  O-Line SSH Plumbing Test");
    println!("========================================");
    println!(
        "  OMNIBUS_IMAGE:  {} (arch={})",
        omnibus_image,
        std::env::consts::ARCH
    );
    println!();

    // Pre-clean any leftover containers from a previous run.
    o_line_sdl::testing::docker::remove_containers(ALL_CONTAINERS);

    let workdir = std::env::temp_dir().join("oline-ssh-plumbing-test");
    let _ = fs::remove_dir_all(&workdir);
    fs::create_dir_all(&workdir).unwrap();

    // ── Step 1: Generate SSH keypair ─────────────────────────────────────────
    let (ssh_pubkey, _ssh_privkey_pem, ssh_key_path) =
        generate_ssh_keypair(&workdir).expect("SSH keygen failed");
    println!("[ssh] SSH key: {:?}", ssh_key_path);

    // ── Step 2: Start 6 cosmos-omnibus containers (SSH-only) ─────────────────
    let specs = [
        (SNAPSHOT, SNAPSHOT_SSH),
        (SEED, SEED_SSH),
        (LEFT_TACKLE, LT_SSH),
        (RIGHT_TACKLE, RT_SSH),
        (LEFT_FORWARD, LF_SSH),
        (RIGHT_FORWARD, RF_SSH),
    ];

    let handles: Vec<ContainerHandle> = specs
        .iter()
        .map(|(name, port)| {
            run_container(&make_spec(name, *port, &ssh_pubkey, &omnibus_image))
                .unwrap_or_else(|e| panic!("Failed to start {}: {}", name, e))
        })
        .collect();

    // Wait for SSH on all ports.
    for &port in ALL_PS {
        print!("[ssh] Waiting for SSH on port {} ", port);
        assert!(
            wait_for_tcp("127.0.0.1", port, SSH_TIMEOUT),
            "SSH never came up on port {}",
            port
        );
    }
    // Brief settle time for sshd.
    std::thread::sleep(Duration::from_secs(2));
    println!("[ssh] All 6 containers SSH-ready.");

    // ── Step 3: push_scripts_sftp to all 6 ───────────────────────────────────
    // Create minimal script files for the test.
    let scripts_dir = workdir.join("scripts");
    fs::create_dir_all(&scripts_dir).unwrap();
    fs::write(scripts_dir.join("tls-setup.sh"), "#!/bin/sh\necho tls-ok").unwrap();
    fs::write(
        scripts_dir.join("oline-entrypoint.sh"),
        "#!/bin/sh\necho entrypoint-ok",
    )
    .unwrap();
    let scripts_str = scripts_dir.to_str().unwrap();

    for (name, port) in &specs {
        let eps = make_endpoints(name, *port);
        push_scripts_sftp(name, &eps, &ssh_key_path, scripts_str, None)
            .await
            .unwrap_or_else(|e| panic!("[{}] push_scripts_sftp failed: {}", name, e));
    }

    // Verify scripts landed on snapshot container.
    let tls_check = container_exec(SNAPSHOT, "cat /tmp/tls-setup.sh");
    assert!(
        tls_check.contains("tls-ok"),
        "tls-setup.sh not found on snapshot: {}",
        tls_check
    );
    let ep_check = container_exec(SNAPSHOT, "cat /tmp/oline-entrypoint-local.sh");
    assert!(
        ep_check.contains("entrypoint-ok"),
        "entrypoint not found on snapshot: {}",
        ep_check
    );
    println!("[ssh] Step 3 PASSED: scripts pushed to all 6 nodes.");

    // ── Step 4: push_pre_start_files to snapshot ─────────────────────────────
    let test_file_content = b"snapshot-test-data-1234567890";
    let pre_start = vec![PreStartFile {
        source: FileSource::Bytes(test_file_content.to_vec()),
        remote_path: "/tmp/test-prestart.dat".into(),
    }];
    let snap_eps = make_endpoints(SNAPSHOT, SNAPSHOT_SSH);
    push_pre_start_files(SNAPSHOT, &snap_eps, &ssh_key_path, &pre_start, 5)
        .await
        .expect("push_pre_start_files failed");

    let pre_check = container_exec(SNAPSHOT, "cat /tmp/test-prestart.dat");
    assert!(
        pre_check.contains("snapshot-test-data"),
        "Pre-start file missing: {}",
        pre_check
    );
    println!("[ssh] Step 4 PASSED: pre-start file delivered to snapshot.");

    // ── Step 5: verify_files_and_signal_start on snapshot with refresh vars ──
    let snap_vars = make_vars(&[
        ("RPC_D_SNAP", "rpc.snapshot.test"),
        ("CHAIN_ID", "ssh-test-1"),
        ("RPC_DOMAIN", "rpc.snapshot.test"),
        ("RPC_P", "26657"),
    ]);
    let snap_refresh = node_refresh_vars(&snap_vars, "SNAPSHOT");

    verify_files_and_signal_start(
        "snapshot",
        &snap_eps,
        &ssh_key_path,
        &["/tmp/test-prestart.dat".to_string()],
        &snap_refresh,
    )
    .await
    .expect("verify_files_and_signal_start failed for snapshot");

    // Verify /tmp/oline-env.sh was written with the expected vars.
    let env_check = container_exec(SNAPSHOT, "cat /tmp/oline-env.sh");
    assert!(
        env_check.contains("RPC_DOMAIN"),
        "oline-env.sh missing RPC_DOMAIN: {}",
        env_check
    );
    assert!(
        env_check.contains("CHAIN_ID"),
        "oline-env.sh missing CHAIN_ID: {}",
        env_check
    );
    println!("[ssh] Step 5 PASSED: snapshot signaled with refresh vars.");

    // ── Step 6: verify_files_and_signal_start on seed with snapshot peer ─────
    let seed_eps = make_endpoints(SEED, SEED_SSH);
    let seed_vars = make_vars(&[
        ("RPC_D_SEED", "rpc.seed.test"),
        ("CHAIN_ID", "ssh-test-1"),
        ("RPC_DOMAIN", "rpc.seed.test"),
        ("RPC_P", "26657"),
        ("TERPD_P2P_PERSISTENT_PEERS", "abc123@snapshot:26656"),
    ]);
    let seed_refresh = node_refresh_vars(&seed_vars, "SEED");

    verify_files_and_signal_start("seed", &seed_eps, &ssh_key_path, &[], &seed_refresh)
        .await
        .expect("verify_files_and_signal_start failed for seed");

    let seed_env = container_exec(SEED, "cat /tmp/oline-env.sh");
    assert!(
        seed_env.contains("TERPD_P2P_PERSISTENT_PEERS"),
        "seed env missing peers: {}",
        seed_env
    );
    println!("[ssh] Step 6 PASSED: seed signaled with snapshot peer.");

    // ── Step 7: Push genesis.json to B/C nodes — verify absent from Phase A ──
    // In production, distribute_snapshot() fetches genesis from the snapshot
    // node and pushes it to tackles + forwards via push_pre_start_files().
    // Phase A nodes (snapshot, seed) download their own genesis — no push.
    let genesis_content =
        br#"{"genesis_time":"2025-01-01T00:00:00Z","chain_id":"ssh-test-1","app_state":{}}"#;
    let genesis_file = vec![PreStartFile {
        source: FileSource::Bytes(genesis_content.to_vec()),
        remote_path: "/tmp/genesis.json".into(),
    }];

    let lt_eps = make_endpoints(LEFT_TACKLE, LT_SSH);
    let rt_eps = make_endpoints(RIGHT_TACKLE, RT_SSH);
    let lf_eps = make_endpoints(LEFT_FORWARD, LF_SSH);
    let rf_eps = make_endpoints(RIGHT_FORWARD, RF_SSH);

    for (label, eps) in [
        ("left-tackle", &lt_eps),
        ("right-tackle", &rt_eps),
        ("left-forward", &lf_eps),
        ("right-forward", &rf_eps),
    ] {
        push_pre_start_files(label, eps, &ssh_key_path, &genesis_file, 5)
            .await
            .unwrap_or_else(|e| panic!("[{}] genesis push failed: {}", label, e));
    }

    // Verify genesis landed on B/C nodes.
    for name in [LEFT_TACKLE, RIGHT_TACKLE, LEFT_FORWARD, RIGHT_FORWARD] {
        let check = container_exec(name, "cat /tmp/genesis.json");
        assert!(
            check.contains("ssh-test-1"),
            "genesis.json missing on {}: {}",
            name,
            check
        );
    }
    // Verify genesis was NOT pushed to Phase A nodes.
    let snap_genesis = container_exec(SNAPSHOT, "cat /tmp/genesis.json 2>&1 || echo MISSING");
    assert!(
        snap_genesis.contains("MISSING") || snap_genesis.contains("No such file"),
        "genesis.json should NOT be on snapshot (Phase A): {}",
        snap_genesis
    );
    let seed_genesis = container_exec(SEED, "cat /tmp/genesis.json 2>&1 || echo MISSING");
    assert!(
        seed_genesis.contains("MISSING") || seed_genesis.contains("No such file"),
        "genesis.json should NOT be on seed (Phase A): {}",
        seed_genesis
    );
    println!("[ssh] Step 7 PASSED: genesis pushed to B/C, absent from Phase A.");

    // ── Step 8: verify_files_and_signal_start on tackles — verify genesis ────
    // Production: signal_all_nodes() verifies /tmp/genesis.json on B/C nodes.
    let tackle_vars = make_vars(&[
        ("RPC_D_TL", "rpc.lt.test"),
        ("RPC_D_TR", "rpc.rt.test"),
        ("RPC_DOMAIN", ""),
        ("RPC_P", "26657"),
        ("CHAIN_ID", "ssh-test-1"),
        ("TERPD_P2P_PERSISTENT_PEERS", "abc123@snapshot:26656"),
    ]);

    let lt_refresh = node_refresh_vars(&tackle_vars, "TACKLE_L");
    verify_files_and_signal_start(
        "left-tackle",
        &lt_eps,
        &ssh_key_path,
        &["/tmp/genesis.json".to_string()],
        &lt_refresh,
    )
    .await
    .expect("signal failed for left-tackle");

    let rt_refresh = node_refresh_vars(&tackle_vars, "TACKLE_R");
    verify_files_and_signal_start(
        "right-tackle",
        &rt_eps,
        &ssh_key_path,
        &["/tmp/genesis.json".to_string()],
        &rt_refresh,
    )
    .await
    .expect("signal failed for right-tackle");

    let lt_env = container_exec(LEFT_TACKLE, "cat /tmp/oline-env.sh");
    assert!(
        lt_env.contains("TERPD_P2P_PERSISTENT_PEERS"),
        "left-tackle env missing peers: {}",
        lt_env
    );
    println!("[ssh] Step 8 PASSED: tackles signaled with genesis verify + snapshot peer.");

    // ── Step 9: push_snapshot_to_node — fake archive to seed ─────────────────
    let snapshot_data = b"FAKE-SNAPSHOT-DATA-FOR-SSH-TEST-0123456789abcdef";
    let snap_file = workdir.join("test-snapshot.tar.lz4");
    fs::write(&snap_file, snapshot_data).unwrap();

    push_snapshot_to_node(
        "seed",
        &seed_eps,
        &ssh_key_path,
        &snap_file,
        "/tmp/snapshot.tar.lz4",
    )
    .await
    .expect("push_snapshot_to_node failed");

    let snap_verify = container_exec(SEED, "wc -c < /tmp/snapshot.tar.lz4");
    let remote_size: usize = snap_verify.trim().parse().unwrap_or(0);
    assert_eq!(
        remote_size,
        snapshot_data.len(),
        "Snapshot size mismatch: expected {}, got {}",
        snapshot_data.len(),
        remote_size
    );
    println!(
        "[ssh] Step 9 PASSED: snapshot pushed to seed ({} bytes).",
        remote_size
    );

    // ── Step 10: verify_files_and_signal_start on forwards — full peer set ───
    // Production: inject_peers() verifies /tmp/genesis.json on forwards.
    let forward_vars = make_vars(&[
        ("RPC_D_FL", "rpc.lf.test"),
        ("RPC_D_FR", "rpc.rf.test"),
        ("RPC_DOMAIN", ""),
        ("RPC_P", "26657"),
        ("CHAIN_ID", "ssh-test-1"),
        ("TERPD_P2P_PERSISTENT_PEERS", "abc123@snapshot:26656"),
        ("TERPD_P2P_SEEDS", "seed123@seed:26656"),
        (
            "TERPD_P2P_PRIVATE_PEER_IDS",
            "lt456@lt:26656,rt789@rt:26656",
        ),
    ]);

    let lf_refresh = node_refresh_vars(&forward_vars, "FORWARD_L");
    verify_files_and_signal_start(
        "left-forward",
        &lf_eps,
        &ssh_key_path,
        &["/tmp/genesis.json".to_string()],
        &lf_refresh,
    )
    .await
    .expect("signal failed for left-forward");

    let rf_refresh = node_refresh_vars(&forward_vars, "FORWARD_R");
    verify_files_and_signal_start(
        "right-forward",
        &rf_eps,
        &ssh_key_path,
        &["/tmp/genesis.json".to_string()],
        &rf_refresh,
    )
    .await
    .expect("signal failed for right-forward");

    let lf_env = container_exec(LEFT_FORWARD, "cat /tmp/oline-env.sh");
    assert!(
        lf_env.contains("TERPD_P2P_PERSISTENT_PEERS"),
        "left-forward env missing persistent_peers: {}",
        lf_env
    );
    assert!(
        lf_env.contains("CHAIN_ID"),
        "left-forward env missing CHAIN_ID: {}",
        lf_env
    );
    println!("[ssh] Step 10 PASSED: forwards signaled with genesis verify + full peer set.");

    // ── Step 11: APPEND behavior — re-signal snapshot ────────────────────────
    let extra_vars = make_vars(&[
        ("RPC_D_SNAP", "rpc2.snapshot.test"),
        ("RPC_DOMAIN", "rpc2.snapshot.test"),
        ("CHAIN_ID", "ssh-test-2"),
    ]);
    let extra_refresh = node_refresh_vars(&extra_vars, "SNAPSHOT");

    verify_files_and_signal_start("snapshot-re", &snap_eps, &ssh_key_path, &[], &extra_refresh)
        .await
        .expect("re-signal failed for snapshot");

    let env_final = container_exec(SNAPSHOT, "cat /tmp/oline-env.sh");
    // Both old and new values should be present (appended).
    assert!(
        env_final.contains("ssh-test-1") || env_final.contains("rpc.snapshot.test"),
        "Original vars lost after re-signal: {}",
        env_final
    );
    assert!(
        env_final.contains("ssh-test-2") || env_final.contains("rpc2.snapshot.test"),
        "New vars not appended after re-signal: {}",
        env_final
    );
    println!("[ssh] Step 11 PASSED: APPEND behavior verified.");

    // ── Step 12: Extract peer IDs from Phase A containers ────────────────────
    // In the full multi test, we would poll RPC for peer IDs. Here we just
    // verify that the containers are still alive and responding to SSH commands
    // (peer ID extraction requires a running chain, which this plumbing test
    // does not start).
    let snap_alive = container_exec(SNAPSHOT, "echo alive");
    assert!(
        snap_alive.contains("alive"),
        "snapshot container not responsive: {}",
        snap_alive
    );
    let seed_alive = container_exec(SEED, "echo alive");
    assert!(
        seed_alive.contains("alive"),
        "seed container not responsive: {}",
        seed_alive
    );
    println!("[ssh] Step 12 PASSED: Phase A containers still responsive (peer ID extraction requires running chain — skipped in plumbing test).");

    println!("\n[ssh] ALL 12 STEPS PASSED.");

    // Containers cleaned up by ContainerHandle::Drop.
    drop(handles);
    let _ = fs::remove_dir_all(&workdir);
}

// ── Test 2: Offline bootstrap stub ──────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker + OMNIBUS_IMAGE + ict-rs terp chain"]
async fn test_oline_ssh_offline_bootstrap() {
    // TODO: Full OLINE_OFFLINE bootstrap with ict-rs chain
    // Phase 0: Setup — spawn local-terp chain, create_snapshot(), genesis_bytes(), node_id()
    // Phase 1: Start Phase A containers (online), push scripts, signal start, extract peer IDs
    // Phase 2: Start Phase B/C containers (OLINE_OFFLINE=1), push genesis+snapshot via SFTP
    // Phase 3: Verify B/C logs, no internet downloads, RPC responds
    eprintln!("[offline-bootstrap] STUB — not yet implemented. Run `just test sentry-ssh` for plumbing test.");
}

// ── Unit test: harness port constants ───────────────────────────────────────

/// Smoke test: validate the harness port constants are self-consistent.
#[test]
fn test_harness_port_constants() {
    use o_line_sdl::testing::harness::*;

    // All SSH ports must be different
    assert_ne!(SNAPSHOT_SSH_HOST_P, SEED_SSH_HOST_P);
    // All RPC ports must be different
    assert_ne!(SNAPSHOT_RPC_HOST_P, SEED_RPC_HOST_P);
    // All P2P ports must be different
    assert_ne!(SNAPSHOT_P2P_HOST_P, SEED_P2P_HOST_P);
    // No port conflicts between snapshot and seed
    let snap = [
        SNAPSHOT_SSH_HOST_P,
        SNAPSHOT_RPC_HOST_P,
        SNAPSHOT_P2P_HOST_P,
    ];
    let seed = [SEED_SSH_HOST_P, SEED_RPC_HOST_P, SEED_P2P_HOST_P];
    for s in snap {
        assert!(
            !seed.contains(&s),
            "Port {} used by both snapshot and seed",
            s
        );
    }
}
