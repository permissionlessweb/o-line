/// Multi-node local test harness for Phase A (snapshot + seed).
///
/// [`LocalPhaseHarness`] starts two `cosmos-omnibus` Docker containers that
/// mirror the Phase A SDL deployment, generates SSH keypairs, and exposes
/// [`ServiceEndpoint`] lists that match the format returned by a real Akash
/// provider.
///
/// The phase step functions (`push_pre_start_files`, `verify_files_and_signal_start`,
/// `extract_peer_id_with_boot_wait`) can be called against these endpoints
/// unchanged — they talk to the local containers via SSH/TCP exactly as they
/// would talk to Akash-hosted containers.
///
/// # Port layout (fixed for predictability)
///
/// | Service  | Internal | Host   | Purpose       |
/// |----------|----------|--------|---------------|
/// | snapshot | 22       | 2232   | SSH / SFTP    |
/// | snapshot | 26657    | 26757  | RPC / status  |
/// | snapshot | 26656    | 26756  | P2P           |
/// | seed     | 22       | 2233   | SSH / SFTP    |
/// | seed     | 26657    | 26767  | RPC / status  |
/// | seed     | 26656    | 26766  | P2P           |
///
/// # Example
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use o_line_sdl::testing::harness::LocalPhaseHarness;
/// use std::path::PathBuf;
///
/// let harness = LocalPhaseHarness::start_phase_a(
///     "ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic",
///     &PathBuf::from("/tmp/oline-harness-test"),
/// ).await.expect("Failed to start Phase A containers");
///
/// // All endpoints are ready — call phase step functions:
/// // push_pre_start_files("snapshot", &harness.snapshot_endpoints(), ...)
/// // verify_files_and_signal_start("snapshot", &harness.snapshot_endpoints(), ...)
/// // ...
/// # }
/// ```
use crate::testing::docker::{container_logs, run_container, wait_for_tcp, ContainerHandle, ContainerPort, ContainerSpec};
use crate::crypto::push_scripts_sftp;
use akash_deploy_rs::ServiceEndpoint;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

// ── Well-known test ports ─────────────────────────────────────────────────────

pub const SNAPSHOT_SSH_HOST_P: u16 = 2232;
pub const SNAPSHOT_RPC_HOST_P: u16 = 26757;
pub const SNAPSHOT_P2P_HOST_P: u16 = 26756;

pub const SEED_SSH_HOST_P: u16 = 2233;
pub const SEED_RPC_HOST_P: u16 = 26767;
pub const SEED_P2P_HOST_P: u16 = 26766;

pub const SNAPSHOT_CONTAINER: &str = "oline-test-snapshot";
pub const SEED_CONTAINER: &str = "oline-test-seed";

pub const SSH_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);

// ── Harness ───────────────────────────────────────────────────────────────────

/// Holds the running containers and all credentials for a local Phase A test.
pub struct LocalPhaseHarness {
    /// Running containers — dropped (force-removed) when harness goes out of scope.
    pub containers: Vec<ContainerHandle>,
    /// ED25519 private key PEM string, matching `SSH_PUBKEY` injected into containers.
    pub ssh_privkey_pem: String,
    /// Path to the private key file on disk (used by `push_pre_start_files`).
    pub ssh_key_path: PathBuf,
    /// Local snapshot archive to deliver via SSH pipe instead of each node downloading
    /// from a public server. Set via `E2E_SNAP_PATH` env var.
    /// When `Some`, containers are started with `SNAPSHOT_MODE=sftp` and the test
    /// builds a `PreStartFile { source: FileSource::Path(...) }` for delivery.
    pub snapshot_local_path: Option<PathBuf>,
}

impl LocalPhaseHarness {
    /// Start snapshot + seed containers and wait for SSH on both.
    ///
    /// The caller must have Docker installed and access to the omnibus image.
    /// `workdir` is used for SSH key and TLS cert files.
    ///
    /// All scripts (`oline-entrypoint.sh`, `tls-setup.sh`, `chain.json`) are
    /// delivered via SFTP after SSH comes up — no remote URL fetches required.
    pub async fn start_phase_a(
        omnibus_image: &str,
        workdir: &Path,
    ) -> Result<Self, String> {
        fs::create_dir_all(workdir)
            .map_err(|e| format!("Failed to create workdir {:?}: {}", workdir, e))?;

        // ── SSH keypair ───────────────────────────────────────────────────────
        let (ssh_pubkey, ssh_privkey_pem, ssh_key_path) = generate_ssh_keypair(workdir)?;

        // ── Local snapshot (optional) ─────────────────────────────────────────
        // If E2E_SNAP_PATH points to an existing archive, the orchestrator
        // pushes it via SFTP so nodes never download from a public server.
        // SNAPSHOT_MODE=sftp tells oline-entrypoint.sh to wait for the file.
        let snapshot_local_path: Option<PathBuf> = std::env::var("E2E_SNAP_PATH")
            .ok()
            .map(PathBuf::from)
            .filter(|p| {
                if p.exists() {
                    true
                } else {
                    println!(
                        "  [harness] E2E_SNAP_PATH set but not found at {:?} — ignoring",
                        p
                    );
                    false
                }
            });

        // ── Common env vars for both nodes ───────────────────────────────────
        // Scripts (entrypoint, tls-setup, chain.json) are delivered via
        // push_scripts_sftp after SSH is ready — not set as env vars.
        let mut shared_env: HashMap<String, String> = [
            ("SSH_PUBKEY", ssh_pubkey.as_str()),
            ("MINIMUM_GAS_PRICES", "0.05uthiol"),
            ("PRUNING", "nothing"),
            ("FASTSYNC_VERSION", "v0"),
            ("STATESYNC_SNAP_INTERVAL", "500"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        if snapshot_local_path.is_some() {
            // SFTP delivery: entrypoint waits for /tmp/snapshot.tar.lz4 from orchestrator
            shared_env.insert("SNAPSHOT_MODE".into(), "sftp".into());
            println!("  [harness] Snapshot mode: SFTP delivery from orchestrator");
        } else {
            // No snapshot — fastest path, cert delivery test only
            shared_env.insert("DOWNLOAD_SNAP".into(), "0".into());
            shared_env.insert("SNAPSHOT_RETAIN".into(), "0".into());
            println!("  [harness] Snapshot mode: disabled");
        }

        // ── Snapshot container ────────────────────────────────────────────────
        // The oline-omnibus image's ENTRYPOINT handles SSH bootstrap:
        // authorize key, start sshd, persist env, wait for SFTP scripts.
        let mut snap_env = shared_env.clone();
        snap_env.insert("MONIKER".into(), "test-snapshot".into());
        snap_env.insert("RPC_DOMAIN".into(), "localhost".into());
        snap_env.insert("RPC_P".into(), SNAPSHOT_RPC_HOST_P.to_string());

        let snapshot_handle = run_container(&ContainerSpec {
            name: SNAPSHOT_CONTAINER.into(),
            image: omnibus_image.into(),
            env: snap_env,
            ports: vec![
                ContainerPort { internal: 22,    host: SNAPSHOT_SSH_HOST_P },
                ContainerPort { internal: 26657, host: SNAPSHOT_RPC_HOST_P },
                ContainerPort { internal: 26656, host: SNAPSHOT_P2P_HOST_P },
            ],
            entrypoint: None,
            command: None,
            extra_hosts: vec![],
        })
        .map_err(|e| format!("Failed to start snapshot container: {}", e))?;

        // ── Seed container ────────────────────────────────────────────────────
        let mut seed_env = shared_env.clone();
        seed_env.insert("MONIKER".into(), "test-seed".into());
        seed_env.insert("RPC_DOMAIN".into(), "localhost".into());
        seed_env.insert("RPC_P".into(), SEED_RPC_HOST_P.to_string());

        let seed_handle = run_container(&ContainerSpec {
            name: SEED_CONTAINER.into(),
            image: omnibus_image.into(),
            env: seed_env,
            ports: vec![
                ContainerPort { internal: 22,    host: SEED_SSH_HOST_P },
                ContainerPort { internal: 26657, host: SEED_RPC_HOST_P },
                ContainerPort { internal: 26656, host: SEED_P2P_HOST_P },
            ],
            entrypoint: None,
            command: None,
            extra_hosts: vec![],
        })
        .map_err(|e| format!("Failed to start seed container: {}", e))?;

        // ── Wait for SSH on both ──────────────────────────────────────────────
        println!(
            "  [harness] Waiting for SSH on snapshot (127.0.0.1:{}) ...",
            SNAPSHOT_SSH_HOST_P
        );
        if !wait_for_tcp("127.0.0.1", SNAPSHOT_SSH_HOST_P, SSH_BOOTSTRAP_TIMEOUT) {
            let logs = container_logs(SNAPSHOT_CONTAINER, 40);
            return Err(format!(
                "Snapshot SSH never came up within {:?}.\nContainer logs:\n{}",
                SSH_BOOTSTRAP_TIMEOUT, logs
            ));
        }

        println!(
            "  [harness] Waiting for SSH on seed (127.0.0.1:{}) ...",
            SEED_SSH_HOST_P
        );
        if !wait_for_tcp("127.0.0.1", SEED_SSH_HOST_P, SSH_BOOTSTRAP_TIMEOUT) {
            let logs = container_logs(SEED_CONTAINER, 40);
            return Err(format!(
                "Seed SSH never came up within {:?}.\nContainer logs:\n{}",
                SSH_BOOTSTRAP_TIMEOUT, logs
            ));
        }

        // Brief pause for sshd to finish key generation.
        std::thread::sleep(Duration::from_secs(2));
        println!("  [harness] Both nodes SSH-ready.");

        // ── Push local scripts to both containers ─────────────────────────────
        // Delivers oline-entrypoint.sh, tls-setup.sh, chain.json, nginx templates.
        // After this, /tmp/oline-entrypoint-local.sh + /tmp/tls-setup.sh + /tmp/chain.json
        // are present — the start phase uses them without any network fetches.
        let snap_eps = snapshot_handle.all_endpoints(SNAPSHOT_CONTAINER);
        push_scripts_sftp(SNAPSHOT_CONTAINER, &snap_eps, &ssh_key_path, "plays/audible", Some("plays/flea-flicker/nginx"))
            .await
            .map_err(|e| format!("Failed to push scripts to snapshot: {}", e))?;

        let seed_eps = seed_handle.all_endpoints(SEED_CONTAINER);
        push_scripts_sftp(SEED_CONTAINER, &seed_eps, &ssh_key_path, "plays/audible", Some("plays/flea-flicker/nginx"))
            .await
            .map_err(|e| format!("Failed to push scripts to seed: {}", e))?;

        println!("  [harness] Local scripts pushed to both containers.");

        Ok(Self {
            containers: vec![snapshot_handle, seed_handle],
            ssh_privkey_pem,
            ssh_key_path,
            snapshot_local_path,
        })
    }

    /// [`ServiceEndpoint`] list for the snapshot node.
    pub fn snapshot_endpoints(&self) -> Vec<ServiceEndpoint> {
        self.containers[0].all_endpoints(SNAPSHOT_CONTAINER)
    }

    /// [`ServiceEndpoint`] list for the seed node.
    pub fn seed_endpoints(&self) -> Vec<ServiceEndpoint> {
        self.containers[1].all_endpoints(SEED_CONTAINER)
    }

    /// All Phase A endpoints combined (used to populate `OLineContext`).
    pub fn all_endpoints(&self) -> Vec<ServiceEndpoint> {
        let mut eps = self.snapshot_endpoints();
        eps.extend(self.seed_endpoints());
        eps
    }

    /// `"http://127.0.0.1:<RPC_P>"` for the snapshot node.
    pub fn snapshot_rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", SNAPSHOT_RPC_HOST_P)
    }

    /// `"127.0.0.1:<P2P_P>"` for the snapshot node.
    pub fn snapshot_p2p_addr(&self) -> String {
        format!("127.0.0.1:{}", SNAPSHOT_P2P_HOST_P)
    }

    /// `"http://127.0.0.1:<RPC_P>"` for the seed node.
    pub fn seed_rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", SEED_RPC_HOST_P)
    }

    /// `"127.0.0.1:<P2P_P>"` for the seed node.
    pub fn seed_p2p_addr(&self) -> String {
        format!("127.0.0.1:{}", SEED_P2P_HOST_P)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

pub fn generate_ssh_keypair(workdir: &Path) -> Result<(String, String, PathBuf), String> {
    let key_path = workdir.join("test-ssh-key");
    let pub_path = workdir.join("test-ssh-key.pub");
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&pub_path);

    let status = Command::new("ssh-keygen")
        .args([
            "-t", "ed25519",
            "-f", key_path.to_str().unwrap(),
            "-N", "",
            "-q",
        ])
        .status()
        .map_err(|e| format!("ssh-keygen not found: {}", e))?;

    if !status.success() {
        return Err("ssh-keygen failed".into());
    }

    let pubkey = fs::read_to_string(&pub_path)
        .map_err(|e| format!("Failed to read pubkey: {}", e))?
        .trim()
        .to_string();
    let privkey = fs::read_to_string(&key_path)
        .map_err(|e| format!("Failed to read privkey: {}", e))?;

    Ok((pubkey, privkey, key_path))
}

