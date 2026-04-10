/// Raw cosmos-sdk chain binary runner for lightweight local testing.
///
/// Runs `<binary> init` + `<binary> start` directly on the host without Docker.
/// Useful for offline unit tests and CI environments where the chain binary is
/// already installed.  Port exposure and SSH-based tests are NOT available in
/// this mode — only RPC/P2P connectivity can be tested.
///
/// # Example
/// ```no_run
/// use o_line_sdl::testing::binary::{init_node, start_node, NodeConfig, NodeProcess};
/// use std::path::PathBuf;
///
/// let cfg = NodeConfig {
///     binary:   "terpd".into(),
///     home:     PathBuf::from("/tmp/oline-test-snapshot"),
///     chain_id: "morocco-1".into(),
///     moniker:  "test-snap".into(),
///     rpc_port:  26757,
///     p2p_port:  26756,
///     grpc_port: 9091,
/// };
/// init_node(&cfg).expect("terpd init failed");
/// let mut proc = start_node(&cfg).expect("terpd start failed");
/// // ... run tests ...
/// drop(proc); // kills the process
/// ```
use std::{
    path::{Path, PathBuf},
    process::{Child, Command},
};

/// Configuration for a locally-started chain node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Cosmos daemon binary name (e.g. `"terpd"`, `"gaiad"`).
    pub binary: String,
    /// Node home directory — must not exist, or `init_node` will fail.
    pub home: PathBuf,
    pub chain_id: String,
    pub moniker: String,
    /// Local TCP port for Tendermint RPC (`/status`, `/net_info`).
    pub rpc_port: u16,
    /// Local TCP port for P2P.
    pub p2p_port: u16,
    /// Local TCP port for gRPC.
    pub grpc_port: u16,
}

/// A running chain node process.  Killed automatically on [`Drop`].
pub struct NodeProcess {
    pub child: Child,
    pub rpc_port: u16,
    pub p2p_port: u16,
}

impl NodeProcess {
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    pub fn p2p_addr(&self) -> String {
        format!("127.0.0.1:{}", self.p2p_port)
    }
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Initialise a new node home directory.
///
/// Runs `<binary> init <moniker> --chain-id <id> --home <home>`.
/// Fails if the binary is not installed or if `home` already exists.
pub fn init_node(cfg: &NodeConfig) -> Result<(), String> {
    let status = Command::new(&cfg.binary)
        .args([
            "init",
            &cfg.moniker,
            "--chain-id",
            &cfg.chain_id,
            "--home",
            cfg.home.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| format!("'{}' not found — install the chain binary: {}", cfg.binary, e))?;

    if !status.success() {
        return Err(format!("{} init failed (exit {:?})", cfg.binary, status.code()));
    }

    // Patch config.toml with the requested ports.
    patch_config_toml(&cfg.home, cfg.rpc_port, cfg.p2p_port, cfg.grpc_port)?;

    Ok(())
}

/// Start the chain node and return a [`NodeProcess`] handle.
pub fn start_node(cfg: &NodeConfig) -> Result<NodeProcess, String> {
    let child = Command::new(&cfg.binary)
        .args(["start", "--home", cfg.home.to_str().unwrap()])
        .spawn()
        .map_err(|e| format!("failed to spawn {}: {}", cfg.binary, e))?;

    Ok(NodeProcess {
        child,
        rpc_port: cfg.rpc_port,
        p2p_port: cfg.p2p_port,
    })
}

/// Remove a node home directory (cleanup helper).
pub fn remove_home(home: &Path) {
    let _ = std::fs::remove_dir_all(home);
}

// ── Internal ─────────────────────────────────────────────────────────────────

fn patch_config_toml(home: &Path, rpc_port: u16, p2p_port: u16, grpc_port: u16) -> Result<(), String> {
    let config_path = home.join("config/config.toml");
    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config.toml: {}", e))?;

    let patched = content
        .replace(
            "laddr = \"tcp://127.0.0.1:26657\"",
            &format!("laddr = \"tcp://127.0.0.1:{}\"", rpc_port),
        )
        .replace(
            "laddr = \"tcp://0.0.0.0:26656\"",
            &format!("laddr = \"tcp://0.0.0.0:{}\"", p2p_port),
        )
        .replace(
            "address = \"0.0.0.0:9090\"",
            &format!("address = \"0.0.0.0:{}\"", grpc_port),
        );

    std::fs::write(&config_path, patched)
        .map_err(|e| format!("Failed to write config.toml: {}", e))
}
