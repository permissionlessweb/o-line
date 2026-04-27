/// Log persistence + proxy deployment protection tests.
///
/// Phase I: verify LogPersister creates directories, writes timestamped lines,
///          handles multiple services concurrently, and replays sessions.
///
/// Phase II: verify SDL template renders, proxy-node deployment protection works,
///           and proxy config integrates with toml_config.
///
/// Run: `cargo test -p o-line-sdl --test log_persistence`

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir(name: &str) -> TempDir {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "oline-test-{}-{}-{}",
        std::process::id(), id, name
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    TempDir(path)
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
impl TempDir {
    fn path(&self) -> &std::path::Path { &self.0 }
}

// ── Phase I: Log Persistence ────────────────────────────────────────────────

#[test]
fn test_log_persister_creates_directory() {
    let tmp = unique_dir("creates-dir");
    let session_dir = tmp.path().join("logs").join("session-001");

    let persister = o_line_sdl::log_persistence::LogPersister::new_at(session_dir.clone()).unwrap();

    assert!(session_dir.exists(), "session directory should be created");
    assert!(session_dir.is_dir());
    assert_eq!(persister.log_path(), session_dir);
}

#[test]
fn test_log_persister_writes_timestamped_lines() {
    let tmp = unique_dir("ts-lines");
    let session_dir = tmp.path().join("session-ts");

    let mut persister = o_line_sdl::log_persistence::LogPersister::new_at(session_dir.clone()).unwrap();

    persister.write_line("sentry-a", "node started").unwrap();
    persister.write_line("sentry-a", "syncing block 100").unwrap();

    let log_path = session_dir.join("sentry-a.log");
    assert!(log_path.exists(), "service log file should be created");

    let contents = fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = contents.lines().collect();

    assert_eq!(lines.len(), 2, "should have 2 lines");
    assert!(lines[0].starts_with('['), "line should start with timestamp bracket");
    assert!(lines[0].contains("] node started"), "line should contain message");
    assert!(lines[1].contains("] syncing block 100"), "second line should contain message");

    // Verify ISO8601 timestamp format
    let ts_end = lines[0].find(']').unwrap();
    let ts = &lines[0][1..ts_end];
    assert!(ts.contains('T'), "timestamp should contain T separator: {}", ts);
    assert!(ts.contains('Z') || ts.contains('+'), "timestamp should have timezone: {}", ts);
}

#[test]
fn test_log_persister_multiple_services() {
    let tmp = unique_dir("multi-svc");
    let session_dir = tmp.path().join("session-multi");

    let mut persister = o_line_sdl::log_persistence::LogPersister::new_at(session_dir.clone()).unwrap();

    persister.write_line("A:snapshot", "snapshot line 1").unwrap();
    persister.write_line("B:left-tackle", "tackle line 1").unwrap();
    persister.write_line("A:snapshot", "snapshot line 2").unwrap();
    persister.write_line("C:left-forward", "forward line 1").unwrap();

    // Colons sanitized to underscores in filenames
    let a_log = session_dir.join("A_snapshot.log");
    let b_log = session_dir.join("B_left-tackle.log");
    let c_log = session_dir.join("C_left-forward.log");

    assert!(a_log.exists(), "A:snapshot log should exist at {:?}", a_log);
    assert!(b_log.exists(), "B:left-tackle log should exist");
    assert!(c_log.exists(), "C:left-forward log should exist");

    let a_contents = fs::read_to_string(&a_log).unwrap();
    assert_eq!(a_contents.lines().count(), 2, "A:snapshot should have 2 lines");

    let b_contents = fs::read_to_string(&b_log).unwrap();
    assert_eq!(b_contents.lines().count(), 1, "B:left-tackle should have 1 line");
}

#[test]
fn test_log_persister_sanitizes_filenames() {
    let tmp = unique_dir("sanitize");
    let session_dir = tmp.path().join("session-sanitize");

    let mut persister = o_line_sdl::log_persistence::LogPersister::new_at(session_dir.clone()).unwrap();

    // Service labels with special chars should be sanitized
    persister.write_line("svc/with/slashes", "line 1").unwrap();
    persister.write_line("svc with spaces", "line 1").unwrap();

    let slash_log = session_dir.join("svc_with_slashes.log");
    let space_log = session_dir.join("svc_with_spaces.log");

    assert!(slash_log.exists(), "slashes should be sanitized to underscores");
    assert!(space_log.exists(), "spaces should be sanitized to underscores");
}

#[test]
fn test_log_persister_appends_to_existing() {
    let tmp = unique_dir("append");
    let session_dir = tmp.path().join("session-append");

    // Write with first persister
    {
        let mut p = o_line_sdl::log_persistence::LogPersister::new_at(session_dir.clone()).unwrap();
        p.write_line("svc", "line 1").unwrap();
        p.write_line("svc", "line 2").unwrap();
    }

    // Write with second persister — should append
    {
        let mut p = o_line_sdl::log_persistence::LogPersister::new_at(session_dir.clone()).unwrap();
        p.write_line("svc", "line 3").unwrap();
    }

    let log_path = session_dir.join("svc.log");
    let contents = fs::read_to_string(&log_path).unwrap();
    assert_eq!(contents.lines().count(), 3, "should have 3 lines (appended)");
}

// ── Phase II: SDL Template Rendering ────────────────────────────────────────

#[test]
fn test_proxy_sdl_template_renders() {
    let template_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/templates/sdls/oline/provider-proxy-node.yml"
    );
    let raw = fs::read_to_string(template_path)
        .expect("provider-proxy-node.yml should exist");

    let mut vars = std::collections::HashMap::new();
    vars.insert("PROXY_SVC".into(), "proxy-node".to_string());
    vars.insert("PROXY_NODE_IMAGE".into(), "ghcr.io/hard-nett/oline-proxy-node:latest".to_string());
    vars.insert("PROXY_DOMAIN".into(), "proxy.terp.network".to_string());
    vars.insert("AKASH_CHAIN_ID".into(), "akashnet-2".to_string());
    vars.insert("AKASH_SEEDS".into(), "seed1@1.2.3.4:26656".to_string());

    let rendered = akash_deploy_rs::substitute_partial(&raw, &vars);

    assert!(!rendered.contains("${PROXY_SVC}"), "PROXY_SVC should be substituted");
    assert!(!rendered.contains("${PROXY_NODE_IMAGE}"), "PROXY_NODE_IMAGE should be substituted");
    assert!(!rendered.contains("${PROXY_DOMAIN}"), "PROXY_DOMAIN should be substituted");
    assert!(!rendered.contains("${AKASH_CHAIN_ID}"), "AKASH_CHAIN_ID should be substituted");
    assert!(!rendered.contains("${AKASH_SEEDS}"), "AKASH_SEEDS should be substituted");

    assert!(rendered.contains("proxy-node:"), "service name should appear in services section");
    assert!(rendered.contains("image: ghcr.io/hard-nett/oline-proxy-node:latest"));
    assert!(rendered.contains("proxy.terp.network"), "domain should appear in accept list");

    assert!(rendered.contains("port: 3000"), "proxy port 3000");
    assert!(rendered.contains("port: 26657"), "RPC port");
    assert!(rendered.contains("port: 1317"), "REST port");
    assert!(rendered.contains("port: 9090"), "gRPC port");
    assert!(rendered.contains("as: 443"), "proxy exposed as 443");
}

#[test]
fn test_proxy_sdl_has_persistent_storage() {
    let template_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/templates/sdls/oline/provider-proxy-node.yml"
    );
    let raw = fs::read_to_string(template_path).unwrap();

    assert!(raw.contains("persistent: true"), "should have persistent storage");
    assert!(raw.contains("proxy-node-data"), "should name persistent volume");
    assert!(raw.contains("/root/.akash"), "mount at Akash home");
}

// ── Phase II: Proxy Deployment Protection ───────────────────────────────────

#[test]
fn test_proxy_deployment_protection() {
    use o_line_sdl::cmd::deploy::{ProxyDeployment, save_proxy_deployment, load_proxy_protected_dseqs};

    let tmp = unique_dir("proxy-protect");
    std::env::set_var("OLINE_CONFIG_DIR", tmp.path().to_str().unwrap());

    // No proxy.json yet
    let dseqs = load_proxy_protected_dseqs();
    assert!(dseqs.is_empty(), "no protected DSEQs without proxy.json");

    // Save a protected deployment
    let dep = ProxyDeployment {
        dseq: 12345,
        protected: true,
        url: "https://proxy.terp.network".into(),
    };
    save_proxy_deployment(&dep).unwrap();

    let dseqs = load_proxy_protected_dseqs();
    assert_eq!(dseqs, vec![12345], "protected DSEQ should be returned");

    // Overwrite with unprotected
    let dep2 = ProxyDeployment {
        dseq: 99999,
        protected: false,
        url: "https://other.example.com".into(),
    };
    save_proxy_deployment(&dep2).unwrap();

    let dseqs = load_proxy_protected_dseqs();
    assert!(dseqs.is_empty(), "unprotected DSEQ should not be returned");

    std::env::remove_var("OLINE_CONFIG_DIR");
}

// ── Phase II: Proxy Config ──────────────────────────────────────────────────

#[test]
fn test_proxy_config_defaults() {
    let config = o_line_sdl::toml_config::TomlConfig::from_defaults();

    assert!(!config.proxy.enabled);
    assert_eq!(config.proxy.image, "ghcr.io/hard-nett/oline-proxy-node:latest");
    assert_eq!(config.proxy.service_name, "proxy-node");
    assert!(config.proxy.url.is_empty());
    assert_eq!(config.proxy.dseq, 0);
    assert_eq!(config.proxy.akash_chain_id, "akashnet-2");
}

#[test]
fn test_logging_config_defaults() {
    let config = o_line_sdl::toml_config::TomlConfig::from_defaults();
    assert!(config.logging.persist, "persistence on by default");
    assert!(config.logging.log_dir.is_empty());
}

#[test]
fn test_proxy_config_in_sdl_vars() {
    let config = o_line_sdl::toml_config::TomlConfig::from_defaults();
    let vars = config.to_sdl_vars();

    assert!(vars.contains_key("PROXY_NODE_IMAGE"));
    assert!(vars.contains_key("PROXY_SVC"));
    assert!(vars.contains_key("PROXY_DOMAIN"));
    assert!(vars.contains_key("AKASH_CHAIN_ID"));
    assert!(vars.contains_key("AKASH_SEEDS"));

    assert_eq!(vars["PROXY_SVC"], "proxy-node");
    assert_eq!(vars["PROXY_NODE_IMAGE"], "ghcr.io/hard-nett/oline-proxy-node:latest");
}

#[test]
fn test_proxy_config_from_toml() {
    let tmp = unique_dir("proxy-toml");
    let config_path = tmp.path().join("config.toml");
    fs::write(&config_path, r#"
[chain]
id = "test-chain"

[proxy]
enabled = true
image = "custom-image:v1"
domain = "proxy.test.network"
akash_chain_id = "akashnet-2"
akash_seeds = "seed1@1.2.3.4:26656,seed2@5.6.7.8:26656"
"#).unwrap();

    let config = o_line_sdl::toml_config::TomlConfig::load(&config_path).unwrap();

    assert!(config.proxy.enabled);
    assert_eq!(config.proxy.image, "custom-image:v1");
    assert_eq!(config.proxy.domain, "proxy.test.network");
    assert_eq!(config.proxy.akash_seeds, "seed1@1.2.3.4:26656,seed2@5.6.7.8:26656");
}

/// Verify the full SDL rendering pipeline: load config -> get sdl_vars -> render template.
#[test]
fn test_proxy_sdl_end_to_end_from_config() {
    let tmp = unique_dir("e2e-sdl");
    let config_path = tmp.path().join("config.toml");
    fs::write(&config_path, r#"
[chain]
id = "test-chain"

[proxy]
enabled = true
image = "my-proxy:v2"
service_name = "my-proxy-svc"
domain = "proxy.e2e.test"
akash_chain_id = "akashnet-2"
akash_seeds = "abc@1.2.3.4:26656"
"#).unwrap();

    let config = o_line_sdl::toml_config::TomlConfig::load(&config_path).unwrap();
    let vars = config.to_sdl_vars();

    let template_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/templates/sdls/oline/provider-proxy-node.yml"
    );
    let raw = fs::read_to_string(template_path).unwrap();
    let rendered = akash_deploy_rs::substitute_partial(&raw, &vars);

    assert!(rendered.contains("my-proxy-svc:"), "custom service name in rendered SDL");
    assert!(rendered.contains("image: my-proxy:v2"), "custom image in rendered SDL");
    assert!(rendered.contains("proxy.e2e.test"), "custom domain in rendered SDL");
}
