//! Integration tests for `oline firewall bootstrap` against a Docker mock pfSense.
//!
//! Requires Docker with the pfsense-mock container running on port 2222.
//! Start with: `docker compose -f docker/pfsense-e2e/docker-compose.yml up -d --build --wait`
//!
//! Run: `cargo test --test firewall_bootstrap -- --nocapture --ignored`

use std::path::PathBuf;
use std::process::Command;

const MOCK_HOST: &str = "127.0.0.1";
const MOCK_P: u16 = 2222;
const MOCK_USER: &str = "admin";
const MOCK_PASS: &str = "pfsense";

fn secrets_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("Failed to create temp dir")
}

/// Wait for the mock pfSense SSH to be reachable.
fn wait_for_ssh() {
    for attempt in 1..=20 {
        let status = Command::new("sshpass")
            .args([
                "-p",
                MOCK_PASS,
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=3",
                "-p",
                &MOCK_P.to_string(),
                &format!("{}@{}", MOCK_USER, MOCK_HOST),
                "echo ok",
            ])
            .output();

        match status {
            Ok(o) if o.status.success() => return,
            _ => {
                if attempt == 20 {
                    panic!("Mock pfSense SSH not reachable after 20 attempts");
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires Docker with pfsense-mock on port 2222"]
async fn test_bootstrap_installs_key_and_verifies() {
    wait_for_ssh();

    let tmp = secrets_dir();
    let secrets = tmp.path().to_str().unwrap();
    std::env::set_var("SECRETS_PATH", secrets);

    // Generate an SSH key
    let privkey = o_line_sdl::crypto::gen_ssh_key();
    let pubkey = privkey.public_key().to_string();
    let key_path = PathBuf::from(secrets).join("pfsense-ssh-key");
    o_line_sdl::crypto::save_ssh_key(&privkey, &key_path);

    // Install the key via sshpass
    o_line_sdl::firewall::pfsense::install_ssh_key(
        MOCK_HOST, MOCK_P, MOCK_USER, MOCK_PASS, &pubkey,
    )
    .expect("install_ssh_key failed");

    // Verify key-based auth works
    o_line_sdl::firewall::pfsense::verify_key_auth(MOCK_HOST, MOCK_P, MOCK_USER, &key_path)
        .await
        .expect("verify_key_auth failed");

    // Verify store persistence
    let store_path = PathBuf::from(secrets).join("firewalls.enc");
    let store = o_line_sdl::firewall::FirewallStore::open(&store_path, "test-pw");
    let record = o_line_sdl::firewall::FirewallRecord::new(
        "test-pfsense",
        MOCK_HOST,
        MOCK_P,
        MOCK_USER,
        "pfsense-ssh-key",
    );
    store.add(record).expect("store.add failed");

    let loaded = store.load().expect("store.load failed");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].host, MOCK_HOST);
}

#[tokio::test]
#[ignore = "requires Docker with pfsense-mock on port 2222"]
async fn test_bootstrap_idempotent() {
    wait_for_ssh();

    let tmp = secrets_dir();
    let secrets = tmp.path().to_str().unwrap();
    std::env::set_var("SECRETS_PATH", secrets);

    // Clear any authorized_keys from previous tests
    o_line_sdl::firewall::pfsense::ssh_with_password(
        MOCK_HOST,
        MOCK_P,
        MOCK_USER,
        MOCK_PASS,
        "rm -f ~/.ssh/authorized_keys",
    )
    .ok();

    let privkey = o_line_sdl::crypto::gen_ssh_key();
    let pubkey = privkey.public_key().to_string();
    let key_path = PathBuf::from(secrets).join("pfsense-ssh-key");
    o_line_sdl::crypto::save_ssh_key(&privkey, &key_path);

    // Install the same key twice
    o_line_sdl::firewall::pfsense::install_ssh_key(
        MOCK_HOST, MOCK_P, MOCK_USER, MOCK_PASS, &pubkey,
    )
    .expect("first install failed");

    o_line_sdl::firewall::pfsense::install_ssh_key(
        MOCK_HOST, MOCK_P, MOCK_USER, MOCK_PASS, &pubkey,
    )
    .expect("second install failed");

    // Verify authorized_keys has exactly 1 entry (sort -u dedup)
    let output = o_line_sdl::firewall::pfsense::ssh_with_password(
        MOCK_HOST,
        MOCK_P,
        MOCK_USER,
        MOCK_PASS,
        "wc -l < ~/.ssh/authorized_keys",
    )
    .expect("SSH failed");

    let count = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<usize>()
        .unwrap_or(0);
    assert_eq!(
        count, 1,
        "Expected exactly 1 authorized_keys entry, got {}",
        count
    );
}

#[tokio::test]
#[ignore = "requires Docker with pfsense-mock on port 2222"]
async fn test_bootstrap_with_existing_pubkey() {
    wait_for_ssh();

    let tmp = secrets_dir();
    let secrets = tmp.path().to_str().unwrap();
    std::env::set_var("SECRETS_PATH", secrets);

    // Generate a key externally
    let privkey = o_line_sdl::crypto::gen_ssh_key();
    let pubkey = privkey.public_key().to_string();
    let key_path = PathBuf::from(secrets).join("existing-key");
    o_line_sdl::crypto::save_ssh_key(&privkey, &key_path);

    // Write pubkey to a .pub file
    let pub_path = PathBuf::from(secrets).join("existing-key.pub");
    std::fs::write(&pub_path, &pubkey).unwrap();

    // Install using the pubkey file content
    let pubkey_content = std::fs::read_to_string(&pub_path).unwrap();
    o_line_sdl::firewall::pfsense::install_ssh_key(
        MOCK_HOST,
        MOCK_P,
        MOCK_USER,
        MOCK_PASS,
        pubkey_content.trim(),
    )
    .expect("install with existing pubkey failed");

    // Verify
    o_line_sdl::firewall::pfsense::verify_key_auth(MOCK_HOST, MOCK_P, MOCK_USER, &key_path)
        .await
        .expect("verify with existing key failed");
}
