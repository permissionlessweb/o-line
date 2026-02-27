use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use akash_deploy_rs::ServiceEndpoint;
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use openssh::{KnownHosts, SessionBuilder};
use rand::RngCore;
use ssh_key::{LineEnding, PrivateKey};
use std::{
    collections::HashMap, env::var, error::Error, path::PathBuf, thread::sleep, time::Duration,
};

use crate::MAX_RETRIES;

pub const SALT_LEN: usize = 16; // AES-256-GCM fixed
pub const NONCE_LEN: usize = 12; // AES-256-GCM fixed
pub const S3_SECRET: usize = 40;
pub const S3_KEY: usize = 24;

pub fn gen_ssh_key() -> ssh_key::PrivateKey {
    use ssh_key::rand_core::OsRng;
    ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap()
}
pub fn save_ssh_key(k: ssh_key::PrivateKey, path: &PathBuf) {
    // write_openssh_file sets 0o600 permissions automatically on Unix
    k.write_openssh_file(path, LineEnding::LF)
        .expect("Failed to save SSH private key");
}
/// Forms `ssh://root@<host>:<port>` from a deployment endpoint URI + forwarded port.
/// Strips any `http://` / `https://` scheme and port suffix from `uri` before use.
pub fn ssh_dest_path(ssh_port: &str, uri: &str) -> String {
    let host = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    // drop any trailing `:port` that may be present in the provider URI
    let host = host.split(':').next().unwrap_or(host);
    format!("ssh://root@{}:{}", host, ssh_port)
}

/// Upload wildcard cert + private key to a remote node via SFTP.
///
/// `remote_cert_path` / `remote_key_path` are absolute paths on the remote host
/// where the TLS setup script will watch for the files (e.g. `/tmp/tls/cert.pem`).
/// Uses `create + truncate` so retries succeed even if a previous attempt left
/// partial files behind.
pub async fn send_cert_sftp(
    dest: &str,
    cert: &[u8],
    privkey: &[u8],
    ssh_key_path: &PathBuf,
    remote_cert_path: &str,
    remote_key_path: &str,
) -> Result<(), Box<dyn Error>> {
    use openssh_sftp_client::Sftp;
    use std::path::Path;

    let sftp = Sftp::from_session(
        SessionBuilder::default()
            .keyfile(ssh_key_path)
            .known_hosts_check(KnownHosts::Add) // ephemeral node — accept changed host keys
            .connect_mux(dest)
            .await?,
        Default::default(),
    )
    .await?;

    // write cert — create or overwrite so retries are safe
    sftp.options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(Path::new(remote_cert_path))
        .await?
        .write_all(cert)
        .await?;

    // write private key
    sftp.options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(Path::new(remote_key_path))
        .await?
        .write_all(privkey)
        .await?;

    Ok(())
}

/// Upload TLS cert + private key to a deployed service via SFTP.
///
/// Finds the SSH-forwarded endpoint in `endpoints` (matched by `SSH_PORT` env,
/// default 22), saves `ssh_privkey_pem` to `ssh_key_path` on disk, then retries
/// the SFTP transfer until it succeeds or `MAX_RETRIES` is exhausted.
///
/// Remote paths default to `/tmp/tls/cert.pem` and `/tmp/tls/privkey.pem` —
/// override with `TLS_REMOTE_CERT_PATH` / `TLS_REMOTE_KEY_PATH` env vars, which
/// must match the paths the node's TLS setup script watches for.
pub async fn push_tls_certs_sftp(
    label: &str,
    endpoints: &[ServiceEndpoint],
    ssh_privkey_pem: &str,
    ssh_key_path: &PathBuf,
    cert: &[u8],
    privkey: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let ssh_port: u16 = var("SSH_PORT")
        .unwrap_or_else(|_| "22".into())
        .parse()
        .unwrap_or(22);

    let ssh_ep = endpoints
        .iter()
        .find(|e| e.internal_port == ssh_port)
        .ok_or_else(|| {
            format!(
                "[{}] No SSH endpoint found for internal port {}",
                label, ssh_port
            )
        })?;

    let k = PrivateKey::from_openssh(ssh_privkey_pem.as_bytes())
        .map_err(|e| format!("[{}] Failed to parse SSH private key: {}", label, e))?;
    save_ssh_key(k, ssh_key_path);

    let dest = ssh_dest_path(&ssh_ep.port.to_string(), &ssh_ep.uri);
    let remote_cert = var("TLS_REMOTE_CERT_PATH").unwrap_or_else(|_| "/tmp/tls/cert.pem".into());
    let remote_key = var("TLS_REMOTE_KEY_PATH").unwrap_or_else(|_| "/tmp/tls/privkey.pem".into());

    tracing::info!(
        "  [{}] SFTP → {} (NodePort {})",
        label,
        ssh_ep.uri,
        ssh_ep.port
    );
    tracing::info!("    dest: {}", dest);
    tracing::info!("  [{}] remote cert path: {}", label, remote_cert);
    tracing::info!("  [{}] remote key  path: {}", label, remote_key);

    let mut retries: u16 = 0;
    loop {
        match send_cert_sftp(
            &dest,
            cert,
            privkey,
            ssh_key_path,
            &remote_cert,
            &remote_key,
        )
        .await
        {
            Ok(_) => {
                tracing::info!("  [{}] TLS certificates uploaded successfully.", label);
                break;
            }
            Err(e) => {
                retries += 1;
                if retries >= MAX_RETRIES {
                    return Err(format!(
                        "[{}] SFTP failed after {} retries: {}",
                        label, MAX_RETRIES, e
                    )
                    .into());
                }
                tracing::info!(
                    "  [{}] SFTP attempt {}/{} failed: {} — retrying in 5s",
                    label,
                    retries,
                    MAX_RETRIES,
                    e
                );
                sleep(Duration::from_secs(5));
            }
        }
    }
    Ok(())
}

/// SSH into the deployed node, verify TLS certs are at the expected paths,
/// then launch the cosmos node setup by re-invoking the entrypoint script
/// with `OLINE_PHASE=start` under `nohup` so it survives the SSH session close.
///
/// This runs immediately after `push_tls_certs_sftp` and gives the orchestrator
/// explicit confirmation that:
///   1. SSH is open and accessible
///   2. The cert files landed at the correct remote paths
///   3. The cosmos node setup has been triggered and is running in the background
pub async fn verify_certs_and_signal_start(
    label: &str,
    endpoints: &[ServiceEndpoint],
    ssh_key_path: &PathBuf,
    remote_cert_path: &str,
    remote_key_path: &str,
    entrypoint_url: &str,
    sdl_vars: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ssh_port: u16 = var("SSH_PORT")
        .unwrap_or_else(|_| "22".into())
        .parse()
        .unwrap_or(22);

    let ssh_ep = endpoints
        .iter()
        .find(|e| e.internal_port == ssh_port)
        .ok_or_else(|| {
            format!(
                "[{}] No SSH endpoint found for internal port {}",
                label, ssh_port
            )
        })?;

    let dest = ssh_dest_path(&ssh_ep.port.to_string(), &ssh_ep.uri);
    tracing::info!("  [{}] SSH verify + launch → {}", label, dest);

    let session = SessionBuilder::default()
        .keyfile(ssh_key_path)
        .known_hosts_check(KnownHosts::Add) // ephemeral node — accept changed host keys
        .connect_mux(&dest)
        .await?;

    // Step 1: verify both cert files are present at their expected paths.
    let verify_cmd = format!(
        "test -f '{cert}' && echo '[OK] {cert}' && test -f '{key}' && echo '[OK] {key}'",
        cert = remote_cert_path,
        key = remote_key_path,
    );
    let verify = session
        .command("sh")
        .arg("-c")
        .arg(&verify_cmd)
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&verify.stdout);
    let stderr = String::from_utf8_lossy(&verify.stderr);
    if !verify.status.success() {
        return Err(format!(
            "[{}] Cert verification failed — files not at expected paths.\n  stdout: {}\n  stderr: {}",
            label,
            stdout.trim(),
            stderr.trim()
        )
        .into());
    }
    for line in stdout.trim().lines() {
        tracing::info!("  [{}] {}", label, line);
    }

    const REFRESH_VARS: &[&str] = &[
        "CHAIN_ID",
        "CHAIN_JSON",
        "ADDRBOOK_URL",
        "TLS_CONFIG_URL",
        "OMNIBUS_IMAGE",
    ];
    let export_lines: Vec<String> = sdl_vars
        .iter()
        .filter(|(k, _)| REFRESH_VARS.contains(&k.as_str()))
        .map(|(k, v)| format!("export {}='{}'", k, v.replace('\'', "'\\''")))
        .collect();
    let refresh_cmd = format!(
        "cat >> /tmp/oline-env.sh <<'__OLINE_ENV__'\n{}\n__OLINE_ENV__",
        export_lines.join("\n")
    );
    let refresh = session
        .command("sh")
        .arg("-c")
        .arg(&refresh_cmd)
        .output()
        .await?;
    if refresh.status.success() {
        tracing::info!(
            "  [{}] Patched /tmp/oline-env.sh ({} vars: {})",
            label,
            export_lines.len(),
            REFRESH_VARS.join(", ")
        );
    } else {
        let stderr = String::from_utf8_lossy(&refresh.stderr);
        tracing::info!(
            "  [{}] Warning: failed to patch /tmp/oline-env.sh: {}",
            label,
            stderr.trim()
        );
    }

    // Step 2: launch cosmos node setup in the background.
    // nohup ensures the process survives after this SSH session closes.
    // Output is redirected to /tmp/oline-node.log for post-hoc inspection.
    // Re-download wrapper.sh first if it was lost (e.g. container restart cleared /tmp/).
    let launch_cmd = format!(
        "[ -f /tmp/wrapper.sh ] || curl -fsSL '{url}' -o /tmp/wrapper.sh; \
         OLINE_PHASE=start nohup bash /tmp/wrapper.sh >/tmp/oline-node.log 2>&1 & echo $!",
        url = entrypoint_url,
    );
    let launch = session
        .command("sh")
        .arg("-c")
        .arg(&launch_cmd)
        .output()
        .await?;

    let pid = String::from_utf8_lossy(&launch.stdout);
    tracing::info!("  [{}] Node setup launched (PID {})", label, pid.trim());

    let provider_host = ssh_ep
        .uri
        .strip_prefix("https://")
        .or_else(|| ssh_ep.uri.strip_prefix("http://"))
        .unwrap_or(&ssh_ep.uri)
        .split(':')
        .next()
        .unwrap_or(&ssh_ep.uri);
    tracing::info!(
        "  [{}] Watch setup:     ssh -i {} -p {} root@{} 'tail -f /tmp/oline-node.log'",
        label,
        ssh_key_path.display(),
        ssh_ep.port,
        provider_host,
    );
    tracing::info!(
        "  [{}] Watch node:      ssh -i {} -p {} root@{} 'tail -f /tmp/node.log'",
        label,
        ssh_key_path.display(),
        ssh_ep.port,
        provider_host,
    );

    Ok(())
}

/// Generate a random alphanumeric credential string of the given length.
pub fn generate_credential(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

pub fn encrypt_mnemonic(mnemonic: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let mut salt = [0u8; SALT_LEN];
    let mut key = [0u8; 32];

    rand::thread_rng().fill_bytes(&mut salt);
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Failed to create cipher: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, mnemonic.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&blob))
}

pub fn decrypt_mnemonic(encrypted_b64: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let blob = BASE64
        .decode(encrypted_b64)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    if blob.len() < SALT_LEN + NONCE_LEN + 1 {
        return Err("Encrypted data too short".into());
    }

    let (salt, nonce_bytes, ciphertext) = (
        &blob[..SALT_LEN],
        &blob[SALT_LEN..SALT_LEN + NONCE_LEN],
        &blob[SALT_LEN + NONCE_LEN..],
    );

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Failed to create cipher: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed — wrong password or corrupted data")?;

    String::from_utf8(plaintext)
        .map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e).into())
}
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hex::encode(hash)
}
