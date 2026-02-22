use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use akash_deploy_rs::{
    AkashBackend, AkashClient, Bid, DeployError, DeploymentRecord, DeploymentState,
    DeploymentStore, DeploymentWorkflow, FileDeploymentStore, InputRequired, KeySigner,
    ProviderInfo, ServiceEndpoint, StepResult, WorkflowConfig,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cloudflare::endpoints::dns::dns::{
    CreateDnsRecord, CreateDnsRecordParams, DeleteDnsRecord, DnsContent, ListDnsRecords,
    ListDnsRecordsParams, UpdateDnsRecord, UpdateDnsRecordParams,
};
use cloudflare::framework::auth::Credentials;
use cloudflare::framework::client::async_api::Client as CfClient;
use cloudflare::framework::client::ClientConfig as CfClientConfig;
use cloudflare::framework::Environment as CfEnvironment;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    error::Error,
    path::{Path, PathBuf},
};
use std::{
    fs,
    io::{self, BufRead, Write},
};

const SALT_LEN: usize = 16; // AES-256-GCM fixed
const NONCE_LEN: usize = 12; // AES-256-GCM fixed

// ── Runtime defaults (loaded from env vars / .env, with hardcoded fallbacks) ──

#[derive(Clone)]
pub struct RuntimeDefaults {
    secret_keys: Vec<String>,
    env_key: String,
    sdl_dir: PathBuf,
    snapshot_state_url: String,
    snapshot_base_url: String,
    chain_json: String,
    addrbook_url: String,
    omnibus_image: String,
    minio_ipfs_image: String,
}

impl RuntimeDefaults {
    fn load() -> Self {
        Self {
            secret_keys: std::env::var("OLINE_SECRET_KEYS")
                .unwrap_or_else(|_| "S3_KEY,S3_SECRET,MINIO_ROOT_USER,MINIO_ROOT_PASSWORD,TERPD_P2P_PRIVATE_PEER_IDS,CF_API_TOKEN".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            env_key: std::env::var("OLINE_ENV_KEY_NAME").unwrap_or_else(|_| "OLINE_ENCRYPTED_MNEMONIC".into()),
            sdl_dir: PathBuf::from(std::env::var("OLINE_SDL_DIR").unwrap_or_else(|_| "sdls".into())),
            snapshot_state_url: std::env::var("OLINE_SNAPSHOT_STATE_URL").expect("latest snapshot json"),
            snapshot_base_url: std::env::var("OLINE_SNAPSHOT_BASE_URL").expect("snapshot server"),
            chain_json: std::env::var("OLINE_CHAIN_JSON").expect("chain json"),
            addrbook_url: std::env::var("OLINE_ADDRBOOK_URL").expect("addrbook"),
            omnibus_image: std::env::var("OLINE_OMNIBUS_IMAGE").expect("omnibus image"),
            minio_ipfs_image: std::env::var("OLINE_MINIO_IPFS_IMAGE").expect("minio-ipfs version")
        }
    }

    fn load_sdl(&self, filename: &str) -> Result<String, Box<dyn Error>> {
        let path = self.sdl_dir.join(filename);
        std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read SDL '{}': {}", path.display(), e).into())
    }

    fn is_secret(&self, key: &str) -> bool {
        self.secret_keys.iter().any(|s| s == key)
    }
}

// ── Encryption ──

fn encrypt_mnemonic(mnemonic: &str, password: &str) -> Result<String, Box<dyn Error>> {
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

fn decrypt_mnemonic(encrypted_b64: &str, password: &str) -> Result<String, Box<dyn Error>> {
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

// ── Credential generation ──

/// Generate a random alphanumeric credential string of the given length.
fn generate_credential(len: usize) -> String {
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

// ── .env file helpers ──

/// Load KEY=VALUE pairs from .env file into process environment.
/// Skips comments (#), empty lines, and the encrypted mnemonic key.
/// Does not override env vars that are already set.
fn load_dotenv(env_key: &str) {
    let env_path = Path::new(".env");
    if let Ok(contents) = fs::read_to_string(env_path) {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                // Don't load the encrypted mnemonic as a regular env var
                if key == env_key {
                    continue;
                }
                // Don't override existing env vars
                if std::env::var(key).is_err() {
                    std::env::set_var(key, value);
                }
            }
        }
    }
}

/// Resolve a default value with priority: env var > saved config > hardcoded default.
fn default_val(env_key: &str, saved: Option<&str>, hardcoded: &str) -> String {
    std::env::var(env_key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| saved.unwrap_or(hardcoded).to_string())
}

/// Like `default_val` but for optional values (no hardcoded fallback).
fn default_val_opt(env_key: &str, saved: Option<&str>) -> Option<String> {
    std::env::var(env_key)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| saved.map(String::from))
}

fn read_encrypted_mnemonic_from_env(env_key: &str) -> Result<String, Box<dyn Error>> {
    let env_path = Path::new(".env");
    if !env_path.exists() {
        return Err("No .env file found. Run `oline encrypt` first to store your mnemonic.".into());
    }

    let contents = fs::read_to_string(env_path)?;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix(&format!("{}=", env_key)) {
            let value = value.trim();
            if !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }

    Err(format!(
        "No {} found in .env file. Run `oline encrypt` first.",
        env_key
    )
    .into())
}

fn write_encrypted_mnemonic_to_env(env_key: &str, blob: &str) -> Result<(), Box<dyn Error>> {
    let env_path = Path::new(".env");
    let entry = format!("{}={}", env_key, blob);

    if env_path.exists() {
        let contents = fs::read_to_string(env_path)?;
        let mut found = false;
        let mut new_lines: Vec<String> = Vec::new();
        for line in contents.lines() {
            if line.trim().starts_with(&format!("{}=", env_key)) {
                new_lines.push(entry.clone());
                found = true;
            } else {
                new_lines.push(line.to_string());
            }
        }
        if !found {
            new_lines.push(entry);
        }
        fs::write(env_path, new_lines.join("\n") + "\n")?;
    } else {
        fs::write(env_path, format!("{}\n", entry))?;
    }

    Ok(())
}

// ── Config persistence ──

fn config_path() -> PathBuf {
    let home = dirs::home_dir().expect("Cannot determine home directory");
    home.join(".oline").join("config.enc")
}

fn save_config(config: &OLineConfig, password: &str) -> Result<(), Box<dyn Error>> {
    let json = serde_json::to_string(config)?;
    let encrypted = encrypt_mnemonic(&json, password)?;
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, encrypted)?;
    Ok(())
}

fn load_config(password: &str) -> Option<OLineConfig> {
    let path = config_path();
    let encrypted = fs::read_to_string(&path).ok()?;
    let json = decrypt_mnemonic(encrypted.trim(), password).ok()?;
    serde_json::from_str(&json).ok()
}

fn has_saved_config() -> bool {
    config_path().exists()
}

// ── Snapshot fetching ──

async fn fetch_latest_snapshot_url(defaults: &RuntimeDefaults) -> Result<String, Box<dyn Error>> {
    let state_url = &defaults.snapshot_state_url;
    let base_url = &defaults.snapshot_base_url;
    tracing::info!("Fetching latest snapshot info from {}...", state_url);
    let resp = reqwest::get(state_url).await?.text().await?;
    let trimmed = resp.trim();
    let state: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("Failed to parse .current_state.json: {}", e))?;
    let snapshot_name = state["snapshot_name"]
        .as_str()
        .ok_or("missing snapshot_name in .current_state.json")?;
    let url = format!("{}{}", base_url, snapshot_name);
    tracing::info!("  Latest snapshot: {}", url);

    Ok(url)
}

// ── Cloudflare DNS ──

/// Update (or create) a CNAME record via the Cloudflare API crate.
/// Lists ALL record types for `name` so stale records of a different type are
/// replaced rather than leaving a conflicting record that blocks creation.
async fn cloudflare_upsert_cname(
    cf_token: &str,
    zone_id: &str,
    name: &str,
    target: &str,
) -> Result<(), Box<dyn Error>> {
    let credentials = Credentials::UserAuthToken {
        token: cf_token.to_string(),
    };
    let client = CfClient::new(
        credentials,
        CfClientConfig::default(),
        CfEnvironment::Production,
    )
    .map_err(|e| format!("Failed to create Cloudflare client: {}", e))?;

    // List ALL records for this name (no type filter) so we find stale A/AAAA etc.
    let list_resp = client
        .request(&ListDnsRecords {
            zone_identifier: zone_id,
            params: ListDnsRecordsParams {
                name: Some(name.to_string()),
                record_type: None,
                ..Default::default()
            },
        })
        .await
        .map_err(|e| format!("Cloudflare list DNS records failed: {:?}", e))?;

    if let Some(existing) = list_resp.result.first() {
        match &existing.content {
            DnsContent::CNAME { .. } => {
                // Same type — update in place.
                client
                    .request(&UpdateDnsRecord {
                        zone_identifier: zone_id,
                        identifier: &existing.id,
                        params: UpdateDnsRecordParams {
                            name,
                            content: DnsContent::CNAME {
                                content: target.to_string(),
                            },
                            ttl: Some(60),
                            proxied: Some(false),
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare CNAME update failed: {:?}", e))?;
                tracing::info!("    Updated CNAME {} → {}", name, target);
            }
            _ => {
                // Wrong type — delete it then create a fresh CNAME.
                tracing::info!("    Replacing existing record for {} with CNAME", name);
                client
                    .request(&DeleteDnsRecord {
                        zone_identifier: zone_id,
                        identifier: &existing.id,
                    })
                    .await
                    .map_err(|e| format!("Cloudflare delete old record failed: {:?}", e))?;
                client
                    .request(&CreateDnsRecord {
                        zone_identifier: zone_id,
                        params: CreateDnsRecordParams {
                            name,
                            content: DnsContent::CNAME {
                                content: target.to_string(),
                            },
                            ttl: Some(60),
                            proxied: Some(false),
                            priority: None,
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare CNAME create failed: {:?}", e))?;
                tracing::info!(
                    "    Created CNAME {} → {} (replaced old record)",
                    name,
                    target
                );
            }
        }
    } else {
        client
            .request(&CreateDnsRecord {
                zone_identifier: zone_id,
                params: CreateDnsRecordParams {
                    name,
                    content: DnsContent::CNAME {
                        content: target.to_string(),
                    },
                    ttl: Some(60),
                    proxied: Some(false),
                    priority: None,
                },
            })
            .await
            .map_err(|e| format!("Cloudflare CNAME create failed: {:?}", e))?;
        tracing::info!("    Created CNAME {} → {}", name, target);
    }

    Ok(())
}

/// Extract the hostname (without scheme or port) from a ServiceEndpoint URI.
/// e.g. "https://abc.provider.com" → "abc.provider.com"
///      "http://host:8080"         → "host"
///      "host:8080"                → "host"
fn endpoint_hostname(uri: &str) -> &str {
    let s = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    // Strip port if present
    s.split(':').next().unwrap_or(s)
}

// ── DNS domains for Phase-A services (match SDL accept: fields) ──
// Snapshot node (oline-a-snapshot): port 26657 RPC → statesync.terp.network
//                                   port 26656 P2P → reuse statesync.terp.network (same provider IP)
// Seed node (oline-a-seed):         port 26657 RPC → seed-statesync.terp.network
//                                   port 26656 P2P → seed.terp.network
const SNAPSHOT_RPC_DOMAIN: &str = "statesync.terp.network";
const SNAPSHOT_P2P_DOMAIN: &str = "statesync.terp.network";
const SEED_RPC_DOMAIN: &str = "seed-statesync.terp.network";
const SEED_P2P_DOMAIN: &str = "seed.terp.network";

/// Fetch the snapshot metadata JSON and return the `url` field.
/// Falls back to `fallback_url` if the metadata is unavailable or malformed.
async fn fetch_snapshot_url_from_metadata(metadata_url: &str, fallback_url: &str) -> String {
    tracing::info!("  Fetching snapshot metadata from {}", metadata_url);
    match reqwest::get(metadata_url).await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(json) => {
                if let Some(url) = json.get("url").and_then(|u| u.as_str()) {
                    tracing::info!("  Snapshot URL from metadata: {}", url);
                    return url.to_string();
                }
                tracing::info!(
                    "  Warning: snapshot metadata JSON has no 'url' field — using fallback"
                );
            }
            Err(e) => tracing::info!(
                "  Warning: failed to parse snapshot metadata JSON: {} — using fallback",
                e
            ),
        },
        Err(e) => tracing::info!(
            "  Warning: failed to fetch snapshot metadata from {}: {} — using fallback",
            metadata_url,
            e
        ),
    }
    tracing::info!("  Using fallback snapshot URL: {}", fallback_url);
    fallback_url.to_string()
}

/// Resolve a hostname to its first IPv4 address.
async fn resolve_to_ipv4(hostname: &str) -> Option<std::net::Ipv4Addr> {
    tokio::net::lookup_host(format!("{}:80", hostname))
        .await
        .ok()?
        .find_map(|addr| match addr {
            std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
            _ => None,
        })
}

/// Upsert a Cloudflare DNS A record: `name` → `ip`.
/// Lists ALL record types for `name` so stale CNAMEs are replaced rather than
/// causing a 400 conflict error.
async fn cloudflare_upsert_a(
    cf_token: &str,
    zone_id: &str,
    name: &str,
    ip: std::net::Ipv4Addr,
) -> Result<(), Box<dyn Error>> {
    let credentials = Credentials::UserAuthToken {
        token: cf_token.to_string(),
    };
    let client = CfClient::new(
        credentials,
        CfClientConfig::default(),
        CfEnvironment::Production,
    )
    .map_err(|e| format!("Failed to create Cloudflare client: {}", e))?;

    // List ALL records for this name (no type filter) so stale CNAMEs are caught.
    let list_resp = client
        .request(&ListDnsRecords {
            zone_identifier: zone_id,
            params: ListDnsRecordsParams {
                name: Some(name.to_string()),
                record_type: None,
                ..Default::default()
            },
        })
        .await
        .map_err(|e| format!("Cloudflare list DNS records failed: {:?}", e))?;

    if let Some(existing) = list_resp.result.first() {
        match &existing.content {
            DnsContent::A { .. } => {
                // Same type — update in place.
                client
                    .request(&UpdateDnsRecord {
                        zone_identifier: zone_id,
                        identifier: &existing.id,
                        params: UpdateDnsRecordParams {
                            name,
                            content: DnsContent::A { content: ip },
                            ttl: Some(60),
                            proxied: Some(false),
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare A record update failed: {:?}", e))?;
                tracing::info!("    Updated A {} → {}", name, ip);
            }
            _ => {
                // Wrong type (e.g. stale CNAME) — delete then create A record.
                tracing::info!("    Replacing existing record for {} with A", name);
                client
                    .request(&DeleteDnsRecord {
                        zone_identifier: zone_id,
                        identifier: &existing.id,
                    })
                    .await
                    .map_err(|e| format!("Cloudflare delete old record failed: {:?}", e))?;
                client
                    .request(&CreateDnsRecord {
                        zone_identifier: zone_id,
                        params: CreateDnsRecordParams {
                            name,
                            content: DnsContent::A { content: ip },
                            ttl: Some(60),
                            proxied: Some(false),
                            priority: None,
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare A record create failed: {:?}", e))?;
                tracing::info!("    Created A {} → {} (replaced old record)", name, ip);
            }
        }
    } else {
        client
            .request(&CreateDnsRecord {
                zone_identifier: zone_id,
                params: CreateDnsRecordParams {
                    name,
                    content: DnsContent::A { content: ip },
                    ttl: Some(60),
                    proxied: Some(false),
                    priority: None,
                },
            })
            .await
            .map_err(|e| format!("Cloudflare A record create failed: {:?}", e))?;
        tracing::info!("    Created A {} → {}", name, ip);
    }

    Ok(())
}

/// Scan the rendered SDL for `accept:` domains on every service expose and update
/// Cloudflare CNAME records so each accept domain points at the provider-assigned
/// ingress hostname (the URI in the provider status response that is NOT itself
/// one of the accept domains).
///
/// This must run immediately after `deploy_phase_with_selection` returns so the
/// public domain resolves to the new provider before services try to use it.
async fn cloudflare_update_accept_domains(
    rendered_sdl: &str,
    endpoints: &[ServiceEndpoint],
    cf_token: &str,
    zone_id: &str,
) {
    let yaml: serde_yaml::Value = match serde_yaml::from_str(rendered_sdl) {
        Ok(y) => y,
        Err(e) => {
            tracing::info!(
                "  Warning: could not parse SDL for Cloudflare DNS update: {}",
                e
            );
            return;
        }
    };

    let services = match yaml.get("services").and_then(|s| s.as_mapping()) {
        Some(s) => s,
        None => return,
    };

    for (svc_key, svc_config) in services {
        let svc_name = match svc_key.as_str() {
            Some(s) => s,
            None => continue,
        };

        // Collect all accept domains across all expose entries for this service.
        let mut accept_domains: Vec<String> = Vec::new();
        if let Some(exposes) = svc_config.get("expose").and_then(|e| e.as_sequence()) {
            for expose in exposes {
                if let Some(arr) = expose.get("accept").and_then(|a| a.as_sequence()) {
                    for v in arr {
                        if let Some(raw) = v.as_str() {
                            // Strip inline YAML comments (e.g. "host # ← note")
                            let domain = raw.split('#').next().unwrap_or(raw).trim();
                            if !domain.is_empty() {
                                accept_domains.push(domain.to_string());
                            }
                        }
                    }
                }
            }
        }

        if accept_domains.is_empty() {
            continue;
        }

        // Build a set for O(1) lookup.
        let accept_set: std::collections::HashSet<&str> =
            accept_domains.iter().map(|s| s.as_str()).collect();

        // The provider-assigned ingress URI comes from the `uris` array in the provider
        // status response and is always HTTPS (port 443) or HTTP (port 80).
        // Forwarded-port endpoints use random ports (e.g. 31039) and cannot be CNAME
        // targets because DNS records don't carry port numbers.
        // Only look at port-80/443 endpoints so we never create a pointless CNAME
        // to the bare provider hostname for TCP-only (RANDOM_PORT) services.
        let provider_ingress = endpoints
            .iter()
            .filter(|e| e.service == svc_name && (e.port == 80 || e.port == 443))
            .map(|e| endpoint_hostname(&e.uri))
            .find(|host| !accept_set.contains(*host));

        match provider_ingress {
            Some(ingress) => {
                // HTTP/HTTPS ingress — set CNAME to the provider-assigned ingress hostname.
                for domain in &accept_domains {
                    tracing::info!("  Cloudflare CNAME: {} → {}", domain, ingress);
                    if let Err(e) =
                        cloudflare_upsert_cname(cf_token, zone_id, domain, ingress).await
                    {
                        tracing::info!("  Warning: Cloudflare CNAME failed for {}: {}", domain, e);
                    }
                }
            }
            None => {
                // No HTTP ingress — service uses RANDOM_PORT (non-80 expose).
                // CNAMEs can't carry ports, so create A records pointing to the provider IP.
                // Find the provider hostname from any RANDOM_PORT endpoint for this service.
                let provider_host = endpoints
                    .iter()
                    .find(|e| e.service == svc_name && e.port != 80 && e.port != 443)
                    .map(|e| endpoint_hostname(&e.uri).to_string());

                let host = match provider_host {
                    Some(h) => h,
                    None => {
                        tracing::info!(
                            "  Warning: no endpoint found for '{}' — skipping DNS",
                            svc_name
                        );
                        continue;
                    }
                };

                // Resolve provider hostname → IPv4.
                let ip = match resolve_to_ipv4(&host).await {
                    Some(ip) => ip,
                    None => {
                        tracing::info!(
                            "  Warning: could not resolve '{}' to IPv4 — skipping A records",
                            host
                        );
                        continue;
                    }
                };

                // Collect all forwarded ports for this service.
                // DNS A records cannot carry port numbers — the A record points to the
                // provider IP and the operator must use the forwarded port for connections.
                let port_endpoints: Vec<(u16, String)> = endpoints
                    .iter()
                    .filter(|e| e.service == svc_name && e.port != 80 && e.port != 443)
                    .map(|e| (e.port, e.uri.clone()))
                    .collect();

                // Print connection strings prominently for each accept domain × port.
                tracing::info!("  [{}] provider IP: {} (DNS A record)", svc_name, ip);
                for domain in &accept_domains {
                    for (port, _) in &port_endpoints {
                        tracing::info!("  [{}] connection string: {}:{}", svc_name, domain, port);
                    }
                }

                for domain in &accept_domains {
                    tracing::info!("  Cloudflare A: {} → {}", domain, ip);
                    if let Err(e) = cloudflare_upsert_a(cf_token, zone_id, domain, ip).await {
                        tracing::info!(
                            "  Warning: Cloudflare A record failed for {}: {}",
                            domain,
                            e
                        );
                    }
                }
            }
        }
    }
}

/// Helper to insert the shared SDL template variables into a HashMap.
fn insert_sdl_defaults(vars: &mut HashMap<String, String>, defaults: &RuntimeDefaults) {
    vars.insert("OMNIBUS_IMAGE".into(), defaults.omnibus_image.clone());
    vars.insert("CHAIN_JSON".into(), defaults.chain_json.clone());
    vars.insert("ADDRBOOK_URL".into(), defaults.addrbook_url.clone());
    vars.insert("ADDRBOOK_URL".into(), defaults.addrbook_url.clone());
}

/// Helper to insert S3 snapshot export variables.
/// `s3_key`, `s3_secret`, and `s3_host` are generated/derived at deploy time.
fn insert_s3_vars(
    vars: &mut HashMap<String, String>,
    config: &OLineConfig,
    s3_key: &str,
    s3_secret: &str,
    s3_host: &str,
) {
    vars.insert("S3_KEY".into(), s3_key.to_string());
    vars.insert("S3_SECRET".into(), s3_secret.to_string());
    vars.insert("S3_HOST".into(), s3_host.to_string());
    vars.insert("SNAPSHOT_PATH".into(), config.snapshot_path.clone());
    vars.insert("SNAPSHOT_TIME".into(), config.snapshot_time.clone());
    vars.insert(
        "SNAPSHOT_SAVE_FORMAT".into(),
        config.snapshot_save_format.clone(),
    );
    // Metadata URL uses the public download domain so URLs in snapshot.json are externally accessible
    vars.insert(
        "SNAPSHOT_METADATA_URL".into(),
        format!(
            "https://{}/{}/snapshot.json",
            config.snapshot_download_domain,
            config.snapshot_path.trim_matches('/')
        ),
    );
    vars.insert(
        "SNAPSHOT_DOWNLOAD_DOMAIN".into(),
        config.snapshot_download_domain.clone(),
    );
    vars.insert("SNAPSHOT_RETAIN".into(), config.snapshot_retain.clone());
    vars.insert(
        "SNAPSHOT_KEEP_LAST".into(),
        config.snapshot_keep_last.clone(),
    );
}

/// Helper to insert minio-ipfs variables.
/// `root_user` and `root_password` are the auto-generated credentials
/// shared between the snapshot node (as S3_KEY/S3_SECRET) and MinIO.
fn insert_minio_vars(
    vars: &mut HashMap<String, String>,
    config: &OLineConfig,
    root_user: &str,
    root_password: &str,
) {
    vars.insert("MINIO_IPFS_IMAGE".into(), config.minio_ipfs_image.clone());
    // Derive MINIO_BUCKET from snapshot_path (first path component, e.g. "snapshots" from "snapshots/terpnetwork")
    let minio_bucket = config
        .snapshot_path
        .split('/')
        .next()
        .unwrap_or("snapshots")
        .to_string();
    vars.insert("MINIO_BUCKET".into(), minio_bucket);
    vars.insert("AUTOPIN_INTERVAL".into(), config.autopin_interval.clone());
    vars.insert("MINIO_ROOT_USER".into(), root_user.to_string());
    vars.insert("MINIO_ROOT_PASSWORD".into(), root_password.to_string());
}

// ── Raw template substitution ──

/// Raw text-based `${VAR}` substitution. Unlike `apply_template` (which is
/// YAML-aware and only substitutes values), this replaces placeholders
/// everywhere — including YAML mapping keys like `${SNAPSHOT_SVC}:`.
fn substitute_template_raw(
    template: &str,
    variables: &HashMap<String, String>,
    defaults: &HashMap<String, String>,
) -> Result<String, Box<dyn Error>> {
    let mut values = defaults.clone();
    values.extend(variables.clone());

    let mut result = String::new();
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() && chars[i + 1] == '{' {
            i += 2; // skip ${
            let start = i;
            while i < chars.len() && chars[i] != '}' {
                i += 1;
            }
            if i >= chars.len() {
                return Err("Unclosed ${...} placeholder in template".into());
            }
            let var_name: String = chars[start..i].iter().collect();
            match values.get(&var_name) {
                Some(val) => result.push_str(val),
                None => return Err(format!("Variable '{}' has no value", var_name).into()),
            }
            i += 1; // skip }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    Ok(result)
}

// ── SDL variable builders ──

fn build_phase_a_vars(config: &OLineConfig, defaults: &RuntimeDefaults) -> HashMap<String, String> {
    let minio_svc = "oline-a-minio-ipfs";
    // Auto-generate credentials shared between snapshot node and MinIO
    let s3_key = generate_credential(24);
    let s3_secret = generate_credential(40);
    // Use the public DNS domain so the snapshot node connects via the provider ingress.
    let s3_host = config.snapshot_download_domain.clone();

    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars, defaults);
    insert_s3_vars(&mut vars, config, &s3_key, &s3_secret, &s3_host);
    insert_minio_vars(&mut vars, config, &s3_key, &s3_secret);
    vars.insert("SNAPSHOT_SVC".into(), "oline-a-snapshot".into());
    vars.insert("SEED_SVC".into(), "oline-a-seed".into());
    vars.insert("MINIO_SVC".into(), minio_svc.into());
    vars.insert("CERTBOT_EMAIL".into(), config.certbot_email.clone());
    vars.insert("TLS_CONFIG_URL".into(), config.tls_config_url.clone());
    vars.insert("ENTRYPOINT_URL".into(), config.tls_config_url.clone());
    vars.insert(
        "SNAPSHOT_MONIKER".into(),
        "oline::special::snapshot-node".into(),
    );
    vars.insert("SEED_MONIKER".into(), "oline::special::seed-node".into());
    vars.insert("SNAPSHOT_URL".into(), config.snapshot_url.clone());
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        config.validator_peer_id.clone(),
    );
    vars
}

fn build_phase_a2_vars(
    config: &OLineConfig,
    defaults: &RuntimeDefaults,
) -> HashMap<String, String> {
    let minio_svc = "oline-a2-minio-ipfs";
    // Auto-generate credentials shared between snapshot node and MinIO
    let s3_key = generate_credential(24);
    let s3_secret = generate_credential(40);
    // Use the public DNS domain so the snapshot node connects via the provider ingress.
    let s3_host = config.snapshot_download_domain.clone();

    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars, defaults);
    insert_s3_vars(&mut vars, config, &s3_key, &s3_secret, &s3_host);
    insert_minio_vars(&mut vars, config, &s3_key, &s3_secret);
    vars.insert("SNAPSHOT_SVC".into(), "oline-a2-snapshot".into());
    vars.insert("SEED_SVC".into(), "oline-a2-seed".into());
    vars.insert("MINIO_SVC".into(), minio_svc.into());
    vars.insert("CERTBOT_EMAIL".into(), config.certbot_email.clone());
    vars.insert(
        "SNAPSHOT_MONIKER".into(),
        "oline::backup::snapshot-node".into(),
    );
    vars.insert("SEED_MONIKER".into(), "oline::backup::seed-node".into());
    vars.insert("SNAPSHOT_URL".into(), config.snapshot_url.clone());
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        config.validator_peer_id.clone(),
    );
    vars.insert("TLS_CONFIG_URL".into(), config.tls_config_url.clone());
    vars
}

fn build_phase_b_vars(
    config: &OLineConfig,
    snapshot_peer: &str,
    snapshot_2_peer: &str,
    snapshot_url: &str,
    // Comma-separated "host:port" pairs for cosmos statesync RPC servers.
    // Uses A1 snapshot node (statesync.terp.network) and A1 seed node (seed-statesync.terp.network).
    statesync_rpc_servers: &str,
    defaults: &RuntimeDefaults,
) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars, defaults);
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        format!("{},{}", snapshot_peer, snapshot_2_peer),
    );
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        config.validator_peer_id.clone(),
    );
    vars.insert(
        "TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(),
        config.validator_peer_id.clone(),
    );
    vars.insert("SNAPSHOT_URL".into(), snapshot_url.to_string());
    vars.insert(
        "SNAPSHOT_SAVE_FORMAT".into(),
        config.snapshot_save_format.clone(),
    );
    // Statesync — use both A1 snapshot RPC and A1 seed RPC so tackles can
    // sync to the network quickly without waiting for a full replay.
    if !statesync_rpc_servers.is_empty() {
        vars.insert("STATESYNC_ENABLE".into(), "true".into());
        vars.insert(
            "STATESYNC_RPC_SERVERS".into(),
            statesync_rpc_servers.to_string(),
        );
    }
    vars
}

fn build_phase_c_vars(
    seed_peer: &str,
    seed_2_peer: &str,
    snapshot_peer: &str,
    snapshot_2_peer: &str,
    left_tackle_peer: &str,
    right_tackle_peer: &str,
    defaults: &RuntimeDefaults,
) -> HashMap<String, String> {
    let tackles_combined = format!("{},{}", left_tackle_peer, right_tackle_peer);
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars, defaults);
    vars.insert(
        "TERPD_P2P_SEEDS".into(),
        format!("{},{}", seed_peer, seed_2_peer),
    );
    vars.insert(
        "TERPD_P2P_PRIVATE_PEER_IDS".into(),
        tackles_combined.clone(),
    );
    vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), tackles_combined);
    vars.insert(
        "TERPD_P2P_PERSISTENT_PEERS".into(),
        format!("{},{}", snapshot_peer, snapshot_2_peer),
    );
    vars
}

// ── OLineConfig & OLineDeployer ──

#[derive(Serialize, Deserialize, Clone)]
pub struct OLineConfig {
    pub mnemonic: String,
    pub rpc_endpoint: String,
    pub grpc_endpoint: String,
    pub snapshot_url: String,
    pub validator_peer_id: String,
    pub trusted_providers: Vec<String>,
    pub auto_select_provider: bool,
    // S3 snapshot export (credentials auto-generated per deployment)
    pub snapshot_path: String,
    pub snapshot_time: String,
    pub snapshot_save_format: String,
    pub snapshot_retain: String,
    pub snapshot_keep_last: String,
    // MinIO-IPFS
    pub minio_ipfs_image: String,
    pub s3_bucket: String,
    pub autopin_interval: String,
    pub snapshot_download_domain: String,
    pub certbot_email: String,
    // Cloudflare DNS (optional — auto-update CNAME after Phase A deploy)
    pub cloudflare_api_token: String,
    pub cloudflare_zone_id: String,
    pub tls_config_url: String,
    pub entrypoint_url: String,
}

pub struct OLineDeployer {
    client: AkashClient,
    signer: KeySigner,
    config: OLineConfig,
    password: String,
    deployment_store: FileDeploymentStore,
    defaults: RuntimeDefaults,
}

impl OLineDeployer {
    pub async fn new(
        config: OLineConfig,
        password: String,
        defaults: RuntimeDefaults,
    ) -> Result<Self, DeployError> {
        let client = AkashClient::new_from_mnemonic(
            &config.mnemonic,
            &config.rpc_endpoint,
            &config.grpc_endpoint,
        )
        .await?;
        let signer = KeySigner::new_mnemonic_str(&config.mnemonic, None)
            .map_err(|e| DeployError::Signer(format!("Failed to create signer: {}", e)))?;
        let deployment_store = FileDeploymentStore::new_default().await?;
        Ok(Self {
            client,
            signer,
            config,
            password,
            deployment_store,
            defaults,
        })
    }

    fn workflow_config(&self) -> WorkflowConfig {
        WorkflowConfig {
            auto_select_cheapest_bid: self.config.auto_select_provider,
            trusted_providers: self.config.trusted_providers.clone(),
            ..Default::default()
        }
    }

    pub async fn deploy_phase_with_selection(
        &self,
        sdl_template: &str,
        variables: HashMap<String, String>,
        defaults: HashMap<String, String>,
        label: &str,
        lines: &mut io::Lines<io::StdinLock<'_>>,
    ) -> Result<(DeploymentState, Vec<ServiceEndpoint>), DeployError> {
        // Pre-render template using raw substitution so ${VAR} in YAML keys
        // (like service names) are replaced before any YAML parsing.
        let rendered_sdl = substitute_template_raw(sdl_template, &variables, &defaults)
            .map_err(|e| DeployError::Template(format!("Template substitution failed: {}", e)))?;

        let mut state = DeploymentState::new(label, self.client.address())
            .with_sdl(&rendered_sdl)
            .with_label(label);

        let workflow = DeploymentWorkflow::new(&self.client, &self.signer, self.workflow_config());

        // Bounded loop — matches akash-deploy-rs/examples/deploy.rs pattern.
        // 60 iterations × ~12s bid wait = ~12 min max before giving up.
        for i in 0..60 {
            tracing::info!("    [{}] step {}: {:?}", label, i, state.step);

            let result = match workflow.advance(&mut state).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::info!("    [{}] error at step {:?}: {:?}", label, state.step, e);
                    return Err(e);
                }
            };

            match result {
                StepResult::Continue => continue,

                StepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                    let choice = self
                        .interactive_select_provider(&bids, lines)
                        .await
                        .map_err(|e| {
                            DeployError::InvalidState(format!("Provider selection failed: {}", e))
                        })?;
                    DeploymentWorkflow::<AkashClient>::select_provider(&mut state, &choice)?;
                }

                StepResult::NeedsInput(InputRequired::ProvideSdl) => {
                    return Err(DeployError::InvalidState(
                        "SDL content missing (should never happen)".into(),
                    ));
                }

                StepResult::Complete => {
                    tracing::info!("\n    [{}] complete!", label);
                    if let Some(dseq) = state.dseq {
                        tracing::info!("    [{}] DSEQ: {}", label, dseq);
                    }
                    for ep in &state.endpoints {
                        tracing::info!(
                            "    [{}] endpoint: {} ({}:{})",
                            label,
                            ep.uri,
                            ep.service,
                            ep.port
                        );
                    }
                    let endpoints = state.endpoints.clone();
                    return Ok((state, endpoints));
                }

                StepResult::Failed(reason) => {
                    return Err(DeployError::InvalidState(format!(
                        "Deployment '{}' failed at step {:?}: {}",
                        label, state.step, reason
                    )));
                }
            }
        }

        Err(DeployError::InvalidState(format!(
            "Deployment '{}' exceeded 60 iterations without completing",
            label
        )))
    }

    /// Query provider info for each bid and display enriched selection.
    /// Follows the pattern from akash-deploy-rs/examples/deploy.rs.
    async fn interactive_select_provider(
        &self,
        bids: &[Bid],
        lines: &mut io::Lines<io::StdinLock<'_>>,
    ) -> Result<String, Box<dyn Error>> {
        tracing::info!("  ═══════════════════════════════════════════════════════════════════════");
        tracing::info!("    PROVIDER SELECTION — {} bid(s) received", bids.len());
        tracing::info!("  ═══════════════════════════════════════════════════════════════════════");

        // Query provider info for each bid (best-effort)
        let mut provider_infos: Vec<Option<ProviderInfo>> = Vec::with_capacity(bids.len());
        for bid in bids {
            match self.client.query_provider_info(&bid.provider).await {
                Ok(info) => provider_infos.push(info),
                Err(_) => provider_infos.push(None),
            }
        }

        for (i, bid) in bids.iter().enumerate() {
            let price_akt = bid.price_uakt as f64 / 1_000_000.0;
            let info = &provider_infos[i];

            tracing::info!(
                "    [{}] {:.6} AKT/block ({} uakt)",
                i + 1,
                price_akt,
                bid.price_uakt
            );
            tracing::info!("        address:  {}", bid.provider);

            if let Some(ref info) = info {
                tracing::info!("        host:     {}", info.host_uri);

                if !info.email.is_empty() {
                    tracing::info!("        email:    {}", info.email);
                }
                if !info.website.is_empty() {
                    tracing::info!("        website:  {}", info.website);
                }

                let audited = info.attributes.iter().any(|(k, _)| k.starts_with("audit-"));
                if audited {
                    tracing::info!("        audited:  YES");
                }

                let interesting_keys = [
                    "host",
                    "organization",
                    "tier",
                    "region",
                    "capabilities/storage/3/class",
                    "capabilities/gpu/vendor/nvidia/model/*",
                ];

                let mut shown_attrs = Vec::new();
                for (key, val) in &info.attributes {
                    for ik in &interesting_keys {
                        if key.contains(ik) {
                            shown_attrs.push(format!("{}={}", key, val));
                        }
                    }
                }
                if !shown_attrs.is_empty() {
                    tracing::info!("        attrs:    {}", shown_attrs.join(", "));
                }
            } else {
                tracing::info!("        host:     (could not query provider info)");
            }
        }

        print!(
            "    Select provider (1-{}) or 'a' to auto-select cheapest: ",
            bids.len()
        );
        io::stdout().flush()?;

        let input = lines.next().unwrap_or(Ok(String::new()))?;
        let input = input.trim().to_lowercase();

        if input == "a" || input == "auto" {
            let cheapest = bids.iter().min_by_key(|b| b.price_uakt).unwrap();
            tracing::info!("\n    Selected: {}", cheapest.provider);
            if let Some(ref info) = provider_infos[bids
                .iter()
                .position(|b| b.provider == cheapest.provider)
                .unwrap()]
            {
                tracing::info!("    Host:     {}", info.host_uri);
            }
            tracing::info!(
                "  ═══════════════════════════════════════════════════════════════════════\n"
            );
            return Ok(cheapest.provider.clone());
        }

        let choice: usize = input
            .parse()
            .map_err(|_| format!("invalid input: '{}'", input))?;

        if choice < 1 || choice > bids.len() {
            return Err(format!("selection {} out of range (1-{})", choice, bids.len()).into());
        }

        let selected = &bids[choice - 1];
        let selected_info = &provider_infos[choice - 1];

        tracing::info!("\n    Selected: {}", selected.provider);
        if let Some(ref info) = selected_info {
            tracing::info!("    Host:     {}", info.host_uri);
        }
        tracing::info!(
            "  ═══════════════════════════════════════════════════════════════════════\n"
        );

        Ok(selected.provider.clone())
    }

    /// Query `rpc_url/status` and return `"<node_id>@<p2p_address>"`.
    /// `p2p_address` is the fully-formatted address string, e.g. `"seed.terp.network:31039"`.
    pub async fn extract_peer_id_at(
        rpc_url: &str,
        p2p_address: &str,
    ) -> Result<String, Box<dyn Error>> {
        let status_url = format!("{}/status", rpc_url.trim_end_matches('/'));
        let resp = reqwest::get(&status_url).await?.text().await?;
        let json: serde_json::Value = serde_json::from_str(&resp)?;
        let node_id = json["result"]["node_info"]["id"]
            .as_str()
            .ok_or("missing node_info.id in /status response")?;
        Ok(format!("{}@{}", node_id, p2p_address))
    }

    /// Retry `extract_peer_id_at` with an optional initial boot wait.
    ///
    /// * `initial_wait_secs` — sleep this long before the first attempt (lets the
    ///   node fully start; 0 means start immediately).
    /// * `max_retries` — number of attempts after the initial wait.
    /// * `retry_delay_secs` — pause between failed attempts.
    ///
    /// Returns `None` if all attempts fail.
    pub async fn extract_peer_id_with_boot_wait(
        rpc_url: &str,
        p2p_address: &str,
        initial_wait_secs: u64,
        max_retries: u32,
        retry_delay_secs: u64,
    ) -> Option<String> {
        if initial_wait_secs > 0 {
            tracing::info!(
                "  Waiting {}m before querying {}/status (node boot time)",
                initial_wait_secs / 60,
                rpc_url,
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(initial_wait_secs)).await;
        }
        for attempt in 1..=max_retries {
            match Self::extract_peer_id_at(rpc_url, p2p_address).await {
                Ok(peer) => return Some(peer),
                Err(e) => {
                    if attempt < max_retries {
                        tracing::info!(
                            "  Peer ID fetch attempt {}/{} for {} failed: {} — retrying in {}s",
                            attempt,
                            max_retries,
                            rpc_url,
                            e,
                            retry_delay_secs
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(retry_delay_secs))
                            .await;
                    } else {
                        tracing::info!(
                            "  Peer ID fetch failed after {} attempts for {}: {}",
                            max_retries,
                            rpc_url,
                            e
                        );
                    }
                }
            }
        }
        None
    }

    /// Find the forwarded endpoint for `service_name` where `internal_port` matches
    /// the SDL-specified port (e.g. 26656 or 26657).  Falls back to the first
    /// endpoint for that service if `internal_port` is 0 (old parsing path).
    fn find_endpoint_by_internal_port<'a>(
        endpoints: &'a [ServiceEndpoint],
        service_name: &str,
        internal_port: u16,
    ) -> Option<&'a ServiceEndpoint> {
        endpoints
            .iter()
            .find(|e| e.service == service_name && e.internal_port == internal_port)
            .or_else(|| endpoints.iter().find(|e| e.service == service_name))
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();

        tracing::info!("\n=== O-Line Deployer ===");
        tracing::info!("Account: {}", self.client.address());

        // ── Phase A: Snapshot + Seed ──
        tracing::info!("\n── Phase 1: Deploy Snapshot + Seed nodes ──");
        if !prompt_continue(&mut lines, "Deploy Kickoff (Speacial Teams)?")? {
            tracing::info!("Aborted.");
            return Ok(());
        }

        let a_vars = build_phase_a_vars(&self.config, &self.defaults);
        let a_defaults = HashMap::new();

        tracing::info!("  Variables:");
        for (k, v) in &a_vars {
            tracing::info!("    {}={}", k, redact_if_secret(k, v, &self.defaults));
        }

        let sdl_a = self.defaults.load_sdl("a.kickoff-special-teams.yml")?;
        tracing::info!("  Deploying...");
        let (a_state, a_endpoints) = self
            .deploy_phase_with_selection(&sdl_a, a_vars, a_defaults, "oline-phase-a", &mut lines)
            .await?;

        tracing::info!("  Deployed! DSEQ: {}", a_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&a_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        if !self.config.cloudflare_api_token.is_empty()
            && !self.config.cloudflare_zone_id.is_empty()
        {
            tracing::info!("  Updating Cloudflare DNS for accept domains...");
            if let Some(sdl) = &a_state.sdl_content {
                cloudflare_update_accept_domains(
                    sdl,
                    &a_endpoints,
                    &self.config.cloudflare_api_token,
                    &self.config.cloudflare_zone_id,
                )
                .await;
            }
        } else {
            tracing::info!("  Note: Cloudflare DNS not configured — update CNAMEs for accept domains manually.");
        }

        // ── Extract peer IDs via DNS domains ──
        // Find the forwarded NodePorts for each service's RPC (26657) and P2P (26656).
        let snap_rpc_ep =
            Self::find_endpoint_by_internal_port(&a_endpoints, "oline-a-snapshot", 26657);
        let snap_p2p_ep =
            Self::find_endpoint_by_internal_port(&a_endpoints, "oline-a-snapshot", 26656);
        let seed_rpc_ep = Self::find_endpoint_by_internal_port(&a_endpoints, "oline-a-seed", 26657);
        let seed_p2p_ep = Self::find_endpoint_by_internal_port(&a_endpoints, "oline-a-seed", 26656);

        // Construct DNS-based query URLs and peer addresses.
        // Format: <node_id>@<dns_domain>:<nodeport>  — the cosmos-sdk peer string.
        let snap_rpc_url =
            snap_rpc_ep.map(|e| format!("http://{}:{}", SNAPSHOT_RPC_DOMAIN, e.port));
        let snap_p2p_addr = snap_p2p_ep.map(|e| format!("{}:{}", SNAPSHOT_P2P_DOMAIN, e.port));
        let seed_rpc_url = seed_rpc_ep.map(|e| format!("http://{}:{}", SEED_RPC_DOMAIN, e.port));
        let seed_p2p_addr = seed_p2p_ep.map(|e| format!("{}:{}", SEED_P2P_DOMAIN, e.port));

        // Statesync RPC servers string for Phase B (cosmos format: "host:port,host:port").
        let a1_statesync_rpc = {
            let s = snap_rpc_ep
                .map(|e| format!("{}:{}", SNAPSHOT_RPC_DOMAIN, e.port))
                .unwrap_or_default();
            let sd = seed_rpc_ep
                .map(|e| format!("{}:{}", SEED_RPC_DOMAIN, e.port))
                .unwrap_or_default();
            match (s.is_empty(), sd.is_empty()) {
                (false, false) => format!("{},{}", s, sd),
                (false, true) => s,
                (true, false) => sd,
                (true, true) => String::new(),
            }
        };

        tracing::info!(
            "  Snapshot RPC: {}",
            snap_rpc_url.as_deref().unwrap_or("(not found)")
        );
        tracing::info!(
            "  Snapshot P2P: {}",
            snap_p2p_addr.as_deref().unwrap_or("(not found)")
        );
        tracing::info!(
            "  Seed RPC:     {}",
            seed_rpc_url.as_deref().unwrap_or("(not found)")
        );
        tracing::info!(
            "  Seed P2P:     {}",
            seed_p2p_addr.as_deref().unwrap_or("(not found)")
        );
        tracing::info!("  Statesync RPC servers: {}", a1_statesync_rpc);

        // Snapshot node: 5 min initial wait (it creates a snapshot on startup before syncing),
        // then retry every 60s up to 20 times (~25 min max total).
        let snapshot_peer = match (snap_rpc_url.as_deref(), snap_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!(
                    "  Warning: no RPC/P2P endpoints found for oline-a-snapshot — skipping peer ID"
                );
                None
            }
        }
        .unwrap_or_else(|| {
            tracing::info!(
                "  Warning: could not fetch snapshot peer ID — Phase B will use empty peer."
            );
            String::new()
        });

        // Seed node: also 5 min initial wait, 20×60s retries.
        let seed_peer = match (seed_rpc_url.as_deref(), seed_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!(
                    "  Warning: no RPC/P2P endpoints found for oline-a-seed — skipping peer ID"
                );
                None
            }
        }
        .unwrap_or_else(|| {
            tracing::info!(
                "  Warning: could not fetch seed peer ID — Phase B will use empty peer."
            );
            String::new()
        });

        tracing::info!("    snapshot_peer: {}", snapshot_peer);
        tracing::info!("    seed_peer:     {}", seed_peer);

        // ── Phase A2: Backup Snapshot + Seed (reuses SDL_A with backup service names) ──
        tracing::info!("\n── Phase 1b: Deploy Backup Snapshot + Seed nodes ──");
        if !prompt_continue(
            &mut lines,
            "Deploy backup kickoff (a.kickoff-special-teams.yml)?",
        )? {
            tracing::info!("Aborted.");
            return Ok(());
        }

        let a2_vars = build_phase_a2_vars(&self.config, &self.defaults);
        let a2_defaults = HashMap::new();

        tracing::info!("  Variables:");
        for (k, v) in &a2_vars {
            tracing::info!("    {}={}", k, redact_if_secret(k, v, &self.defaults));
        }

        tracing::info!("  Deploying...");
        let (a2_state, a2_endpoints) = self
            .deploy_phase_with_selection(&sdl_a, a2_vars, a2_defaults, "oline-phase-a2", &mut lines)
            .await?;

        tracing::info!("  Deployed! DSEQ: {}", a2_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&a2_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        // ── Cloudflare DNS for Phase A2 accept domains ──
        if !self.config.cloudflare_api_token.is_empty()
            && !self.config.cloudflare_zone_id.is_empty()
        {
            if let Some(sdl) = &a2_state.sdl_content {
                cloudflare_update_accept_domains(
                    sdl,
                    &a2_endpoints,
                    &self.config.cloudflare_api_token,
                    &self.config.cloudflare_zone_id,
                )
                .await;
            }
        }

        // ── Extract peer IDs from Phase A2 (backup nodes, same DNS domains) ──
        let snap2_rpc_ep =
            Self::find_endpoint_by_internal_port(&a2_endpoints, "oline-a2-snapshot", 26657);
        let snap2_p2p_ep =
            Self::find_endpoint_by_internal_port(&a2_endpoints, "oline-a2-snapshot", 26656);
        let seed2_rpc_ep =
            Self::find_endpoint_by_internal_port(&a2_endpoints, "oline-a2-seed", 26657);
        let seed2_p2p_ep =
            Self::find_endpoint_by_internal_port(&a2_endpoints, "oline-a2-seed", 26656);

        let snap2_rpc_url =
            snap2_rpc_ep.map(|e| format!("http://{}:{}", SNAPSHOT_RPC_DOMAIN, e.port));
        let snap2_p2p_addr = snap2_p2p_ep.map(|e| format!("{}:{}", SNAPSHOT_P2P_DOMAIN, e.port));
        let seed2_rpc_url = seed2_rpc_ep.map(|e| format!("http://{}:{}", SEED_RPC_DOMAIN, e.port));
        let seed2_p2p_addr = seed2_p2p_ep.map(|e| format!("{}:{}", SEED_P2P_DOMAIN, e.port));

        let snapshot_2_peer = match (snap2_rpc_url.as_deref(), snap2_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!("  Warning: no RPC/P2P endpoints found for oline-a2-snapshot — skipping peer ID");
                None
            }
        }.unwrap_or_else(|| {
            tracing::info!("  Warning: could not fetch snapshot-2 peer ID.");
            String::new()
        });

        let seed_2_peer = match (seed2_rpc_url.as_deref(), seed2_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!(
                    "  Warning: no RPC/P2P endpoints found for oline-a2-seed — skipping peer ID"
                );
                None
            }
        }
        .unwrap_or_else(|| {
            tracing::info!("  Warning: could not fetch seed-2 peer ID.");
            String::new()
        });

        tracing::info!("    snapshot_2_peer: {}", snapshot_2_peer);
        tracing::info!("    seed_2_peer:     {}", seed_2_peer);

        // ── Phase B: Left & Right Tackles ──
        tracing::info!("\n── Phase 2: Deploy Left & Right Tackles ──");
        if !prompt_continue(&mut lines, "Deploy b.left-and-right-tackle.yml?")? {
            tracing::info!("Aborted.");
            return Ok(());
        }

        // Fetch the snapshot download URL from the MinIO metadata JSON.
        // Fallback: construct from config path if metadata isn't available yet.
        let b_snapshot_fallback = format!(
            "https://{}/{}/latest.{}",
            self.config.snapshot_download_domain,
            self.config.snapshot_path.trim_matches('/'),
            self.config.snapshot_save_format
        );
        let b_snapshot_metadata_url = format!(
            "https://{}/{}/snapshot.json",
            self.config.snapshot_download_domain,
            self.config.snapshot_path.trim_matches('/')
        );
        let b_snapshot_url =
            fetch_snapshot_url_from_metadata(&b_snapshot_metadata_url, &b_snapshot_fallback).await;
        tracing::info!("  Phase B snapshot URL: {}", b_snapshot_url);

        let b_vars = build_phase_b_vars(
            &self.config,
            &snapshot_peer,
            &snapshot_2_peer,
            &b_snapshot_url,
            &a1_statesync_rpc,
            &self.defaults,
        );
        let b_defaults = HashMap::new();

        tracing::info!("  Variables:");
        for (k, v) in &b_vars {
            tracing::info!("    {}={}", k, redact_if_secret(k, v, &self.defaults));
        }

        let sdl_b = self.defaults.load_sdl("b.left-and-right-tackle.yml")?;
        tracing::info!("  Deploying...");
        let (b_state, b_endpoints) = self
            .deploy_phase_with_selection(&sdl_b, b_vars, b_defaults, "oline-phase-b", &mut lines)
            .await?;

        tracing::info!("  Deployed! DSEQ: {}", b_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&b_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        // Extract peer IDs from Phase B tackles.
        // Tackles don't have public DNS domains — use provider URI hostname + forwarded P2P port.
        let left_rpc_ep =
            Self::find_endpoint_by_internal_port(&b_endpoints, "oline-b-left-node", 26657);
        let left_p2p_ep =
            Self::find_endpoint_by_internal_port(&b_endpoints, "oline-b-left-node", 26656);
        let right_rpc_ep =
            Self::find_endpoint_by_internal_port(&b_endpoints, "oline-b-right-node", 26657);
        let right_p2p_ep =
            Self::find_endpoint_by_internal_port(&b_endpoints, "oline-b-right-node", 26656);

        let left_rpc_url = left_rpc_ep.map(|e| e.uri.clone());
        let left_p2p_addr =
            left_p2p_ep.map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));
        let right_rpc_url = right_rpc_ep.map(|e| e.uri.clone());
        let right_p2p_addr =
            right_p2p_ep.map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

        // 5 min initial wait, 20×60s retries — tackles need to sync from statesync first.
        let left_tackle_peer = match (left_rpc_url.as_deref(), left_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!("  Warning: no endpoints for oline-b-left-node");
                None
            }
        }
        .unwrap_or_else(|| {
            tracing::info!("  Warning: could not fetch left-tackle peer ID.");
            String::new()
        });

        let right_tackle_peer = match (right_rpc_url.as_deref(), right_p2p_addr.as_deref()) {
            (Some(rpc), Some(p2p)) => {
                Self::extract_peer_id_with_boot_wait(rpc, p2p, 300, 20, 60).await
            }
            _ => {
                tracing::info!("  Warning: no endpoints for oline-b-right-node");
                None
            }
        }
        .unwrap_or_else(|| {
            tracing::info!("  Warning: could not fetch right-tackle peer ID.");
            String::new()
        });

        tracing::info!("    left_tackle:  {}", left_tackle_peer);
        tracing::info!("    right_tackle: {}", right_tackle_peer);

        // ── Phase C: Left & Right Forwards ──
        tracing::info!("\n── Phase 3: Deploy Left & Right Forwards ──");
        if !prompt_continue(&mut lines, "Deploy c.left-and-right-forwards.yml?")? {
            tracing::info!("Aborted.");
            return Ok(());
        }

        let c_vars = build_phase_c_vars(
            &seed_peer,
            &seed_2_peer,
            &snapshot_peer,
            &snapshot_2_peer,
            &left_tackle_peer,
            &right_tackle_peer,
            &self.defaults,
        );
        let c_defaults = HashMap::new();

        tracing::info!("  Variables:");
        for (k, v) in &c_vars {
            tracing::info!("    {}={}", k, redact_if_secret(k, v, &self.defaults));
        }

        let sdl_c = self.defaults.load_sdl("c.left-and-right-forwards.yml")?;
        tracing::info!("  Deploying...");
        let (c_state, _c_endpoints) = self
            .deploy_phase_with_selection(&sdl_c, c_vars, c_defaults, "oline-phase-c", &mut lines)
            .await?;

        tracing::info!("  Deployed! DSEQ: {}", c_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&c_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        tracing::info!("\n=== All deployments complete! ===");
        tracing::info!("  Phase A1 DSEQ: {}", a_state.dseq.unwrap_or(0));
        tracing::info!("  Phase A2 DSEQ: {}", a2_state.dseq.unwrap_or(0));
        tracing::info!("  Phase B  DSEQ: {}", b_state.dseq.unwrap_or(0));
        tracing::info!("  Phase C  DSEQ: {}", c_state.dseq.unwrap_or(0));
        Ok(())
    }
}

// ── Secret redaction ──
fn redact_if_secret(key: &str, value: &str, defaults: &RuntimeDefaults) -> String {
    if defaults.is_secret(key) {
        if value.len() <= 4 {
            "****".to_string()
        } else {
            format!("{}...{}", &value[..2], &value[value.len() - 2..])
        }
    } else {
        value.to_string()
    }
}

// ── Interactive helpers ──
fn prompt_continue(
    lines: &mut io::Lines<io::StdinLock<'_>>,
    question: &str,
) -> Result<bool, io::Error> {
    print!("  {} [Y/n]: ", question);
    io::stdout().flush()?;
    let answer = lines.next().unwrap_or(Ok(String::new()))?;
    let answer = answer.trim().to_lowercase();
    Ok(answer.is_empty() || answer == "y" || answer == "yes")
}

fn read_input(
    lines: &mut io::Lines<io::StdinLock<'_>>,
    prompt: &str,
    default: Option<&str>,
) -> Result<String, io::Error> {
    if let Some(def) = default {
        // Show default as a dim placeholder on the input line
        tracing::info!("  {}", prompt);
        print!("  \x1b[2m{}\x1b[0m > ", def);
    } else {
        print!("  {}: ", prompt);
    }
    io::stdout().flush()?;
    let input = lines.next().unwrap_or(Ok(String::new()))?;
    let input = input.trim().to_string();
    if input.is_empty() {
        if let Some(def) = default {
            return Ok(def.to_string());
        }
    }
    Ok(input)
}

/// Like `read_input` but hides the typed value (for secrets).
fn read_secret_input(prompt: &str, default: Option<&str>) -> Result<String, Box<dyn Error>> {
    let display = if let Some(def) = default {
        // Show prompt, then placeholder hint (rpassword hides typed input)
        tracing::info!("  {}", prompt);
        format!("  \x1b[2m{}\x1b[0m > ", def)
    } else {
        format!("  {}: ", prompt)
    };
    let input = rpassword::prompt_password(&display)?;
    let input = input.trim().to_string();
    if input.is_empty() {
        if let Some(def) = default {
            return Ok(def.to_string());
        }
    }
    Ok(input)
}

// ── Subcommand: encrypt ──

fn cmd_encrypt(defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Encrypt Mnemonic ===\n");

    let mnemonic = rpassword::prompt_password("Enter mnemonic: ")?;
    if mnemonic.trim().is_empty() {
        return Err("Mnemonic cannot be empty.".into());
    }

    let password = rpassword::prompt_password("Enter password: ")?;
    if password.is_empty() {
        return Err("Password cannot be empty.".into());
    }

    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        return Err("Passwords do not match.".into());
    }

    let blob = encrypt_mnemonic(mnemonic.trim(), &password)?;
    write_encrypted_mnemonic_to_env(&defaults.env_key, &blob)?;

    tracing::info!("\nEncrypted mnemonic written to .env");
    tracing::info!("You can now run `oline deploy` to deploy using your encrypted mnemonic.");
    Ok(())
}

// ── Unlock mnemonic helper ──

fn unlock_mnemonic(defaults: &RuntimeDefaults) -> Result<(String, String), Box<dyn Error>> {
    let blob = read_encrypted_mnemonic_from_env(&defaults.env_key)?;
    let password = rpassword::prompt_password("Enter password: ")?;
    let mnemonic = decrypt_mnemonic(&blob, &password)?;
    tracing::info!("Mnemonic decrypted successfully.\n");
    Ok((mnemonic, password))
}

// ── Config collection ──

async fn collect_config(
    password: &str,
    mnemonic: String,
    lines: &mut io::Lines<io::StdinLock<'_>>,
    defaults: &RuntimeDefaults,
) -> Result<OLineConfig, Box<dyn Error>> {
    // Try to load saved config
    let saved = if has_saved_config() {
        if let Some(cfg) = load_config(password) {
            tracing::info!("  Found saved config:");
            tracing::info!("    RPC endpoint:     {}", cfg.rpc_endpoint);
            tracing::info!("    gRPC endpoint:    {}", cfg.grpc_endpoint);
            tracing::info!("    Snapshot URL:     {}", cfg.snapshot_url);
            tracing::info!(
                "    Validator peer:   {}",
                redact_if_secret(
                    "TERPD_P2P_PRIVATE_PEER_IDS",
                    &cfg.validator_peer_id,
                    defaults
                )
            );
            tracing::info!("    Trusted providers: {:?}", cfg.trusted_providers);
            tracing::info!("    Snapshot path:    {}", cfg.snapshot_path);
            tracing::info!("    MinIO-IPFS image: {}", cfg.minio_ipfs_image);
            tracing::info!("    S3 bucket:        {}", cfg.s3_bucket);
            tracing::info!(
                "    Cloudflare DNS:   {}",
                if cfg.cloudflare_api_token.is_empty() {
                    "not configured"
                } else {
                    "configured"
                }
            );

            if prompt_continue(lines, "Use saved config?")? {
                Some(cfg)
            } else {
                None
            }
        } else {
            tracing::info!("  Saved config found but could not decrypt (wrong password?). Continuing with fresh config.\n");
            None
        }
    } else {
        None
    };
    let d = default_val(
        "OLINE_RPC_ENDPOINT",
        saved.as_ref().map(|s| s.rpc_endpoint.as_str()),
        "https://rpc.akashnet.net:443",
    );
    let rpc_endpoint = read_input(lines, "RPC endpoint", Some(&d))?;

    let d = default_val(
        "OLINE_GRPC_ENDPOINT",
        saved.as_ref().map(|s| s.grpc_endpoint.as_str()),
        "https://grpc.akashnet.net:443",
    );
    let grpc_endpoint = read_input(lines, "gRPC endpoint", Some(&d))?;

    let snapshot_url = {
        let env_url = default_val_opt(
            "OLINE_SNAPSHOT_URL",
            saved.as_ref().map(|s| s.snapshot_url.as_str()),
        );
        if let Some(url) = env_url {
            read_input(lines, "Snapshot URL", Some(&url))?
        } else {
            match fetch_latest_snapshot_url(defaults).await {
                Ok(url) => read_input(lines, "Snapshot URL (fetched from itrocket)", Some(&url))?,
                Err(e) => {
                    tracing::info!("  Warning: failed to fetch snapshot: {}", e);
                    let url = read_input(lines, "Enter snapshot URL manually", None)?;
                    if url.is_empty() {
                        return Err("Snapshot URL is required.".into());
                    }
                    url
                }
            }
        }
    };

    let d = default_val_opt(
        "OLINE_VALIDATOR_PEER_ID",
        saved.as_ref().map(|s| s.validator_peer_id.as_str()),
    );
    let validator_peer_id = read_secret_input("Validator peer ID (id@host:port)", d.as_deref())?;
    if validator_peer_id.is_empty() {
        return Err("Validator peer ID is required.".into());
    }

    let d = default_val(
        "OLINE_TRUSTED_PROVIDERS",
        saved
            .as_ref()
            .map(|s| s.trusted_providers.join(","))
            .as_deref(),
        "",
    );
    let providers_input = read_input(
        lines,
        "Trusted provider addresses (comma-separated, or empty)",
        Some(&d),
    )?;
    let trusted_providers: Vec<String> = if providers_input.is_empty() {
        vec![]
    } else {
        providers_input
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    };

    let auto_default = if saved
        .as_ref()
        .map(|s| s.auto_select_provider)
        .unwrap_or(false)
    {
        "n"
    } else {
        "n"
    };
    let d = default_val("OLINE_AUTO_SELECT_PROVIDER", None, auto_default);
    let auto_select = read_input(lines, "Auto-select cheapest provider? (y/n)", Some(&d))?;
    let auto_select_provider = auto_select.is_empty() || auto_select == "y" || auto_select == "yes";

    // Snapshot export config (credentials auto-generated per deployment)
    tracing::info!("\n── Snapshot Export ──");
    tracing::info!("  Note: S3/MinIO credentials are auto-generated per deployment.");

    let d = default_val(
        "OLINE_SNAPSHOT_PATH",
        saved.as_ref().map(|s| s.snapshot_path.as_str()),
        "snapshots/terpnetwork",
    );
    let snapshot_path = read_input(lines, "S3 snapshot path (bucket/path)", Some(&d))?;

    let d = default_val(
        "OLINE_SNAPSHOT_TIME",
        saved.as_ref().map(|s| s.snapshot_time.as_str()),
        "00:00:00",
    );
    let snapshot_time = read_input(lines, "Snapshot schedule time (HH:MM:SS)", Some(&d))?;

    let d = default_val(
        "OLINE_SNAPSHOT_SAVE_FORMAT",
        saved.as_ref().map(|s| s.snapshot_save_format.as_str()),
        "tar.gz",
    );
    let snapshot_save_format = read_input(lines, "Snapshot save format", Some(&d))?;

    let d = default_val(
        "OLINE_SNAPSHOT_RETAIN",
        saved.as_ref().map(|s| s.snapshot_retain.as_str()),
        "2 days",
    );
    let snapshot_retain = read_input(lines, "Snapshot retention period", Some(&d))?;

    let d = default_val(
        "OLINE_SNAPSHOT_KEEP_LAST",
        saved.as_ref().map(|s| s.snapshot_keep_last.as_str()),
        "2",
    );
    let snapshot_keep_last = read_input(lines, "Minimum snapshots to keep", Some(&d))?;

    let d = default_val("TLS_CONFIG_URL", None, "");
    let tls_config_url = read_input(lines, "TLS setup command", Some(&d))?;

    let d = default_val("ENTRYPOINT_URL", None, "");
    let entrypoint_url = read_input(lines, "entrypoint url", Some(&d))?;

    // MinIO-IPFS config
    tracing::info!("\n── MinIO-IPFS ──");

    let d = default_val(
        "OLINE_MINIO_IPFS_IMAGE",
        saved.as_ref().map(|s| s.minio_ipfs_image.as_str()),
        &defaults.minio_ipfs_image,
    );
    let minio_ipfs_image = read_input(lines, "MinIO-IPFS image", Some(&d))?;

    let d = default_val(
        "OLINE_S3_BUCKET",
        saved.as_ref().map(|s| s.s3_bucket.as_str()),
        "terp-snapshots",
    );
    let s3_bucket = read_input(lines, "S3 bucket name", Some(&d))?;

    let d = default_val(
        "OLINE_AUTOPIN_INTERVAL",
        saved.as_ref().map(|s| s.autopin_interval.as_str()),
        "300",
    );
    let autopin_interval = read_input(lines, "IPFS auto-pin interval (seconds)", Some(&d))?;

    let d = default_val(
        "OLINE_SNAPSHOT_DOWNLOAD_DOMAIN",
        saved.as_ref().map(|s| s.snapshot_download_domain.as_str()),
        "snapshots.terp.network",
    );
    let snapshot_download_domain =
        read_input(lines, "Snapshot download domain (public S3 API)", Some(&d))?;

    let d = default_val(
        "OLINE_CERTBOT_EMAIL",
        saved.as_ref().map(|s| s.certbot_email.as_str()),
        "admin@terp.network",
    );
    let certbot_email = read_input(
        lines,
        "Certbot email (Let's Encrypt registration for nginx-snapshot)",
        Some(&d),
    )?;

    // Cloudflare DNS (optional — auto-update CNAME after deploy)
    tracing::info!("\n── Cloudflare DNS (optional) ──");
    tracing::info!("  Set these to auto-update CNAME records after deployment.");
    tracing::info!("  Leave empty to skip automatic DNS updates.\n");

    let d = default_val_opt(
        "OLINE_CF_API_TOKEN",
        saved
            .as_ref()
            .map(|s| s.cloudflare_api_token.as_str())
            .filter(|s| !s.is_empty()),
    );
    let cloudflare_api_token =
        read_secret_input("Cloudflare API token (DNS:Edit permission)", d.as_deref())?;

    let d = default_val_opt(
        "OLINE_CF_ZONE_ID",
        saved
            .as_ref()
            .map(|s| s.cloudflare_zone_id.as_str())
            .filter(|s| !s.is_empty()),
    );
    let cloudflare_zone_id = read_input(lines, "Cloudflare zone ID", d.as_deref())?;

    let config = OLineConfig {
        mnemonic,
        rpc_endpoint,
        grpc_endpoint,
        snapshot_url,
        validator_peer_id,
        trusted_providers,
        auto_select_provider,
        snapshot_path,
        snapshot_time,
        snapshot_save_format,
        snapshot_retain,
        snapshot_keep_last,
        minio_ipfs_image,
        s3_bucket,
        autopin_interval,
        snapshot_download_domain,
        certbot_email,
        cloudflare_api_token,
        cloudflare_zone_id,
        tls_config_url,
        entrypoint_url,
    };

    // Offer to save
    if prompt_continue(lines, "Save config for next time?")? {
        if let Err(e) = save_config(&config, password) {
            tracing::info!("  Warning: failed to save config: {}", e);
        } else {
            tracing::info!("  Config saved to {}", config_path().display());
        }
    }

    Ok(config)
}

// ── Subcommand: deploy ──

async fn cmd_deploy(raw: bool, defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Welcome to O-Line Deployer ===\n");

    let (mnemonic, password) = if raw {
        let m = rpassword::prompt_password("Enter mnemonic: ")?;
        if m.trim().is_empty() {
            return Err("Mnemonic cannot be empty.".into());
        }
        let password = rpassword::prompt_password("Enter a password (for config encryption): ")?;
        (m.trim().to_string(), password)
    } else {
        unlock_mnemonic(defaults)?
    };

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let config = collect_config(&password, mnemonic, &mut lines, defaults).await?;

    // Drop the stdin lock before OLineDeployer::run() re-acquires it
    drop(lines);

    let mut deployer = OLineDeployer::new(config, password, defaults.clone()).await?;
    deployer.run().await
}

// ── Subcommand: generate-sdl ──

async fn cmd_generate_sdl(defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Generate SDL ===\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    tracing::info!("  Select phase to render:");
    tracing::info!("    a  - Phase A: Kickoff Special Teams (snapshot + seed)");
    tracing::info!("    a2 - Phase A2: Backup Kickoff");
    tracing::info!("    b  - Phase B: Left & Right Tackles");
    tracing::info!("    c  - Phase C: Left & Right Forwards");
    tracing::info!("    all - All phases");
    let phase = read_input(&mut lines, "Phase", Some("all"))?;

    // Load config (optionally from saved)
    let config = if has_saved_config() {
        tracing::info!("\n  Found saved config.");
        let password = rpassword::prompt_password(
            "Enter password to decrypt config (or press Enter to skip): ",
        )?;
        if password.is_empty() {
            None
        } else {
            load_config(&password)
        }
    } else {
        None
    };

    // Build a minimal OLineConfig for variable generation
    let config = if let Some(saved) = config {
        tracing::info!("  Using saved config.\n");
        saved
    } else {
        tracing::info!("  No saved config loaded. Prompting for values.\n");

        let snapshot_url = {
            let env_url = default_val_opt("OLINE_SNAPSHOT_URL", None);
            if let Some(url) = env_url {
                read_input(&mut lines, "Snapshot URL", Some(&url))?
            } else {
                match fetch_latest_snapshot_url(defaults).await {
                    Ok(url) => read_input(&mut lines, "Snapshot URL", Some(&url))?,
                    Err(_) => read_input(&mut lines, "Snapshot URL", None)?,
                }
            }
        };

        let d = default_val("OLINE_VALIDATOR_PEER_ID", None, "<VALIDATOR_PEER_ID>");
        let validator_peer_id = read_input(
            &mut lines,
            "Validator peer ID (or press Enter for placeholder)",
            Some(&d),
        )?;

        tracing::info!("  Note: S3/MinIO credentials are auto-generated per deployment.\n");
        let d = default_val("OLINE_SNAPSHOT_PATH", None, "snapshots/terpnetwork");
        let snapshot_path = read_input(&mut lines, "S3 snapshot path", Some(&d))?;

        let d = default_val("OLINE_SNAPSHOT_TIME", None, "00:00:00");
        let snapshot_time = read_input(&mut lines, "Snapshot schedule time", Some(&d))?;

        let d = default_val("OLINE_SNAPSHOT_SAVE_FORMAT", None, "tar.gz");
        let snapshot_save_format = read_input(&mut lines, "Snapshot save format", Some(&d))?;

        let d = default_val("OLINE_SNAPSHOT_RETAIN", None, "2 days");
        let snapshot_retain = read_input(&mut lines, "Snapshot retention period", Some(&d))?;

        let d = default_val("OLINE_SNAPSHOT_KEEP_LAST", None, "2");
        let snapshot_keep_last = read_input(&mut lines, "Minimum snapshots to keep", Some(&d))?;

        let d = default_val("OLINE_MINIO_IPFS_IMAGE", None, &defaults.minio_ipfs_image);
        let minio_ipfs_image = read_input(&mut lines, "MinIO-IPFS image", Some(&d))?;

        let d = default_val("OLINE_S3_BUCKET", None, "terp-snapshots");
        let s3_bucket = read_input(&mut lines, "S3 bucket name", Some(&d))?;

        let d = default_val("OLINE_AUTOPIN_INTERVAL", None, "300");
        let autopin_interval =
            read_input(&mut lines, "IPFS auto-pin interval (seconds)", Some(&d))?;

        let d = default_val(
            "OLINE_SNAPSHOT_DOWNLOAD_DOMAIN",
            None,
            "snapshots.terp.network",
        );
        let snapshot_download_domain = read_input(
            &mut lines,
            "Snapshot download domain (public S3 API)",
            Some(&d),
        )?;

        let d = default_val("OLINE_CERTBOT_EMAIL", None, "admin@terp.network");
        let certbot_email = read_input(&mut lines, "Certbot email (Let's Encrypt)", Some(&d))?;

        let d = default_val_opt("OLINE_CF_API_TOKEN", None);
        let cloudflare_api_token = if let Some(tok) = d {
            tok
        } else {
            read_input(
                &mut lines,
                "Cloudflare API token (optional, press Enter to skip)",
                Some(""),
            )?
        };

        let d = default_val_opt("OLINE_CF_ZONE_ID", None);
        let cloudflare_zone_id = if let Some(zid) = d {
            zid
        } else {
            read_input(
                &mut lines,
                "Cloudflare zone ID (optional, press Enter to skip)",
                Some(""),
            )?
        };

        let d = default_val("TLS_CONFIG_URL", None, "2");
        let tls_config_url = read_input(&mut lines, "TLS setup command", Some(&d))?;
        let d = default_val("ENTRYPOINT_URL", None, "2");
        let entrypoint_url = read_input(&mut lines, "TLS setup command", Some(&d))?;

        OLineConfig {
            mnemonic: String::new(),
            rpc_endpoint: String::new(),
            grpc_endpoint: String::new(),
            snapshot_url,
            validator_peer_id,
            trusted_providers: vec![],
            auto_select_provider: true,
            snapshot_path,
            snapshot_time,
            snapshot_save_format,
            snapshot_retain,
            snapshot_keep_last,
            minio_ipfs_image,
            s3_bucket,
            autopin_interval,
            snapshot_download_domain,
            certbot_email,
            cloudflare_api_token,
            cloudflare_zone_id,
            tls_config_url,
            entrypoint_url,
        }
    };

    // For phases B/C, prompt for peer IDs or use placeholders
    let needs_peers = matches!(phase.as_str(), "b" | "c" | "all");
    let (snapshot_peer, snapshot_2_peer, seed_peer, seed_2_peer) = if needs_peers {
        let sp = read_input(
            &mut lines,
            "Snapshot peer 1 (id@host:port)",
            Some("<SNAPSHOT_PEER_1>"),
        )?;
        let sp2 = read_input(
            &mut lines,
            "Snapshot peer 2 (id@host:port)",
            Some("<SNAPSHOT_PEER_2>"),
        )?;
        let sd = read_input(
            &mut lines,
            "Seed peer 1 (id@host:port)",
            Some("<SEED_PEER_1>"),
        )?;
        let sd2 = read_input(
            &mut lines,
            "Seed peer 2 (id@host:port)",
            Some("<SEED_PEER_2>"),
        )?;
        (sp, sp2, sd, sd2)
    } else {
        (String::new(), String::new(), String::new(), String::new())
    };

    // Phase B snapshot URL and statesync RPC (prompt operator — they know these after Phase A).
    let (b_snapshot_url, b_statesync_rpc) = if needs_peers {
        let snap_url = read_input(
            &mut lines,
            "Snapshot download URL (from metadata or fallback)",
            Some(&format!(
                "https://{}/{}/latest.{}",
                config.snapshot_download_domain,
                config.snapshot_path.trim_matches('/'),
                config.snapshot_save_format
            )),
        )?;
        let statesync_rpc = read_input(
            &mut lines,
            &format!(
                "Statesync RPC servers (e.g. {}:PORT,{}:PORT)",
                SNAPSHOT_RPC_DOMAIN, SEED_RPC_DOMAIN
            ),
            Some(""),
        )?;
        (snap_url, statesync_rpc)
    } else {
        (String::new(), String::new())
    };

    let needs_tackles = matches!(phase.as_str(), "c" | "all");
    let (left_tackle_peer, right_tackle_peer) = if needs_tackles {
        let lt = read_input(
            &mut lines,
            "Left tackle peer (id@host:port)",
            Some("<LEFT_TACKLE_PEER>"),
        )?;
        let rt = read_input(
            &mut lines,
            "Right tackle peer (id@host:port)",
            Some("<RIGHT_TACKLE_PEER>"),
        )?;
        (lt, rt)
    } else {
        (String::new(), String::new())
    };

    let template_defaults = HashMap::new();

    let sdl_a = defaults.load_sdl("a.kickoff-special-teams.yml")?;
    let sdl_b = defaults.load_sdl("b.left-and-right-tackle.yml")?;
    let sdl_c = defaults.load_sdl("c.left-and-right-forwards.yml")?;

    let render = |label: &str,
                  template: &str,
                  vars: &HashMap<String, String>|
     -> Result<(), Box<dyn Error>> {
        tracing::info!("\n── {} ──", label);
        let rendered = substitute_template_raw(template, vars, &template_defaults)?;
        tracing::info!("{}", rendered);
        Ok(())
    };

    match phase.as_str() {
        "a" => {
            let vars = build_phase_a_vars(&config, defaults);
            render("Phase A: Kickoff Special Teams", &sdl_a, &vars)?;
        }
        "a2" => {
            let vars = build_phase_a2_vars(&config, defaults);
            render("Phase A2: Backup Kickoff", &sdl_a, &vars)?;
        }
        "b" => {
            let vars = build_phase_b_vars(
                &config,
                &snapshot_peer,
                &snapshot_2_peer,
                &b_snapshot_url,
                &b_statesync_rpc,
                defaults,
            );
            render("Phase B: Left & Right Tackles", &sdl_b, &vars)?;
        }
        "c" => {
            let vars = build_phase_c_vars(
                &seed_peer,
                &seed_2_peer,
                &snapshot_peer,
                &snapshot_2_peer,
                &left_tackle_peer,
                &right_tackle_peer,
                defaults,
            );
            render("Phase C: Left & Right Forwards", &sdl_c, &vars)?;
        }
        "all" => {
            let a_vars = build_phase_a_vars(&config, defaults);
            render("Phase A: Kickoff Special Teams", &sdl_a, &a_vars)?;

            let a2_vars = build_phase_a2_vars(&config, defaults);
            render("Phase A2: Backup Kickoff", &sdl_a, &a2_vars)?;

            let b_vars = build_phase_b_vars(
                &config,
                &snapshot_peer,
                &snapshot_2_peer,
                &b_snapshot_url,
                &b_statesync_rpc,
                defaults,
            );
            render("Phase B: Left & Right Tackles", &sdl_b, &b_vars)?;

            let c_vars = build_phase_c_vars(
                &seed_peer,
                &seed_2_peer,
                &snapshot_peer,
                &snapshot_2_peer,
                &left_tackle_peer,
                &right_tackle_peer,
                defaults,
            );
            render("Phase C: Left & Right Forwards", &sdl_c, &c_vars)?;
        }
        _ => {
            tracing::info!("Unknown phase: {}. Choose a, a2, b, c, or all.", phase);
        }
    }

    Ok(())
}

// ── Subcommand: manage ──

async fn cmd_manage_deployments(defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Manage Deployments ===\n");

    let mut store = FileDeploymentStore::new_default().await?;
    let records = store.list().await?;

    if records.is_empty() {
        tracing::info!("  No deployments found.");
        return Ok(());
    }

    tracing::info!(
        "  {:<6} {:<20} {:<18} {:<20} {:<20}",
        "DSEQ",
        "Label",
        "Step",
        "Provider",
        "Created"
    );
    tracing::info!("  {:-<90}", "");

    for r in &records {
        let provider = r
            .selected_provider
            .as_deref()
            .map(|p| {
                if p.len() > 18 {
                    format!("{}..{}", &p[..8], &p[p.len() - 4..])
                } else {
                    p.to_string()
                }
            })
            .unwrap_or_else(|| "-".into());

        let created = chrono_format_timestamp(r.created_at);

        tracing::info!(
            "  {:<6} {:<20} {:<18} {:<20} {:<20}",
            r.dseq,
            truncate(&r.label, 20),
            r.step.name(),
            provider,
            created,
        );
    }

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let dseq_str = read_input(&mut lines, "Enter DSEQ to manage (or 'q' to quit)", None)?;
    if dseq_str == "q" || dseq_str.is_empty() {
        return Ok(());
    }

    let dseq: u64 = dseq_str.parse().map_err(|_| "Invalid DSEQ number")?;

    let record = records.iter().find(|r| r.dseq == dseq);
    if record.is_none() {
        tracing::info!("  No record found for DSEQ {}", dseq);
        return Ok(());
    }

    tracing::info!("\n  Actions:");
    tracing::info!("    1. Close deployment");
    tracing::info!("    2. View record (JSON)");
    tracing::info!("    3. Update SDL (not yet implemented)");

    let action = read_input(&mut lines, "Select action", None)?;

    match action.as_str() {
        "1" => {
            if !prompt_continue(&mut lines, &format!("Close deployment DSEQ {}?", dseq))? {
                tracing::info!("  Cancelled.");
                return Ok(());
            }

            let (mnemonic, _password) = unlock_mnemonic(defaults)?;

            // Load saved config for RPC/gRPC endpoints
            let (rpc, grpc) = if has_saved_config() {
                let pw = rpassword::prompt_password("Enter config password: ")?;
                if let Some(cfg) = load_config(&pw) {
                    (cfg.rpc_endpoint, cfg.grpc_endpoint)
                } else {
                    let rpc = read_input(
                        &mut lines,
                        "RPC endpoint",
                        Some("https://rpc.akashnet.net:443"),
                    )?;
                    let grpc = read_input(
                        &mut lines,
                        "gRPC endpoint",
                        Some("https://grpc.akashnet.net:443"),
                    )?;
                    (rpc, grpc)
                }
            } else {
                let rpc = read_input(
                    &mut lines,
                    "RPC endpoint",
                    Some("https://rpc.akashnet.net:443"),
                )?;
                let grpc = read_input(
                    &mut lines,
                    "gRPC endpoint",
                    Some("https://grpc.akashnet.net:443"),
                )?;
                (rpc, grpc)
            };

            let client = AkashClient::new_from_mnemonic(&mnemonic, &rpc, &grpc).await?;
            let signer = KeySigner::new_mnemonic_str(&mnemonic, None)
                .map_err(|e| format!("Failed to create signer: {}", e))?;

            tracing::info!("  Closing deployment DSEQ {}...", dseq);
            let result = client
                .broadcast_close_deployment(&signer, &client.address(), dseq)
                .await?;

            tracing::info!("  Closed! TX hash: {}", result.hash);

            store.delete(dseq).await?;
            tracing::info!("  Record removed from store.");
        }
        "2" => {
            let json = serde_json::to_string_pretty(record.unwrap())?;
            tracing::info!("\n{}", json);
        }
        "3" => {
            tracing::info!("  Update SDL is not yet implemented.");
        }
        _ => {
            tracing::info!("  Unknown action.");
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}

fn chrono_format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "-".to_string();
    }
    // Simple UTC timestamp formatting without chrono dependency
    let secs = ts;
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let mins = (rem % 3600) / 60;

    // Rough date from epoch (good enough for display)
    // 1970-01-01 + days
    let (year, month, day) = days_to_date(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}Z",
        year, month, day, hours, mins
    )
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Simple Gregorian calendar conversion from days since epoch
    let mut y = 1970;
    let mut remaining = days;

    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }

    let month_days: [u64; 12] = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md {
            m = i;
            break;
        }
        remaining -= md;
    }

    (y, (m + 1) as u64, remaining + 1)
}

fn is_leap_year(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

// ── S3 AWS Signature V4 ──

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hex::encode(hash)
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Sign an S3 request using AWS Signature V4 (path-style).
/// Returns the Authorization header value and headers to add.
fn s3_signed_headers(
    method: &str,
    url: &reqwest::Url,
    payload: &[u8],
    access_key: &str,
    secret_key: &str,
    region: &str,
) -> Vec<(String, String)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Format timestamps (manual — no chrono dependency)
    let (year, month, day) = days_to_date(now / 86400);
    let rem = now % 86400;
    let hours = rem / 3600;
    let mins = (rem % 3600) / 60;
    let secs = rem % 60;

    let date_stamp = format!("{:04}{:02}{:02}", year, month, day);
    let amz_date = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        year, month, day, hours, mins, secs
    );

    let host = match url.port() {
        Some(port) => format!("{}:{}", url.host_str().unwrap_or(""), port),
        None => url.host_str().unwrap_or("").to_string(),
    };
    let path = url.path();
    let query = url.query().unwrap_or("");
    let payload_hash = sha256_hex(payload);

    // Canonical headers (sorted by key, lowercase)
    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host, payload_hash, amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    // Canonical request
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, query, canonical_headers, signed_headers, payload_hash
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        sha256_hex(canonical_request.as_bytes())
    );

    // Signing key
    let k_date = hmac_sha256(
        format!("AWS4{}", secret_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, scope, signed_headers, signature
    );

    vec![
        ("Authorization".into(), auth),
        ("x-amz-date".into(), amz_date),
        ("x-amz-content-sha256".into(), payload_hash),
    ]
}

async fn s3_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    payload: &[u8],
    access_key: &str,
    secret_key: &str,
    region: &str,
) -> Result<reqwest::Response, Box<dyn Error>> {
    let parsed_url = reqwest::Url::parse(url)?;
    let headers = s3_signed_headers(
        method.as_str(),
        &parsed_url,
        payload,
        access_key,
        secret_key,
        region,
    );

    let mut req = client.request(method, parsed_url);
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if !payload.is_empty() {
        req = req.body(payload.to_vec());
    }
    Ok(req.send().await?)
}

// ── Subcommand: test-s3 ──

async fn cmd_test_s3(defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== S3 Connection Test ===\n");

    tracing::info!("  Note: S3/MinIO credentials are auto-generated per deployment.");
    tracing::info!("  Enter the credentials from your running MinIO instance to test.\n");

    // Check for env vars first (enables non-interactive / CI usage)
    let (s3_key, s3_secret, s3_host, snapshot_path) = match (
        std::env::var("S3_KEY"),
        std::env::var("S3_SECRET"),
        std::env::var("S3_HOST"),
        std::env::var("SNAPSHOT_PATH"),
    ) {
        (Ok(k), Ok(s), Ok(h), Ok(p))
            if !k.is_empty() && !s.is_empty() && !h.is_empty() && !p.is_empty() =>
        {
            tracing::info!("  Using credentials from environment variables.\n");
            (k, s, h, p)
        }
        _ => {
            let stdin = io::stdin();
            let mut lines = stdin.lock().lines();
            prompt_s3_creds(&mut lines)?
        }
    };

    // Parse bucket and prefix from snapshot_path (e.g. "snapshots/terpnetwork")
    let (bucket_name, prefix) = match snapshot_path.split_once('/') {
        Some((b, p)) => (b.to_string(), format!("{}/", p)),
        None => (snapshot_path.clone(), String::new()),
    };

    tracing::info!("  S3 host:    {}", s3_host);
    tracing::info!("  Bucket:     {}", bucket_name);
    tracing::info!(
        "  Prefix:     {}",
        if prefix.is_empty() { "(root)" } else { &prefix }
    );
    tracing::info!(
        "  Access key: {}",
        redact_if_secret("S3_KEY", &s3_key, defaults)
    );

    let client = reqwest::Client::new();
    let region = "us-east-1";
    let base = format!("{}/{}", s3_host, bucket_name);
    let mut rw_ok = true;
    let mut list_ok = true;

    // Test 1: List objects (GET /?prefix=...&max-keys=5)
    print!("  [1/4] List objects in bucket... ");
    io::stdout().flush()?;
    let list_url = format!(
        "{}?list-type=2&prefix={}&max-keys=5",
        base,
        urlencoded(&prefix)
    );
    match s3_request(
        &client,
        reqwest::Method::GET,
        &list_url,
        b"",
        &s3_key,
        &s3_secret,
        region,
    )
    .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.text().await.unwrap_or_default();
                let count = body.matches("<Key>").count();
                tracing::info!("OK (HTTP 200, {} objects listed)", count);
            } else {
                tracing::info!(
                    "SKIPPED (HTTP {} — provider may not support ListObjects)",
                    status
                );
                list_ok = false;
            }
        }
        Err(e) => {
            tracing::info!("SKIPPED: {}", e);
            list_ok = false;
        }
    }

    // Test 2: Put test object
    let test_key = format!("{}.oline-test", prefix);
    let test_data = b"oline s3 connectivity test";
    let put_url = format!("{}/{}", base, test_key);

    print!("  [2/4] Put test object ({})... ", test_key);
    io::stdout().flush()?;
    match s3_request(
        &client,
        reqwest::Method::PUT,
        &put_url,
        test_data,
        &s3_key,
        &s3_secret,
        region,
    )
    .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if (200..300).contains(&status) {
                tracing::info!("OK (HTTP {})", status);
            } else {
                let body = resp.text().await.unwrap_or_default();
                tracing::info!("FAILED (HTTP {})", status);
                if !body.is_empty() {
                    tracing::info!("    Response: {}", &body[..body.len().min(200)]);
                }
                rw_ok = false;
            }
        }
        Err(e) => {
            tracing::info!("FAILED: {}", e);
            rw_ok = false;
        }
    }

    // Test 3: Get test object
    let get_url = format!("{}/{}", base, test_key);
    print!("  [3/4] Get test object... ");
    io::stdout().flush()?;
    match s3_request(
        &client,
        reqwest::Method::GET,
        &get_url,
        b"",
        &s3_key,
        &s3_secret,
        region,
    )
    .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.bytes().await.unwrap_or_default();
                if body.as_ref() == test_data {
                    tracing::info!("OK (data verified)");
                } else {
                    tracing::info!("OK (HTTP 200, content differs — still functional)");
                }
            } else {
                tracing::info!("FAILED (HTTP {})", status);
                rw_ok = false;
            }
        }
        Err(e) => {
            tracing::info!("FAILED: {}", e);
            rw_ok = false;
        }
    }

    // Test 4: Delete test object
    let del_url = format!("{}/{}", base, test_key);
    print!("  [4/4] Delete test object... ");
    io::stdout().flush()?;
    match s3_request(
        &client,
        reqwest::Method::DELETE,
        &del_url,
        b"",
        &s3_key,
        &s3_secret,
        region,
    )
    .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 200 || status == 204 {
                tracing::info!("OK (HTTP {})", status);
            } else {
                tracing::info!(
                    "WARN (HTTP {} — may need manual cleanup of {})",
                    status,
                    test_key
                );
            }
        }
        Err(e) => {
            tracing::info!("WARN: {} — test object may remain at {}", e, test_key);
        }
    }

    if rw_ok && list_ok {
        tracing::info!("All S3 tests passed. Credentials are fully functional.");
    } else if rw_ok {
        tracing::info!("Read/write tests passed. Credentials are functional.");
        tracing::info!("Note: ListObjects not supported by this provider (common with Filebase).");
        tracing::info!("This does not affect O-Line deployments — only PUT/GET/DELETE are used.");
    } else {
        tracing::info!("S3 read/write tests failed. Check credentials and bucket permissions.");
    }
    Ok(())
}

fn urlencoded(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

fn prompt_s3_creds(
    lines: &mut io::Lines<io::StdinLock<'_>>,
) -> Result<(String, String, String, String), Box<dyn Error>> {
    let s3_key = read_secret_input("S3 access key", None)?;
    let s3_secret = read_secret_input("S3 secret key", None)?;
    let s3_host = read_input(lines, "S3 host", Some("https://s3.filebase.com"))?;
    let snapshot_path = read_input(
        lines,
        "S3 snapshot path (bucket/path)",
        Some("snapshots/terpnetwork"),
    )?;
    Ok((s3_key, s3_secret, s3_host, snapshot_path))
}

// ── Main menu ──

async fn cmd_main_menu(defaults: &RuntimeDefaults) -> Result<(), Box<dyn Error>> {
    let store = FileDeploymentStore::new_default().await?;
    let records = store.list().await.unwrap_or_default();
    let has_deployments = !records.is_empty();

    tracing::info!("=== O-Line Deployer ===\n");
    tracing::info!("  1. Deploy (full automated deployment)");
    tracing::info!("  2. Generate SDL (render & print, no broadcast)");
    if has_deployments {
        tracing::info!("  3. Manage Deployments ({} active)", records.len());
    }
    tracing::info!("  4. Test S3 Connection");
    tracing::info!("  5. Encrypt Mnemonic");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let choice = read_input(&mut lines, "\nSelect option", None)?;
    drop(lines);

    match choice.as_str() {
        "1" => cmd_deploy(false, defaults).await,
        "2" => cmd_generate_sdl(defaults).await,
        "3" if has_deployments => cmd_manage_deployments(defaults).await,
        "4" => cmd_test_s3(defaults).await,
        "5" => cmd_encrypt(defaults),
        _ => {
            tracing::info!("Invalid option.");
            Ok(())
        }
    }
}

// ── Main ──

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing subscriber.
    // Control verbosity with RUST_LOG env var:
    //   RUST_LOG=info   — default (deployment steps, tx results)
    //   RUST_LOG=debug  — bid queries, dseq resolution, gRPC details
    //   RUST_LOG=trace  — raw event attributes, full response bodies
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Determine the env key name before loading .env (may come from process env)
    load_dotenv(
        &std::env::var("OLINE_ENV_KEY_NAME").unwrap_or_else(|_| "OLINE_ENCRYPTED_MNEMONIC".into()),
    );

    // Now build runtime defaults (reads env vars, including those just loaded from .env)
    let defaults = RuntimeDefaults::load();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("encrypt") => cmd_encrypt(&defaults),
        Some("deploy") => {
            let raw = args.get(2).map(|s| s.as_str()) == Some("--raw");
            cmd_deploy(raw, &defaults).await
        }
        Some("sdl") | Some("generate-sdl") => cmd_generate_sdl(&defaults).await,
        Some("manage") => cmd_manage_deployments(&defaults).await,
        Some("test-s3") => cmd_test_s3(&defaults).await,
        None => cmd_main_menu(&defaults).await,
        Some(other) => {
            tracing::info!("Unknown command: {}", other);
            tracing::info!("Usage:");
            tracing::info!("  oline                 Interactive main menu");
            tracing::info!("  oline encrypt         Encrypt mnemonic and store in .env");
            tracing::info!("  oline deploy          Deploy using encrypted mnemonic from .env");
            tracing::info!(
                "  oline deploy --raw    Deploy with mnemonic entered directly (hidden)"
            );
            tracing::info!("  oline sdl             Generate SDL templates (render & preview)");
            tracing::info!("  oline manage          Manage active deployments");
            tracing::info!("  oline test-s3         Test S3 bucket connectivity");
            std::process::exit(1);
        }
    }
}
