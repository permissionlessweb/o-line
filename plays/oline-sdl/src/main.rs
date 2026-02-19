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
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

// Embed SDLs at compile time
const SDL_A: &str = include_str!("../sdls/a.kickoff-special-teams.yml");
const SDL_B: &str = include_str!("../sdls/b.left-and-right-tackle.yml");
const SDL_C: &str = include_str!("../sdls/c.left-and-right-forwards.yml");

const ENV_KEY: &str = "OLINE_ENCRYPTED_MNEMONIC";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

// Snapshot & SDL defaults
const ITROCKET_STATE_URL: &str = "https://server-4.itrocket.net/mainnet/terp/.current_state.json";
const ITROCKET_SNAPSHOT_BASE: &str = "https://server-4.itrocket.net/mainnet/terp/";
const DEFAULT_CHAIN_JSON: &str =
    "https://raw.githubusercontent.com/permissionlessweb/chain-registry/refs/heads/terpnetwork%40v5.0.2/terpnetwork/chain.json";
const DEFAULT_ADDRBOOK_URL: &str =
    "https://raw.githubusercontent.com/111STAVR111/props/main/Terp/addrbook.json";
const DEFAULT_OMNIBUS_IMAGE: &str = "ghcr.io/akash-network/cosmos-omnibus:v1.2.37-generic";

// ── Encryption ──

fn encrypt_mnemonic(mnemonic: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut key = [0u8; 32];
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

    let salt = &blob[..SALT_LEN];
    let nonce_bytes = &blob[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &blob[SALT_LEN + NONCE_LEN..];

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

// ── .env file helpers ──

fn read_encrypted_mnemonic_from_env() -> Result<String, Box<dyn Error>> {
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
        if let Some(value) = line.strip_prefix(&format!("{}=", ENV_KEY)) {
            let value = value.trim();
            if !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }

    Err(format!(
        "No {} found in .env file. Run `oline encrypt` first.",
        ENV_KEY
    )
    .into())
}

fn write_encrypted_mnemonic_to_env(blob: &str) -> Result<(), Box<dyn Error>> {
    let env_path = Path::new(".env");
    let entry = format!("{}={}", ENV_KEY, blob);

    if env_path.exists() {
        let contents = fs::read_to_string(env_path)?;
        let mut found = false;
        let mut new_lines: Vec<String> = Vec::new();
        for line in contents.lines() {
            if line.trim().starts_with(&format!("{}=", ENV_KEY)) {
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

#[derive(Serialize, Deserialize, Clone)]
pub struct SavedConfig {
    pub rpc_endpoint: String,
    pub grpc_endpoint: String,
    pub snapshot_url: String,
    pub validator_peer_id: String,
    pub trusted_providers: Vec<String>,
    pub auto_select_provider: bool,
    pub s3_key: String,
    pub s3_secret: String,
    pub s3_host: String,
    pub snapshot_path: String,
    pub snapshot_time: String,
    pub snapshot_save_format: String,
    pub snapshot_metadata_url: String,
    pub snapshot_retain: String,
    pub snapshot_keep_last: String,
}

impl From<&OLineConfig> for SavedConfig {
    fn from(c: &OLineConfig) -> Self {
        Self {
            rpc_endpoint: c.rpc_endpoint.clone(),
            grpc_endpoint: c.grpc_endpoint.clone(),
            snapshot_url: c.snapshot_url.clone(),
            validator_peer_id: c.validator_peer_id.clone(),
            trusted_providers: c.trusted_providers.clone(),
            auto_select_provider: c.auto_select_provider,
            s3_key: c.s3_key.clone(),
            s3_secret: c.s3_secret.clone(),
            s3_host: c.s3_host.clone(),
            snapshot_path: c.snapshot_path.clone(),
            snapshot_time: c.snapshot_time.clone(),
            snapshot_save_format: c.snapshot_save_format.clone(),
            snapshot_metadata_url: c.snapshot_metadata_url.clone(),
            snapshot_retain: c.snapshot_retain.clone(),
            snapshot_keep_last: c.snapshot_keep_last.clone(),
        }
    }
}

impl SavedConfig {
    pub fn to_oline_config(&self, mnemonic: String) -> OLineConfig {
        OLineConfig {
            mnemonic,
            rpc_endpoint: self.rpc_endpoint.clone(),
            grpc_endpoint: self.grpc_endpoint.clone(),
            snapshot_url: self.snapshot_url.clone(),
            validator_peer_id: self.validator_peer_id.clone(),
            trusted_providers: self.trusted_providers.clone(),
            auto_select_provider: self.auto_select_provider,
            s3_key: self.s3_key.clone(),
            s3_secret: self.s3_secret.clone(),
            s3_host: self.s3_host.clone(),
            snapshot_path: self.snapshot_path.clone(),
            snapshot_time: self.snapshot_time.clone(),
            snapshot_save_format: self.snapshot_save_format.clone(),
            snapshot_metadata_url: self.snapshot_metadata_url.clone(),
            snapshot_retain: self.snapshot_retain.clone(),
            snapshot_keep_last: self.snapshot_keep_last.clone(),
        }
    }
}

fn config_path() -> PathBuf {
    let home = dirs::home_dir().expect("Cannot determine home directory");
    home.join(".oline").join("config.enc")
}

fn save_config(config: &SavedConfig, password: &str) -> Result<(), Box<dyn Error>> {
    let json = serde_json::to_string(config)?;
    let encrypted = encrypt_mnemonic(&json, password)?;
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, encrypted)?;
    Ok(())
}

fn load_config(password: &str) -> Option<SavedConfig> {
    let path = config_path();
    let encrypted = fs::read_to_string(&path).ok()?;
    let json = decrypt_mnemonic(encrypted.trim(), password).ok()?;
    serde_json::from_str(&json).ok()
}

fn has_saved_config() -> bool {
    config_path().exists()
}

// ── Snapshot fetching ──

async fn fetch_latest_snapshot_url() -> Result<String, Box<dyn Error>> {
    println!("  Fetching latest snapshot info from itrocket...");
    let resp = reqwest::get(ITROCKET_STATE_URL).await?.text().await?;
    let trimmed = resp.trim();
    let state: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("Failed to parse .current_state.json: {}", e))?;
    let snapshot_name = state["snapshot_name"]
        .as_str()
        .ok_or("missing snapshot_name in .current_state.json")?;
    let url = format!("{}{}", ITROCKET_SNAPSHOT_BASE, snapshot_name);
    println!("  Latest snapshot: {}", url);
    Ok(url)
}

/// Helper to insert the shared SDL template variables into a HashMap.
fn insert_sdl_defaults(vars: &mut HashMap<String, String>) {
    vars.insert("OMNIBUS_IMAGE".into(), DEFAULT_OMNIBUS_IMAGE.into());
    vars.insert("CHAIN_JSON".into(), DEFAULT_CHAIN_JSON.into());
    vars.insert("ADDRBOOK_URL".into(), DEFAULT_ADDRBOOK_URL.into());
}

/// Helper to insert S3 snapshot export variables from config.
fn insert_s3_vars(vars: &mut HashMap<String, String>, config: &OLineConfig) {
    vars.insert("S3_KEY".into(), config.s3_key.clone());
    vars.insert("S3_SECRET".into(), config.s3_secret.clone());
    vars.insert("S3_HOST".into(), config.s3_host.clone());
    vars.insert("SNAPSHOT_PATH".into(), config.snapshot_path.clone());
    vars.insert("SNAPSHOT_TIME".into(), config.snapshot_time.clone());
    vars.insert(
        "SNAPSHOT_SAVE_FORMAT".into(),
        config.snapshot_save_format.clone(),
    );
    vars.insert(
        "SNAPSHOT_METADATA_URL".into(),
        config.snapshot_metadata_url.clone(),
    );
    vars.insert("SNAPSHOT_RETAIN".into(), config.snapshot_retain.clone());
    vars.insert(
        "SNAPSHOT_KEEP_LAST".into(),
        config.snapshot_keep_last.clone(),
    );
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

fn build_phase_a_vars(config: &OLineConfig) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars);
    insert_s3_vars(&mut vars, config);
    vars.insert("SNAPSHOT_SVC".into(), "oline-a-snapshot".into());
    vars.insert("SEED_SVC".into(), "oline-a-seed".into());
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

fn build_phase_a2_vars(config: &OLineConfig) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars);
    insert_s3_vars(&mut vars, config);
    vars.insert("SNAPSHOT_SVC".into(), "oline-a2-snapshot".into());
    vars.insert("SEED_SVC".into(), "oline-a2-seed".into());
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
    vars
}

fn build_phase_b_vars(
    config: &OLineConfig,
    snapshot_peer: &str,
    snapshot_2_peer: &str,
) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars);
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
    vars
}

fn build_phase_c_vars(
    seed_peer: &str,
    seed_2_peer: &str,
    snapshot_peer: &str,
    snapshot_2_peer: &str,
    left_tackle_peer: &str,
    right_tackle_peer: &str,
) -> HashMap<String, String> {
    let tackles_combined = format!("{},{}", left_tackle_peer, right_tackle_peer);
    let mut vars = HashMap::new();
    insert_sdl_defaults(&mut vars);
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

pub struct OLineConfig {
    pub mnemonic: String,
    pub rpc_endpoint: String,
    pub grpc_endpoint: String,
    pub snapshot_url: String,
    pub validator_peer_id: String,
    pub trusted_providers: Vec<String>,
    pub auto_select_provider: bool,
    // S3 snapshot export
    pub s3_key: String,
    pub s3_secret: String,
    pub s3_host: String,
    pub snapshot_path: String,
    pub snapshot_time: String,
    pub snapshot_save_format: String,
    pub snapshot_metadata_url: String,
    pub snapshot_retain: String,
    pub snapshot_keep_last: String,
}

pub struct OLineDeployer {
    client: AkashClient,
    signer: KeySigner,
    config: OLineConfig,
    password: String,
    deployment_store: FileDeploymentStore,
}

impl OLineDeployer {
    pub async fn new(config: OLineConfig, password: String) -> Result<Self, DeployError> {
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

        loop {
            match workflow.advance(&mut state).await? {
                StepResult::Continue => continue,
                StepResult::Complete => {
                    let endpoints = state.endpoints.clone();
                    return Ok((state, endpoints));
                }
                StepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                    self.present_bids(&bids).await;
                    let choice = Self::prompt_provider_choice(lines, &bids).map_err(|e| {
                        DeployError::InvalidState(format!("Provider selection failed: {}", e))
                    })?;
                    DeploymentWorkflow::<AkashClient>::select_provider(&mut state, &choice)?;
                }
                StepResult::NeedsInput(InputRequired::ProvideSdl) => {
                    return Err(DeployError::InvalidState(
                        "SDL content missing (should never happen)".into(),
                    ));
                }
                StepResult::Failed(reason) => {
                    return Err(DeployError::InvalidState(format!(
                        "Deployment '{}' failed: {}",
                        label, reason
                    )));
                }
            }
        }
    }

    async fn present_bids(&self, bids: &[Bid]) {
        println!("\n  Available Providers:");
        println!("  {:-<100}", "");
        println!(
            "  {:<4} {:<30} {:>12} {:<30} {:<20}",
            "No.", "Name", "Price (AKT)", "Website", "Region"
        );
        println!("  {:-<100}", "");

        for (idx, bid) in bids.iter().enumerate() {
            let akt = bid.price_uakt as f64 / 1_000_000.0;

            let info: Option<ProviderInfo> = self
                .client
                .query_provider_info(&bid.provider)
                .await
                .ok()
                .flatten();

            let name = if let Some(ref info) = info {
                if !info.website.is_empty() {
                    info.website
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .split('/')
                        .next()
                        .unwrap_or(&bid.provider[..12])
                        .to_string()
                } else {
                    format!(
                        "{}..{}",
                        &bid.provider[..8],
                        &bid.provider[bid.provider.len() - 4..]
                    )
                }
            } else {
                format!(
                    "{}..{}",
                    &bid.provider[..8],
                    &bid.provider[bid.provider.len() - 4..]
                )
            };

            let website = info
                .as_ref()
                .map(|i| i.website.as_str())
                .filter(|w: &&str| !w.is_empty())
                .unwrap_or("-");

            let region = info
                .as_ref()
                .and_then(|i: &ProviderInfo| {
                    i.attributes
                        .iter()
                        .find(|(k, _): &&(String, String)| {
                            k == "region" || k == "datacenter" || k == "location"
                        })
                        .map(|(_, v)| v.as_str())
                })
                .unwrap_or("-");

            let display_name = if name.len() > 30 {
                format!("{}...", &name[..27])
            } else {
                name
            };
            let display_website = if website.len() > 30 {
                format!("{}...", &website[..27])
            } else {
                website.to_string()
            };
            let display_region = if region.len() > 20 {
                format!("{}...", &region[..17])
            } else {
                region.to_string()
            };

            println!(
                "  {:<4} {:<30} {:>12.6} {:<30} {:<20}",
                idx + 1,
                display_name,
                akt,
                display_website,
                display_region
            );
        }

        println!("  {:-<100}", "");
    }

    fn prompt_provider_choice(
        lines: &mut io::Lines<io::StdinLock<'_>>,
        bids: &[Bid],
    ) -> Result<String, Box<dyn Error>> {
        loop {
            print!(
                "  Select provider (1-{}) or 'a' to auto-select cheapest: ",
                bids.len()
            );
            io::stdout().flush()?;

            let input = lines
                .next()
                .ok_or("EOF while reading provider choice")??
                .trim()
                .to_lowercase();

            if input == "a" || input == "auto" {
                let cheapest = bids.iter().min_by_key(|b| b.price_uakt).unwrap();
                println!("  -> Auto-selected: {}", cheapest.provider);
                return Ok(cheapest.provider.clone());
            }

            if let Ok(choice) = input.parse::<usize>() {
                if choice >= 1 && choice <= bids.len() {
                    println!("  -> Selected: {}", bids[choice - 1].provider);
                    return Ok(bids[choice - 1].provider.clone());
                }
            }

            println!("  Invalid choice. Please enter 1-{} or 'a'.", bids.len());
        }
    }

    pub async fn extract_peer_id(endpoint: &ServiceEndpoint) -> Result<String, Box<dyn Error>> {
        let status_url = format!("http://{}/status", endpoint.uri);
        let resp = reqwest::get(&status_url).await?.text().await?;
        let json: serde_json::Value = serde_json::from_str(&resp)?;

        let node_id = json["result"]["node_info"]["id"]
            .as_str()
            .ok_or("missing node_info.id in /status response")?;

        let host = endpoint.uri.split(':').next().unwrap_or(&endpoint.uri);
        let peer = format!("{}@{}:26656", node_id, host);
        Ok(peer)
    }

    fn find_rpc_endpoint<'a>(
        endpoints: &'a [ServiceEndpoint],
        service_name: &str,
    ) -> Option<&'a ServiceEndpoint> {
        endpoints
            .iter()
            .find(|e| e.service == service_name && e.port == 26657)
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();

        println!("\n=== O-Line Deployer ===");
        println!("Account: {}", self.client.address());

        // ── Phase A: Snapshot + Seed ──
        println!("\n── Phase 1: Deploy Snapshot + Seed nodes ──");
        if !prompt_continue(&mut lines, "Deploy a.kickoff-special-teams.yml?")? {
            println!("Aborted.");
            return Ok(());
        }

        let mut a_vars = HashMap::new();
        insert_sdl_defaults(&mut a_vars);
        insert_s3_vars(&mut a_vars, &self.config);
        a_vars.insert("SNAPSHOT_SVC".into(), "oline-a-snapshot".into());
        a_vars.insert("SEED_SVC".into(), "oline-a-seed".into());
        a_vars.insert(
            "SNAPSHOT_MONIKER".into(),
            "oline::special::snapshot-node".into(),
        );
        a_vars.insert("SEED_MONIKER".into(), "oline::special::seed-node".into());
        a_vars.insert("SNAPSHOT_URL".into(), self.config.snapshot_url.clone());
        a_vars.insert(
            "TERPD_P2P_PRIVATE_PEER_IDS".into(),
            self.config.validator_peer_id.clone(),
        );
        let a_defaults = HashMap::new();

        println!("  Variables:");
        for (k, v) in &a_vars {
            println!("    {}={}", k, redact_if_secret(k, v));
        }

        println!("  Deploying...");
        let (a_state, a_endpoints) = self
            .deploy_phase_with_selection(SDL_A, a_vars, a_defaults, "oline-phase-a", &mut lines)
            .await?;

        println!("  Deployed! DSEQ: {}", a_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&a_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        // Extract peer IDs from phase A
        println!("  Extracting peer IDs...");
        let snapshot_rpc = Self::find_rpc_endpoint(&a_endpoints, "oline-a-snapshot")
            .ok_or("No RPC endpoint found for oline-a-snapshot")?;
        let seed_rpc = Self::find_rpc_endpoint(&a_endpoints, "oline-a-seed")
            .ok_or("No RPC endpoint found for oline-a-seed")?;

        let snapshot_peer = Self::extract_peer_id(snapshot_rpc).await?;
        let seed_peer = Self::extract_peer_id(seed_rpc).await?;

        println!("    snapshot_peer: {}", snapshot_peer);
        println!("    seed_peer: {}", seed_peer);

        // ── Phase A2: Backup Snapshot + Seed (reuses SDL_A with backup service names) ──
        println!("\n── Phase 1b: Deploy Backup Snapshot + Seed nodes ──");
        if !prompt_continue(
            &mut lines,
            "Deploy backup kickoff (a.kickoff-special-teams.yml)?",
        )? {
            println!("Aborted.");
            return Ok(());
        }

        let mut a2_vars = HashMap::new();
        insert_sdl_defaults(&mut a2_vars);
        insert_s3_vars(&mut a2_vars, &self.config);
        a2_vars.insert("SNAPSHOT_SVC".into(), "oline-a2-snapshot".into());
        a2_vars.insert("SEED_SVC".into(), "oline-a2-seed".into());
        a2_vars.insert(
            "SNAPSHOT_MONIKER".into(),
            "oline::backup::snapshot-node".into(),
        );
        a2_vars.insert("SEED_MONIKER".into(), "oline::backup::seed-node".into());
        a2_vars.insert("SNAPSHOT_URL".into(), self.config.snapshot_url.clone());
        a2_vars.insert(
            "TERPD_P2P_PRIVATE_PEER_IDS".into(),
            self.config.validator_peer_id.clone(),
        );
        let a2_defaults = HashMap::new();

        println!("  Variables:");
        for (k, v) in &a2_vars {
            println!("    {}={}", k, redact_if_secret(k, v));
        }

        println!("  Deploying...");
        let (a2_state, a2_endpoints) = self
            .deploy_phase_with_selection(SDL_A, a2_vars, a2_defaults, "oline-phase-a2", &mut lines)
            .await?;

        println!("  Deployed! DSEQ: {}", a2_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&a2_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        // Extract peer IDs from phase A2
        println!("  Extracting peer IDs...");
        let snapshot_2_rpc = Self::find_rpc_endpoint(&a2_endpoints, "oline-a2-snapshot")
            .ok_or("No RPC endpoint found for oline-a2-snapshot")?;
        let seed_2_rpc = Self::find_rpc_endpoint(&a2_endpoints, "oline-a2-seed")
            .ok_or("No RPC endpoint found for oline-a2-seed")?;

        let snapshot_2_peer = Self::extract_peer_id(snapshot_2_rpc).await?;
        let seed_2_peer = Self::extract_peer_id(seed_2_rpc).await?;

        println!("    snapshot_2_peer: {}", snapshot_2_peer);
        println!("    seed_2_peer: {}", seed_2_peer);

        // ── Phase B: Left & Right Tackles ──
        println!("\n── Phase 2: Deploy Left & Right Tackles ──");
        if !prompt_continue(&mut lines, "Deploy b.left-and-right-tackle.yml?")? {
            println!("Aborted.");
            return Ok(());
        }

        let mut b_vars = HashMap::new();
        insert_sdl_defaults(&mut b_vars);
        b_vars.insert(
            "TERPD_P2P_PERSISTENT_PEERS".into(),
            format!("{},{}", snapshot_peer, snapshot_2_peer),
        );
        b_vars.insert(
            "TERPD_P2P_PRIVATE_PEER_IDS".into(),
            self.config.validator_peer_id.clone(),
        );
        b_vars.insert(
            "TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(),
            self.config.validator_peer_id.clone(),
        );
        let b_defaults = HashMap::new();

        println!("  Variables:");
        for (k, v) in &b_vars {
            println!("    {}={}", k, redact_if_secret(k, v));
        }

        println!("  Deploying...");
        let (b_state, b_endpoints) = self
            .deploy_phase_with_selection(SDL_B, b_vars, b_defaults, "oline-phase-b", &mut lines)
            .await?;

        println!("  Deployed! DSEQ: {}", b_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&b_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        // Extract peer IDs from phase B
        println!("  Extracting peer IDs...");
        let left_rpc = Self::find_rpc_endpoint(&b_endpoints, "oline-b-left-node")
            .ok_or("No RPC endpoint found for oline-b-left-node")?;
        let right_rpc = Self::find_rpc_endpoint(&b_endpoints, "oline-b-right-node")
            .ok_or("No RPC endpoint found for oline-b-right-node")?;

        let left_tackle_peer = Self::extract_peer_id(left_rpc).await?;
        let right_tackle_peer = Self::extract_peer_id(right_rpc).await?;

        println!("    left_tackle: {}", left_tackle_peer);
        println!("    right_tackle: {}", right_tackle_peer);

        // ── Phase C: Left & Right Forwards ──
        println!("\n── Phase 3: Deploy Left & Right Forwards ──");
        if !prompt_continue(&mut lines, "Deploy c.left-and-right-forwards.yml?")? {
            println!("Aborted.");
            return Ok(());
        }

        let tackles_combined = format!("{},{}", left_tackle_peer, right_tackle_peer);
        let mut c_vars = HashMap::new();
        insert_sdl_defaults(&mut c_vars);
        c_vars.insert(
            "TERPD_P2P_SEEDS".into(),
            format!("{},{}", seed_peer, seed_2_peer),
        );
        c_vars.insert(
            "TERPD_P2P_PRIVATE_PEER_IDS".into(),
            tackles_combined.clone(),
        );
        c_vars.insert("TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(), tackles_combined);
        c_vars.insert(
            "TERPD_P2P_PERSISTENT_PEERS".into(),
            format!("{},{}", snapshot_peer, snapshot_2_peer),
        );
        let c_defaults = HashMap::new();

        println!("  Variables:");
        for (k, v) in &c_vars {
            println!("    {}={}", k, redact_if_secret(k, v));
        }

        println!("  Deploying...");
        let (c_state, _c_endpoints) = self
            .deploy_phase_with_selection(SDL_C, c_vars, c_defaults, "oline-phase-c", &mut lines)
            .await?;

        println!("  Deployed! DSEQ: {}", c_state.dseq.unwrap_or(0));
        let record = DeploymentRecord::from_state(&c_state, &self.password)?;
        self.deployment_store.save(&record).await.ok();

        println!("\n=== All deployments complete! ===");
        println!("  Phase A1 DSEQ: {}", a_state.dseq.unwrap_or(0));
        println!("  Phase A2 DSEQ: {}", a2_state.dseq.unwrap_or(0));
        println!("  Phase B  DSEQ: {}", b_state.dseq.unwrap_or(0));
        println!("  Phase C  DSEQ: {}", c_state.dseq.unwrap_or(0));
        Ok(())
    }
}

// ── Secret redaction ──

const SECRET_KEYS: &[&str] = &["S3_KEY", "S3_SECRET", "TERPD_P2P_PRIVATE_PEER_IDS"];

fn redact_if_secret(key: &str, value: &str) -> String {
    if SECRET_KEYS.iter().any(|&s| s == key) {
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
        print!("{} [{}]: ", prompt, def);
    } else {
        print!("{}: ", prompt);
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
        format!("{} [{}]: ", prompt, def)
    } else {
        format!("{}: ", prompt)
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

fn cmd_encrypt() -> Result<(), Box<dyn Error>> {
    println!("=== Encrypt Mnemonic ===\n");

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
    write_encrypted_mnemonic_to_env(&blob)?;

    println!("\nEncrypted mnemonic written to .env");
    println!("You can now run `oline deploy` to deploy using your encrypted mnemonic.");
    Ok(())
}

// ── Unlock mnemonic helper ──

fn unlock_mnemonic() -> Result<(String, String), Box<dyn Error>> {
    let blob = read_encrypted_mnemonic_from_env()?;
    let password = rpassword::prompt_password("Enter password: ")?;
    let mnemonic = decrypt_mnemonic(&blob, &password)?;
    println!("Mnemonic decrypted successfully.\n");
    Ok((mnemonic, password))
}

// ── Config collection ──

async fn collect_config(
    password: &str,
    mnemonic: String,
    lines: &mut io::Lines<io::StdinLock<'_>>,
) -> Result<OLineConfig, Box<dyn Error>> {
    // Try to load saved config
    let saved = if has_saved_config() {
        if let Some(cfg) = load_config(password) {
            println!("  Found saved config:");
            println!("    RPC endpoint:     {}", cfg.rpc_endpoint);
            println!("    gRPC endpoint:    {}", cfg.grpc_endpoint);
            println!("    Snapshot URL:     {}", cfg.snapshot_url);
            println!(
                "    Validator peer:   {}",
                redact_if_secret("TERPD_P2P_PRIVATE_PEER_IDS", &cfg.validator_peer_id)
            );
            println!("    Trusted providers: {:?}", cfg.trusted_providers);
            println!(
                "    S3 key:           {}",
                redact_if_secret("S3_KEY", &cfg.s3_key)
            );
            println!("    S3 host:          {}", cfg.s3_host);
            println!("    Snapshot path:    {}", cfg.snapshot_path);
            println!();
            if prompt_continue(lines, "Use saved config?")? {
                Some(cfg)
            } else {
                None
            }
        } else {
            println!("  Saved config found but could not decrypt (wrong password?). Continuing with fresh config.\n");
            None
        }
    } else {
        None
    };

    let rpc_endpoint = read_input(
        lines,
        "Enter RPC endpoint",
        Some(
            saved
                .as_ref()
                .map(|s| s.rpc_endpoint.as_str())
                .unwrap_or("https://rpc.akashnet.net:443"),
        ),
    )?;

    let grpc_endpoint = read_input(
        lines,
        "Enter gRPC endpoint",
        Some(
            saved
                .as_ref()
                .map(|s| s.grpc_endpoint.as_str())
                .unwrap_or("https://grpc.akashnet.net:443"),
        ),
    )?;

    let snapshot_url = if let Some(ref s) = saved {
        read_input(
            lines,
            "Snapshot URL (press Enter to keep saved, or paste override)",
            Some(&s.snapshot_url),
        )?
    } else {
        match fetch_latest_snapshot_url().await {
            Ok(url) => read_input(
                lines,
                "Snapshot URL (press Enter to use fetched URL, or paste override)",
                Some(&url),
            )?,
            Err(e) => {
                eprintln!("  Warning: failed to fetch snapshot: {}", e);
                let url = read_input(lines, "Enter snapshot URL manually", None)?;
                if url.is_empty() {
                    return Err("Snapshot URL is required.".into());
                }
                url
            }
        }
    };

    let validator_peer_id = read_secret_input(
        "Enter validator peer ID (id@host:port)",
        saved.as_ref().map(|s| s.validator_peer_id.as_str()),
    )?;
    if validator_peer_id.is_empty() {
        return Err("Validator peer ID is required.".into());
    }

    let providers_input = read_input(
        lines,
        "Enter trusted provider addresses (comma-separated, or empty for none)",
        Some(
            saved
                .as_ref()
                .map(|s| s.trusted_providers.join(","))
                .unwrap_or_default()
                .as_str(),
        ),
    )?;
    let trusted_providers: Vec<String> = if providers_input.is_empty() {
        vec![]
    } else {
        providers_input
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    };

    let auto_select = read_input(
        lines,
        "Auto-select cheapest provider? (y/n)",
        Some(
            if saved
                .as_ref()
                .map(|s| s.auto_select_provider)
                .unwrap_or(true)
            {
                "y"
            } else {
                "n"
            },
        ),
    )?;
    let auto_select_provider = auto_select.is_empty() || auto_select == "y" || auto_select == "yes";

    // S3 snapshot export config
    println!("\n── S3 Snapshot Export ──");
    let s3_key = read_secret_input("S3 access key", saved.as_ref().map(|s| s.s3_key.as_str()))?;
    let s3_secret = read_secret_input(
        "S3 secret key",
        saved.as_ref().map(|s| s.s3_secret.as_str()),
    )?;
    let s3_host = read_input(
        lines,
        "S3 host",
        Some(
            saved
                .as_ref()
                .map(|s| s.s3_host.as_str())
                .unwrap_or("https://s3.filebase.com"),
        ),
    )?;
    let snapshot_path = read_input(
        lines,
        "S3 snapshot path (bucket/path)",
        Some(
            saved
                .as_ref()
                .map(|s| s.snapshot_path.as_str())
                .unwrap_or("snapshots/terpnetwork"),
        ),
    )?;
    let snapshot_time = read_input(
        lines,
        "Snapshot schedule time (HH:MM:SS)",
        Some(
            saved
                .as_ref()
                .map(|s| s.snapshot_time.as_str())
                .unwrap_or("00:00:00"),
        ),
    )?;
    let snapshot_save_format = read_input(
        lines,
        "Snapshot save format",
        Some(
            saved
                .as_ref()
                .map(|s| s.snapshot_save_format.as_str())
                .unwrap_or("tar.gz"),
        ),
    )?;
    let snapshot_metadata_url = read_input(
        lines,
        "Snapshot metadata URL (where snapshots are served from)",
        saved.as_ref().map(|s| s.snapshot_metadata_url.as_str()),
    )?;
    let snapshot_retain = read_input(
        lines,
        "Snapshot retention period",
        Some(
            saved
                .as_ref()
                .map(|s| s.snapshot_retain.as_str())
                .unwrap_or("2 days"),
        ),
    )?;
    let snapshot_keep_last = read_input(
        lines,
        "Minimum snapshots to keep",
        Some(
            saved
                .as_ref()
                .map(|s| s.snapshot_keep_last.as_str())
                .unwrap_or("2"),
        ),
    )?;

    let config = OLineConfig {
        mnemonic,
        rpc_endpoint,
        grpc_endpoint,
        snapshot_url,
        validator_peer_id,
        trusted_providers,
        auto_select_provider,
        s3_key,
        s3_secret,
        s3_host,
        snapshot_path,
        snapshot_time,
        snapshot_save_format,
        snapshot_metadata_url,
        snapshot_retain,
        snapshot_keep_last,
    };

    // Offer to save
    if prompt_continue(lines, "Save config for next time?")? {
        let saved_cfg = SavedConfig::from(&config);
        if let Err(e) = save_config(&saved_cfg, password) {
            eprintln!("  Warning: failed to save config: {}", e);
        } else {
            println!("  Config saved to {}", config_path().display());
        }
    }

    Ok(config)
}

// ── Subcommand: deploy ──

async fn cmd_deploy(raw: bool) -> Result<(), Box<dyn Error>> {
    println!("=== Welcome to O-Line Deployer ===\n");

    let (mnemonic, password) = if raw {
        let m = rpassword::prompt_password("Enter mnemonic: ")?;
        if m.trim().is_empty() {
            return Err("Mnemonic cannot be empty.".into());
        }
        let password = rpassword::prompt_password("Enter a password (for config encryption): ")?;
        (m.trim().to_string(), password)
    } else {
        unlock_mnemonic()?
    };

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let config = collect_config(&password, mnemonic, &mut lines).await?;

    // Drop the stdin lock before OLineDeployer::run() re-acquires it
    drop(lines);

    let mut deployer = OLineDeployer::new(config, password).await?;
    deployer.run().await
}

// ── Subcommand: generate-sdl ──

async fn cmd_generate_sdl() -> Result<(), Box<dyn Error>> {
    println!("=== Generate SDL ===\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    println!("  Select phase to render:");
    println!("    a  - Phase A: Kickoff Special Teams (snapshot + seed)");
    println!("    a2 - Phase A2: Backup Kickoff");
    println!("    b  - Phase B: Left & Right Tackles");
    println!("    c  - Phase C: Left & Right Forwards");
    println!("    all - All phases");
    let phase = read_input(&mut lines, "Phase", Some("all"))?;

    // Load config (optionally from saved)
    let config = if has_saved_config() {
        println!("\n  Found saved config.");
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
        println!("  Using saved config.\n");
        saved.to_oline_config(String::new()) // mnemonic not needed for SDL generation
    } else {
        println!("  No saved config loaded. Prompting for values.\n");

        let snapshot_url = match fetch_latest_snapshot_url().await {
            Ok(url) => read_input(&mut lines, "Snapshot URL", Some(&url))?,
            Err(_) => read_input(&mut lines, "Snapshot URL", None)?,
        };

        let validator_peer_id = read_input(
            &mut lines,
            "Validator peer ID (or press Enter for placeholder)",
            Some("<VALIDATOR_PEER_ID>"),
        )?;

        let s3_key = read_input(
            &mut lines,
            "S3 access key (or Enter for placeholder)",
            Some("<S3_KEY>"),
        )?;
        let s3_secret = read_input(
            &mut lines,
            "S3 secret key (or Enter for placeholder)",
            Some("<S3_SECRET>"),
        )?;
        let s3_host = read_input(&mut lines, "S3 host", Some("https://s3.filebase.com"))?;
        let snapshot_path = read_input(
            &mut lines,
            "S3 snapshot path",
            Some("snapshots/terpnetwork"),
        )?;
        let snapshot_time = read_input(&mut lines, "Snapshot schedule time", Some("00:00:00"))?;
        let snapshot_save_format = read_input(&mut lines, "Snapshot save format", Some("tar.gz"))?;
        let snapshot_metadata_url = read_input(
            &mut lines,
            "Snapshot metadata URL",
            Some("<SNAPSHOT_METADATA_URL>"),
        )?;
        let snapshot_retain = read_input(&mut lines, "Snapshot retention period", Some("2 days"))?;
        let snapshot_keep_last = read_input(&mut lines, "Minimum snapshots to keep", Some("2"))?;

        OLineConfig {
            mnemonic: String::new(),
            rpc_endpoint: String::new(),
            grpc_endpoint: String::new(),
            snapshot_url,
            validator_peer_id,
            trusted_providers: vec![],
            auto_select_provider: true,
            s3_key,
            s3_secret,
            s3_host,
            snapshot_path,
            snapshot_time,
            snapshot_save_format,
            snapshot_metadata_url,
            snapshot_retain,
            snapshot_keep_last,
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

    let defaults = HashMap::new();

    let render = |label: &str,
                  template: &str,
                  vars: &HashMap<String, String>|
     -> Result<(), Box<dyn Error>> {
        println!("\n── {} ──", label);
        let rendered = substitute_template_raw(template, vars, &defaults)?;
        println!("{}", rendered);
        Ok(())
    };

    match phase.as_str() {
        "a" => {
            let vars = build_phase_a_vars(&config);
            render("Phase A: Kickoff Special Teams", SDL_A, &vars)?;
        }
        "a2" => {
            let vars = build_phase_a2_vars(&config);
            render("Phase A2: Backup Kickoff", SDL_A, &vars)?;
        }
        "b" => {
            let vars = build_phase_b_vars(&config, &snapshot_peer, &snapshot_2_peer);
            render("Phase B: Left & Right Tackles", SDL_B, &vars)?;
        }
        "c" => {
            let vars = build_phase_c_vars(
                &seed_peer,
                &seed_2_peer,
                &snapshot_peer,
                &snapshot_2_peer,
                &left_tackle_peer,
                &right_tackle_peer,
            );
            render("Phase C: Left & Right Forwards", SDL_C, &vars)?;
        }
        "all" => {
            let a_vars = build_phase_a_vars(&config);
            render("Phase A: Kickoff Special Teams", SDL_A, &a_vars)?;

            let a2_vars = build_phase_a2_vars(&config);
            render("Phase A2: Backup Kickoff", SDL_A, &a2_vars)?;

            let b_vars = build_phase_b_vars(&config, &snapshot_peer, &snapshot_2_peer);
            render("Phase B: Left & Right Tackles", SDL_B, &b_vars)?;

            let c_vars = build_phase_c_vars(
                &seed_peer,
                &seed_2_peer,
                &snapshot_peer,
                &snapshot_2_peer,
                &left_tackle_peer,
                &right_tackle_peer,
            );
            render("Phase C: Left & Right Forwards", SDL_C, &c_vars)?;
        }
        _ => {
            eprintln!("Unknown phase: {}. Choose a, a2, b, c, or all.", phase);
        }
    }

    Ok(())
}

// ── Subcommand: manage ──

async fn cmd_manage_deployments() -> Result<(), Box<dyn Error>> {
    println!("=== Manage Deployments ===\n");

    let mut store = FileDeploymentStore::new_default().await?;
    let records = store.list().await?;

    if records.is_empty() {
        println!("  No deployments found.");
        return Ok(());
    }

    println!(
        "  {:<6} {:<20} {:<18} {:<20} {:<20}",
        "DSEQ", "Label", "Step", "Provider", "Created"
    );
    println!("  {:-<90}", "");

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

        println!(
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

    println!();
    let dseq_str = read_input(&mut lines, "Enter DSEQ to manage (or 'q' to quit)", None)?;
    if dseq_str == "q" || dseq_str.is_empty() {
        return Ok(());
    }

    let dseq: u64 = dseq_str.parse().map_err(|_| "Invalid DSEQ number")?;

    let record = records.iter().find(|r| r.dseq == dseq);
    if record.is_none() {
        eprintln!("  No record found for DSEQ {}", dseq);
        return Ok(());
    }

    println!("\n  Actions:");
    println!("    1. Close deployment");
    println!("    2. View record (JSON)");
    println!("    3. Update SDL (not yet implemented)");

    let action = read_input(&mut lines, "Select action", None)?;

    match action.as_str() {
        "1" => {
            if !prompt_continue(&mut lines, &format!("Close deployment DSEQ {}?", dseq))? {
                println!("  Cancelled.");
                return Ok(());
            }

            let (mnemonic, _password) = unlock_mnemonic()?;

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

            println!("  Closing deployment DSEQ {}...", dseq);
            let result = client
                .broadcast_close_deployment(&signer, &client.address(), dseq)
                .await?;

            println!("  Closed! TX hash: {}", result.hash);

            store.delete(dseq).await?;
            println!("  Record removed from store.");
        }
        "2" => {
            let json = serde_json::to_string_pretty(record.unwrap())?;
            println!("\n{}", json);
        }
        "3" => {
            println!("  Update SDL is not yet implemented.");
        }
        _ => {
            eprintln!("  Unknown action.");
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
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── S3 AWS Signature V4 ──

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hex::encode(hash)
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC key length");
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

    let host = url.host_str().unwrap_or("");
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

async fn cmd_test_s3() -> Result<(), Box<dyn Error>> {
    println!("=== S3 Connection Test ===\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    // Load S3 credentials from saved config or prompt
    let (s3_key, s3_secret, s3_host, snapshot_path) = if has_saved_config() {
        println!("  Found saved config.");
        let password =
            rpassword::prompt_password("Enter password to decrypt config (or Enter to skip): ")?;
        if !password.is_empty() {
            if let Some(cfg) = load_config(&password) {
                println!("  Using saved config.\n");
                (cfg.s3_key, cfg.s3_secret, cfg.s3_host, cfg.snapshot_path)
            } else {
                println!("  Could not decrypt. Prompting for values.\n");
                prompt_s3_creds(&mut lines)?
            }
        } else {
            prompt_s3_creds(&mut lines)?
        }
    } else {
        prompt_s3_creds(&mut lines)?
    };

    // Parse bucket and prefix from snapshot_path (e.g. "snapshots/terpnetwork")
    let (bucket_name, prefix) = match snapshot_path.split_once('/') {
        Some((b, p)) => (b.to_string(), format!("{}/", p)),
        None => (snapshot_path.clone(), String::new()),
    };

    println!("  S3 host:    {}", s3_host);
    println!("  Bucket:     {}", bucket_name);
    println!(
        "  Prefix:     {}",
        if prefix.is_empty() { "(root)" } else { &prefix }
    );
    println!("  Access key: {}", redact_if_secret("S3_KEY", &s3_key));
    println!();

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
                println!("OK (HTTP 200, {} objects listed)", count);
            } else {
                println!("SKIPPED (HTTP {} — provider may not support ListObjects)", status);
                list_ok = false;
            }
        }
        Err(e) => {
            println!("SKIPPED: {}", e);
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
            if status >= 200 && status < 300 {
                println!("OK (HTTP {})", status);
            } else {
                let body = resp.text().await.unwrap_or_default();
                println!("FAILED (HTTP {})", status);
                if !body.is_empty() {
                    eprintln!("    Response: {}", &body[..body.len().min(200)]);
                }
                rw_ok = false;
            }
        }
        Err(e) => {
            println!("FAILED: {}", e);
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
                    println!("OK (data verified)");
                } else {
                    println!("OK (HTTP 200, content differs — still functional)");
                }
            } else {
                println!("FAILED (HTTP {})", status);
                rw_ok = false;
            }
        }
        Err(e) => {
            println!("FAILED: {}", e);
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
                println!("OK (HTTP {})", status);
            } else {
                println!(
                    "WARN (HTTP {} — may need manual cleanup of {})",
                    status, test_key
                );
            }
        }
        Err(e) => {
            println!("WARN: {} — test object may remain at {}", e, test_key);
        }
    }

    println!();
    if rw_ok && list_ok {
        println!("  All S3 tests passed. Credentials are fully functional.");
    } else if rw_ok {
        println!("  Read/write tests passed. Credentials are functional.");
        println!("  Note: ListObjects not supported by this provider (common with Filebase).");
        println!("  This does not affect O-Line deployments — only PUT/GET/DELETE are used.");
    } else {
        println!("  S3 read/write tests failed. Check credentials and bucket permissions.");
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

async fn cmd_main_menu() -> Result<(), Box<dyn Error>> {
    let store = FileDeploymentStore::new_default().await?;
    let records = store.list().await.unwrap_or_default();
    let has_deployments = !records.is_empty();

    println!("=== O-Line Deployer ===\n");
    println!("  1. Deploy (full automated deployment)");
    println!("  2. Generate SDL (render & print, no broadcast)");
    if has_deployments {
        println!("  3. Manage Deployments ({} active)", records.len());
    }
    println!("  4. Test S3 Connection");
    println!("  5. Encrypt Mnemonic");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let choice = read_input(&mut lines, "\nSelect option", None)?;
    drop(lines);

    match choice.as_str() {
        "1" => cmd_deploy(false).await,
        "2" => cmd_generate_sdl().await,
        "3" if has_deployments => cmd_manage_deployments().await,
        "4" => cmd_test_s3().await,
        "5" => cmd_encrypt(),
        _ => {
            eprintln!("Invalid option.");
            Ok(())
        }
    }
}

// ── Main ──

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("encrypt") => cmd_encrypt(),
        Some("deploy") => {
            let raw = args.get(2).map(|s| s.as_str()) == Some("--raw");
            cmd_deploy(raw).await
        }
        Some("sdl") | Some("generate-sdl") => cmd_generate_sdl().await,
        Some("manage") => cmd_manage_deployments().await,
        Some("test-s3") => cmd_test_s3().await,
        None => cmd_main_menu().await,
        Some(other) => {
            eprintln!("Unknown command: {}", other);
            eprintln!();
            eprintln!("Usage:");
            eprintln!("  oline                 Interactive main menu");
            eprintln!("  oline encrypt         Encrypt mnemonic and store in .env");
            eprintln!("  oline deploy          Deploy using encrypted mnemonic from .env");
            eprintln!("  oline deploy --raw    Deploy with mnemonic entered directly (hidden)");
            eprintln!("  oline sdl             Generate SDL templates (render & preview)");
            eprintln!("  oline manage          Manage active deployments");
            eprintln!("  oline test-s3         Test S3 bucket connectivity");
            std::process::exit(1);
        }
    }
}
