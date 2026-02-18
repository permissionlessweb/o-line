use akash_deploy_rs::{
    AkashBackend, AkashClient, Bid, DeployError, DeploymentState, DeploymentWorkflow,
    InputRequired, KeySigner, ProviderInfo, ServiceEndpoint, StepResult, WorkflowConfig,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

// Embed SDLs at compile time
const SDL_A: &str = include_str!("../sdls/a.kickoff-special-teams.yml");
const SDL_B: &str = include_str!("../sdls/b.left-and-right-tackle.yml");
const SDL_C: &str = include_str!("../sdls/c.left-and-right-forwards.yml");

const ENV_KEY: &str = "OLINE_ENCRYPTED_MNEMONIC";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

// Snapshot & SDL defaults
const ITROCKET_STATE_URL: &str =
    "https://server-4.itrocket.net/mainnet/terp/.current_state.json";
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

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

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

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed — wrong password or corrupted data")?;

    String::from_utf8(plaintext).map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e).into())
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

    Err(format!("No {} found in .env file. Run `oline encrypt` first.", ENV_KEY).into())
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
    vars.insert("SNAPSHOT_SAVE_FORMAT".into(), config.snapshot_save_format.clone());
    vars.insert("SNAPSHOT_METADATA_URL".into(), config.snapshot_metadata_url.clone());
    vars.insert("SNAPSHOT_RETAIN".into(), config.snapshot_retain.clone());
    vars.insert("SNAPSHOT_KEEP_LAST".into(), config.snapshot_keep_last.clone());
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
}

impl OLineDeployer {
    pub async fn new(config: OLineConfig) -> Result<Self, DeployError> {
        let client =
            AkashClient::new_from_mnemonic(&config.mnemonic, &config.rpc_endpoint, &config.grpc_endpoint)
                .await?;
        let signer = KeySigner::new_mnemonic_str(&config.mnemonic, None)
            .map_err(|e| DeployError::Signer(format!("Failed to create signer: {}", e)))?;
        Ok(Self { client, signer, config })
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
        let mut state = DeploymentState::new(label, self.client.address())
            .with_sdl(sdl_template)
            .with_template(defaults)
            .with_variables(variables)
            .with_label(label);

        let workflow =
            DeploymentWorkflow::new(&self.client, &self.signer, self.workflow_config());

        loop {
            match workflow.advance(&mut state).await? {
                StepResult::Continue => continue,
                StepResult::Complete => {
                    let endpoints = state.endpoints.clone();
                    return Ok((state, endpoints));
                }
                StepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                    self.present_bids(&bids).await;
                    let choice = Self::prompt_provider_choice(lines, &bids)
                        .map_err(|e| DeployError::InvalidState(format!("Provider selection failed: {}", e)))?;
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
                        .find(|(k, _): &&(String, String)| k == "region" || k == "datacenter" || k == "location")
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

    pub async fn extract_peer_id(
        endpoint: &ServiceEndpoint,
    ) -> Result<String, Box<dyn Error>> {
        let status_url = format!("http://{}/status", endpoint.uri);
        let resp = reqwest::get(&status_url).await?.text().await?;
        let json: serde_json::Value = serde_json::from_str(&resp)?;

        let node_id = json["result"]["node_info"]["id"]
            .as_str()
            .ok_or("missing node_info.id in /status response")?;

        let host = endpoint
            .uri
            .split(':')
            .next()
            .unwrap_or(&endpoint.uri);
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

    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
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
        a_vars.insert("SNAPSHOT_MONIKER".into(), "oline::special::snapshot-node".into());
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
        let (_a_state, a_endpoints) =
            self.deploy_phase_with_selection(SDL_A, a_vars, a_defaults, "oline-phase-a", &mut lines).await?;

        println!(
            "  Deployed! DSEQ: {}",
            _a_state.dseq.unwrap_or(0)
        );

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
        if !prompt_continue(&mut lines, "Deploy backup kickoff (a.kickoff-special-teams.yml)?")? {
            println!("Aborted.");
            return Ok(());
        }

        let mut a2_vars = HashMap::new();
        insert_sdl_defaults(&mut a2_vars);
        insert_s3_vars(&mut a2_vars, &self.config);
        a2_vars.insert("SNAPSHOT_SVC".into(), "oline-a2-snapshot".into());
        a2_vars.insert("SEED_SVC".into(), "oline-a2-seed".into());
        a2_vars.insert("SNAPSHOT_MONIKER".into(), "oline::backup::snapshot-node".into());
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
        let (_a2_state, a2_endpoints) =
            self.deploy_phase_with_selection(SDL_A, a2_vars, a2_defaults, "oline-phase-a2", &mut lines).await?;

        println!(
            "  Deployed! DSEQ: {}",
            _a2_state.dseq.unwrap_or(0)
        );

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
        let (_b_state, b_endpoints) =
            self.deploy_phase_with_selection(SDL_B, b_vars, b_defaults, "oline-phase-b", &mut lines).await?;

        println!(
            "  Deployed! DSEQ: {}",
            _b_state.dseq.unwrap_or(0)
        );

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
        c_vars.insert(
            "TERPD_P2P_UNCONDITIONAL_PEER_IDS".into(),
            tackles_combined,
        );
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
        let (_c_state, _c_endpoints) =
            self.deploy_phase_with_selection(SDL_C, c_vars, c_defaults, "oline-phase-c", &mut lines).await?;

        println!(
            "  Deployed! DSEQ: {}",
            _c_state.dseq.unwrap_or(0)
        );

        println!("\n=== All deployments complete! ===");
        println!("  Phase A1 DSEQ: {}", _a_state.dseq.unwrap_or(0));
        println!("  Phase A2 DSEQ: {}", _a2_state.dseq.unwrap_or(0));
        println!("  Phase B  DSEQ: {}", _b_state.dseq.unwrap_or(0));
        println!("  Phase C  DSEQ: {}", _c_state.dseq.unwrap_or(0));
        Ok(())
    }
}

// ── Secret redaction ──

const SECRET_KEYS: &[&str] = &[
    "S3_KEY",
    "S3_SECRET",
    "TERPD_P2P_PRIVATE_PEER_IDS",
];

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
    let answer = lines
        .next()
        .unwrap_or(Ok(String::new()))?;
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
    let input = lines
        .next()
        .unwrap_or(Ok(String::new()))?;
    let input = input.trim().to_string();
    if input.is_empty() {
        if let Some(def) = default {
            return Ok(def.to_string());
        }
    }
    Ok(input)
}

/// Like `read_input` but hides the typed value (for secrets).
fn read_secret_input(
    prompt: &str,
    default: Option<&str>,
) -> Result<String, Box<dyn Error>> {
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

// ── Subcommand: deploy ──

async fn cmd_deploy(raw: bool) -> Result<(), Box<dyn Error>> {
    println!("=== Welcome to O-Line Deployer ===\n");

    let mnemonic = if raw {
        // Raw mode: prompt for mnemonic directly (hidden)
        let m = rpassword::prompt_password("Enter mnemonic: ")?;
        if m.trim().is_empty() {
            return Err("Mnemonic cannot be empty.".into());
        }
        m.trim().to_string()
    } else {
        // Default mode: read encrypted mnemonic from .env
        let blob = read_encrypted_mnemonic_from_env()?;
        let password = rpassword::prompt_password("Enter password: ")?;
        let m = decrypt_mnemonic(&blob, &password)?;
        println!("Mnemonic decrypted successfully.\n");
        m
    };

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let rpc_endpoint = read_input(
        &mut lines,
        "Enter RPC endpoint",
        Some("https://rpc.akashnet.net:443"),
    )?;

    let grpc_endpoint = read_input(
        &mut lines,
        "Enter gRPC endpoint",
        Some("https://grpc.akashnet.net:443"),
    )?;

    // Auto-fetch latest snapshot URL from itrocket, with manual override
    let snapshot_url = match fetch_latest_snapshot_url().await {
        Ok(url) => {
            let override_url = read_input(
                &mut lines,
                "Snapshot URL (press Enter to use fetched URL, or paste override)",
                Some(&url),
            )?;
            override_url
        }
        Err(e) => {
            eprintln!("  Warning: failed to fetch snapshot: {}", e);
            let url = read_input(&mut lines, "Enter snapshot URL manually", None)?;
            if url.is_empty() {
                return Err("Snapshot URL is required.".into());
            }
            url
        }
    };

    let validator_peer_id = read_secret_input("Enter validator peer ID (id@host:port)", None)?;
    if validator_peer_id.is_empty() {
        return Err("Validator peer ID is required.".into());
    }

    let providers_input = read_input(
        &mut lines,
        "Enter trusted provider addresses (comma-separated, or empty for none)",
        Some(""),
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
        &mut lines,
        "Auto-select cheapest provider? (y/n)",
        Some("y"),
    )?;
    let auto_select_provider =
        auto_select.is_empty() || auto_select == "y" || auto_select == "yes";

    // S3 snapshot export config
    println!("\n── S3 Snapshot Export ──");
    let s3_key = read_secret_input("S3 access key", None)?;
    let s3_secret = read_secret_input("S3 secret key", None)?;
    let s3_host = read_input(
        &mut lines,
        "S3 host",
        Some("https://s3.filebase.com"),
    )?;
    let snapshot_path = read_input(
        &mut lines,
        "S3 snapshot path (bucket/path)",
        Some("snapshots/terpnetwork"),
    )?;
    let snapshot_time = read_input(
        &mut lines,
        "Snapshot schedule time (HH:MM:SS)",
        Some("00:00:00"),
    )?;
    let snapshot_save_format = read_input(
        &mut lines,
        "Snapshot save format",
        Some("tar.gz"),
    )?;
    let snapshot_metadata_url = read_input(
        &mut lines,
        "Snapshot metadata URL (where snapshots are served from)",
        None,
    )?;
    let snapshot_retain = read_input(
        &mut lines,
        "Snapshot retention period",
        Some("2 days"),
    )?;
    let snapshot_keep_last = read_input(
        &mut lines,
        "Minimum snapshots to keep",
        Some("2"),
    )?;

    // Drop the stdin lock before OLineDeployer::run() re-acquires it
    drop(lines);

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

    let deployer = OLineDeployer::new(config).await?;
    deployer.run().await
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
        None => {
            // Default to deploy
            cmd_deploy(false).await
        }
        Some(other) => {
            eprintln!("Unknown command: {}", other);
            eprintln!();
            eprintln!("Usage:");
            eprintln!("  oline encrypt        Encrypt mnemonic and store in .env");
            eprintln!("  oline deploy          Deploy using encrypted mnemonic from .env");
            eprintln!("  oline deploy --raw    Deploy with mnemonic entered directly (hidden)");
            std::process::exit(1);
        }
    }
}
