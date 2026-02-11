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
const SDL_A: &str = include_str!("../scripts/sdls/a.kickoff-special-teams.yml");
const SDL_A2: &str = include_str!("../scripts/sdls/a2.kickoff-backup.yml");
const SDL_B: &str = include_str!("../scripts/sdls/b.left-and-right-tackle.yml");
const SDL_C: &str = include_str!("../scripts/sdls/c.left-and-right-forwards.yml");

const ENV_KEY: &str = "OLINE_ENCRYPTED_MNEMONIC";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

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

// ── OLineConfig & OLineDeployer ──

pub struct OLineConfig {
    pub mnemonic: String,
    pub rpc_endpoint: String,
    pub snapshot_url: String,
    pub validator_peer_id: String,
    pub trusted_providers: Vec<String>,
    pub auto_select_provider: bool,
}

pub struct OLineDeployer {
    client: AkashClient,
    signer: KeySigner,
    config: OLineConfig,
}

impl OLineDeployer {
    pub async fn new(config: OLineConfig) -> Result<Self, DeployError> {
        let client =
            AkashClient::new_from_mnemonic(&config.mnemonic, &config.rpc_endpoint).await?;
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
        a_vars.insert(
            "SNAPSHOT_URL".to_string(),
            self.config.snapshot_url.clone(),
        );
        a_vars.insert(
            "TERPD_P2P_PRIVATE_PEER_IDS".to_string(),
            self.config.validator_peer_id.clone(),
        );
        let a_defaults = HashMap::new();

        println!("  Variables:");
        for (k, v) in &a_vars {
            println!("    {}={}", k, v);
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

        // ── Phase A2: Backup Snapshot + Seed ──
        println!("\n── Phase 1b: Deploy Backup Snapshot + Seed nodes ──");
        if !prompt_continue(&mut lines, "Deploy a2.kickoff-backup.yml?")? {
            println!("Aborted.");
            return Ok(());
        }

        let mut a2_vars = HashMap::new();
        a2_vars.insert(
            "SNAPSHOT_URL".to_string(),
            self.config.snapshot_url.clone(),
        );
        a2_vars.insert(
            "TERPD_P2P_PRIVATE_PEER_IDS".to_string(),
            self.config.validator_peer_id.clone(),
        );
        let a2_defaults = HashMap::new();

        println!("  Variables:");
        for (k, v) in &a2_vars {
            println!("    {}={}", k, v);
        }

        println!("  Deploying...");
        let (_a2_state, a2_endpoints) =
            self.deploy_phase_with_selection(SDL_A2, a2_vars, a2_defaults, "oline-phase-a2", &mut lines).await?;

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
        b_vars.insert(
            "TERPD_P2P_PERSISTENT_PEERS".to_string(),
            format!("{},{}", snapshot_peer, snapshot_2_peer),
        );
        b_vars.insert(
            "TERPD_P2P_PRIVATE_PEER_IDS".to_string(),
            self.config.validator_peer_id.clone(),
        );
        b_vars.insert(
            "TERPD_P2P_UNCONDITIONAL_PEER_IDS".to_string(),
            self.config.validator_peer_id.clone(),
        );
        let b_defaults = HashMap::new();

        println!("  Variables:");
        for (k, v) in &b_vars {
            println!("    {}={}", k, v);
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
        c_vars.insert(
            "TERPD_P2P_SEEDS".to_string(),
            format!("{},{}", seed_peer, seed_2_peer),
        );
        c_vars.insert(
            "TERPD_P2P_PRIVATE_PEER_IDS".to_string(),
            tackles_combined.clone(),
        );
        c_vars.insert(
            "TERPD_P2P_UNCONDITIONAL_PEER_IDS".to_string(),
            tackles_combined,
        );
        c_vars.insert(
            "TERPD_P2P_PERSISTENT_PEERS".to_string(),
            format!("{},{}", snapshot_peer, snapshot_2_peer),
        );
        let c_defaults = HashMap::new();

        println!("  Variables:");
        for (k, v) in &c_vars {
            println!("    {}={}", k, v);
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

    let snapshot_url = read_input(&mut lines, "Enter snapshot URL", None)?;
    if snapshot_url.is_empty() {
        return Err("Snapshot URL is required.".into());
    }

    let validator_peer_id = read_input(&mut lines, "Enter validator peer ID (id@host:port)", None)?;
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

    // Drop the stdin lock before OLineDeployer::run() re-acquires it
    drop(lines);

    let config = OLineConfig {
        mnemonic,
        rpc_endpoint,
        snapshot_url,
        validator_peer_id,
        trusted_providers,
        auto_select_provider,
    };

    let deployer = OLineDeployer::new(config).await?;
    deployer.run().await
}

// ── Main ──

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
