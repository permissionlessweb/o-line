use akash_deploy_rs::AkashBackend;

use crate::{
    akash::*,
    authz::*,
    cli::*,
    config::*,
    crypto::decrypt_mnemonic,
    deployer::OLineDeployer,
    toml_config::{TomlConfig, CONFIG_FIELDS},
    with_examples,
};
use std::{
    collections::HashMap,
    error::Error,
    fs,
    io::{self, BufRead},
    path::Path,
};

with_examples! {
    #[derive(clap::Args, Debug, Default)]
    pub struct SdlArgs {
        /// Write rendered SDL files and deploy-config.json to this directory.
        #[arg(long, short = 'o', value_name = "DIR")]
        pub output: Option<String>,

        /// Load a deploy-config.json instead of prompting for values.
        #[arg(long, value_name = "PATH")]
        pub load_config: Option<String>,
    }
    => "../../docs/examples/sdl.md"
}

/// Shared init for both deploy --sdl steps: load env, render SDL, create deployer.
async fn init_sdl_deploy(
    sdl_path: &str,
) -> Result<
    (
        OLineDeployer,
        String,
        std::collections::HashMap<String, String>,
        String,
    ),
    Box<dyn Error>,
> {
    tracing::info!("=== Deploy SDL: {} ===", sdl_path);

    let raw_sdl = std::fs::read_to_string(sdl_path)
        .map_err(|e| format!("Cannot read SDL {}: {}", sdl_path, e))?;

    // Build vars from TOML config + env vars (env vars take priority)
    let config_for_vars = build_config_from_env(String::new(), None);
    let vars: std::collections::HashMap<String, String> = config_for_vars
        .to_sdl_vars()
        .into_iter()
        .chain(std::env::vars())
        .collect();

    // Partial substitution: resolves known vars, passes through shell runtime vars
    let rendered = akash_deploy_rs::substitute_partial(&raw_sdl, &vars);

    tracing::info!("  Rendered SDL ({} bytes)", rendered.len());

    // Check AuthZ first (passwordless), then env, then interactive
    let authz_state = load_authz_state();
    let non_interactive = std::env::var("OLINE_NON_INTERACTIVE").is_ok() || authz_state.is_some();

    let (mnemonic, authz_granter) = if let Some(ref state) = authz_state {
        let m = load_deployer_mnemonic().map_err(|e| -> Box<dyn Error> { e.into() })?;
        tracing::info!(
            "Using AuthZ delegation (deployer → {})",
            state.granter_address
        );
        (m, Some(state.granter_address.clone()))
    } else if non_interactive {
        let p = std::env::var("OLINE_PASSWORD").unwrap_or_else(|_| "oline-test".to_string());
        let m = if let Some(raw) = std::env::var("OLINE_MNEMONIC")
            .ok()
            .filter(|s| !s.trim().is_empty())
        {
            raw.trim().to_string()
        } else {
            let blob = read_encrypted_mnemonic().map_err(|_| {
                "OLINE_NON_INTERACTIVE requires OLINE_MNEMONIC or OLINE_ENCRYPTED_MNEMONIC"
            })?;
            decrypt_mnemonic(&blob, &p).map_err(|e| format!("Failed to decrypt mnemonic: {}", e))?
        };
        (m, None)
    } else {
        (unlock_mnemonic()?.0, None)
    };

    let config = build_config_from_env(mnemonic, None);
    let deployer = if let Some(granter) = authz_granter {
        OLineDeployer::new_authz(config, granter).await?
    } else {
        let password = std::env::var("OLINE_PASSWORD").unwrap_or_default();
        OLineDeployer::new(config, password).await?
    };

    let label = std::path::Path::new(sdl_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("custom-sdl")
        .to_string();

    Ok((deployer, rendered, vars, label))
}

// ── Subcommand: deploy --sdl <path> (step 1: create deployment + list bids) ──
pub async fn cmd_deploy_sdl(sdl_path: &str) -> Result<(), Box<dyn Error>> {
    let (deployer, rendered, vars, label) = init_sdl_deploy(sdl_path).await?;

    let (state, bids) = deployer
        .deploy_phase_until_bids(&rendered, &vars, &label)
        .await
        .map_err(|e| format!("Deployment failed: {}", e))?;

    let dseq = state.dseq.unwrap_or(0);

    // Print bids as structured output for LLM/script consumption
    println!("DSEQ={}", dseq);
    println!("BIDS={}", bids.len());
    for (i, bid) in bids.iter().enumerate() {
        let price_akt = bid.price as f64 / 1_000_000.0;
        // Query provider info for context
        let info = deployer
            .client
            .query_provider_info(&bid.provider)
            .await
            .ok()
            .flatten();
        let host = info
            .as_ref()
            .map(|i| i.host_uri.as_str())
            .unwrap_or("unknown");
        let email = info.as_ref().map(|i| i.email.as_str()).unwrap_or("");
        let website = info.as_ref().map(|i| i.website.as_str()).unwrap_or("");

        println!(
            "BID[{}] provider={} price={} price_akt={:.6} host={} email={} website={}",
            i, bid.provider, bid.price, price_akt, host, email, website
        );
    }
    println!();
    println!("To select a provider, run:");
    println!(
        "  oline deploy --sdl {} --select {} <PROVIDER_ADDRESS>",
        sdl_path, dseq
    );

    Ok(())
}

// ── Subcommand: deploy --sdl <path> --select <dseq> <provider> (step 2: complete) ──
pub async fn cmd_deploy_sdl_select(
    sdl_path: &str,
    dseq: u64,
    provider: &str,
) -> Result<(), Box<dyn Error>> {
    use akash_deploy_rs::{DeploymentState, DeploymentStore, DeploymentWorkflow};

    let (deployer, rendered, _vars, label) = init_sdl_deploy(sdl_path).await?;

    // rendered is already fully substituted by init_sdl_deploy
    let mut state = DeploymentState::new(&label, deployer.client.address())
        .with_sdl(&rendered)
        .with_label(&label);
    state.dseq = Some(dseq);

    // Add synthetic bid so select_provider validation passes
    state.bids.push(akash_deploy_rs::Bid {
        provider: provider.to_string(),
        price: 0,
        price_denom: String::new(),
        resources: akash_deploy_rs::Resources {
            cpu_millicores: 0,
            memory_bytes: 0,
            storage_bytes: 0,
            gpu_count: 0,
        },
    });

    // Select the provider
    DeploymentWorkflow::<akash_deploy_rs::AkashClient>::select_provider(&mut state, provider)?;

    // Complete the deployment (lease + manifest + endpoints)
    let endpoints = deployer
        .deploy_phase_complete(&mut state, &label)
        .await
        .map_err(|e| format!("Deployment failed: {}", e))?;

    println!("DSEQ={}", dseq);
    println!("PROVIDER={}", provider);
    for ep in &endpoints {
        println!(
            "ENDPOINT={} port={} internal_port={} service={}",
            ep.uri, ep.port, ep.internal_port, ep.service
        );
    }
    println!("DEPLOY_COMPLETE=true");

    // Save to local store so `oline manage logs/close` can find this deployment
    let password = std::env::var("OLINE_PASSWORD").unwrap_or_default();
    if let Ok(record) = akash_deploy_rs::DeploymentRecord::from_state(&state, &password) {
        let mut store = akash_deploy_rs::FileDeploymentStore::new_default().await?;
        store.save(&record).await?;
        tracing::info!("Saved deployment record for DSEQ {}", dseq);
    }

    Ok(())
}

// ── Subcommand: generate-sdl ──
pub async fn cmd_generate_sdl(
    output: Option<&str>,
    load_config_path: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Generate SDL ===\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    tracing::info!("  Select phase to render:");
    tracing::info!("    a  - Phase A: Kickoff Special Teams (snapshot + seed)");
    tracing::info!("    a2 - Phase A2: Backup Kickoff");
    tracing::info!("    b  - Phase B: Left & Right Tackles");
    tracing::info!("    c  - Phase C: Left & Right Forwards");
    tracing::info!("    e  - Phase E: IBC Relayer");
    tracing::info!("    f  - Phase F: Argus Indexer");
    tracing::info!("    all - All phases");
    let phase = read_input(&mut lines, "Phase", Some("all"))?;

    // ── Load config ──────────────────────────��───────────────────────────────
    let config = if let Some(cfg_path) = load_config_path {
        tracing::info!("  Loading config from: {}\n", cfg_path);
        let raw = fs::read_to_string(cfg_path)
            .map_err(|e| format!("Cannot read '{}': {}", cfg_path, e))?;
        let deploy_config: DeployConfig =
            serde_json::from_str(&raw).map_err(|e| format!("Invalid deploy-config.json: {}", e))?;
        // Rebuild OLineConfig from deploy-config values + env overrides
        let mut toml_cfg = TomlConfig::from_defaults();
        for field in CONFIG_FIELDS {
            let env_var = crate::toml_config::env_key(field.path);
            if let Some(saved) = deploy_config.config.get(&env_var) {
                if !saved.is_empty() {
                    toml_cfg.set_value(field.path, saved.clone());
                }
            }
        }
        // Also check legacy key names in the saved config
        for (key, val) in &deploy_config.config {
            if !val.is_empty() {
                // Set as env var so TomlConfig legacy overrides pick it up
                if std::env::var(key).is_err() {
                    std::env::set_var(key, val);
                }
            }
        }
        toml_cfg.apply_env_overrides();
        let cfg = OLineConfig::from_toml(&toml_cfg, String::new());
        (cfg, Some(deploy_config.peers))
    } else {
        // Interactive collection
        let saved = if has_saved_config() {
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

        let cfg = if let Some(saved) = saved {
            tracing::info!("  Using saved config.\n");
            saved
        } else {
            tracing::info!("  No saved config loaded. Prompting for values.\n");
            let mut toml_cfg = if Path::new("config.toml").exists() {
                TomlConfig::load("config.toml").unwrap_or_else(|_| TomlConfig::from_defaults())
            } else {
                TomlConfig::from_defaults()
            };
            for field in CONFIG_FIELDS {
                let resolved = toml_cfg.get_value(field.path);
                let value = if field.is_secret && !resolved.is_empty() {
                    resolved
                } else {
                    read_input(&mut lines, field.description, Some(&resolved))?
                };
                toml_cfg.set_value(field.path, value);
            }
            OLineConfig::from_toml(&toml_cfg, String::new())
        };
        (cfg, None)
    };
    let (config, preloaded_peers) = config;

    // ── Peer inputs ───────���───────────────────────────���───────────────────────
    let needs_peers = matches!(phase.as_str(), "b" | "c" | "all");
    let (snapshot_peer, seed_peer) = if needs_peers {
        let default_snap = preloaded_peers
            .as_ref()
            .map(|p| p.snapshot.as_str())
            .unwrap_or("<SNAPSHOT_PEER_1>");
        let default_seed = preloaded_peers
            .as_ref()
            .map(|p| p.seed.as_str())
            .unwrap_or("<SEED_PEER_1>");
        let sp = read_input(
            &mut lines,
            "Snapshot peer 1 (id@host:port)",
            Some(default_snap),
        )?;
        let sd = read_input(&mut lines, "Seed peer 1 (id@host:port)", Some(default_seed))?;
        (sp, sd)
    } else {
        (
            preloaded_peers
                .as_ref()
                .map(|p| p.snapshot.clone())
                .unwrap_or_default(),
            preloaded_peers
                .as_ref()
                .map(|p| p.seed.clone())
                .unwrap_or_default(),
        )
    };

    let statesync_rpc = if needs_peers {
        let default_rpc = preloaded_peers
            .as_ref()
            .map(|p| p.statesync_rpc.as_str())
            .unwrap_or("");
        read_input(&mut lines, "Statesync RPC servers", Some(default_rpc))?
    } else {
        preloaded_peers
            .as_ref()
            .map(|p| p.statesync_rpc.clone())
            .unwrap_or_default()
    };

    let needs_tackles = matches!(phase.as_str(), "c" | "all");
    let (left_tackle_peer, right_tackle_peer) = if needs_tackles {
        let default_lt = preloaded_peers
            .as_ref()
            .map(|p| p.left_tackle.as_str())
            .unwrap_or("<LEFT_TACKLE_PEER>");
        let default_rt = preloaded_peers
            .as_ref()
            .map(|p| p.right_tackle.as_str())
            .unwrap_or("<RIGHT_TACKLE_PEER>");
        let lt = read_input(
            &mut lines,
            "Left tackle peer (id@host:port)",
            Some(default_lt),
        )?;
        let rt = read_input(
            &mut lines,
            "Right tackle peer (id@host:port)",
            Some(default_rt),
        )?;
        (lt, rt)
    } else {
        (
            preloaded_peers
                .as_ref()
                .map(|p| p.left_tackle.clone())
                .unwrap_or_default(),
            preloaded_peers
                .as_ref()
                .map(|p| p.right_tackle.clone())
                .unwrap_or_default(),
        )
    };

    // ── SDL templates ─────────────────────────────────────────────────────────
    let sdl_a = config.load_sdl("a.yml")?;
    let sdl_b = config.load_sdl("b.yml")?;
    let sdl_c = config.load_sdl("c.yml")?;
    let sdl_e = config.load_sdl("e.yml")?;
    let sdl_f = config.load_sdl("f.yml")?;

    let render = |label: &str,
                  template: &str,
                  vars: &HashMap<String, String>|
     -> Result<String, Box<dyn Error>> {
        tracing::info!("\n── {} ���─", label);
        let rendered = akash_deploy_rs::substitute_partial(template, vars);
        tracing::info!("{}", rendered);
        Ok(rendered)
    };

    let mut rendered_files: Vec<(&str, String)> = Vec::new();
    let secrets = crate::config::oline_config_dir()
        .to_string_lossy()
        .into_owned();

    // Phase A generates SSH keys — prompt for encryption password
    let key_password = if matches!(phase.as_str(), "a" | "all") {
        rpassword::prompt_password("  Key encryption password: ")?
    } else {
        String::new()
    };

    match phase.as_str() {
        "a" => {
            let vars = build_phase_a_vars(&config, &secrets, &key_password).await?;
            rendered_files.push((
                "a.yml",
                render("Phase A: Kickoff Special Teams", &sdl_a, &vars)?,
            ));
        }
        "b" => {
            let vars = build_phase_b_vars(&config, &snapshot_peer, &statesync_rpc);
            rendered_files.push((
                "b.yml",
                render("Phase B: Left & Right Tackles", &sdl_b, &vars)?,
            ));
        }
        "c" => {
            let vars = build_phase_c_vars(
                &config,
                &seed_peer,
                &snapshot_peer,
                &left_tackle_peer,
                &right_tackle_peer,
                &statesync_rpc,
            );
            rendered_files.push((
                "c.yml",
                render("Phase C: Left & Right Forwards", &sdl_c, &vars)?,
            ));
        }
        "e" => {
            let vars = build_phase_rly_vars(&config);
            rendered_files.push(("e.yml", render("Phase E: IBC Relayer", &sdl_e, &vars)?));
        }
        "f" => {
            let vars = build_phase_f_vars(&config, &statesync_rpc);
            rendered_files.push(("f.yml", render("Phase F: Argus Indexer", &sdl_f, &vars)?));
        }
        "all" => {
            let (a, b, c, e, f) = (
                build_phase_a_vars(&config, &secrets, &key_password).await?,
                build_phase_b_vars(&config, &snapshot_peer, &statesync_rpc),
                build_phase_c_vars(
                    &config,
                    &seed_peer,
                    &snapshot_peer,
                    &left_tackle_peer,
                    &right_tackle_peer,
                    &statesync_rpc,
                ),
                build_phase_rly_vars(&config),
                build_phase_f_vars(&config, &statesync_rpc),
            );
            rendered_files.push((
                "a.yml",
                render("Phase A: Kickoff Special Teams", &sdl_a, &a)?,
            ));
            rendered_files.push((
                "b.yml",
                render("Phase B: Left & Right Tackles", &sdl_b, &b)?,
            ));
            rendered_files.push((
                "c.yml",
                render("Phase C: Left & Right Forwards", &sdl_c, &c)?,
            ));
            rendered_files.push(("e.yml", render("Phase E: IBC Relayer", &sdl_e, &e)?));
            rendered_files.push(("f.yml", render("Phase F: Argus Indexer", &sdl_f, &f)?));
        }
        _ => {
            tracing::info!(
                "Unknown phase: {}. Choose a, a2, b, c, e, f, or all.",
                phase
            );
            return Ok(());
        }
    }

    // ── Optional file output ──────────────────────────────────────────────────
    if let Some(dir) = output {
        let dir = Path::new(dir);
        fs::create_dir_all(dir)?;

        for (filename, content) in &rendered_files {
            let dest = dir.join(filename);
            fs::write(&dest, content)?;
            tracing::info!("  Wrote: {}", dest.display());
        }

        let peers = PeerInputs {
            snapshot: snapshot_peer,
            seed: seed_peer,
            statesync_rpc,
            left_tackle: left_tackle_peer,
            right_tackle: right_tackle_peer,
        };
        let deploy_config = DeployConfig::from_oline_config(&config, peers);
        let config_path = dir.join("deploy-config.json");
        deploy_config.write_to_file(&config_path)?;
        tracing::info!("  Wrote: {}", config_path.display());
    }

    Ok(())
}
