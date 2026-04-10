use crate::{akash::*, cli::*, config::{resolve_fd_value, *}, with_examples, FIELD_DESCRIPTORS};

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

use std::{
    collections::HashMap,
    error::Error,
    fs,
    io::{self, BufRead},
    path::Path,
};

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

    // ── Load config ──────────────────────────────────────────────────────────
    let config = if let Some(cfg_path) = load_config_path {
        // Load from deploy-config.json
        tracing::info!("  Loading config from: {}\n", cfg_path);
        let raw = fs::read_to_string(cfg_path)
            .map_err(|e| format!("Cannot read '{}': {}", cfg_path, e))?;
        let deploy_config: DeployConfig = serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid deploy-config.json: {}", e))?;
        // Rebuild OLineConfig. Resolution order: env var > JSON value > FD default.
        // Iterating FDs (not the raw JSON map) ensures every known field is present
        // and env vars always take the highest precedence.
        let mut cfg = OLineConfig::default();
        for fd in FIELD_DESCRIPTORS.iter() {
            let saved = deploy_config
                .config
                .get(fd.ev)
                .map(String::as_str);
            cfg.set(fd.ev, resolve_fd_value(fd, saved));
        }
        (cfg, Some(deploy_config.peers))
    } else {
        // Interactive collection (mirroring the old flow)
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
            let mut cfg = OLineConfig::default();
            for fd in FIELD_DESCRIPTORS.iter() {
                // env var always wins; fd.d is the fallback default shown in prompt
                let resolved = resolve_fd_value(fd, None);
                let value = if fd.s && !resolved.is_empty() {
                    resolved // carry secrets silently — never re-prompt
                } else {
                    read_input(&mut lines, fd.p, Some(&resolved))?
                };
                cfg.set(fd.ev, value);
            }
            cfg
        };
        (cfg, None)
    };
    let (config, preloaded_peers) = config;

    // ── Peer inputs ───────────────────────────────────────────────────────────
    let needs_peers = matches!(phase.as_str(), "b" | "c" | "all");
    let (snapshot_peer, seed_peer) = if needs_peers {
        let default_snap = preloaded_peers.as_ref().map(|p| p.snapshot.as_str()).unwrap_or("<SNAPSHOT_PEER_1>");
        let default_seed = preloaded_peers.as_ref().map(|p| p.seed.as_str()).unwrap_or("<SEED_PEER_1>");
        let sp = read_input(&mut lines, "Snapshot peer 1 (id@host:port)", Some(default_snap))?;
        let sd = read_input(&mut lines, "Seed peer 1 (id@host:port)", Some(default_seed))?;
        (sp, sd)
    } else {
        (
            preloaded_peers.as_ref().map(|p| p.snapshot.clone()).unwrap_or_default(),
            preloaded_peers.as_ref().map(|p| p.seed.clone()).unwrap_or_default(),
        )
    };

    let statesync_rpc = if needs_peers {
        let default_rpc = preloaded_peers.as_ref().map(|p| p.statesync_rpc.as_str()).unwrap_or("");
        read_input(
            &mut lines,
            "Statesync RPC servers (e.g. statesync.terp.network:PORT,seed.terp.network:PORT)",
            Some(default_rpc),
        )?
    } else {
        preloaded_peers.as_ref().map(|p| p.statesync_rpc.clone()).unwrap_or_default()
    };

    let needs_tackles = matches!(phase.as_str(), "c" | "all");
    let (left_tackle_peer, right_tackle_peer) = if needs_tackles {
        let default_lt = preloaded_peers.as_ref().map(|p| p.left_tackle.as_str()).unwrap_or("<LEFT_TACKLE_PEER>");
        let default_rt = preloaded_peers.as_ref().map(|p| p.right_tackle.as_str()).unwrap_or("<RIGHT_TACKLE_PEER>");
        let lt = read_input(&mut lines, "Left tackle peer (id@host:port)", Some(default_lt))?;
        let rt = read_input(&mut lines, "Right tackle peer (id@host:port)", Some(default_rt))?;
        (lt, rt)
    } else {
        (
            preloaded_peers.as_ref().map(|p| p.left_tackle.clone()).unwrap_or_default(),
            preloaded_peers.as_ref().map(|p| p.right_tackle.clone()).unwrap_or_default(),
        )
    };

    // ── SDL templates ─────────────────────────────────────────────────────────
    let sdl_a = config.load_sdl("a.yml")?;
    let sdl_b = config.load_sdl("b.yml")?;
    let sdl_c = config.load_sdl("c.yml")?;
    let sdl_e = config.load_sdl("e.yml")?;
    let sdl_f = config.load_sdl("f.yml")?;

    // render: print to stdout and return the rendered string.
    let render = |label: &str,
                  template: &str,
                  vars: &HashMap<String, String>|
     -> Result<String, Box<dyn Error>> {
        tracing::info!("\n── {} ──", label);
        let rendered = substitute_template_raw(template, vars)?;
        tracing::info!("{}", rendered);
        Ok(rendered)
    };

    // ── Render phase(s) ───────────────────────────────────────────────────────
    // Collect (filename, rendered_content) pairs for optional file output.
    let mut rendered_files: Vec<(&str, String)> = Vec::new();
    let secrets = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());

    match phase.as_str() {
        "a" => {
            let vars = build_phase_a_vars(&config, &secrets).await?;
            rendered_files.push(("a.yml", render("Phase A: Kickoff Special Teams", &sdl_a, &vars)?));
        }
        "b" => {
            let vars = build_phase_b_vars(&config, &snapshot_peer, &statesync_rpc);
            rendered_files.push(("b.yml", render("Phase B: Left & Right Tackles", &sdl_b, &vars)?));
        }
        "c" => {
            let vars = build_phase_c_vars(&config, &seed_peer, &snapshot_peer, &left_tackle_peer, &right_tackle_peer, &statesync_rpc);
            rendered_files.push(("c.yml", render("Phase C: Left & Right Forwards", &sdl_c, &vars)?));
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
                build_phase_a_vars(&config, &secrets).await?,
                build_phase_b_vars(&config, &snapshot_peer, &statesync_rpc),
                build_phase_c_vars(&config, &seed_peer, &snapshot_peer, &left_tackle_peer, &right_tackle_peer, &statesync_rpc),
                build_phase_rly_vars(&config),
                build_phase_f_vars(&config, &statesync_rpc),
            );
            rendered_files.push(("a.yml", render("Phase A: Kickoff Special Teams", &sdl_a, &a)?));
            rendered_files.push(("b.yml", render("Phase B: Left & Right Tackles", &sdl_b, &b)?));
            rendered_files.push(("c.yml", render("Phase C: Left & Right Forwards", &sdl_c, &c)?));
            rendered_files.push(("e.yml", render("Phase E: IBC Relayer", &sdl_e, &e)?));
            rendered_files.push(("f.yml", render("Phase F: Argus Indexer", &sdl_f, &f)?));
        }
        _ => {
            tracing::info!("Unknown phase: {}. Choose a, a2, b, c, e, f, or all.", phase);
            return Ok(());
        }
    }

    // ── Optional file output ──────────────────────────────────────────────────
    if let Some(dir) = output {
        let dir = Path::new(dir);
        fs::create_dir_all(dir)?;

        // Write SDL files
        for (filename, content) in &rendered_files {
            let dest = dir.join(filename);
            fs::write(&dest, content)?;
            tracing::info!("  Wrote: {}", dest.display());
        }

        // Write deploy-config.json
        let peers = PeerInputs {
            snapshot: snapshot_peer,
            seed: seed_peer,
            statesync_rpc,
            left_tackle: left_tackle_peer,
            right_tackle: right_tackle_peer,
        };
        let deploy_config = DeployConfig::from_config(&config, &FIELD_DESCRIPTORS, peers);
        let config_path = dir.join("deploy-config.json");
        deploy_config.write_to_file(&config_path)?;
        tracing::info!("  Wrote: {}", config_path.display());
    }

    Ok(())
}
