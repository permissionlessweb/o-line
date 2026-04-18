use crate::{cli::*, config::*, templates, with_examples};
use crate::toml_config::{TomlConfig, CONFIG_FIELDS};
use std::collections::HashSet;
use std::{
    error::Error,
    io::{self, BufRead},
    path::Path,
};

with_examples! {
    #[derive(clap::Args, Debug, Default)]
    pub struct InitArgs {
        /// Path to write deploy-config.json.
        #[arg(long, short = 'o', default_value = "deploy-config.json")]
        pub output: String,

        /// Use a named template for non-interactive config generation.
        #[arg(long, short = 't', value_name = "NAME")]
        pub template: Option<String>,

        /// Print available template names and exit.
        #[arg(long)]
        pub list_templates: bool,
    }
    => "../../docs/examples/sdl.md"
}

pub async fn cmd_init(args: &InitArgs) -> Result<(), Box<dyn Error>> {
    // ── list-templates ────────────────────────────────────────────────────────
    if args.list_templates {
        tracing::info!("Available templates:\n");
        for t in templates::list_all() {
            tracing::info!("  {:20}  {}", t.name, t.description);
        }
        return Ok(());
    }

    tracing::info!("=== Init Deployment Config ===\n");

    // ── template (non-interactive) ────────────────────────────────────────────
    if let Some(ref name) = args.template {
        let t = templates::find(name).ok_or_else(|| {
            format!(
                "Unknown template '{}'. Run `oline init --list-templates` to see options.",
                name
            )
        })?;
        tracing::info!("  Using template: {} — {}", t.name, t.description);
        let config = t.build_config();
        let peers = PeerInputs::default();
        let deploy_config = DeployConfig::from_oline_config(&config, peers);
        deploy_config.write_to_file(Path::new(&args.output))?;
        tracing::info!("\n  Config written to: {}", args.output);
        tracing::info!("  Review and customise, then render SDL with:");
        tracing::info!("    oline sdl --load-config {}", args.output);
        return Ok(());
    }

    // ── interactive ───────────────────────────────────────────────────────────
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    // Load TOML config as baseline
    let mut toml_cfg = if std::path::Path::new("config.toml").exists() {
        TomlConfig::load("config.toml").unwrap_or_else(|_| TomlConfig::from_defaults())
    } else {
        TomlConfig::from_defaults()
    };

    // Merge saved config if available
    if has_saved_config() {
        tracing::info!("  Found saved config.");
        let password = rpassword::prompt_password(
            "Enter password to decrypt config (or press Enter to skip): ",
        )?;
        if !password.is_empty() {
            if let Some(saved) = load_config(&password) {
                for field in CONFIG_FIELDS {
                    let env_var = crate::toml_config::env_key(field.path);
                    if toml_cfg.get_value(field.path).is_empty() {
                        if let Some(v) = saved.get_str(&env_var) {
                            if !v.is_empty() {
                                toml_cfg.set_value(field.path, v.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    let resolved: Vec<String> = CONFIG_FIELDS.iter().map(|f| toml_cfg.get_value(f.path)).collect();
    print_config_table(&resolved);
    let overrides: HashSet<usize> = read_override_selection(&mut lines)?;

    for (i, field) in CONFIG_FIELDS.iter().enumerate() {
        if overrides.contains(&i) {
            let value = if field.is_secret {
                read_secret_input(field.description, Some(&resolved[i]))?
            } else {
                read_input(&mut lines, field.description, Some(&resolved[i]))?
            };
            toml_cfg.set_value(field.path, value);
        }
    }

    let config = OLineConfig::from_toml(&toml_cfg, String::new());

    // Peer inputs
    tracing::info!("\n  Peer IDs (press Enter to leave blank — fill in after Phase A):");
    let snapshot = read_input(&mut lines, "Snapshot peer (id@host:port)", Some(""))?;
    let seed = read_input(&mut lines, "Seed peer (id@host:port)", Some(""))?;
    let statesync_rpc = read_input(&mut lines, "Statesync RPC (host:port,...)", Some(""))?;
    let left_tackle = read_input(&mut lines, "Left tackle peer (id@host:port)", Some(""))?;
    let right_tackle = read_input(&mut lines, "Right tackle peer (id@host:port)", Some(""))?;

    let peers = PeerInputs { snapshot, seed, statesync_rpc, left_tackle, right_tackle };
    let deploy_config = DeployConfig::from_oline_config(&config, peers);
    deploy_config.write_to_file(Path::new(&args.output))?;

    tracing::info!("\n  Config written to: {}", args.output);
    tracing::info!("  Render SDL from it with: oline sdl --load-config {}", args.output);
    Ok(())
}
