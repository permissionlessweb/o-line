use crate::{cli::*, config::{resolve_fd_value, *}, templates, with_examples, FIELD_DESCRIPTORS};
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
        /// All FIELD_DESCRIPTOR defaults are applied; template overrides are layered on top.
        /// Run with --list-templates to see available names.
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
        let deploy_config = DeployConfig::from_config(&config, &FIELD_DESCRIPTORS, peers);
        deploy_config.write_to_file(Path::new(&args.output))?;
        tracing::info!("\n  Config written to: {}", args.output);
        tracing::info!("  Review and customise, then render SDL with:");
        tracing::info!("    oline sdl --load-config {}", args.output);
        return Ok(());
    }

    // ── interactive ───────────────────────────────────────────────────────────
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    // Try saved config as a starting point.
    let saved = if has_saved_config() {
        tracing::info!("  Found saved config.");
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

    // Resolve all values: env var > saved config > FD default.
    let resolved_values: Vec<String> = FIELD_DESCRIPTORS
        .iter()
        .map(|fd| {
            let saved_val = saved
                .as_ref()
                .and_then(|s| s.get_str(fd.ev));
            resolve_fd_value(fd, saved_val)
        })
        .collect();

    // Show numbered overview; let user pick which fields to override.
    print_config_table(&resolved_values);
    let overrides: HashSet<usize> = read_override_selection(&mut lines)?;

    let mut cfg = OLineConfig::default();
    for (i, fd) in FIELD_DESCRIPTORS.iter().enumerate() {
        let value = if overrides.contains(&i) {
            if fd.s {
                read_secret_input(fd.p, Some(&resolved_values[i]))?
            } else {
                read_input(&mut lines, fd.p, Some(&resolved_values[i]))?
            }
        } else {
            resolved_values[i].clone()
        };
        cfg.set(fd.ev, value);
    }
    let config = cfg;

    // Peer inputs — optional, fill in after Phase A completes.
    tracing::info!("\n  Peer IDs (press Enter to leave blank — fill in after Phase A):");
    let snapshot = read_input(&mut lines, "Snapshot peer (id@host:port)", Some(""))?;
    let seed = read_input(&mut lines, "Seed peer (id@host:port)", Some(""))?;
    let statesync_rpc = read_input(&mut lines, "Statesync RPC (host:port,...)", Some(""))?;
    let left_tackle = read_input(&mut lines, "Left tackle peer (id@host:port)", Some(""))?;
    let right_tackle = read_input(&mut lines, "Right tackle peer (id@host:port)", Some(""))?;

    let peers = PeerInputs {
        snapshot,
        seed,
        statesync_rpc,
        left_tackle,
        right_tackle,
    };

    let deploy_config = DeployConfig::from_config(&config, &FIELD_DESCRIPTORS, peers);
    deploy_config.write_to_file(Path::new(&args.output))?;

    tracing::info!("\n  Config written to: {}", args.output);
    tracing::info!("  Render SDL from it with: oline sdl --load-config {}", args.output);
    Ok(())
}
