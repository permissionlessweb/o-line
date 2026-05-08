use crate::config::oline_deploy_config_path;
use crate::toml_config::{TomlConfig, CONFIG_FIELDS};
use crate::{cli::*, config::*, templates, with_examples};
use std::collections::HashSet;
use std::{
    error::Error,
    io::{self, BufRead},
    path::Path,
};

with_examples! {
    #[derive(clap::Args, Debug, Default)]
    pub struct InitArgs {
        /// Path to write deploy-config.json. Default: ~/.oline/deploy-config.json
        #[arg(long, short = 'o')]
        pub output: Option<String>,

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
    let output: String = args
        .output
        .clone()
        .unwrap_or_else(|| oline_deploy_config_path().to_string_lossy().into_owned());
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
        let deploy_config = DeployConfig::from_oline_config(&config);
        deploy_config.write_to_file(Path::new(&output))?;
        tracing::info!("\n  Config written to: {}", output);
        tracing::info!("  Review and customise, then render SDL with:");
        tracing::info!("    oline sdl --load-config {}", output);
        return Ok(());
    }
    let (toml_config, toml_content) = TomlConfig::default_with_template();
    let oline_config = OLineConfig::from_toml(&toml_config, String::new());
    let deploy_config = DeployConfig::from_oline_config(&oline_config);
    deploy_config.write_to_file(Path::new(&output))?;

    tracing::info!("\n  Config written to: {}", output);
    tracing::info!(
        "  Render SDL from it with: oline sdl --load-config {}",
        output
    );
    Ok(())
}
