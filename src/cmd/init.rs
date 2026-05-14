use crate::config::{oline_config_dir, oline_deploy_config_path, DeployConfig, TomlConfig};
use crate::with_examples;
use std::{error::Error, path::Path};


with_examples! {
    #[derive(clap::Args, Debug, Default)]
    pub struct InitArgs {
        /// Path to write deploy-config.json. Default: ~/.oline/deploy-config.json
        #[arg(long, short = 'o')]
        pub output: Option<String>,



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

    tracing::info!("=== Init Deployment Config ===\n");
    let (toml_config, toml_content) = TomlConfig::default_with_template();
    // ── write YAML config to ~/.oline/config.toml ──────────────────────────
    let config_path = oline_config_dir().join("config.toml");
    std::fs::write(&config_path, &toml_content)?;
    tracing::info!("  Config written to: {}", config_path.display());
    // ── end ─────────────────────────────────────────────────────────────────

    let oline_config = TomlConfig::from_toml(&toml_config, String::new());
    let deploy_config = DeployConfig::from_oline_config(&oline_config);
    deploy_config.write_to_file(Path::new(&output))?;

    tracing::info!("\n  Config written to: {}", output);
    tracing::info!(
        "  Render SDL from it with: oline sdl --load-config {}",
        output
    );
    Ok(())
}
