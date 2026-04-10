use clap::{Args, Subcommand};
use std::error::Error;

use crate::registry::{import, server, storage};

#[derive(Args, Debug)]
pub struct RegistryArgs {
    #[command(subcommand)]
    pub command: RegistryCommand,
}

#[derive(Subcommand, Debug)]
pub enum RegistryCommand {
    /// Start the OCI container registry server
    Serve,
    /// Import a local Docker image into the registry
    Import {
        /// Docker image reference (e.g. oline-omnibus:v0.3.0)
        image: String,
        /// Push via Docker API to running registry (requires registry serve to be running).
        /// Without this flag, imports directly to filesystem storage.
        #[arg(long)]
        push: bool,
    },
    /// List images available in the registry
    List,
}

pub async fn cmd_registry(args: &RegistryArgs) -> Result<(), Box<dyn Error>> {
    match &args.command {
        RegistryCommand::Serve => cmd_registry_serve().await,
        RegistryCommand::Import { image, push } => cmd_registry_import(image, *push).await,
        RegistryCommand::List => cmd_registry_list(),
    }
}

async fn cmd_registry_serve() -> Result<(), Box<dyn Error>> {
    let port: u16 = std::env::var("OLINE_REGISTRY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    let username = std::env::var("OLINE_REGISTRY_USERNAME").unwrap_or_else(|_| "oline".to_string());
    let password = std::env::var("OLINE_REGISTRY_PASSWORD").unwrap_or_default();

    server::serve(port, &username, &password).await
}

async fn cmd_registry_import(image: &str, push: bool) -> Result<(), Box<dyn Error>> {
    if push {
        // Push via Docker API — requires running registry
        let port: u16 = std::env::var("OLINE_REGISTRY_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5000);
        let registry_url = std::env::var("OLINE_REGISTRY_URL")
            .unwrap_or_else(|_| format!("http://localhost:{port}"));
        let username =
            std::env::var("OLINE_REGISTRY_USERNAME").unwrap_or_else(|_| "oline".to_string());
        let password = std::env::var("OLINE_REGISTRY_PASSWORD").unwrap_or_default();

        import::import_image(image, &registry_url, &username, &password).await
    } else {
        // Direct filesystem import — no running registry needed
        let dir = storage::ensure_registry_dir()?;
        import::import_image_direct(image, &dir).await
    }
}

fn cmd_registry_list() -> Result<(), Box<dyn Error>> {
    let dir = storage::registry_dir();
    if !dir.exists() {
        tracing::info!("Registry storage not found at {}", dir.display());
        tracing::info!("Run `oline registry serve` or `oline registry import` first.");
        return Ok(());
    }

    let images = storage::list_registry_images(&dir)?;
    if images.is_empty() {
        tracing::info!("No images in registry at {}", dir.display());
    } else {
        tracing::info!("Images in registry ({}):", dir.display());
        for img in &images {
            tracing::info!("  {img}");
        }
    }
    Ok(())
}
