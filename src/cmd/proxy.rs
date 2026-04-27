//! `oline proxy` subcommand — deploy and manage the provider-proxy-node.
//!
//! The proxy-node is a specialty deployment (protected from accidental close)
//! that runs a provider proxy + co-located Akash light node on Akash Network.

use crate::{
    cli::unlock_mnemonic,
    cmd::deploy::{save_proxy_deployment, ProxyDeployment},
    config::{build_config_from_env, oline_config_dir, oline_config_toml_path},
    deployer::OLineDeployer,
    with_examples,
};
use akash_deploy_rs::{AkashBackend as _, substitute_partial, DeploymentStore, FileDeploymentStore};
use std::error::Error;

// ── Clap arg structs ───────────────────────────────────────────────────────

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct ProxyArgs {
        #[command(subcommand)]
        pub cmd: ProxySubcommand,
    }
    => "../../docs/examples/proxy.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum ProxySubcommand {
    /// Deploy the provider-proxy-node SDL as a protected specialty deployment
    Deploy,
    /// Show proxy deployment status and on-chain health
    Status,
    /// Print the proxy's public URL
    Url,
}

// ── Dispatcher ─────────────────────────────────────────────────────────────

pub async fn cmd_proxy(args: &ProxyArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        ProxySubcommand::Deploy => cmd_proxy_deploy().await,
        ProxySubcommand::Status => cmd_proxy_status().await,
        ProxySubcommand::Url => cmd_proxy_url(),
    }
}

// ── proxy deploy ───────────────────────────────────────────────────────────

async fn cmd_proxy_deploy() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Proxy: Deploy Provider-Proxy-Node ===\n");

    // 1. Unlock mnemonic interactively (never pipe credentials)
    let (mnemonic, password) = unlock_mnemonic()?;
    let config = build_config_from_env(mnemonic, None);

    // 2. Locate and render the SDL template
    let sdl_dir = {
        let home_templates = oline_config_dir().join("templates");
        if home_templates.exists() {
            home_templates
        } else {
            std::path::PathBuf::from("templates/sdls/oline")
        }
    };
    let sdl_path = sdl_dir.join("provider-proxy-node.yml");
    if !sdl_path.exists() {
        return Err(format!(
            "SDL template not found at {}. Install templates to ~/.oline/templates/.",
            sdl_path.display()
        )
        .into());
    }

    let raw_sdl = std::fs::read_to_string(&sdl_path)
        .map_err(|e| format!("Cannot read SDL {}: {}", sdl_path.display(), e))?;

    let vars = config.to_sdl_vars();
    let rendered = substitute_partial(&raw_sdl, &vars);

    tracing::info!("  SDL template: {}", sdl_path.display());
    tracing::info!("  Rendered SDL:  {} bytes", rendered.len());

    // 3. Build deployer and run interactive deployment
    let deployer = OLineDeployer::new(config, password).await?;

    deployer.preflight_check().await?;

    let label = "provider-proxy-node";

    let (state, bids) = deployer
        .deploy_phase_until_bids(&rendered, &vars, label)
        .await
        .map_err(|e| format!("Deployment failed: {}", e))?;

    let dseq = state.dseq.unwrap_or(0);

    if bids.is_empty() {
        return Err("No bids received. Check provider availability and SDL resources.".into());
    }

    // Print bids for interactive selection
    tracing::info!("\n  DSEQ: {}", dseq);
    tracing::info!("  {} bid(s) received:\n", bids.len());

    for (i, bid) in bids.iter().enumerate() {
        let price_akt = bid.price as f64 / 1_000_000.0;
        let info: Option<akash_deploy_rs::ProviderInfo> = deployer
            .client
            .query_provider_info(&bid.provider)
            .await
            .ok()
            .flatten();
        let host = info
            .as_ref()
            .map(|i| i.host_uri.as_str())
            .unwrap_or("unknown");

        tracing::info!(
            "  [{}] {} — {:.6} AKT/block — {}",
            i, bid.provider, price_akt, host
        );
    }

    // Interactive provider selection (never pipe credentials)
    let selected_idx = if bids.len() == 1 {
        tracing::info!("\n  Auto-selecting single bidder.");
        0
    } else {
        use std::io::{self, Write};
        print!("\n  Select provider [0-{}]: ", bids.len() - 1);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        input
            .trim()
            .parse::<usize>()
            .map_err(|_| "Invalid selection")?
    };

    if selected_idx >= bids.len() {
        return Err(format!("Invalid selection: {}", selected_idx).into());
    }

    let provider = &bids[selected_idx].provider;
    tracing::info!("  Selected provider: {}", provider);

    // Complete deployment
    use akash_deploy_rs::DeploymentWorkflow;
    let mut state = state;

    DeploymentWorkflow::<akash_deploy_rs::AkashClient>::select_provider(
        &mut state,
        provider,
    )?;

    let endpoints = deployer
        .deploy_phase_complete(&mut state, label)
        .await
        .map_err(|e| format!("Deployment failed: {}", e))?;

    tracing::info!("\n  Deployment complete!");
    tracing::info!("  DSEQ: {}", dseq);
    for ep in &endpoints {
        tracing::info!(
            "  Endpoint: {} ({}:{})",
            ep.uri, ep.service, ep.port
        );
    }

    // 4. Derive the proxy URL from endpoints
    let proxy_url = endpoints
        .iter()
        .find(|ep| ep.port == 443 || ep.port == 3000)
        .map(|ep| {
            if ep.uri.starts_with("http") {
                ep.uri.clone()
            } else {
                format!("https://{}", ep.uri)
            }
        })
        .unwrap_or_default();

    // 5. Save proxy.json with protection
    let deployment = ProxyDeployment {
        dseq,
        protected: true,
        url: proxy_url.clone(),
    };
    save_proxy_deployment(&deployment)?;
    tracing::info!("  Saved proxy record to ~/.oline/proxy.json (protected)");

    // 6. Update [proxy] section in config.toml
    if let Err(e) = update_proxy_config_toml(dseq, &proxy_url) {
        tracing::warn!("  Could not update config.toml: {}", e);
    } else {
        tracing::info!("  Updated [proxy] in config.toml");
    }

    // 7. Save deployment record
    if let Ok(record) = akash_deploy_rs::DeploymentRecord::from_state(&state, &deployer.password) {
        let mut store = FileDeploymentStore::new_default().await?;
        store.save(&record).await?;
        tracing::info!("  Saved deployment record for DSEQ {}", dseq);
    }

    tracing::info!("\n  Proxy URL: {}", proxy_url);
    tracing::info!("  Run `oline proxy status` to check health.");

    Ok(())
}

// ── proxy status ───────────────────────────────────────────────────────────

async fn cmd_proxy_status() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Proxy: Status ===\n");

    let deployment = load_proxy_deployment()?;

    tracing::info!("  DSEQ:       {}", deployment.dseq);
    tracing::info!("  URL:        {}", deployment.url);
    tracing::info!("  Protected:  {}", deployment.protected);

    // Check local deployment store for more details
    let store = FileDeploymentStore::new_default().await?;
    if let Ok(Some(record)) = store.load(deployment.dseq).await {
        tracing::info!("  Label:      {}", record.label);
        if let Some(ref provider) = record.selected_provider {
            tracing::info!("  Provider:   {}", provider);
        }
    }

    // Query on-chain status
    let (mnemonic, _password) = unlock_mnemonic()?;
    let config = build_config_from_env(mnemonic.clone(), None);
    let grpc = {
        let ep = config.val("OLINE_GRPC_ENDPOINT");
        if ep.starts_with("https://") || ep.starts_with("http://") {
            ep
        } else {
            format!("https://{}", ep)
        }
    };

    let owner = crate::accounts::child_address_str(&mnemonic, 0, "akash")
        .map_err(|e| format!("Failed to derive address: {}", e))?;

    use akash_deploy_rs::gen::akash::deployment::v1beta4::{
        query_client::QueryClient as DeployQueryClient, DeploymentFilters,
        QueryDeploymentsRequest,
    };

    let mut deploy_client = DeployQueryClient::connect(grpc)
        .await
        .map_err(|e| format!("Failed to connect gRPC: {}", e))?;

    let resp = deploy_client
        .deployments(QueryDeploymentsRequest {
            filters: Some(DeploymentFilters {
                owner,
                dseq: deployment.dseq,
                state: String::new(),
            }),
            pagination: None,
        })
        .await
        .map_err(|e| format!("Deployment query failed: {}", e))?;

    let deployments = resp.into_inner().deployments;
    if deployments.is_empty() {
        tracing::warn!("  On-chain:   NOT FOUND (may have been closed)");
    } else {
        let dep = &deployments[0];
        let state_str = dep
            .deployment
            .as_ref()
            .map(|d| {
                // state field is an i32 enum: 0=invalid, 1=active, 2=closed
                match d.state {
                    1 => "ACTIVE",
                    2 => "CLOSED",
                    _ => "UNKNOWN",
                }
            })
            .unwrap_or("UNKNOWN");
        tracing::info!("  On-chain:   {}", state_str);
    }

    Ok(())
}

// ── proxy url ──────────────────────────────────────────────────────────────

fn cmd_proxy_url() -> Result<(), Box<dyn Error>> {
    let deployment = load_proxy_deployment()?;
    if deployment.url.is_empty() {
        return Err("Proxy URL not set. Run `oline proxy deploy` first.".into());
    }
    println!("{}", deployment.url);
    Ok(())
}

// ── helpers ────────────────────────────────────────────────────────────────

/// Load the proxy deployment record from ~/.oline/proxy.json.
fn load_proxy_deployment() -> Result<ProxyDeployment, Box<dyn Error>> {
    let path = oline_config_dir().join("proxy.json");
    if !path.exists() {
        return Err("No proxy deployment found. Run `oline proxy deploy` first.".into());
    }
    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let dep: ProxyDeployment = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to parse proxy.json: {}", e))?;
    Ok(dep)
}

/// Update the [proxy] section in ~/.oline/config.toml with the deployed URL and DSEQ.
fn update_proxy_config_toml(dseq: u64, url: &str) -> Result<(), Box<dyn Error>> {
    let path = oline_config_toml_path();
    if !path.exists() {
        // Also try local config.toml
        let local = std::path::Path::new("config.toml");
        if local.exists() {
            return update_toml_proxy_fields(local, dseq, url);
        }
        return Err("No config.toml found".into());
    }
    update_toml_proxy_fields(&path, dseq, url)
}

/// Read a TOML file, update proxy.url, proxy.dseq, proxy.enabled, and write back.
fn update_toml_proxy_fields(
    path: &std::path::Path,
    dseq: u64,
    url: &str,
) -> Result<(), Box<dyn Error>> {
    let content = std::fs::read_to_string(path)?;
    let mut doc: toml::Value = content.parse()?;

    if let Some(table) = doc.as_table_mut() {
        let proxy = table
            .entry("proxy")
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
        if let Some(proxy_table) = proxy.as_table_mut() {
            proxy_table.insert("url".into(), toml::Value::String(url.to_string()));
            proxy_table.insert("dseq".into(), toml::Value::Integer(dseq as i64));
            proxy_table.insert("enabled".into(), toml::Value::Boolean(true));
        }
    }

    // Serialize back — toml crate produces valid TOML
    let output = toml::to_string_pretty(&doc)?;
    std::fs::write(path, output)?;
    Ok(())
}
