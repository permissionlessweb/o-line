use crate::{
    providers::{TrustedProvider, TrustedProviderStore},
    with_examples,
};
use clap::Subcommand;
use std::error::Error;

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct ProvidersArgs {
        #[command(subcommand)]
        pub cmd: ProvidersSubcommand,
    }
    => "../../docs/examples/providers.md"
}

#[derive(Subcommand, Debug)]
pub enum ProvidersSubcommand {
    /// List all trusted providers.
    List,
    /// Add a provider to the trusted list (fetches provider info from chain).
    Add {
        /// Provider address (akash1...) or alias of an existing entry to update.
        address: String,
        /// Optional human-readable alias (e.g. "mycloud", "prod-eu").
        #[arg(long)]
        alias: Option<String>,
        /// Free-form notes (region, tier, reason for trusting, etc.).
        #[arg(long)]
        notes: Option<String>,
        /// RPC endpoint to query provider info from. Defaults to AKASH_NODE env var.
        #[arg(long)]
        rpc: Option<String>,
    },
    /// Remove a provider from the trusted list.
    Remove {
        /// Provider address (akash1...) or alias.
        query: String,
    },
    /// Show detailed info for a trusted provider.
    Inspect {
        /// Provider address (akash1...) or alias.
        query: String,
        /// RPC endpoint. Defaults to AKASH_NODE env var.
        #[arg(long)]
        rpc: Option<String>,
    },
    /// Print the path to the trusted providers file.
    Path,
}

pub async fn cmd_providers(args: &ProvidersArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        ProvidersSubcommand::List => cmd_providers_list(),
        ProvidersSubcommand::Add {
            address,
            alias,
            notes,
            rpc,
        } => cmd_providers_add(address, alias.as_deref(), notes.as_deref(), rpc.as_deref()).await,
        ProvidersSubcommand::Remove { query } => cmd_providers_remove(query),
        ProvidersSubcommand::Inspect { query, rpc } => {
            cmd_providers_inspect(query, rpc.as_deref()).await
        }
        ProvidersSubcommand::Path => {
            println!("{}", TrustedProviderStore::default_path().display());
            Ok(())
        }
    }
}

// ── List ──────────────────────────────────────────────────────────────────────

fn cmd_providers_list() -> Result<(), Box<dyn Error>> {
    let store = TrustedProviderStore::open(TrustedProviderStore::default_path());
    let providers = store.load();

    if providers.is_empty() {
        tracing::info!("No trusted providers saved.");
        tracing::info!("Add one with:  oline providers add <akash1...>");
        return Ok(());
    }

    tracing::info!("Trusted providers ({}):", providers.len());
    tracing::info!(
        "  {:<22}  {:<18}  {:<40}",
        "ALIAS / ADDRESS",
        "ADDED",
        "HOST"
    );
    tracing::info!("  {}", "─".repeat(84));

    for p in &providers {
        let label = p
            .alias
            .as_deref()
            .unwrap_or_else(|| &p.address[..p.address.len().min(20)]);
        // Format Unix timestamp as YYYY-MM-DD without chrono.
        let added_date = format_unix_date(p.added_at);
        tracing::info!(
            "  {:<22}  {:<12}  {}",
            label,
            added_date,
            p.host_uri
        );
        if p.alias.is_some() {
            tracing::info!("    address: {}", p.address);
        }
        if let Some(ref notes) = p.notes {
            tracing::info!("    notes:   {}", notes);
        }
    }
    Ok(())
}

// ── Add ───────────────────────────────────────────────────────────────────────

async fn cmd_providers_add(
    address: &str,
    alias: Option<&str>,
    notes: Option<&str>,
    rpc: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let rpc_url = rpc
        .map(|s| s.to_string())
        .or_else(|| std::env::var("AKASH_NODE").ok())
        .unwrap_or_else(|| "http://rpc.akashnet.net:443".into());

    tracing::info!("  Querying provider info for {} ...", address);

    // Try to fetch provider metadata; proceed with empty host if unavailable.
    let host_uri = match fetch_provider_host(&rpc_url, address).await {
        Ok(Some(host)) => {
            tracing::info!("  host_uri: {}", host);
            host
        }
        Ok(None) => {
            tracing::info!("  Provider not found on chain — saving address only.");
            String::new()
        }
        Err(e) => {
            tracing::warn!("  Could not query provider info ({}); saving without host.", e);
            String::new()
        }
    };

    let mut p = TrustedProvider::new(address, host_uri);
    p.alias = alias.map(str::to_string);
    p.notes = notes.map(str::to_string);

    let store = TrustedProviderStore::open(TrustedProviderStore::default_path());
    store.add(p)?;

    let path = TrustedProviderStore::default_path();
    tracing::info!("  Saved to {}", path.display());
    Ok(())
}

// ── Remove ────────────────────────────────────────────────────────────────────

fn cmd_providers_remove(query: &str) -> Result<(), Box<dyn Error>> {
    let store = TrustedProviderStore::open(TrustedProviderStore::default_path());
    match store.remove(query)? {
        0 => tracing::info!("  No provider matched '{}'.", query),
        n => tracing::info!("  Removed {} entry/entries matching '{}'.", n, query),
    }
    Ok(())
}

// ── Inspect ───────────────────────────────────────────────────────────────────

async fn cmd_providers_inspect(query: &str, rpc: Option<&str>) -> Result<(), Box<dyn Error>> {
    let store = TrustedProviderStore::open(TrustedProviderStore::default_path());
    let local = store.find(query);

    // Resolve address: use local entry or treat query as raw address.
    let address = local
        .as_ref()
        .map(|p| p.address.as_str())
        .unwrap_or(query);

    let rpc_url = rpc
        .map(|s| s.to_string())
        .or_else(|| std::env::var("AKASH_NODE").ok())
        .unwrap_or_else(|| "http://rpc.akashnet.net:443".into());

    if let Some(ref p) = local {
        tracing::info!("Trusted provider entry:");
        tracing::info!("  address:  {}", p.address);
        tracing::info!("  host:     {}", p.host_uri);
        if let Some(ref a) = p.alias {
            tracing::info!("  alias:    {}", a);
        }
        if let Some(ref n) = p.notes {
            tracing::info!("  notes:    {}", n);
        }
    } else {
        tracing::info!("(Not in trusted list — querying chain only)");
    }

    tracing::info!("\nLive chain info for {}:", address);
    match fetch_provider_details(&rpc_url, address).await {
        Ok(Some(info)) => {
            tracing::info!("  host_uri: {}", info.host_uri);
            tracing::info!("  email:    {}", info.email);
            tracing::info!("  website:  {}", info.website);
            for (k, v) in &info.attributes {
                tracing::info!("  {:.<32} {}", format!("{}  ", k), v);
            }
        }
        Ok(None) => tracing::info!("  (provider not found on chain)"),
        Err(e) => tracing::warn!("  Could not query chain: {}", e),
    }
    Ok(())
}

// ── Chain query helpers ───────────────────────────────────────────────────────

/// Query provider host URI using the deployer's AkashClient.
/// Requires OLINE_MNEMONIC (or prompts) + AKASH_NODE to be set.
async fn fetch_provider_host(
    rpc: &str,
    address: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    Ok(fetch_provider_details(rpc, address)
        .await?
        .map(|i| i.host_uri))
}

async fn fetch_provider_details(
    rpc: &str,
    address: &str,
) -> Result<Option<akash_deploy_rs::ProviderInfo>, Box<dyn Error>> {
    use akash_deploy_rs::{AkashBackend, AkashClient};
    // Use a throwaway mnemonic for read-only provider info queries.
    // The mnemonic is never used for signing here.
    let dummy = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let client = AkashClient::new_from_mnemonic(dummy, rpc, "")
        .await
        .map_err(|e| format!("Could not connect to {}: {}", rpc, e))?;
    Ok(client.query_provider_info(address).await?)
}

/// Format a Unix epoch (seconds) as YYYY-MM-DD without external crates.
fn format_unix_date(ts: u64) -> String {
    // Days from 1970-01-01
    let days = ts / 86400;
    // Gregorian calendar calculation
    let mut y = 1970u64;
    let mut d = days;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let ydays = if leap { 366 } else { 365 };
        if d < ydays {
            break;
        }
        d -= ydays;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days: [u64; 12] = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 1u64;
    for &md in &month_days {
        if d < md {
            break;
        }
        d -= md;
        m += 1;
    }
    format!("{:04}-{:02}-{:02}", y, m, d + 1)
}
