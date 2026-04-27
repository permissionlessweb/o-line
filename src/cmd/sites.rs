//! `oline sites` — IPFS static website management via MinIO-IPFS on Akash.

use crate::{
    akash::build_ipfs_site_vars,
    cli::*,
    config::*,
    deployer::OLineDeployer,
    dns::cloudflare::{cloudflare_set_dnslink, cloudflare_upsert_cname},
    snapshots::s3_request,
    sites::{SiteRecord, SiteStore},
    with_examples,
};
use akash_deploy_rs::ServiceEndpoint;
use std::{
    error::Error,
    io::{self, BufRead},
    path::Path,
};

// ── Clap arg structs ──────────────────────────────────────────────────────────

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct SitesArgs {
        #[command(subcommand)]
        pub cmd: SiteSubcommand,
    }
    => "../../docs/examples/sites.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum SiteSubcommand {
    /// Deploy a standalone MinIO-IPFS gateway on Akash
    Deploy,
    /// Upload a local file or directory to the site's S3 bucket
    Upload {
        /// Site domain (must already be deployed)
        domain: String,
        /// Local file or directory to upload
        path: String,
        /// S3 key prefix / path inside the bucket (optional)
        #[arg(long, default_value = "")]
        prefix: String,
    },
    /// Set DNSLink TXT record to point a domain at an IPFS CID
    Publish {
        /// Site domain
        domain: String,
        /// IPFS CID to publish (e.g. bafybeig6xv...)
        cid: String,
    },
    /// List managed IPFS sites
    List,
}

// ── cmd_sites (entry point) ───────────────────────────────────────────────────

pub async fn cmd_sites(args: &SitesArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        SiteSubcommand::Deploy => cmd_sites_deploy().await,
        SiteSubcommand::Upload { domain, path, prefix } => {
            cmd_sites_upload(domain, path, prefix).await
        }
        SiteSubcommand::Publish { domain, cid } => cmd_sites_publish(domain, cid).await,
        SiteSubcommand::List => cmd_sites_list(),
    }
}

// ── deploy ────────────────────────────────────────────────────────────────────

async fn cmd_sites_deploy() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Deploy IPFS Site Gateway ===\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    // Credentials
    let (mnemonic, password) = unlock_mnemonic()?;

    // Site config
    let domain = read_input(
        &mut lines,
        "Site domain (e.g. mysite.example.com)",
        None,
    )?;
    if domain.is_empty() {
        return Err("Domain is required.".into());
    }

    let default_bucket = domain.split('.').next().unwrap_or("site").to_string();
    let bucket = read_input(&mut lines, "S3 bucket name", Some(&default_bucket))?;
    let bucket = if bucket.is_empty() { default_bucket } else { bucket };

    let cf_zone_id_default = std::env::var("OLINE_CF_ZONE_ID").unwrap_or_default();
    let cf_zone_id = read_input(
        &mut lines,
        "Cloudflare zone ID (leave blank to skip DNS)",
        if cf_zone_id_default.is_empty() { None } else { Some(&cf_zone_id_default) },
    )?;

    let cf_token = if !cf_zone_id.is_empty() {
        let tok = std::env::var("OLINE_CF_API_TOKEN").unwrap_or_default();
        if tok.is_empty() {
            read_input(&mut lines, "Cloudflare API token", None)?
        } else {
            tok
        }
    } else {
        String::new()
    };

    // Load config
    let config = collect_config(&password, mnemonic, &mut lines, None).await?;
    drop(lines);

    // Build SDL vars
    let vars = build_ipfs_site_vars(&config, &domain, &bucket);

    // Deploy
    let deployer = OLineDeployer::new(config, password.clone())
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    let sdl_template = deployer.config.load_sdl("g.yml")
        .map_err(|e| format!("Failed to load g.yml: {}", e))?;

    let stdin2 = io::stdin();
    let mut lines2 = stdin2.lock().lines();

    tracing::info!("\n  Deploying MinIO-IPFS gateway to Akash...");
    let (state, endpoints) = deployer
        .deploy_phase_with_selection(&sdl_template, &vars, "IPFS Gateway", &mut lines2)
        .await
        .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;

    // Find the ingress endpoint (port 80) — Akash provider returns ingress hostname
    let ingress_ep = find_global_endpoint(&endpoints, 80);

    tracing::info!("\n  Deployment complete!");
    tracing::info!("  DSEQ:           {}", state.dseq.unwrap_or(0));
    if let Some(ref ep) = ingress_ep {
        tracing::info!("  Ingress:        {}", ep.uri);
    }

    let gw_domain = vars.get("SITES_GATEWAY_DOMAIN").cloned().unwrap_or_default();
    let s3_domain = vars.get("SITES_S3_DOMAIN").cloned().unwrap_or_default();
    let console_domain = vars.get("SITES_CONSOLE_DOMAIN").cloned().unwrap_or_default();

    tracing::info!("  Gateway:        {}", if gw_domain.is_empty() { "(none)" } else { &gw_domain });
    tracing::info!("  S3:             {}", if s3_domain.is_empty() { "(none)" } else { &s3_domain });
    tracing::info!("  Console:        {}", if console_domain.is_empty() { "(none)" } else { &console_domain });

    // Update DNS CNAMEs for all three domains
    if !cf_zone_id.is_empty() && !cf_token.is_empty() {
        let ingress_host = ingress_ep
            .map(|ep| crate::akash::endpoint_hostname(&ep.uri).to_string())
            .unwrap_or_default();

        if !ingress_host.is_empty() {
            tracing::info!("\n  Updating Cloudflare DNS...");
            for (label, domain_val) in [
                ("Gateway", &gw_domain),
                ("S3", &s3_domain),
                ("Console", &console_domain),
            ] {
                if !domain_val.is_empty() {
                    match cloudflare_upsert_cname(&cf_token, &cf_zone_id, domain_val, &ingress_host).await {
                        Ok(_) => tracing::info!("  {} CNAME {} → {}", label, domain_val, ingress_host),
                        Err(e) => tracing::info!("  Warning: {} DNS failed: {}", label, e),
                    }
                }
            }
        }
    }

    // S3 host: use the DNS domain (stable URL) if available, else fallback to NodePort
    let s3_host = if !s3_domain.is_empty() {
        format!("https://{}", s3_domain)
    } else {
        find_global_endpoint(&endpoints, 9000)
            .map(|ep| ep.uri.clone())
            .unwrap_or_default()
    };

    // Save to encrypted store
    let record = SiteRecord::new(
        domain.clone(),
        state.dseq.unwrap_or(0),
        bucket.clone(),
        vars["S3_KEY"].clone(),
        vars["S3_SECRET"].clone(),
        s3_host,
        cf_zone_id,
    );

    let store = SiteStore::open(SiteStore::default_path(), &password);
    store.add(record)?;

    tracing::info!("\n  Site record saved to {:?}", SiteStore::default_path());
    tracing::info!("  Next steps:");
    tracing::info!("    Upload assets:  oline sites upload {} ./dist/", domain);
    tracing::info!("    Publish CID:    oline sites publish {} <cid>", domain);

    Ok(())
}

// ── upload ────────────────────────────────────────────────────────────────────

async fn cmd_sites_upload(
    domain: &str,
    local_path: &str,
    prefix: &str,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Upload to IPFS Site ===\n");

    let password = rpassword::prompt_password("Site store password: ")?;
    let store = SiteStore::open(SiteStore::default_path(), &password);
    let record = store
        .get(domain)?
        .ok_or_else(|| format!("No site found for domain '{}'. Run `oline sites deploy` first.", domain))?;

    let client = reqwest::Client::new();
    let region = "us-east-1";
    let path = Path::new(local_path);

    let files = collect_upload_files(path)?;
    if files.is_empty() {
        tracing::info!("  No files found at {}", local_path);
        return Ok(());
    }

    tracing::info!(
        "  Uploading {} file(s) to s3://{}/{} ...\n",
        files.len(),
        record.bucket,
        prefix
    );

    let mut uploaded = 0usize;
    let mut failed = 0usize;

    for (file_path, object_key_suffix) in &files {
        let object_key = if prefix.is_empty() {
            object_key_suffix.clone()
        } else {
            format!("{}/{}", prefix.trim_matches('/'), object_key_suffix)
        };

        let data = std::fs::read(file_path)?;
        let url = format!(
            "{}/{}/{}",
            record.s3_host.trim_end_matches('/'),
            record.bucket,
            object_key
        );

        let _content_type = guess_content_type(&object_key);

        match s3_request(
            &client,
            reqwest::Method::PUT,
            &url,
            &data,
            &record.s3_key,
            &record.s3_secret,
            region,
        )
        .await
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("  ✓  {}", object_key);
                uploaded += 1;
            }
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                tracing::info!("  ✗  {} (HTTP {}): {}", object_key, status, &body[..body.len().min(120)]);
                failed += 1;
            }
            Err(e) => {
                tracing::info!("  ✗  {}: {}", object_key, e);
                failed += 1;
            }
        }
    }

    tracing::info!(
        "\n  Uploaded: {}  Failed: {}",
        uploaded,
        failed
    );

    if failed == 0 {
        tracing::info!("\n  All files uploaded successfully.");
        tracing::info!("  Files are auto-pinned to IPFS by the gateway (~{}s interval).", 300);
        tracing::info!("  Once pinned, get the CID from your IPFS node and run:");
        tracing::info!("    oline sites publish {} <cid>", domain);
    }

    Ok(())
}

// ── publish ───────────────────────────────────────────────────────────────────

async fn cmd_sites_publish(domain: &str, cid: &str) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Publish IPFS Site ===\n");
    tracing::info!("  Domain: {}", domain);
    tracing::info!("  CID:    {}", cid);

    let cf_token = std::env::var("OLINE_CF_API_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("OLINE_CF_API_TOKEN not set")?;

    let password = rpassword::prompt_password("Site store password: ")?;
    let store = SiteStore::open(SiteStore::default_path(), &password);
    let record = store
        .get(domain)?
        .ok_or_else(|| format!("No site found for '{}'. Run `oline sites deploy` first.", domain))?;

    if record.cf_zone_id.is_empty() {
        return Err(
            "No Cloudflare zone ID saved for this site. Set OLINE_CF_ZONE_ID and re-deploy.".into(),
        );
    }

    tracing::info!("\n  Updating Cloudflare DNS...");
    cloudflare_set_dnslink(&cf_token, &record.cf_zone_id, domain, cid).await?;

    // Persist updated CID
    store.update(domain, |r| r.cid = cid.to_string())?;

    tracing::info!("\n  Published! Site is now live at:");
    tracing::info!("    https://{}", domain);
    tracing::info!("  (DNS propagation may take 1-2 minutes)");

    Ok(())
}

// ── list ──────────────────────────────────────────────────────────────────────

fn cmd_sites_list() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== IPFS Sites ===\n");

    let password = rpassword::prompt_password("Site store password: ")?;
    let store = SiteStore::open(SiteStore::default_path(), &password);
    let records = store.load()?;

    if records.is_empty() {
        tracing::info!("  No sites found. Run `oline sites deploy` to create one.");
        return Ok(());
    }

    tracing::info!(
        "  {:<35} {:<12} {:<55}",
        "Domain",
        "DSEQ",
        "CID"
    );
    tracing::info!("  {:-<105}", "");

    for r in &records {
        let cid = if r.cid.is_empty() {
            "(not published)".to_string()
        } else if r.cid.len() > 52 {
            format!("{}...", &r.cid[..52])
        } else {
            r.cid.clone()
        };
        tracing::info!("  {:<35} {:<12} {}", r.domain, r.dseq, cid);
    }

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Find a globally-exposed endpoint by its internal port.
fn find_global_endpoint(endpoints: &[ServiceEndpoint], internal_port: u16) -> Option<&ServiceEndpoint> {
    endpoints.iter().find(|e| e.internal_port == internal_port)
}

/// Collect (file_path, object_key_suffix) pairs for upload.
/// If `path` is a file, returns one entry with the filename as key.
/// If `path` is a directory, recursively walks it and uses relative paths as keys.
fn collect_upload_files(
    path: &Path,
) -> Result<Vec<(std::path::PathBuf, String)>, Box<dyn Error>> {
    let mut result = Vec::new();
    if path.is_file() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        result.push((path.to_path_buf(), name));
    } else if path.is_dir() {
        walk_dir(path, path, &mut result)?;
    } else {
        return Err(format!("'{}' is not a file or directory", path.display()).into());
    }
    Ok(result)
}

fn walk_dir(
    base: &Path,
    current: &Path,
    out: &mut Vec<(std::path::PathBuf, String)>,
) -> Result<(), Box<dyn Error>> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            walk_dir(base, &p, out)?;
        } else if p.is_file() {
            let rel = p.strip_prefix(base)?.to_string_lossy().to_string();
            // Normalize path separators to forward slashes
            let key = rel.replace('\\', "/");
            out.push((p, key));
        }
    }
    Ok(())
}

/// Guess a Content-Type header value from the file extension.
fn guess_content_type(key: &str) -> &'static str {
    match key.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "wasm" => "application/wasm",
        "txt" | "md" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
