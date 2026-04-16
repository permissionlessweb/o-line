//! `oline brain` — Generate and publish the terp-brain knowledge site.

use crate::{
    // dns::cloudflare::cloudflare_set_dnslink is needed once CID retrieval is wired (see TODO)
    sites::SiteStore,
    snapshots::s3_request,
    with_examples,
};
use std::{
    error::Error,
    io::{Read as _, Write as _},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

// ── Constants ─────────────────────────────────────────────────────────────────

const BRAIN_DOMAIN: &str = "brain.terp.network";
// const DNSLINK_NAME: &str = "_dnslink.brain.terp.network"; // used once CID retrieval is wired
const DEFAULT_PREVIEW_PORT: u16 = 8080;

// ── Clap arg structs ──────────────────────────────────────────────────────────

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct BrainArgs {
        #[command(subcommand)]
        pub cmd: BrainSubcommand,
    }
    => "../../docs/examples/brain.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum BrainSubcommand {
    /// Generate static site from terp-brain markdown nodes
    Build,
    /// Upload to MinIO-IPFS and update DNSLink
    Publish,
    /// Build + publish in one step
    Deploy,
    /// Local HTTP preview server
    Preview {
        /// Port to listen on
        #[arg(long, default_value_t = DEFAULT_PREVIEW_PORT)]
        port: u16,
    },
}

// ── cmd_brain (entry point) ───────────────────────────────────────────────────

pub async fn cmd_brain(args: &BrainArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        BrainSubcommand::Build => cmd_brain_build(),
        BrainSubcommand::Publish => cmd_brain_publish().await,
        BrainSubcommand::Deploy => cmd_brain_deploy().await,
        BrainSubcommand::Preview { port } => cmd_brain_preview(*port),
    }
}

// ── build ─────────────────────────────────────────────────────────────────────

fn resolve_brain_path() -> PathBuf {
    std::env::var("TERP_BRAIN_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("terp-brain/nodes")
        })
}

fn resolve_dist_path() -> PathBuf {
    std::env::var("BRAIN_DIST_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("dist/brain"))
}

fn resolve_graphify_path() -> Option<PathBuf> {
    std::env::var("GRAPHIFY_PATH")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            let default = dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("terp-core/graphify-out/graph.json");
            if default.exists() {
                Some(default)
            } else {
                None
            }
        })
}

fn resolve_build_script() -> PathBuf {
    std::env::var("OLINE_BRAIN_SCRIPT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("scripts/brain/build.py"))
}

fn cmd_brain_build() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Brain Build ===\n");

    let script = resolve_build_script();
    let brain_path = resolve_brain_path();
    let dist_path = resolve_dist_path();

    tracing::info!("  Script:  {}", script.display());
    tracing::info!("  Source:  {}", brain_path.display());
    tracing::info!("  Output:  {}", dist_path.display());

    if !script.exists() {
        return Err(format!(
            "Build script not found: {}\nSet OLINE_BRAIN_SCRIPT to override.",
            script.display()
        )
        .into());
    }

    if !brain_path.exists() {
        return Err(format!(
            "Brain source not found: {}\nSet TERP_BRAIN_PATH to override.",
            brain_path.display()
        )
        .into());
    }

    // Ensure output directory exists
    std::fs::create_dir_all(&dist_path)?;

    let mut cmd = Command::new("python3");
    cmd.arg(&script)
        .arg("--source")
        .arg(&brain_path)
        .arg("--output")
        .arg(&dist_path);

    if let Some(graphify_path) = resolve_graphify_path() {
        tracing::info!("  Graphify: {}", graphify_path.display());
        cmd.arg("--graphify").arg(&graphify_path);
    }

    tracing::info!("");

    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    let status = cmd.status()?;
    if !status.success() {
        return Err(format!(
            "Build script exited with status: {}",
            status.code().unwrap_or(-1)
        )
        .into());
    }

    tracing::info!("\n  Build complete: {}", dist_path.display());
    Ok(())
}

// ── publish ───────────────────────────────────────────────────────────────────

async fn cmd_brain_publish() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Brain Publish ===\n");

    let dist_path = resolve_dist_path();
    if !dist_path.exists() {
        return Err(format!(
            "Dist directory not found: {}\nRun `oline brain build` first.",
            dist_path.display()
        )
        .into());
    }

    // Open sites store to get S3 credentials & Cloudflare zone
    let password = rpassword::prompt_password("Site store password: ")?;
    let store = SiteStore::open(SiteStore::default_path(), &password);
    let record = store.get(BRAIN_DOMAIN)?.ok_or_else(|| {
        format!(
            "No site found for '{}'. Run `oline sites deploy` first to set up the IPFS gateway.",
            BRAIN_DOMAIN
        )
    })?;

    // Upload files using the same S3 upload logic as `oline sites upload`
    let client = reqwest::Client::new();
    let region = "us-east-1";

    let files = collect_upload_files(&dist_path)?;
    if files.is_empty() {
        return Err("No files found in dist directory.".into());
    }

    tracing::info!(
        "  Uploading {} file(s) to s3://{} ...\n",
        files.len(),
        record.bucket,
    );

    let mut uploaded = 0usize;
    let mut failed = 0usize;

    for (file_path, object_key) in &files {
        let data = std::fs::read(file_path)?;
        let url = format!(
            "{}/{}/{}",
            record.s3_host.trim_end_matches('/'),
            record.bucket,
            object_key
        );

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
                tracing::info!(
                    "  ✗  {} (HTTP {}): {}",
                    object_key,
                    status,
                    &body[..body.len().min(120)]
                );
                failed += 1;
            }
            Err(e) => {
                tracing::info!("  ✗  {}: {}", object_key, e);
                failed += 1;
            }
        }
    }

    tracing::info!("\n  Uploaded: {}  Failed: {}", uploaded, failed);

    if failed > 0 {
        return Err(format!("{} file(s) failed to upload.", failed).into());
    }

    // TODO: Retrieve the IPFS CID from the MinIO-IPFS gateway.
    // The exact API depends on the gateway's pinning/CID endpoint.
    // For now, we log a placeholder and skip DNSLink update.
    //
    // Once wired, the flow is:
    //   1. GET <gateway>/api/v0/pin/ls?arg=<bucket-root> or similar
    //   2. Extract the root CID
    //   3. Call cloudflare_set_dnslink() below
    tracing::info!("\n  Files uploaded. Waiting for IPFS pin...");
    tracing::info!("  Auto-pin interval is ~300s. Once pinned, retrieve the CID and run:");
    tracing::info!("    oline sites publish {} <cid>", BRAIN_DOMAIN);
    tracing::info!(
        "\n  (Automatic CID retrieval + DNSLink update coming soon — see TODO in brain.rs)"
    );

    // When CID retrieval is implemented, uncomment:
    // let cid = retrieve_ipfs_cid(&record).await?;
    // let cf_token = std::env::var("OLINE_CF_API_TOKEN")
    //     .ok()
    //     .filter(|s| !s.is_empty())
    //     .ok_or("OLINE_CF_API_TOKEN not set")?;
    // cloudflare_set_dnslink(&cf_token, &record.cf_zone_id, BRAIN_DOMAIN, &cid).await?;
    // store.update(BRAIN_DOMAIN, |r| r.cid = cid.clone())?;
    // tracing::info!("\n  Published!");
    // tracing::info!("  CID: {}", cid);
    // tracing::info!("  URL: https://{}", BRAIN_DOMAIN);

    Ok(())
}

// ── deploy ────────────────────────────────────────────────────────────────────

async fn cmd_brain_deploy() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Brain Deploy (build + publish) ===\n");
    cmd_brain_build()?;
    tracing::info!("");
    cmd_brain_publish().await
}

// ── preview ───────────────────────────────────────────────────────────────────

fn cmd_brain_preview(port: u16) -> Result<(), Box<dyn Error>> {
    let dist_path = resolve_dist_path();
    if !dist_path.exists() {
        return Err(format!(
            "Dist directory not found: {}\nRun `oline brain build` first.",
            dist_path.display()
        )
        .into());
    }

    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)?;
    tracing::info!("=== Brain Preview ===");
    tracing::info!("  Serving {} on http://{}", dist_path.display(), addr);
    tracing::info!("  Press Ctrl+C to stop.\n");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let dist = dist_path.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_http_request(&mut stream, &dist) {
                        tracing::debug!("Request error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Accept error: {}", e);
            }
        }
    }

    Ok(())
}

/// Minimal HTTP/1.1 file server for preview.
fn handle_http_request(
    stream: &mut std::net::TcpStream,
    root: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse GET /path HTTP/1.x
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let decoded = path.trim_start_matches('/');
    let file_path = if decoded.is_empty() || decoded.ends_with('/') {
        root.join(decoded).join("index.html")
    } else {
        let candidate = root.join(decoded);
        if candidate.is_dir() {
            candidate.join("index.html")
        } else {
            candidate
        }
    };

    // Security: prevent path traversal
    let canonical = file_path
        .canonicalize()
        .unwrap_or_else(|_| file_path.clone());
    let root_canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    if !canonical.starts_with(&root_canonical) || !canonical.is_file() {
        let body = "404 Not Found";
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes())?;
        return Ok(());
    }

    let data = std::fs::read(&canonical)?;
    let content_type = guess_content_type(canonical.to_str().unwrap_or(""));
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content_type,
        data.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(&data)?;

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Collect (file_path, object_key) pairs for upload, walking the directory recursively.
fn collect_upload_files(root: &Path) -> Result<Vec<(PathBuf, String)>, Box<dyn Error>> {
    let mut result = Vec::new();
    walk_dir(root, root, &mut result)?;
    Ok(result)
}

fn walk_dir(
    base: &Path,
    current: &Path,
    out: &mut Vec<(PathBuf, String)>,
) -> Result<(), Box<dyn Error>> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            walk_dir(base, &p, out)?;
        } else if p.is_file() {
            let rel = p.strip_prefix(base)?.to_string_lossy().to_string();
            let key = rel.replace('\\', "/");
            out.push((p, key));
        }
    }
    Ok(())
}

/// Guess Content-Type from file extension.
fn guess_content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
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
