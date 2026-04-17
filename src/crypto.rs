use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use akash_deploy_rs::ServiceEndpoint;
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use openssh::{KnownHosts, SessionBuilder};
use rand::RngCore;
use ssh_key::LineEnding;
use std::{
    collections::HashMap,
    env::var,
    error::Error,
    fs,
    io::{Read as _, Write as _},
    path::PathBuf,
    process::Stdio,
    thread::sleep,
    time::{Duration, Instant},
};

/// Human-readable byte size (e.g. "1.23 GB", "456.7 MB").
pub fn fmt_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Pipe a local file into an SSH process stdin with progress reporting.
///
/// Returns the exit status. Progress is printed to stderr via `\r` overwrite.
pub fn pipe_file_to_process(
    src: &mut fs::File,
    child: &mut std::process::Child,
    total_bytes: u64,
    label: &str,
) -> std::io::Result<std::process::ExitStatus> {
    let mut stdin = child.stdin.take().expect("stdin not piped");
    let mut buf = [0u8; 256 * 1024]; // 256 KB chunks
    let mut transferred: u64 = 0;
    let start = Instant::now();
    let mut last_print = Instant::now();

    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        stdin.write_all(&buf[..n])?;
        transferred += n as u64;

        // Update progress at most every 500ms
        if last_print.elapsed() >= Duration::from_millis(500) || transferred == total_bytes {
            let elapsed = start.elapsed().as_secs_f64().max(0.001);
            let rate = transferred as f64 / elapsed;
            let pct = if total_bytes > 0 {
                (transferred as f64 / total_bytes as f64 * 100.0).min(100.0)
            } else {
                0.0
            };
            eprint!(
                "\r  [{}] {:.1}%  {} / {}  ({}/s)    ",
                label,
                pct,
                fmt_bytes(transferred),
                fmt_bytes(total_bytes),
                fmt_bytes(rate as u64),
            );
            last_print = Instant::now();
        }
    }
    drop(stdin); // close stdin so remote cat finishes
    eprintln!(); // newline after progress
    child.wait()
}

/// Read from an SSH process stdout into a local file with progress reporting.
///
/// `total_hint`: optional expected size (0 if unknown — shows bytes only, no percentage).
pub fn pipe_process_to_file(
    child: &mut std::process::Child,
    dest: &mut fs::File,
    total_hint: u64,
    label: &str,
) -> std::io::Result<std::process::ExitStatus> {
    let mut stdout = child.stdout.take().expect("stdout not piped");
    let mut buf = [0u8; 256 * 1024];
    let mut transferred: u64 = 0;
    let start = Instant::now();
    let mut last_print = Instant::now();

    loop {
        let n = stdout.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dest.write_all(&buf[..n])?;
        transferred += n as u64;

        if last_print.elapsed() >= Duration::from_millis(500) {
            let elapsed = start.elapsed().as_secs_f64().max(0.001);
            let rate = transferred as f64 / elapsed;
            if total_hint > 0 {
                let pct = (transferred as f64 / total_hint as f64 * 100.0).min(100.0);
                eprint!(
                    "\r  [{}] {:.1}%  {} / {}  ({}/s)    ",
                    label,
                    pct,
                    fmt_bytes(transferred),
                    fmt_bytes(total_hint),
                    fmt_bytes(rate as u64),
                );
            } else {
                eprint!(
                    "\r  [{}] {}  ({}/s)    ",
                    label,
                    fmt_bytes(transferred),
                    fmt_bytes(rate as u64),
                );
            }
            last_print = Instant::now();
        }
    }
    drop(stdout);
    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    let rate = transferred as f64 / elapsed;
    eprintln!(
        "\r  [{}] Done: {} in {:.1}s ({}/s)    ",
        label,
        fmt_bytes(transferred),
        elapsed,
        fmt_bytes(rate as u64),
    );
    child.wait()
}

pub const SALT_LEN: usize = 16; // AES-256-GCM fixed
pub const NONCE_LEN: usize = 12; // AES-256-GCM fixed
pub const S3_SECRET: usize = 40;
pub const S3_KEY: usize = 24;

/// Common SSH arguments optimised for high-throughput file transfers.
///
/// - `aes128-gcm@openssh.com` — fastest cipher on CPUs with AES-NI (~3-5x faster
///   than the default chacha20-poly1305).
/// - `Compression=no` — snapshot data is already lz4/zstd compressed; SSH
///   compression just burns CPU.
/// - `ServerAliveInterval=15` — detect stalled connections quickly.
pub const SSH_FAST_ARGS: &[&str] = &[
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=10",
    "-o", "BatchMode=yes",
    "-o", "Compression=no",
    "-o", "ServerAliveInterval=15",
    "-c", "aes128-gcm@openssh.com",
];

pub fn gen_ssh_key() -> ssh_key::PrivateKey {
    use ssh_key::rand_core::OsRng;
    ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap()
}

pub fn save_ssh_key(k: &ssh_key::PrivateKey, path: &PathBuf) -> Result<(), Box<dyn Error>> {
    // write_openssh_file sets 0o600 permissions automatically on Unix
    k.write_openssh_file(path, LineEnding::LF)
        .map_err(|e| format!("Failed to save SSH private key to {:?}: {}", path, e))?;
    Ok(())
}

/// Load an existing SSH key from `path`, or generate a new one and save it there.
///
/// Returns the private key. Logs whether the key was reused or freshly generated.
pub fn ensure_ssh_key(path: &PathBuf) -> Result<ssh_key::PrivateKey, Box<dyn Error>> {
    if path.exists() {
        let key = ssh_key::PrivateKey::read_openssh_file(path)
            .map_err(|e| format!("Failed to load SSH key from {:?}: {}", path, e))?;
        tracing::info!("  SSH key reused from {:?}", path);
        Ok(key)
    } else {
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create SSH key directory {:?}: {}", parent, e))?;
        }
        let key = gen_ssh_key();
        save_ssh_key(&key, path)?;
        tracing::info!("  SSH key generated → {:?}", path);
        Ok(key)
    }
}
/// Forms `ssh://root@<host>:<port>` from a deployment endpoint URI + forwarded port.
/// Strips any `http://` / `https://` scheme and port suffix from `uri` before use.
pub fn ssh_dest_path(ssh_port: &str, uri: &str) -> String {
    let host = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    // drop any trailing `:port` that may be present in the provider URI
    let host = host.split(':').next().unwrap_or(host);
    format!("ssh://root@{}:{}", host, ssh_port)
}

/// Source for a pre-start file delivery.
#[derive(Clone)]
pub enum FileSource {
    /// File content already in memory — delivered via SFTP.
    /// Use for small files (scripts, configs).
    Bytes(Vec<u8>),
    /// Local filesystem path — streamed via SSH pipe.
    /// Use for large files (snapshots, multi-GB archives).
    Path(std::path::PathBuf),
}

/// A file to deliver to a remote node before its bootstrap process starts.
///
/// `push_pre_start_files` accepts any mix of `Bytes` (SFTP) and `Path` (SSH pipe)
/// sources.  Pass an empty slice to skip delivery entirely.
#[derive(Clone)]
pub struct PreStartFile {
    pub source: FileSource,
    /// Absolute path on the remote host where this file should land.
    /// Parent directories are created automatically.
    pub remote_path: String,
}

/// Upload pre-start files to a deployed node before its bootstrap starts.
///
/// - `Bytes` files are uploaded via SFTP (suitable for small files).
/// - `Path` files are streamed via SSH stdin pipe (suitable for large snapshots).
///
/// An empty `files` slice is a no-op.  `Bytes` uploads are retried up to
/// `max_retries` times; `Path` streams are attempted once (too large to retry).
pub async fn push_pre_start_files(
    label: &str,
    endpoints: &[ServiceEndpoint],
    ssh_key_path: &PathBuf,
    files: &[PreStartFile],
    max_retries: u16,
) -> Result<(), Box<dyn Error>> {
    use openssh_sftp_client::Sftp;
    use std::path::Path;

    if files.is_empty() {
        tracing::info!("  [{}] No pre-start files to push — skipping.", label);
        return Ok(());
    }

    let ssh_port: u16 = var("SSH_P")
        .unwrap_or_else(|_| "22".into())
        .parse()
        .unwrap_or(22);
    let ssh_ep = endpoints
        .iter()
        .find(|e| e.internal_port == ssh_port)
        .ok_or_else(|| format!("[{}] No SSH endpoint for internal port {}", label, ssh_port))?;

    let dest = ssh_dest_path(&ssh_ep.port.to_string(), &ssh_ep.uri);

    // ── SSH-pipe files (large: snapshots) ─────────────────────────────────────
    for file in files.iter().filter(|f| matches!(f.source, FileSource::Path(_))) {
        if let FileSource::Path(ref local_path) = file.source {
            let size = fs::metadata(local_path)
                .map_err(|e| format!("[{}] Cannot stat {:?}: {}", label, local_path, e))?
                .len();
            tracing::info!(
                "  [{}] SSH-pipe {:?} ({} bytes) → {}",
                label, local_path, size, file.remote_path
            );
            let host = ssh_ep.uri
                .strip_prefix("https://").or_else(|| ssh_ep.uri.strip_prefix("http://"))
                .unwrap_or(&ssh_ep.uri).split(':').next().unwrap_or(&ssh_ep.uri);
            let port_str = ssh_ep.port.to_string();

            // Retry loop — containers may not have SSH ready immediately after deploy.
            let mut attempt = 0u16;
            loop {
                attempt += 1;
                // Ensure remote parent dir exists
                let parent = file.remote_path.rsplit('/').skip(1)
                    .collect::<Vec<_>>().into_iter().rev()
                    .collect::<Vec<_>>().join("/");
                let root_host = format!("root@{}", host);
                let mkdir_remote = format!("mkdir -p '{}'", parent);
                if !parent.is_empty() {
                    let mut mkdir_args: Vec<&str> = vec!["-i", ssh_key_path.to_str().unwrap(), "-p", &port_str];
                    mkdir_args.extend_from_slice(SSH_FAST_ARGS);
                    mkdir_args.extend_from_slice(&[&root_host, &mkdir_remote]);
                    let _ = std::process::Command::new("ssh").args(&mkdir_args).status();
                }
                let mut src_file = fs::File::open(local_path)
                    .map_err(|e| format!("[{}] Cannot open {:?}: {}", label, local_path, e))?;
                let cat_remote = format!("cat > '{}'", file.remote_path);
                let mut ssh_args: Vec<&str> = vec!["-i", ssh_key_path.to_str().unwrap(), "-p", &port_str];
                ssh_args.extend_from_slice(SSH_FAST_ARGS);
                ssh_args.extend_from_slice(&[&root_host as &str, &cat_remote as &str]);
                let mut child = std::process::Command::new("ssh")
                    .args(&ssh_args)
                    .stdin(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("[{}] ssh not found: {}", label, e))?;
                let status = pipe_file_to_process(&mut src_file, &mut child, size, label)
                    .map_err(|e| format!("[{}] pipe error: {}", label, e))?;
                if status.success() {
                    break;
                }
                if attempt >= max_retries {
                    return Err(format!(
                        "[{}] SSH pipe failed for {:?} after {} attempts",
                        label, local_path, max_retries
                    ).into());
                }
                tracing::info!(
                    "  [{}] SSH-pipe attempt {}/{} failed (exit {:?}) — retrying in 10s",
                    label, attempt, max_retries, status.code()
                );
                sleep(Duration::from_secs(10));
            }
            tracing::info!("  [{}] Pushed {:?} → {}", label, local_path, file.remote_path);
        }
    }

    // ── SFTP files (small: scripts, configs) ──────────────────────────────────
    let bytes_files: Vec<(&[u8], &str)> = files.iter()
        .filter_map(|f| if let FileSource::Bytes(ref b) = f.source {
            Some((b.as_slice(), f.remote_path.as_str()))
        } else { None })
        .collect();

    if bytes_files.is_empty() {
        return Ok(());
    }

    let mut retries: u16 = 0;
    loop {
        let sftp_result = async {
            let sftp = Sftp::from_session(
                SessionBuilder::default()
                    .keyfile(ssh_key_path)
                    .known_hosts_check(KnownHosts::Add)
                    .connect_mux(&dest)
                    .await?,
                Default::default(),
            )
            .await?;
            for (content, remote_path) in &bytes_files {
                sftp.options()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(Path::new(remote_path))
                    .await?
                    .write_all(content)
                    .await?;
                tracing::info!("  [{}] SFTP → {}", label, remote_path);
            }
            Ok::<_, Box<dyn Error>>(())
        }
        .await;

        match sftp_result {
            Ok(_) => break,
            Err(e) => {
                retries += 1;
                if retries >= max_retries {
                    return Err(format!(
                        "[{}] SFTP failed after {} retries: {}",
                        label, max_retries, e
                    ).into());
                }
                tracing::info!(
                    "  [{}] SFTP attempt {}/{} failed: {} — retrying in 5s",
                    label, retries, max_retries, e
                );
                sleep(Duration::from_secs(5));
            }
        }
    }

    tracing::info!("  [{}] Pre-start files delivered ({} files).", label, files.len());
    Ok(())
}

/// Upload local script files and nginx templates to a deployed node via SFTP.
///
/// Scripts are placed at paths that `oline-entrypoint.sh` and `tls-setup.sh`
/// check before falling back to downloading from GitHub, enabling local
/// iteration without requiring a push to the remote repository.
///
/// `scripts_dir`: local directory containing the scripts (env: `OLINE_SCRIPTS_PATH`,
/// default `plays/audible`).
/// `nginx_dir`: local directory containing nginx templates (env: `OLINE_NGINX_PATH`,
/// default `plays/flea-flicker/nginx`).
///
/// Script files (any not found on disk are silently skipped):
///   `tls-setup.sh`             → `/tmp/tls-setup.sh`
///   `config-node-endpoints.sh` → `/tmp/node-config.sh`
///   `oline-entrypoint.sh`      → `/tmp/oline-entrypoint-local.sh`
///
/// Nginx templates (uploaded to `/tmp/nginx/<name>`):
///   `template`, `rpc`, `api`, `grpc`
pub async fn push_scripts_sftp(
    label: &str,
    endpoints: &[ServiceEndpoint],
    ssh_key_path: &PathBuf,
    scripts_dir: &str,
    nginx_dir: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use openssh_sftp_client::Sftp;
    use std::path::Path;

    let ssh_port: u16 = var("SSH_P")
        .unwrap_or_else(|_| "22".into())
        .parse()
        .unwrap_or(22);

    let ssh_ep = endpoints
        .iter()
        .find(|e| e.internal_port == ssh_port)
        .ok_or_else(|| format!("[{}] No SSH endpoint for internal port {}", label, ssh_port))?;

    let dest = ssh_dest_path(&ssh_ep.port.to_string(), &ssh_ep.uri);
    tracing::info!("  [{}] Pushing local scripts → {}", label, dest);

    let sftp = Sftp::from_session(
        SessionBuilder::default()
            .keyfile(ssh_key_path)
            .known_hosts_check(KnownHosts::Add)
            .connect_mux(&dest)
            .await?,
        Default::default(),
    )
    .await?;

    let sbase = scripts_dir.trim_end_matches('/');
    let mut uploads: Vec<(String, String)> = vec![
        (
            format!("{}/tls-setup.sh", sbase),
            "/tmp/tls-setup.sh".into(),
        ),
        (
            format!("{}/config-node-endpoints.sh", sbase),
            "/tmp/node-config.sh".into(),
        ),
        (
            format!("{}/oline-entrypoint.sh", sbase),
            "/tmp/oline-entrypoint-local.sh".into(),
        ),
        // Private chain.json: if present locally the entrypoint uses it
        // instead of fetching from CHAIN_JSON URL at container startup.
        ("templates/json/chain.json".into(), "/tmp/chain.json".into()),
    ];

    // Nginx templates — placed in /tmp/nginx/ so tls-setup.sh uses them
    // instead of downloading from GitHub. Local changes take effect immediately.
    if let Some(ndir) = nginx_dir {
        // Ensure remote /tmp/nginx/ directory exists before uploading.
        let mk_session = SessionBuilder::default()
            .keyfile(ssh_key_path)
            .known_hosts_check(KnownHosts::Add)
            .connect_mux(&dest)
            .await?;
        mk_session
            .command("mkdir")
            .arg("-p")
            .arg("/tmp/nginx")
            .output()
            .await?;

        let nbase = ndir.trim_end_matches('/');
        for tmpl in ["template", "rpc", "api", "grpc"] {
            uploads.push((
                format!("{}/{}", nbase, tmpl),
                format!("/tmp/nginx/{}", tmpl),
            ));
        }
    }

    for (local_path, remote_path) in &uploads {
        let local_name = local_path.rsplit('/').next().unwrap_or(local_path);
        match fs::read(local_path) {
            Ok(content) => {
                sftp.options()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(Path::new(remote_path.as_str()))
                    .await?
                    .write_all(&content)
                    .await?;
                tracing::info!("  [{}]   {} → {}", label, local_name, remote_path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(
                    "  [{}]   {} not found locally — skipping",
                    label,
                    local_name
                );
            }
            Err(e) => {
                tracing::info!(
                    "  [{}]   Warning: could not read {}: {}",
                    label,
                    local_path,
                    e
                );
            }
        }
    }

    Ok(())
}

/// SSH into the deployed node, optionally verify that pre-start files landed at their
/// expected remote paths, then launch the cosmos node setup by re-invoking the
/// entrypoint script with `OLINE_PHASE=start` under `nohup`.
///
/// Pass an empty `remote_paths` slice to skip file verification and go straight to
/// the launch signal (use when no pre-start files were pushed).
pub async fn verify_files_and_signal_start(
    label: &str,
    endpoints: &[ServiceEndpoint],
    ssh_key_path: &PathBuf,
    remote_paths: &[String],
    sdl_vars: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ssh_port: u16 = var("SSH_P")
        .unwrap_or_else(|_| "22".into())
        .parse()
        .unwrap_or(22);

    let ssh_ep = endpoints
        .iter()
        .find(|e| e.internal_port == ssh_port)
        .ok_or_else(|| {
            format!(
                "[{}] No SSH endpoint found for internal port {}",
                label, ssh_port
            )
        })?;

    let dest = ssh_dest_path(&ssh_ep.port.to_string(), &ssh_ep.uri);
    tracing::info!("  [{}] SSH verify + launch → {}", label, dest);

    // The previous SFTP/SSH-pipe session may have just closed; sshd sometimes
    // needs a moment before it will accept a new connection.  Retry with backoff.
    const CONNECT_RETRIES: u32 = 8;
    let session = {
        let mut attempt = 0u32;
        loop {
            match SessionBuilder::default()
                .keyfile(ssh_key_path)
                .known_hosts_check(KnownHosts::Add)
                .connect_mux(&dest)
                .await
            {
                Ok(s) => break s,
                Err(e) => {
                    attempt += 1;
                    if attempt >= CONNECT_RETRIES {
                        return Err(e.into());
                    }
                    let delay = Duration::from_secs(2u64.pow(attempt).min(30));
                    tracing::info!(
                        "  [{}] SSH connect attempt {}/{} failed: {} — retrying in {:?}",
                        label, attempt, CONNECT_RETRIES, e, delay
                    );
                    sleep(delay);
                }
            }
        }
    };

    // Step 1: verify pre-start files are present (skip if none were pushed).
    if !remote_paths.is_empty() {
        let verify_cmd = remote_paths
            .iter()
            .map(|p| format!("test -f '{}' && echo '[OK] {}'", p, p))
            .collect::<Vec<_>>()
            .join(" && ");
        let verify = session
            .command("sh")
            .arg("-c")
            .arg(&verify_cmd)
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&verify.stdout);
        let stderr = String::from_utf8_lossy(&verify.stderr);
        if !verify.status.success() {
            return Err(format!(
                "[{}] Pre-start file verification failed.\n  stdout: {}\n  stderr: {}",
                label,
                stdout.trim(),
                stderr.trim()
            )
            .into());
        }
        for line in stdout.trim().lines() {
            tracing::info!("  [{}] {}", label, line);
        }
    }

    const REFRESH_VARS: &[&str] = &[
        "CHAIN_ID",
        "CHAIN_JSON",
        "ADDRBOOK_URL",
        "OMNIBUS_IMAGE",
        "SNAPSHOT_JSON",
        "SNAPSHOT_URL",
        "OLINE_SNAP_FULL_URL",
        "TERPD_P2P_PRIVATE_PEER_IDS",
        "TERPD_P2P_PERSISTENT_PEERS",
        "RPC_DOMAIN",
        "RPC_P",
        "API_D",
        "API_P",
        "GRPC_D",
        "GRPC_P",
        "P2P_D",
        "P2P_P",
        "P2P_EXT_PORT",
        "P2P_PEX",
        "P2P_ADDR_BOOK_STRICT",
        "STATESYNC_ENABLE",
        "STATESYNC_RPC_SERVERS",
        "STATESYNC_TRUST_HEIGHT",
        "STATESYNC_TRUST_HASH",
        "STATESYNC_TRUST_PERIOD",
    ];
    let export_lines: Vec<String> = sdl_vars
        .iter()
        .filter(|(k, _)| REFRESH_VARS.contains(&k.as_str()))
        .map(|(k, v)| format!("export {}='{}'", k, v.replace('\'', "'\\''")))
        .collect();
    let refresh_cmd = format!(
        "cat >> /tmp/oline-env.sh <<'__OLINE_ENV__'\n{}\n__OLINE_ENV__",
        export_lines.join("\n")
    );
    let refresh = session
        .command("sh")
        .arg("-c")
        .arg(&refresh_cmd)
        .output()
        .await?;
    if refresh.status.success() {
        tracing::info!(
            "  [{}] Patched /tmp/oline-env.sh ({} vars)",
            label,
            export_lines.len()
        );
    } else {
        let stderr = String::from_utf8_lossy(&refresh.stderr);
        tracing::info!(
            "  [{}] Warning: failed to patch /tmp/oline-env.sh: {}",
            label,
            stderr.trim()
        );
    }

    // Step 2: launch cosmos node setup in the background.
    // Scripts are always delivered via SFTP (push_scripts_sftp), so prefer the local
    // entrypoint; fall back to the bootstrapped wrapper if present.
    // OLINE_LOCAL_ENTRYPOINT=1 suppresses the self-override exec inside
    // oline-entrypoint.sh (prevents infinite re-exec).
    let launch_cmd =
        "if [ -f /tmp/oline-entrypoint-local.sh ]; then _ep=/tmp/oline-entrypoint-local.sh; \
         elif [ -f /tmp/wrapper.sh ]; then _ep=/tmp/wrapper.sh; \
         else echo 'ERROR: no entrypoint found — push_scripts_sftp may have failed' >&2; exit 1; fi; \
         OLINE_PHASE=start OLINE_LOCAL_ENTRYPOINT=1 nohup bash \"$_ep\" >>/proc/1/fd/1 2>&1 & echo $!";
    let launch = session
        .command("sh")
        .arg("-c")
        .arg(&launch_cmd)
        .output()
        .await?;

    let pid = String::from_utf8_lossy(&launch.stdout);
    tracing::info!("  [{}] Node setup launched (PID {})", label, pid.trim());

    tracing::info!("  [{}] Stream logs:     oline manage logs <dseq>", label);

    Ok(())
}

/// SSH into a deployed node and write the TLS-terminating gRPC nginx server block,
/// then reload nginx. This configures the NodePort TLS listener (internal 9091,
/// external 9090) so native gRPC clients can connect directly without going through
/// the Akash HTTP ingress.
pub async fn update_nginx_grpc_tls(
    label: &str,
    endpoints: &[ServiceEndpoint],
    ssh_key_path: &PathBuf,
    grpc_domain: &str,
    grpc_port: u16,
    tls_cert: &str,
    tls_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ssh_port: u16 = var("SSH_P")
        .unwrap_or_else(|_| "22".into())
        .parse()
        .unwrap_or(22);
    let ep = endpoints
        .iter()
        .find(|e| e.internal_port == ssh_port)
        .ok_or_else(|| format!("[{}] No SSH endpoint for port {}", label, ssh_port))?;
    let dest = ssh_dest_path(&ep.port.to_string(), &ep.uri);

    let session = SessionBuilder::default()
        .keyfile(ssh_key_path)
        .known_hosts_check(KnownHosts::Add)
        .connect_mux(&dest)
        .await?;

    // Build the nginx server block. The heredoc delimiter is single-quoted so
    // nginx variables like $host are written literally (not expanded by the shell).
    let conf = format!(
        "server {{\n\
         \x20   listen      9091 ssl;\n\
         \x20   http2       on;\n\
         \x20   server_name {domain};\n\n\
         \x20   ssl_certificate     {cert};\n\
         \x20   ssl_certificate_key {key};\n\
         \x20   ssl_protocols       TLSv1.2 TLSv1.3;\n\
         \x20   ssl_ciphers         HIGH:!aNULL:!MD5;\n\n\
         \x20   location / {{\n\
         \x20       grpc_pass            grpc://127.0.0.1:{port};\n\
         \x20       grpc_set_header Host $host;\n\
         \x20   }}\n\
         }}",
        domain = grpc_domain,
        cert = tls_cert,
        key = tls_key,
        port = grpc_port,
    );
    let write_cmd = format!(
        "mkdir -p /etc/nginx/conf.d && cat > /etc/nginx/conf.d/grpc.conf <<'__GRPC_CONF__'\n{}\n__GRPC_CONF__",
        conf
    );
    let write = session
        .command("sh")
        .arg("-c")
        .arg(&write_cmd)
        .output()
        .await?;
    if !write.status.success() {
        let stderr = String::from_utf8_lossy(&write.stderr);
        return Err(format!("[{}] Failed to write grpc.conf: {}", label, stderr.trim()).into());
    }

    // nginx -t validates config; fall through to reload only if test passes.
    let test = session.command("nginx").arg("-t").output().await?;
    if !test.status.success() {
        let out = String::from_utf8_lossy(&test.stderr);
        return Err(format!("[{}] nginx config test failed: {}", label, out.trim()).into());
    }

    let reload = session
        .command("sh")
        .arg("-c")
        .arg("nginx -s reload 2>/dev/null || nginx")
        .output()
        .await?;
    if !reload.status.success() {
        let stderr = String::from_utf8_lossy(&reload.stderr);
        tracing::info!("  [{}] Warning: nginx reload: {}", label, stderr.trim());
    } else {
        tracing::info!(
            "  [{}] nginx grpc.conf written and reloaded ({}:9091 ssl → grpc://127.0.0.1:{})",
            label,
            grpc_domain,
            grpc_port
        );
    }

    Ok(())
}

/// Build the shell commands used by both SSH and local bootstrap modes.
fn bootstrap_commands(
    home_dir: &str,
    binary: &str,
    persistent_peers: &str,
    snapshot_url: &str,
    snapshot_format: &str,
) -> (Option<String>, Option<String>, String, Option<String>) {
    let peers_cmd = if !persistent_peers.is_empty() {
        Some(format!(
            "sed -i 's|^persistent_peers *=.*|persistent_peers = \"{peers}\"|' \
             '{home}/config/config.toml'",
            peers = persistent_peers,
            home = home_dir,
        ))
    } else {
        None
    };

    let stop_cmd = Some(format!(
        "systemctl stop {bin} 2>/dev/null; pkill -f {bin} 2>/dev/null; true",
        bin = binary,
    ));

    let clean_cmd = format!(
        "rm -rf '{home}/data' '{home}/wasm'; mkdir -p '{home}/data'",
        home = home_dir,
    );

    let extract_cmd = if snapshot_url.is_empty() {
        None
    } else {
        Some(match snapshot_format {
            "tar.lz4" => format!(
                "curl -fsSL '{url}' | lz4 -d | tar xf - -C '{home}/data'",
                url = snapshot_url,
                home = home_dir,
            ),
            "tar.zst" | "tar.zstd" => format!(
                "curl -fsSL '{url}' | zstd -d | tar xf - -C '{home}/data'",
                url = snapshot_url,
                home = home_dir,
            ),
            _ => format!(
                "curl -fsSL '{url}' | tar xzf - -C '{home}/data'",
                url = snapshot_url,
                home = home_dir,
            ),
        })
    };

    (peers_cmd, stop_cmd, clean_cmd, extract_cmd)
}

/// SSH into a private (non-Akash) validator node and bootstrap it:
///   1. Patch `persistent_peers` in config.toml if provided
///   2. Stop any running node process
///   3. Clear the data directory
///   4. Download and extract the snapshot from `snapshot_url`
///
/// `snapshot_format`: `"tar.lz4"`, `"tar.zst"`, or `"tar.gz"` (default).
pub async fn bootstrap_private_node(
    label: &str,
    ssh_host: &str,
    ssh_port: u16,
    ssh_key_path: &PathBuf,
    home_dir: &str,
    binary: &str,
    persistent_peers: &str,
    snapshot_url: &str,
    snapshot_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let dest = format!("ssh://root@{}:{}", ssh_host, ssh_port);
    tracing::info!("  [{}] Connecting via SSH → {}", label, dest);

    let session = SessionBuilder::default()
        .keyfile(ssh_key_path)
        .known_hosts_check(KnownHosts::Add)
        .connect_mux(&dest)
        .await?;

    let (peers_cmd, stop_cmd, clean_cmd, extract_cmd) = bootstrap_commands(
        home_dir,
        binary,
        persistent_peers,
        snapshot_url,
        snapshot_format,
    );

    if let Some(cmd) = peers_cmd {
        let out = session.command("sh").arg("-c").arg(&cmd).output().await?;
        if out.status.success() {
            tracing::info!("  [{}] Set persistent_peers.", label);
        } else {
            tracing::info!(
                "  [{}] Warning: could not set persistent_peers: {}",
                label,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }

    if extract_cmd.is_none() {
        tracing::info!("  [{}] No snapshot URL — skipping download.", label);
        return Ok(());
    }

    tracing::info!("  [{}] Stopping node process ({})...", label, binary);
    if let Some(cmd) = stop_cmd {
        session
            .command("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .await
            .ok();
    }

    tracing::info!("  [{}] Clearing data directory...", label);
    let out = session
        .command("sh")
        .arg("-c")
        .arg(&clean_cmd)
        .output()
        .await?;
    if !out.status.success() {
        return Err(format!(
            "[{}] Failed to clear data dir: {}",
            label,
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }

    tracing::info!(
        "  [{}] Downloading and extracting snapshot ({})...",
        label,
        snapshot_format
    );
    let out = session
        .command("sh")
        .arg("-c")
        .arg(extract_cmd.unwrap())
        .output()
        .await?;
    if out.status.success() {
        tracing::info!("  [{}] Snapshot installed successfully.", label);
    } else {
        return Err(format!(
            "[{}] Snapshot extraction failed: {}",
            label,
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }

    Ok(())
}

/// Run the same bootstrap steps as `bootstrap_private_node` but execute
/// shell commands locally (no SSH). Useful for testing and for nodes
/// running on the same machine as the deployer.
pub async fn bootstrap_private_node_local(
    label: &str,
    home_dir: &str,
    binary: &str,
    persistent_peers: &str,
    snapshot_url: &str,
    snapshot_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("  [{}] Running bootstrap locally.", label);

    let run = |cmd: &str| -> Result<std::process::Output, std::io::Error> {
        std::process::Command::new("sh").arg("-c").arg(cmd).output()
    };

    let (peers_cmd, stop_cmd, clean_cmd, extract_cmd) = bootstrap_commands(
        home_dir,
        binary,
        persistent_peers,
        snapshot_url,
        snapshot_format,
    );

    if let Some(cmd) = peers_cmd {
        let out = run(&cmd)?;
        if out.status.success() {
            tracing::info!("  [{}] Set persistent_peers.", label);
        } else {
            tracing::info!(
                "  [{}] Warning: could not set persistent_peers: {}",
                label,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }

    if extract_cmd.is_none() {
        tracing::info!("  [{}] No snapshot URL — skipping download.", label);
        return Ok(());
    }

    tracing::info!("  [{}] Stopping node process ({})...", label, binary);
    if let Some(cmd) = stop_cmd {
        run(&cmd).ok();
    }

    tracing::info!("  [{}] Clearing data directory...", label);
    let out = run(&clean_cmd)?;
    if !out.status.success() {
        return Err(format!(
            "[{}] Failed to clear data dir: {}",
            label,
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }

    tracing::info!(
        "  [{}] Downloading and extracting snapshot ({})...",
        label,
        snapshot_format
    );
    let out = run(&extract_cmd.unwrap())?;
    if out.status.success() {
        tracing::info!("  [{}] Snapshot installed successfully.", label);
    } else {
        return Err(format!(
            "[{}] Snapshot extraction failed: {}",
            label,
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }

    Ok(())
}

/// Generate a random alphanumeric credential string of the given length.
pub fn generate_credential(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

pub fn encrypt_mnemonic(mnemonic: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let mut salt = [0u8; SALT_LEN];
    let mut key = [0u8; 32];

    rand::thread_rng().fill_bytes(&mut salt);
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Failed to create cipher: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, mnemonic.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&blob))
}

pub fn decrypt_mnemonic(encrypted_b64: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let blob = BASE64
        .decode(encrypted_b64)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    if blob.len() < SALT_LEN + NONCE_LEN + 1 {
        return Err("Encrypted data too short".into());
    }

    let (salt, nonce_bytes, ciphertext) = (
        &blob[..SALT_LEN],
        &blob[SALT_LEN..SALT_LEN + NONCE_LEN],
        &blob[SALT_LEN + NONCE_LEN..],
    );

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Failed to create cipher: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed — wrong password or corrupted data")?;

    String::from_utf8(plaintext)
        .map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e).into())
}
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hex::encode(hash)
}

// ── SSH direct-host helpers ────────────────────────────────────────────────────

/// Connect to `host:port` via SSH, write env vars to `/tmp/oline-env.sh`, and
/// run an arbitrary shell command.  Output from the command is printed via
/// `tracing::info!` line-by-line.
///
/// `env_vars`: if non-empty, each entry is written as `export KEY='VALUE'` and
/// appended to `/tmp/oline-env.sh` before `command` runs.
/// `command`: run with `sh -c` after the env update; pass `""` to skip.
///
/// Uses exponential-backoff SSH reconnect (same as `verify_files_and_signal_start`).
pub async fn ssh_push_env_and_run(
    label: &str,
    host: &str,
    port: u16,
    key_path: &PathBuf,
    env_vars: &HashMap<String, String>,
    command: &str,
) -> Result<(), Box<dyn Error>> {
    let dest = format!("ssh://root@{}:{}", host, port);
    tracing::info!("  [{}] Connecting → {}", label, dest);

    const CONNECT_RETRIES: u32 = 5;
    let session = {
        let mut attempt = 0u32;
        loop {
            match SessionBuilder::default()
                .keyfile(key_path)
                .known_hosts_check(KnownHosts::Add)
                .connect_mux(&dest)
                .await
            {
                Ok(s) => break s,
                Err(e) => {
                    attempt += 1;
                    if attempt >= CONNECT_RETRIES {
                        return Err(format!(
                            "[{}] SSH connect to {} failed after {} attempts: {}",
                            label, dest, CONNECT_RETRIES, e
                        )
                        .into());
                    }
                    let delay = Duration::from_secs(2u64.pow(attempt).min(30));
                    tracing::info!(
                        "  [{}] SSH connect attempt {}/{} failed: {} — retrying in {:?}",
                        label, attempt, CONNECT_RETRIES, e, delay
                    );
                    sleep(delay);
                }
            }
        }
    };

    // Write env vars
    if !env_vars.is_empty() {
        let export_lines: Vec<String> = env_vars
            .iter()
            .map(|(k, v)| format!("export {}='{}'", k, v.replace('\'', "'\\''")))
            .collect();
        let env_cmd = format!(
            "cat > /tmp/oline-env.sh <<'__OLINE_ENV__'\n{}\n__OLINE_ENV__",
            export_lines.join("\n")
        );
        let out = session
            .command("sh")
            .arg("-c")
            .arg(&env_cmd)
            .output()
            .await?;
        if out.status.success() {
            tracing::info!(
                "  [{}] Wrote {} env vars to /tmp/oline-env.sh",
                label,
                env_vars.len()
            );
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            tracing::info!("  [{}] Warning: env write failed: {}", label, err.trim());
        }
    }

    // Run command
    if command.is_empty() {
        return Ok(());
    }
    tracing::info!("  [{}] Running: {}", label, command);
    let out = session
        .command("sh")
        .arg("-c")
        .arg(command)
        .output()
        .await?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        tracing::info!("  [{}] {}", label, line);
    }
    if !out.stderr.is_empty() {
        for line in String::from_utf8_lossy(&out.stderr).lines() {
            tracing::info!("  [{}] stderr: {}", label, line);
        }
    }
    if !out.status.success() {
        return Err(format!(
            "[{}] Command exited non-zero: {:?}",
            label,
            out.status.code()
        )
        .into());
    }
    Ok(())
}

/// Run a quick RPC health check: GET `<rpc_url>/status` and return the node
/// moniker + latest block height, or an error string.
pub async fn check_rpc_health(rpc_url: &str) -> Result<String, String> {
    let url = format!("{}/status", rpc_url.trim_end_matches('/'));
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())?;

    let moniker = resp
        .pointer("/result/node_info/moniker")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let height = resp
        .pointer("/result/sync_info/latest_block_height")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    Ok(format!("{} @ height {}", moniker, height))
}
