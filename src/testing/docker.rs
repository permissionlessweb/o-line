/// Docker container lifecycle for local integration tests.
///
/// Each [`ContainerHandle`] has a [`Drop`] impl that force-removes the container,
/// so containers are always cleaned up on test exit or panic.
use akash_deploy_rs::ServiceEndpoint;
use std::{
    collections::HashMap,
    net::TcpStream,
    process::Command,
    time::{Duration, Instant},
};

/// Port mapping: container-internal port → host-mapped port.
#[derive(Debug, Clone)]
pub struct ContainerPort {
    pub internal: u16,
    pub host: u16,
}

/// All parameters needed to start a test container.
pub struct ContainerSpec {
    /// Docker container name (must be unique per test run).
    pub name: String,
    /// Docker image to pull and run.
    pub image: String,
    /// Environment variables injected via `-e KEY=VALUE`.
    pub env: HashMap<String, String>,
    /// Port mappings (`-p host:internal`).
    pub ports: Vec<ContainerPort>,
    /// Optional override entrypoint. Defaults to the image's entrypoint.
    pub entrypoint: Option<String>,
    /// Command to pass to the entrypoint (passed as `sh -c "<cmd>"`).
    pub command: Option<String>,
    /// Extra host entries (`--add-host hostname:ip`).
    /// On Linux use `"host.docker.internal:host-gateway"` to reach the host.
    /// Docker Desktop (Mac/Windows) adds `host.docker.internal` automatically.
    pub extra_hosts: Vec<String>,
}

/// A running Docker container.  Removed automatically on [`Drop`].
pub struct ContainerHandle {
    /// Container name (`docker rm -f <name>` is called on drop).
    pub name: String,
    /// Always `"127.0.0.1"` for local tests.
    pub host: String,
    /// Effective port mappings set at startup.
    pub ports: Vec<ContainerPort>,
}

impl Drop for ContainerHandle {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

impl ContainerHandle {
    /// Build a [`ServiceEndpoint`] for the given `internal_port` and `service` name.
    ///
    /// The `uri` uses `"http://127.0.0.1"` — endpoint helpers strip the scheme
    /// and use the `port` field (host-mapped) to connect.
    pub fn endpoint(&self, service: &str, internal_port: u16) -> Option<ServiceEndpoint> {
        self.ports
            .iter()
            .find(|p| p.internal == internal_port)
            .map(|p| ServiceEndpoint {
                service: service.to_string(),
                uri: format!("http://{}", self.host),
                port: p.host,
                internal_port: p.internal,
            })
    }

    /// All [`ServiceEndpoint`]s for this container.
    pub fn all_endpoints(&self, service: &str) -> Vec<ServiceEndpoint> {
        self.ports
            .iter()
            .map(|p| ServiceEndpoint {
                service: service.to_string(),
                uri: format!("http://{}", self.host),
                port: p.host,
                internal_port: p.internal,
            })
            .collect()
    }
}

/// Start a Docker container and return its [`ContainerHandle`].
///
/// The container is started with `-d` (detached).  Use [`wait_for_tcp`] or
/// [`wait_for_ssh`] after this call to confirm the container is accepting
/// connections before proceeding.
pub fn run_container(spec: &ContainerSpec) -> Result<ContainerHandle, String> {
    // Idempotent cleanup of any leftover container from a previous run.
    let _ = Command::new("docker")
        .args(["rm", "-f", &spec.name])
        .output();

    // Remove stale SSH host key if SSH is exposed (avoids "host key changed" errors).
    for port in &spec.ports {
        if port.internal == 22 {
            let _ = Command::new("ssh-keygen")
                .args(["-R", &format!("[127.0.0.1]:{}", port.host)])
                .output();
        }
    }

    let mut args: Vec<String> = vec!["run".into(), "-d".into(), "--name".into(), spec.name.clone()];

    for host_entry in &spec.extra_hosts {
        args.push("--add-host".into());
        args.push(host_entry.clone());
    }

    if let Some(ref ep) = spec.entrypoint {
        args.push("--entrypoint".into());
        args.push(ep.clone());
    }

    for (k, v) in &spec.env {
        args.push("-e".into());
        args.push(format!("{}={}", k, v));
    }

    for p in &spec.ports {
        args.push("-p".into());
        args.push(format!("{}:{}", p.host, p.internal));
    }

    args.push(spec.image.clone());

    if let Some(ref cmd) = spec.command {
        args.push("-c".into());
        args.push(cmd.clone());
    }

    let status = Command::new("docker")
        .args(&args)
        .status()
        .map_err(|e| format!("docker not found — install Docker: {}", e))?;

    if !status.success() {
        return Err(format!(
            "docker run failed for container '{}' (exit {:?})",
            spec.name, status.code()
        ));
    }

    Ok(ContainerHandle {
        name: spec.name.clone(),
        host: "127.0.0.1".into(),
        ports: spec.ports.clone(),
    })
}

/// Poll a TCP address until it accepts a connection or `timeout` elapses.
///
/// Prints dots while waiting so test output shows progress.
/// Returns `true` if the port became connectable within the timeout.
pub fn wait_for_tcp(host: &str, port: u16, timeout: Duration) -> bool {
    let addr: std::net::SocketAddr = format!("{}:{}", host, port).parse().unwrap();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
            println!();
            return true;
        }
        print!(".");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::thread::sleep(Duration::from_secs(2));
    }
    println!();
    false
}

/// Retrieve the last `tail` lines of container logs.
pub fn container_logs(name: &str, tail: usize) -> String {
    Command::new("docker")
        .args(["logs", "--tail", &tail.to_string(), name])
        .output()
        .map(|o| {
            let combined = [o.stdout.as_slice(), o.stderr.as_slice()].concat();
            String::from_utf8_lossy(&combined).into_owned()
        })
        .unwrap_or_default()
}

/// Run a shell command inside a running container via `docker exec`.
/// Returns combined stdout+stderr, or an error string if docker exec fails.
pub fn container_exec(name: &str, cmd: &str) -> String {
    Command::new("docker")
        .args(["exec", name, "sh", "-c", cmd])
        .output()
        .map(|o| {
            let combined = [o.stdout.as_slice(), o.stderr.as_slice()].concat();
            String::from_utf8_lossy(&combined).into_owned()
        })
        .unwrap_or_else(|e| format!("(docker exec failed: {})", e))
}

/// Force-remove a list of containers by name.  Silently ignores containers
/// that are not running.  Useful for belt-and-suspenders cleanup at test
/// start and in `Drop` impls.
pub fn remove_containers(names: &[&str]) {
    for name in names {
        let _ = Command::new("docker")
            .args(["rm", "-f", name])
            .output();
    }
}

/// RAII guard for a Tokio [`tokio::task::JoinHandle`].
///
/// Calls [`tokio::task::JoinHandle::abort`] on drop, so the task is always
/// cancelled when the guard goes out of scope — including on panic unwind.
/// Unlike dropping a raw `JoinHandle` (which merely detaches), this ensures
/// the task stops and any bound port is released.
pub struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
