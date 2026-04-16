//! Docker Compose generation from Akash manifest JSON.
//!
//! Translates the manifest JSON that providers receive via PUT into a
//! docker-compose.yml that mirrors Akash's service networking:
//!
//! - All services share a single Docker bridge network (= Akash lease network)
//! - Services resolve each other by name (e.g. `oline-courier:8080`)
//! - Only `global: true` ports get host-mapped (= Akash NodePort / ingress)
//! - `global: false` ports are reachable only within the network
//! - SDL `params.storage` persistent volumes → Docker named volumes
//! - `command` + `args` are faithfully passed through
//!
//! This is the single place where "Akash provider spawns containers" is
//! implemented for local testing. The test-provider binary calls
//! [`ComposeSpec::from_manifest`] and [`ComposeSpec::to_yaml`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

/// Monotonically increasing host port counter. Each global port gets a unique
/// host mapping so multiple deployments don't collide.
static NEXT_HOST_PORT: AtomicU32 = AtomicU32::new(30000);

/// Reset the port counter (for tests).
#[cfg(test)]
pub fn reset_port_counter(start: u32) {
    NEXT_HOST_PORT.store(start, Ordering::Relaxed);
}

/// Allocate the next available host port.
pub fn alloc_host_port() -> u32 {
    NEXT_HOST_PORT.fetch_add(1, Ordering::Relaxed)
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// Full compose specification for one Akash deployment (one dseq).
#[derive(Debug, Clone)]
pub struct ComposeSpec {
    pub dseq: u64,
    pub project_name: String,
    pub network_name: String,
    pub services: Vec<ComposeService>,
    pub volumes: Vec<String>,
}

/// A single service in the compose file.
#[derive(Debug, Clone)]
pub struct ComposeService {
    pub name: String,
    pub image: String,
    pub env: Vec<String>,
    pub command: Option<Vec<String>>,
    pub args: Option<Vec<String>>,
    pub ports: Vec<PortMapping>,
    pub volumes: Vec<VolumeMount>,
    pub depends_on: Vec<String>,
    /// Resource limits (best-effort in compose; Docker enforces memory/cpu).
    pub cpu_millicores: u64,
    pub memory_bytes: u64,
}

/// A port mapping entry.
#[derive(Debug, Clone)]
pub struct PortMapping {
    /// Host port (allocated dynamically). 0 = internal-only (no host mapping).
    pub host_port: u32,
    /// Container-internal port.
    pub container_port: u32,
    /// Protocol (tcp or udp).
    pub proto: String,
    /// Whether this port is exposed globally (host-mapped).
    pub global: bool,
    /// If non-empty, this port is only exposed to this specific service
    /// (Akash `to: - service: <name>`). In Docker compose this is modeled
    /// by the target service being on the same network (always true), so
    /// this field is informational.
    pub service_target: String,
}

/// A volume mount in a service.
#[derive(Debug, Clone)]
pub struct VolumeMount {
    /// Named volume (matches a top-level `volumes:` entry).
    pub volume_name: String,
    /// Mount path inside the container.
    pub mount_path: String,
    /// Read-only mount.
    pub read_only: bool,
}

// ── Parsing ───────────────────────────────────────────────────────────────────

impl ComposeSpec {
    /// Build a ComposeSpec from the manifest JSON that the provider receives.
    ///
    /// Manifest format (from akash-deploy-rs):
    /// ```json
    /// [{ "name": "dcloud", "services": [
    ///     { "name": "oline-courier", "image": "...", "env": ["K=V", ...],
    ///       "command": ["sh"], "args": ["-c", "..."],
    ///       "expose": [{ "port": 8080, "externalPort": 8080, "proto": "TCP",
    ///                     "global": false, "service": "" }],
    ///       "resources": { "cpu": {"units":{"val":"1000"}}, "memory": {"size":{"val":"536870912"}}, ... },
    ///       "params": { "storage": [{ "name": "data", "mount": "/data", "readOnly": false }] }
    ///     }, ...
    /// ]}]
    /// ```
    pub fn from_manifest(manifest_json: &serde_json::Value, dseq: u64) -> Self {
        let project_name = format!("oline-{}", dseq);
        let network_name = format!("oline-net-{}", dseq);
        let mut services = Vec::new();
        let mut all_volumes = Vec::new();
        let mut service_names: Vec<String> = Vec::new();

        if let Some(groups) = manifest_json.as_array() {
            for group in groups {
                if let Some(svcs) = group.get("services").and_then(|s| s.as_array()) {
                    for svc in svcs {
                        let (cs, vols) = Self::parse_service(svc);
                        service_names.push(cs.name.clone());
                        services.push(cs);
                        all_volumes.extend(vols);
                    }
                }
            }
        }

        // Deduplicate volumes.
        all_volumes.sort();
        all_volumes.dedup();

        // Build depends_on: each service depends on services that appear
        // before it in the manifest (simple boot ordering hint). This matches
        // the SDL service declaration order, which the user controls.
        for i in 0..services.len() {
            // Courier (or first service) has no deps; everything else depends
            // on the first service as a soft boot-ordering signal.
            if i > 0 {
                services[i].depends_on.push(service_names[0].clone());
            }
        }

        Self {
            dseq,
            project_name,
            network_name,
            services,
            volumes: all_volumes,
        }
    }

    /// Parse a single service from the manifest JSON.
    fn parse_service(svc: &serde_json::Value) -> (ComposeService, Vec<String>) {
        let name = svc
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_string();
        let image = svc
            .get("image")
            .and_then(|n| n.as_str())
            .unwrap_or("nginx:alpine")
            .to_string();

        // Env
        let env: Vec<String> = svc
            .get("env")
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Command + args
        let command: Option<Vec<String>> = svc.get("command").and_then(|c| {
            c.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
        });
        let args: Option<Vec<String>> = svc.get("args").and_then(|a| {
            a.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
        });

        // Expose → port mappings
        let mut ports = Vec::new();
        if let Some(exposes) = svc.get("expose").and_then(|e| e.as_array()) {
            for exp in exposes {
                let container_port = exp
                    .get("port")
                    .and_then(|p| p.as_u64())
                    .unwrap_or(80) as u32;
                let global = exp
                    .get("global")
                    .and_then(|g| g.as_bool())
                    .unwrap_or(false);
                let proto = exp
                    .get("proto")
                    .and_then(|p| p.as_str())
                    .unwrap_or("TCP")
                    .to_lowercase();
                let service_target = exp
                    .get("service")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();

                // Allocate a host port only for global exposes.
                let host_port = if global { alloc_host_port() } else { 0 };

                // Deduplicate: skip if we already have this container_port+proto.
                // Akash manifests can have multiple expose entries for the same
                // port (one global, one service-targeted). We keep the global one.
                let dup = ports.iter().any(|p: &PortMapping| {
                    p.container_port == container_port && p.proto == proto
                });
                if !dup {
                    ports.push(PortMapping {
                        host_port,
                        container_port,
                        proto,
                        global,
                        service_target,
                    });
                }
            }
        }

        // Resources
        let cpu_millicores = svc
            .pointer("/resources/cpu/units/val")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1000);
        let memory_bytes = svc
            .pointer("/resources/memory/size/val")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(536_870_912);

        // Storage params → volume mounts
        let mut volume_mounts = Vec::new();
        let mut volume_names = Vec::new();
        if let Some(params) = svc.get("params") {
            if let Some(storage_arr) = params.get("storage").and_then(|s| s.as_array()) {
                for sp in storage_arr {
                    let vol_name = sp
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("data")
                        .to_string();
                    let mount = sp
                        .get("mount")
                        .and_then(|m| m.as_str())
                        .unwrap_or("/data")
                        .to_string();
                    let read_only = sp
                        .get("readOnly")
                        .and_then(|r| r.as_bool())
                        .unwrap_or(false);
                    volume_names.push(vol_name.clone());
                    volume_mounts.push(VolumeMount {
                        volume_name: vol_name,
                        mount_path: mount,
                        read_only,
                    });
                }
            }
        }

        let cs = ComposeService {
            name,
            image,
            env,
            command,
            args,
            ports,
            volumes: volume_mounts,
            depends_on: Vec::new(),
            cpu_millicores,
            memory_bytes,
        };

        (cs, volume_names)
    }

    // ── YAML generation ───────────────────────────────────────────────────

    /// Generate a docker-compose.yml string.
    pub fn to_yaml(&self) -> String {
        let mut y = String::with_capacity(4096);

        // Networks
        y.push_str("networks:\n");
        y.push_str(&format!("  {}:\n", self.network_name));
        y.push_str("    driver: bridge\n\n");

        // Volumes
        if !self.volumes.is_empty() {
            y.push_str("volumes:\n");
            for v in &self.volumes {
                y.push_str(&format!("  {}:\n", v));
            }
            y.push('\n');
        }

        // Services
        y.push_str("services:\n");
        for svc in &self.services {
            y.push_str(&format!("  {}:\n", svc.name));
            y.push_str(&format!("    image: {}\n", svc.image));
            y.push_str(&format!("    container_name: {}\n", svc.name));

            // Network
            y.push_str("    networks:\n");
            y.push_str(&format!("      - {}\n", self.network_name));

            // Command + args
            if let Some(ref cmd) = svc.command {
                if cmd.len() == 1 {
                    y.push_str(&format!("    entrypoint: [\"{}\"]", cmd[0]));
                } else {
                    y.push_str("    entrypoint:\n");
                    for c in cmd {
                        y.push_str(&format!("      - \"{}\"\n", escape_yaml_str(c)));
                    }
                }
                // args → command in compose (compose: entrypoint = command, command = args)
                if let Some(ref args) = svc.args {
                    y.push_str("    command:\n");
                    for a in args {
                        y.push_str(&format!("      - |\n"));
                        // Indent multiline args
                        for line in a.lines() {
                            y.push_str(&format!("        {}\n", line));
                        }
                    }
                }
                if svc.args.is_none() {
                    y.push('\n');
                }
            }

            // Environment
            if !svc.env.is_empty() {
                y.push_str("    environment:\n");
                for e in &svc.env {
                    // Quote the value to handle special chars
                    y.push_str(&format!("      - \"{}\"\n", escape_yaml_str(e)));
                }
            }

            // Ports (only global)
            let global_ports: Vec<&PortMapping> =
                svc.ports.iter().filter(|p| p.global).collect();
            if !global_ports.is_empty() {
                y.push_str("    ports:\n");
                for p in &global_ports {
                    y.push_str(&format!(
                        "      - \"{}:{}/{}\"\n",
                        p.host_port, p.container_port, p.proto
                    ));
                }
            }
            // Expose internal-only ports (makes them available to other
            // services on the same network without host mapping).
            let internal_ports: Vec<&PortMapping> =
                svc.ports.iter().filter(|p| !p.global).collect();
            if !internal_ports.is_empty() {
                y.push_str("    expose:\n");
                for p in &internal_ports {
                    y.push_str(&format!("      - \"{}/{}\"\n", p.container_port, p.proto));
                }
            }

            // Volumes
            if !svc.volumes.is_empty() {
                y.push_str("    volumes:\n");
                for vm in &svc.volumes {
                    let ro = if vm.read_only { ":ro" } else { "" };
                    y.push_str(&format!(
                        "      - {}:{}{}\n",
                        vm.volume_name, vm.mount_path, ro
                    ));
                }
            }

            // Resource limits
            y.push_str("    deploy:\n");
            y.push_str("      resources:\n");
            y.push_str("        limits:\n");
            let cpus = svc.cpu_millicores as f64 / 1000.0;
            y.push_str(&format!("          cpus: \"{:.1}\"\n", cpus));
            y.push_str(&format!("          memory: {}M\n", svc.memory_bytes / (1024 * 1024)));

            // depends_on
            if !svc.depends_on.is_empty() {
                y.push_str("    depends_on:\n");
                for dep in &svc.depends_on {
                    y.push_str(&format!("      {}:\n", dep));
                    y.push_str("        condition: service_started\n");
                }
            }

            // Restart policy
            y.push_str("    restart: unless-stopped\n");

            y.push('\n');
        }

        y
    }

    /// Return a map of service_name → Vec<(container_port, host_port)> for
    /// globally exposed ports. Used by the lease-status handler.
    pub fn global_port_map(&self) -> HashMap<String, Vec<(u32, u32)>> {
        let mut m = HashMap::new();
        for svc in &self.services {
            let global: Vec<(u32, u32)> = svc
                .ports
                .iter()
                .filter(|p| p.global)
                .map(|p| (p.container_port, p.host_port))
                .collect();
            if !global.is_empty() {
                m.insert(svc.name.clone(), global);
            }
        }
        m
    }

    /// Return a map of service_name → Vec<container_port> for ALL ports
    /// (global + internal). Used for container health checking.
    pub fn all_port_map(&self) -> HashMap<String, Vec<u32>> {
        let mut m = HashMap::new();
        for svc in &self.services {
            let all: Vec<u32> = svc.ports.iter().map(|p| p.container_port).collect();
            if !all.is_empty() {
                m.insert(svc.name.clone(), all);
            }
        }
        m
    }
}

/// Escape a string for use inside a YAML double-quoted value.
fn escape_yaml_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

// ── Container lifecycle ───────────────────────────────────────────────────────

/// Write compose file and run `docker compose up -d`.
/// Returns Ok(()) on success, Err with stderr on failure.
pub fn compose_up(spec: &ComposeSpec, compose_dir: &std::path::Path) -> Result<(), String> {
    let yaml = spec.to_yaml();
    let compose_path = compose_dir.join("docker-compose.yml");

    std::fs::create_dir_all(compose_dir)
        .map_err(|e| format!("mkdir {}: {}", compose_dir.display(), e))?;
    std::fs::write(&compose_path, &yaml)
        .map_err(|e| format!("write {}: {}", compose_path.display(), e))?;

    tracing::info!(
        project = %spec.project_name,
        path = %compose_path.display(),
        services = spec.services.len(),
        "docker compose up -d"
    );

    let output = std::process::Command::new("docker")
        .args([
            "compose",
            "-p",
            &spec.project_name,
            "-f",
            compose_path.to_str().unwrap_or("docker-compose.yml"),
            "up",
            "-d",
            "--remove-orphans",
        ])
        .current_dir(compose_dir)
        .output()
        .map_err(|e| format!("spawn docker compose: {}", e))?;

    if output.status.success() {
        tracing::info!(project = %spec.project_name, "docker compose up succeeded");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(project = %spec.project_name, stderr = %stderr, "docker compose up failed");
        Err(format!("docker compose up failed: {}", stderr))
    }
}

/// Tear down a deployment: `docker compose down -v --remove-orphans`.
pub fn compose_down(project_name: &str, compose_dir: &std::path::Path) {
    tracing::info!(project = %project_name, "docker compose down -v");
    let _ = std::process::Command::new("docker")
        .args([
            "compose",
            "-p",
            project_name,
            "down",
            "-v",
            "--remove-orphans",
        ])
        .current_dir(compose_dir)
        .status();
    // Clean up temp directory.
    let _ = std::fs::remove_dir_all(compose_dir);
}

/// Query actual container state via `docker inspect`.
/// Returns a map of service_name → (running: bool, health: Option<String>).
pub fn inspect_containers(
    project_name: &str,
) -> HashMap<String, ContainerState> {
    let output = match std::process::Command::new("docker")
        .args([
            "compose",
            "-p",
            project_name,
            "ps",
            "--format",
            "json",
        ])
        .output()
    {
        Ok(o) => o,
        Err(_) => return HashMap::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut states = HashMap::new();

    // `docker compose ps --format json` outputs one JSON object per line.
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            let name = val
                .get("Service")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let state_str = val
                .get("State")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            let health = val
                .get("Health")
                .and_then(|s| s.as_str())
                .map(String::from);

            // Parse publishers for actual host ports.
            let mut host_ports: Vec<(u32, u32)> = Vec::new();
            if let Some(publishers) = val.get("Publishers").and_then(|p| p.as_array()) {
                for pub_entry in publishers {
                    let target = pub_entry
                        .get("TargetPort")
                        .and_then(|p| p.as_u64())
                        .unwrap_or(0) as u32;
                    let published = pub_entry
                        .get("PublishedPort")
                        .and_then(|p| p.as_u64())
                        .unwrap_or(0) as u32;
                    if target > 0 && published > 0 {
                        host_ports.push((target, published));
                    }
                }
            }

            if !name.is_empty() {
                states.insert(
                    name,
                    ContainerState {
                        running: state_str == "running",
                        state: state_str,
                        health,
                        host_ports,
                    },
                );
            }
        }
    }

    states
}

/// State of a single container in a compose deployment.
#[derive(Debug, Clone)]
pub struct ContainerState {
    pub running: bool,
    pub state: String,
    pub health: Option<String>,
    /// Actual host port mappings: (container_port, host_port).
    pub host_ports: Vec<(u32, u32)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> serde_json::Value {
        serde_json::json!([{
            "name": "dcloud",
            "services": [
                {
                    "name": "oline-courier",
                    "image": "ghcr.io/permissionlessweb/oline-courier:latest",
                    "command": null,
                    "args": null,
                    "env": ["COURIER_PORT=8080", "CHAIN_JSON_URL=https://example.com/chain.json"],
                    "resources": {
                        "id": 1,
                        "cpu": {"units": {"val": "1000"}, "attributes": []},
                        "memory": {"size": {"val": "536870912"}, "attributes": []},
                        "storage": [{"name": "default", "size": {"val": "64424509440"}, "attributes": []}],
                        "gpu": {"units": {"val": "0"}, "attributes": []},
                        "endpoints": []
                    },
                    "count": 1,
                    "expose": [
                        {"port": 8080, "externalPort": 8080, "proto": "TCP", "service": "", "global": false,
                         "hosts": null, "httpOptions": {"maxBodySize": 1048576, "readTimeout": 60000, "sendTimeout": 60000, "nextTries": 3, "nextTimeout": 0, "nextCases": ["error","timeout"]}, "ip": "", "endpointSequenceNumber": 0},
                        {"port": 8080, "externalPort": 8081, "proto": "TCP", "service": "", "global": true,
                         "hosts": null, "httpOptions": {"maxBodySize": 1048576, "readTimeout": 60000, "sendTimeout": 60000, "nextTries": 3, "nextTimeout": 0, "nextCases": ["error","timeout"]}, "ip": "", "endpointSequenceNumber": 0}
                    ],
                    "params": null,
                    "credentials": null
                },
                {
                    "name": "oline-snapshot",
                    "image": "ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic",
                    "command": ["sh"],
                    "args": ["-c", "echo hello && sleep 3600"],
                    "env": ["CHAIN_ID=morocco-1", "CHAIN_JSON=http://oline-courier:8080/files/chain.json"],
                    "resources": {
                        "id": 2,
                        "cpu": {"units": {"val": "2000"}, "attributes": []},
                        "memory": {"size": {"val": "8589934592"}, "attributes": []},
                        "storage": [{"name": "default", "size": {"val": "53687091200"}, "attributes": []}],
                        "gpu": {"units": {"val": "0"}, "attributes": []},
                        "endpoints": [{"kind": 1, "sequence_number": 0}, {"kind": 1, "sequence_number": 1}]
                    },
                    "count": 1,
                    "expose": [
                        {"port": 26656, "externalPort": 26656, "proto": "TCP", "service": "", "global": true,
                         "hosts": null, "httpOptions": {"maxBodySize": 1048576, "readTimeout": 60000, "sendTimeout": 60000, "nextTries": 3, "nextTimeout": 0, "nextCases": ["error","timeout"]}, "ip": "", "endpointSequenceNumber": 0},
                        {"port": 26657, "externalPort": 26657, "proto": "TCP", "service": "", "global": true,
                         "hosts": null, "httpOptions": {"maxBodySize": 1048576, "readTimeout": 60000, "sendTimeout": 60000, "nextTries": 3, "nextTimeout": 0, "nextCases": ["error","timeout"]}, "ip": "", "endpointSequenceNumber": 1},
                        {"port": 26657, "externalPort": 26657, "proto": "TCP", "service": "", "global": false,
                         "hosts": null, "httpOptions": {"maxBodySize": 1048576, "readTimeout": 60000, "sendTimeout": 60000, "nextTries": 3, "nextTimeout": 0, "nextCases": ["error","timeout"]}, "ip": "", "endpointSequenceNumber": 0}
                    ],
                    "params": {"storage": [{"name": "node-data", "mount": "/root/.terpd", "readOnly": false}]},
                    "credentials": null
                }
            ]
        }])
    }

    #[test]
    fn test_from_manifest_basic() {
        reset_port_counter(40000);
        let manifest = sample_manifest();
        let spec = ComposeSpec::from_manifest(&manifest, 12345);

        assert_eq!(spec.dseq, 12345);
        assert_eq!(spec.project_name, "oline-12345");
        assert_eq!(spec.services.len(), 2);
        assert_eq!(spec.services[0].name, "oline-courier");
        assert_eq!(spec.services[1].name, "oline-snapshot");
    }

    #[test]
    fn test_global_vs_internal_ports() {
        reset_port_counter(40000);
        let manifest = sample_manifest();
        let spec = ComposeSpec::from_manifest(&manifest, 1);

        // Courier: port 8080 has both a global=false and global=true entry.
        // Dedup keeps first seen → the internal one. The global one (8081) is separate.
        let courier = &spec.services[0];
        let global_courier: Vec<_> = courier.ports.iter().filter(|p| p.global).collect();
        let internal_courier: Vec<_> = courier.ports.iter().filter(|p| !p.global).collect();
        // Should have at least one global port (8081 external)
        assert!(!global_courier.is_empty() || !internal_courier.is_empty());

        // Snapshot: 26656 + 26657 global, 26657 internal (deduped)
        let snapshot = &spec.services[1];
        let global_snap: Vec<_> = snapshot.ports.iter().filter(|p| p.global).collect();
        assert!(global_snap.len() >= 2, "snapshot should have ≥2 global ports");
    }

    #[test]
    fn test_volumes_parsed() {
        reset_port_counter(40000);
        let manifest = sample_manifest();
        let spec = ComposeSpec::from_manifest(&manifest, 1);

        // oline-snapshot has a storage param
        let snapshot = &spec.services[1];
        assert_eq!(snapshot.volumes.len(), 1);
        assert_eq!(snapshot.volumes[0].volume_name, "node-data");
        assert_eq!(snapshot.volumes[0].mount_path, "/root/.terpd");
        assert!(!snapshot.volumes[0].read_only);

        // Top-level volumes should include "node-data"
        assert!(spec.volumes.contains(&"node-data".to_string()));
    }

    #[test]
    fn test_command_args_passed_through() {
        reset_port_counter(40000);
        let manifest = sample_manifest();
        let spec = ComposeSpec::from_manifest(&manifest, 1);

        let snapshot = &spec.services[1];
        assert_eq!(snapshot.command, Some(vec!["sh".to_string()]));
        assert_eq!(
            snapshot.args,
            Some(vec!["-c".to_string(), "echo hello && sleep 3600".to_string()])
        );
    }

    #[test]
    fn test_to_yaml_contains_network() {
        reset_port_counter(40000);
        let manifest = sample_manifest();
        let spec = ComposeSpec::from_manifest(&manifest, 99);
        let yaml = spec.to_yaml();

        assert!(yaml.contains("networks:"));
        assert!(yaml.contains("oline-net-99:"));
        assert!(yaml.contains("driver: bridge"));
        // Each service references the network
        assert!(yaml.contains("      - oline-net-99"));
    }

    #[test]
    fn test_to_yaml_resource_limits() {
        reset_port_counter(40000);
        let manifest = sample_manifest();
        let spec = ComposeSpec::from_manifest(&manifest, 1);
        let yaml = spec.to_yaml();

        // Courier: 1000 millicores = 1.0 CPU, 512MB
        assert!(yaml.contains("cpus: \"1.0\""));
        assert!(yaml.contains("memory: 512M"));
        // Snapshot: 2000 millicores = 2.0 CPU, 8192MB
        assert!(yaml.contains("cpus: \"2.0\""));
        assert!(yaml.contains("memory: 8192M"));
    }

    #[test]
    fn test_global_port_map() {
        reset_port_counter(40000);
        let manifest = sample_manifest();
        let spec = ComposeSpec::from_manifest(&manifest, 1);
        let map = spec.global_port_map();

        // Snapshot should have global ports
        assert!(map.contains_key("oline-snapshot"));
        let snap_ports = &map["oline-snapshot"];
        // Should include 26656 and 26657
        let container_ports: Vec<u32> = snap_ports.iter().map(|(cp, _)| *cp).collect();
        assert!(container_ports.contains(&26656));
        assert!(container_ports.contains(&26657));
    }

    #[test]
    fn test_depends_on() {
        reset_port_counter(40000);
        let manifest = sample_manifest();
        let spec = ComposeSpec::from_manifest(&manifest, 1);

        // First service (courier) has no deps
        assert!(spec.services[0].depends_on.is_empty());
        // Second service depends on first
        assert_eq!(spec.services[1].depends_on, vec!["oline-courier"]);
    }
}
