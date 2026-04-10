//! SSH helpers for WireGuard management on pfSense.
//!
//! All operations use key-based SSH auth against a stored `FirewallRecord`.
//! pfSense runs FreeBSD; WireGuard ships as a first-party component in pfSense 2.5.2+.

use crate::firewall::FirewallRecord;
use std::{
    error::Error,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

// ── Low-level SSH exec ─────────────────────────────────────────────────────────

/// Run a command on pfSense via key-based SSH. Returns stdout on success.
pub fn ssh_exec(fw: &FirewallRecord, key_path: &Path, command: &str) -> Result<String, Box<dyn Error>> {
    let output = Command::new("ssh")
        .args([
            "-i", key_path.to_str().unwrap_or(""),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15",
            "-p", &fw.ssh_port.to_string(),
            &format!("{}@{}", fw.user, fw.host),
            command,
        ])
        .output()
        .map_err(|e| format!("Failed to run ssh: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("SSH command failed: {}", stderr.trim()).into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Pipe `stdin_data` to a command on pfSense via SSH (for writing files and running pfSsh.php).
pub fn ssh_exec_stdin(
    fw: &FirewallRecord,
    key_path: &Path,
    command: &str,
    stdin_data: &[u8],
) -> Result<String, Box<dyn Error>> {
    let mut child = Command::new("ssh")
        .args([
            "-i", key_path.to_str().unwrap_or(""),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15",
            "-p", &fw.ssh_port.to_string(),
            &format!("{}@{}", fw.user, fw.host),
            command,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn ssh: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_data).map_err(|e| format!("Failed to write stdin: {}", e))?;
    }

    let output = child.wait_with_output().map_err(|e| format!("SSH wait failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("SSH stdin command failed: {}", stderr.trim()).into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// ── WireGuard operations ───────────────────────────────────────────────────────

/// Check that WireGuard is available on pfSense. Returns the version string.
pub fn check_wg_available(fw: &FirewallRecord, key_path: &Path) -> Result<String, Box<dyn Error>> {
    let out = ssh_exec(fw, key_path, "wg --version")
        .map_err(|e| format!("WireGuard not found on pfSense (wg --version failed): {}", e))?;
    Ok(out.trim().to_string())
}

/// Write a WireGuard config file to pfSense via SSH.
///
/// Creates `/usr/local/etc/wireguard/` if needed, then writes `<iface>.conf`.
pub fn write_wg_config(
    fw: &FirewallRecord,
    key_path: &Path,
    iface: &str,
    config_content: &str,
) -> Result<(), Box<dyn Error>> {
    // Create directory first (idempotent)
    ssh_exec(fw, key_path, "mkdir -p /usr/local/etc/wireguard && chmod 700 /usr/local/etc/wireguard")?;

    // Write config via stdin → `cat > /path`
    let remote_path = format!("/usr/local/etc/wireguard/{}.conf", iface);
    let cmd = format!("cat > {} && chmod 600 {}", remote_path, remote_path);
    ssh_exec_stdin(fw, key_path, &cmd, config_content.as_bytes())?;

    Ok(())
}

/// Start or reload the WireGuard interface on pfSense (or a Linux mock).
///
/// Symlinks the FreeBSD config path into /etc/wireguard/ for Linux compatibility,
/// then tries `service wireguard start` (FreeBSD) falling back to `wg-quick up` (Linux).
pub fn reload_wg(fw: &FirewallRecord, key_path: &Path, iface: &str) -> Result<(), Box<dyn Error>> {
    // Ensure Linux wg-quick path is populated from the FreeBSD-style path.
    // On real pfSense this is a no-op (ln target already exists).
    let reload_cmd = format!(
        "mkdir -p /etc/wireguard && \
         cp /usr/local/etc/wireguard/{iface}.conf /etc/wireguard/{iface}.conf 2>/dev/null || true; \
         wg-quick down {iface} 2>/dev/null || true; \
         service wireguard start {iface} 2>/dev/null || wg-quick up {iface}",
        iface = iface
    );
    ssh_exec(fw, key_path, &reload_cmd)?;
    Ok(())
}

/// Add a UDP pass firewall rule on the pfSense WAN interface for the WireGuard port.
///
/// Uses `pfSsh.php playback` pattern to modify `$config` and call `filter_configure()`.
pub fn add_fw_rule(
    fw: &FirewallRecord,
    key_path: &Path,
    listen_port: u16,
) -> Result<(), Box<dyn Error>> {
    let php_script = format!(
        r#"parse_config(true);
if (!is_array($config["filter"]["rule"])) {{ $config["filter"]["rule"] = array(); }}
$removed = 0;
foreach ($config["filter"]["rule"] as $r) {{
    if (isset($r["descr"]) && strpos($r["descr"], "oline: WireGuard UDP {port}") === 0) {{ $removed++; }}
}}
if ($removed == 0) {{
    $config["filter"]["rule"][] = array(
        "type"        => "pass",
        "interface"   => "wan",
        "ipprotocol"  => "inet",
        "protocol"    => "udp",
        "destination" => array("port" => "{port}"),
        "descr"       => "oline: WireGuard UDP {port}"
    );
    write_config("oline: WireGuard UDP pass rule {port}");
    filter_configure();
}}
exec
exit
"#,
        port = listen_port
    );

    ssh_exec_stdin(
        fw,
        key_path,
        "/usr/local/sbin/pfSsh.php",
        php_script.as_bytes(),
    )?;

    Ok(())
}

/// Show the WireGuard interface status on pfSense.
pub fn wg_status(fw: &FirewallRecord, key_path: &Path, iface: &str) -> Result<String, Box<dyn Error>> {
    let cmd = format!("wg show {}", iface);
    let out = ssh_exec(fw, key_path, &cmd)
        .map_err(|e| format!("Failed to get WireGuard status: {}", e))?;
    Ok(out)
}

/// Hot-add a peer to a running WireGuard interface (no restart needed).
pub fn add_peer_hot(
    fw: &FirewallRecord,
    key_path: &Path,
    iface: &str,
    peer_pub_key: &str,
    allowed_ips: &str,
) -> Result<(), Box<dyn Error>> {
    let cmd = format!(
        "wg set {} peer {} allowed-ips {}",
        iface, peer_pub_key, allowed_ips,
    );
    ssh_exec(fw, key_path, &cmd)?;
    Ok(())
}

/// Hot-remove a peer from a running WireGuard interface.
pub fn remove_peer_hot(
    fw: &FirewallRecord,
    key_path: &Path,
    iface: &str,
    peer_pub_key: &str,
) -> Result<(), Box<dyn Error>> {
    let cmd = format!("wg set {} peer {} remove", iface, peer_pub_key);
    ssh_exec(fw, key_path, &cmd)?;
    Ok(())
}

/// SSH-push a WireGuard client config to a remote machine.
///
/// Writes the config content to `~/wg0.conf` (or `~/<iface>.conf`) on the target.
/// Uses the user's default SSH keys (or whatever is in `~/.ssh/config`).
/// `target` is in the format `[user@]host[:port]`.
pub fn push_client_conf(
    target: &str,
    iface: &str,
    conf_content: &str,
) -> Result<(), Box<dyn Error>> {
    let (user_host, port) = parse_target(target);
    let remote_path = format!("~/{}.conf", iface);
    let cmd = format!("cat > {}", remote_path);

    let mut args: Vec<&str> = vec![
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=15",
    ];

    let port_str = port.to_string();
    if port != 22 {
        args.extend_from_slice(&["-p", &port_str]);
    }
    args.push(&user_host);
    args.push(&cmd);

    let mut child = Command::new("ssh")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to SSH to {}: {}", target, e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(conf_content.as_bytes())
            .map_err(|e| format!("Failed to write conf to {}: {}", target, e))?;
    }

    let output = child.wait_with_output()
        .map_err(|e| format!("SSH wait failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to push config to {}: {}", target, stderr.trim()).into());
    }

    Ok(())
}

/// SSH-push a WireGuard client config using an explicit key file.
///
/// Same as `push_client_conf` but uses a specific SSH private key instead of the agent.
/// Used in tests and automation where the key path is known.
pub fn push_client_conf_with_key(
    target: &str,
    iface: &str,
    conf_content: &str,
    key_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let (user_host, port) = parse_target(target);
    let remote_path = format!("~/{}.conf", iface);
    let cmd = format!("cat > {}", remote_path);

    let port_str = port.to_string();
    let key_str = key_path.to_str().unwrap_or("");
    let mut args: Vec<&str> = vec![
        "-i", key_str,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=15",
    ];
    if port != 22 {
        args.extend_from_slice(&["-p", &port_str]);
    }
    args.push(&user_host);
    args.push(&cmd);

    let mut child = Command::new("ssh")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to SSH to {}: {}", target, e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(conf_content.as_bytes())
            .map_err(|e| format!("Failed to write conf to {}: {}", target, e))?;
    }

    let output = child.wait_with_output()
        .map_err(|e| format!("SSH wait failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to push config to {}: {}", target, stderr.trim()).into());
    }

    Ok(())
}

/// Remove the WireGuard config file from a remote machine.
pub fn remove_client_conf(target: &str, iface: &str) -> Result<(), Box<dyn Error>> {
    let (user_host, port) = parse_target(target);
    let remote_path = format!("~/{}.conf", iface);
    let cmd = format!("rm -f {}", remote_path);

    let port_str = port.to_string();
    let mut args: Vec<&str> = vec![
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=15",
    ];
    if port != 22 {
        args.extend_from_slice(&["-p", &port_str]);
    }
    args.push(&user_host);
    args.push(&cmd);

    let output = Command::new("ssh")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to SSH to {}: {}", target, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("Failed to remove config from {}: {}", target, stderr.trim());
    }

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Parse `[user@]host[:port]` into `("user@host", port)`.
/// Defaults: user=current user (omitted from output), port=22.
fn parse_target(target: &str) -> (String, u16) {
    let (user_at, host_port) = if let Some(at) = target.find('@') {
        (format!("{}@", &target[..at]), &target[at + 1..])
    } else {
        (String::new(), target)
    };

    let (host, port) = if let Some(colon) = host_port.rfind(':') {
        let port_str = &host_port[colon + 1..];
        if let Ok(p) = port_str.parse::<u16>() {
            (host_port[..colon].to_string(), p)
        } else {
            (host_port.to_string(), 22)
        }
    } else {
        (host_port.to_string(), 22)
    };

    (format!("{}{}", user_at, host), port)
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_full() {
        let (uh, port) = parse_target("alice@10.0.0.50:2222");
        assert_eq!(uh, "alice@10.0.0.50");
        assert_eq!(port, 2222);
    }

    #[test]
    fn test_parse_target_user_host() {
        let (uh, port) = parse_target("alice@10.0.0.50");
        assert_eq!(uh, "alice@10.0.0.50");
        assert_eq!(port, 22);
    }

    #[test]
    fn test_parse_target_host_only() {
        let (uh, port) = parse_target("10.0.0.50");
        assert_eq!(uh, "10.0.0.50");
        assert_eq!(port, 22);
    }
}
