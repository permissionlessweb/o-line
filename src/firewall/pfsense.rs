//! pfSense SSH key provisioning.
//!
//! Two methods for initial key install:
//!   - `ssh-copy-id` (preferred): standard tool, handles authorized_keys natively
//!   - `sshpass` (fallback): manual key install via password-authenticated SSH
//!
//! After bootstrap, all SSH uses the `openssh` crate with key-based auth.

use std::{error::Error, fmt, path::Path, process::Command};

// ── Key install method ─────────────────────────────────────────────────────────

/// How to install the SSH public key on the remote host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyInstallMethod {
    /// Use `ssh-copy-id` — the standard OpenSSH key installer.
    /// Interactive: prompts for password itself.
    /// Non-interactive: wrapped with `sshpass`.
    SshCopyId,
    /// Use `sshpass` + manual append to `~/.ssh/authorized_keys`.
    Sshpass,
}

impl fmt::Display for KeyInstallMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SshCopyId => write!(f, "ssh-copy-id"),
            Self::Sshpass => write!(f, "sshpass"),
        }
    }
}

impl KeyInstallMethod {
    /// Parse from CLI string. Returns `None` for "auto".
    pub fn parse(s: &str) -> Result<Option<Self>, String> {
        match s {
            "auto" => Ok(None),
            "ssh-copy-id" => Ok(Some(Self::SshCopyId)),
            "sshpass" => Ok(Some(Self::Sshpass)),
            other => Err(format!("Unknown method '{}'. Use: auto, ssh-copy-id, sshpass", other)),
        }
    }
}

/// Check if a binary is available on PATH.
fn has_binary(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Detect the best available key install method.
/// Prefers `ssh-copy-id`, falls back to `sshpass`.
pub fn detect_method() -> Result<KeyInstallMethod, Box<dyn Error>> {
    if has_binary("ssh-copy-id") {
        Ok(KeyInstallMethod::SshCopyId)
    } else if has_binary("sshpass") {
        Ok(KeyInstallMethod::Sshpass)
    } else {
        Err("Neither ssh-copy-id nor sshpass found. Install one:\n  \
             ssh-copy-id: included with OpenSSH (brew install openssh / apt install openssh-client)\n  \
             sshpass:     brew install hudochenkov/sshpass/sshpass (macOS) / apt install sshpass (Debian)"
            .into())
    }
}

/// Resolve a method choice: if explicit, validate the binary exists; if auto, detect.
pub fn resolve_method(choice: Option<KeyInstallMethod>) -> Result<KeyInstallMethod, Box<dyn Error>> {
    match choice {
        Some(KeyInstallMethod::SshCopyId) => {
            if !has_binary("ssh-copy-id") {
                return Err("ssh-copy-id not found on PATH".into());
            }
            Ok(KeyInstallMethod::SshCopyId)
        }
        Some(KeyInstallMethod::Sshpass) => {
            check_sshpass()?;
            Ok(KeyInstallMethod::Sshpass)
        }
        None => detect_method(),
    }
}

/// Check that `sshpass` is available on PATH.
pub fn check_sshpass() -> Result<(), Box<dyn Error>> {
    if has_binary("sshpass") {
        Ok(())
    } else {
        Err("sshpass not found. Install it first:\n  \
             macOS:  brew install hudochenkov/sshpass/sshpass\n  \
             Debian: apt install sshpass"
            .into())
    }
}

/// Run a command on the remote host via `sshpass -p <password> ssh`.
/// Uses `/bin/sh -c` to bypass the pfSense interactive menu.
pub fn ssh_with_password(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    command: &str,
) -> Result<std::process::Output, Box<dyn Error>> {
    // Pass command as a single string so SSH's remote shell parses it correctly.
    // Using `/bin/sh -c '...'` bypasses the pfSense interactive console menu.
    let wrapped = format!("/bin/sh -c '{}'", command.replace('\'', "'\\''"));
    let output = Command::new("sshpass")
        .args([
            "-p",
            password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-p",
            &port.to_string(),
            &format!("{}@{}", user, host),
            &wrapped,
        ])
        .output()
        .map_err(|e| format!("Failed to run sshpass: {}", e))?;

    Ok(output)
}

/// Build the shell command that installs a pubkey into authorized_keys.
/// Idempotent via `sort -u`.
pub fn build_install_key_command(pubkey: &str) -> String {
    format!(
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
         echo '{}' >> ~/.ssh/authorized_keys && \
         sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys && \
         chmod 600 ~/.ssh/authorized_keys",
        pubkey
    )
}

/// Install an SSH public key on the remote pfSense host via password auth (sshpass method).
pub fn install_ssh_key(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    pubkey: &str,
) -> Result<(), Box<dyn Error>> {
    let cmd = build_install_key_command(pubkey);
    let output = ssh_with_password(host, port, user, password, &cmd)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to install SSH key: {}", stderr.trim()).into());
    }

    Ok(())
}

/// Install an SSH public key using `ssh-copy-id`.
///
/// In non-interactive mode (password provided), wraps with `sshpass`.
/// In interactive mode (password is None), `ssh-copy-id` prompts the user directly.
pub fn install_ssh_key_copy_id(
    host: &str,
    port: u16,
    user: &str,
    password: Option<&str>,
    pubkey_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let pubkey_path_str = pubkey_path
        .to_str()
        .ok_or("Public key path contains invalid UTF-8")?;

    let dest = format!("{}@{}", user, host);

    let output = if let Some(pw) = password {
        // Non-interactive: wrap ssh-copy-id with sshpass
        Command::new("sshpass")
            .args([
                "-p",
                pw,
                "ssh-copy-id",
                "-i",
                pubkey_path_str,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-p",
                &port.to_string(),
                &dest,
            ])
            .output()
            .map_err(|e| format!("Failed to run sshpass ssh-copy-id: {}", e))?
    } else {
        // Interactive: ssh-copy-id prompts for password
        Command::new("ssh-copy-id")
            .args([
                "-i",
                pubkey_path_str,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-p",
                &port.to_string(),
                &dest,
            ])
            .output()
            .map_err(|e| format!("Failed to run ssh-copy-id: {}", e))?
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("ssh-copy-id failed: {}", stderr.trim()).into());
    }

    Ok(())
}

/// Test password-based SSH connectivity without sshpass.
/// Uses `ssh-copy-id` path's password handling — just runs a simple ssh command.
/// Returns the uname output on success.
pub fn test_ssh_connectivity(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
) -> Result<String, Box<dyn Error>> {
    let output = ssh_with_password(host, port, user, password, "uname -a")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("SSH connection failed: {}", stderr.trim()).into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Verify that key-based SSH auth works (no password needed).
pub async fn verify_key_auth(
    host: &str,
    port: u16,
    user: &str,
    key_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let output = Command::new("ssh")
        .args([
            "-i",
            key_path.to_str().unwrap_or(""),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-p",
            &port.to_string(),
            &format!("{}@{}", user, host),
            "echo ok",
        ])
        .output()
        .map_err(|e| format!("Failed to run ssh: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Key-based auth verification failed: {}", stderr.trim()).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().contains("ok") {
        return Err("Key-based auth: unexpected response (expected 'ok')".into());
    }

    Ok(())
}

/// Build an SSH ProxyCommand string for tunneling through a jump host with key auth.
pub fn build_proxy_command(
    jump_host: &str,
    jump_port: u16,
    jump_user: &str,
    jump_key_path: &Path,
) -> String {
    format!(
        "ssh -i {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {} -W %h:%p {}@{}",
        jump_key_path.to_str().unwrap_or(""),
        jump_port,
        jump_user,
        jump_host,
    )
}

/// Install an SSH public key on a target server via a pfSense jump host.
///
/// Uses ProxyCommand to tunnel through pfSense (key auth) to the target (password auth).
/// The same pubkey is installed on both pfSense and the target.
pub fn forward_ssh_key_via_jump(
    jump_host: &str,
    jump_port: u16,
    jump_user: &str,
    jump_key_path: &Path,
    target_host: &str,
    target_port: u16,
    target_user: &str,
    target_password: &str,
    pubkey: &str,
) -> Result<(), Box<dyn Error>> {
    let install_cmd = build_install_key_command(pubkey);
    let proxy_cmd = build_proxy_command(jump_host, jump_port, jump_user, jump_key_path);

    let output = Command::new("sshpass")
        .args([
            "-p",
            target_password,
            "ssh",
            "-o",
            &format!("ProxyCommand={}", proxy_cmd),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-p",
            &target_port.to_string(),
            &format!("{}@{}", target_user, target_host),
            &install_cmd,
        ])
        .output()
        .map_err(|e| format!("Failed to forward SSH key via jump host: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "SSH key forward to {}@{} failed: {}",
            target_user,
            target_host,
            stderr.trim()
        )
        .into());
    }

    Ok(())
}

/// Verify key-based SSH auth to a target via a pfSense jump host (no password).
pub async fn verify_key_auth_via_jump(
    jump_host: &str,
    jump_port: u16,
    jump_user: &str,
    jump_key_path: &Path,
    target_host: &str,
    target_port: u16,
    target_user: &str,
    target_key_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let proxy_cmd = build_proxy_command(jump_host, jump_port, jump_user, jump_key_path);

    let output = Command::new("ssh")
        .args([
            "-i",
            target_key_path.to_str().unwrap_or(""),
            "-o",
            &format!("ProxyCommand={}", proxy_cmd),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-p",
            &target_port.to_string(),
            &format!("{}@{}", target_user, target_host),
            "echo ok",
        ])
        .output()
        .map_err(|e| format!("Failed to verify via jump host: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Key-based auth verification via jump failed: {}",
            stderr.trim()
        )
        .into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().contains("ok") {
        return Err("Key-based auth via jump: unexpected response (expected 'ok')".into());
    }

    Ok(())
}

/// Build the shell command that removes a pubkey from authorized_keys by its base64 key data.
/// Uses `grep -vF` (fixed-string invert match) — safe for base64, no regex issues.
pub fn build_remove_key_command(key_data: &str) -> String {
    format!(
        "if [ -f ~/.ssh/authorized_keys ]; then \
         grep -vF '{}' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && \
         mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys && \
         chmod 600 ~/.ssh/authorized_keys; \
         fi",
        key_data
    )
}

/// Remove an SSH public key from a target server via a pfSense jump host (key auth, no password).
pub fn revoke_ssh_key_via_jump(
    jump_host: &str,
    jump_port: u16,
    jump_user: &str,
    jump_key_path: &Path,
    target_host: &str,
    target_port: u16,
    target_user: &str,
    key_data: &str,
) -> Result<(), Box<dyn Error>> {
    let remove_cmd = build_remove_key_command(key_data);
    let proxy_cmd = build_proxy_command(jump_host, jump_port, jump_user, jump_key_path);

    let output = Command::new("ssh")
        .args([
            "-i",
            jump_key_path.to_str().unwrap_or(""),
            "-o",
            &format!("ProxyCommand={}", proxy_cmd),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-p",
            &target_port.to_string(),
            &format!("{}@{}", target_user, target_host),
            &remove_cmd,
        ])
        .output()
        .map_err(|e| format!("Failed to revoke SSH key via jump host: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "SSH key revocation on {}@{} failed: {}",
            target_user, target_host, stderr.trim()
        )
        .into());
    }

    Ok(())
}

/// Format an SSH destination string for display/logging.
pub fn ssh_dest(host: &str, port: u16, user: &str) -> String {
    if port == 22 {
        format!("{}@{}", user, host)
    } else {
        format!("{}@{}:{}", user, host, port)
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_install_command() {
        let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test@host";
        let cmd = build_install_key_command(pubkey);

        assert!(cmd.contains("mkdir -p ~/.ssh"));
        assert!(cmd.contains("chmod 700 ~/.ssh"));
        assert!(cmd.contains(pubkey));
        assert!(cmd.contains("sort -u ~/.ssh/authorized_keys"));
        assert!(cmd.contains("chmod 600 ~/.ssh/authorized_keys"));
    }

    #[test]
    fn test_build_install_command_special_chars() {
        let pubkey = "ssh-rsa AAAA+/== user@host";
        let cmd = build_install_key_command(pubkey);
        assert!(cmd.contains(pubkey));
    }

    #[test]
    fn test_ssh_dest_default_port() {
        assert_eq!(ssh_dest("192.168.1.1", 22, "admin"), "admin@192.168.1.1");
    }

    #[test]
    fn test_ssh_dest_custom_port() {
        assert_eq!(
            ssh_dest("10.0.0.1", 2222, "root"),
            "root@10.0.0.1:2222"
        );
    }

    #[test]
    fn test_install_command_idempotent() {
        // The sort -u ensures that running the command multiple times
        // with the same key only keeps one entry.
        let pubkey = "ssh-ed25519 AAAAC3Test test@host";
        let cmd = build_install_key_command(pubkey);
        // Verify the idempotency mechanism is present
        assert!(cmd.contains("sort -u"));
        assert!(cmd.contains("-o ~/.ssh/authorized_keys"));
    }

    #[test]
    fn test_method_parse() {
        assert_eq!(KeyInstallMethod::parse("auto").unwrap(), None);
        assert_eq!(
            KeyInstallMethod::parse("ssh-copy-id").unwrap(),
            Some(KeyInstallMethod::SshCopyId)
        );
        assert_eq!(
            KeyInstallMethod::parse("sshpass").unwrap(),
            Some(KeyInstallMethod::Sshpass)
        );
        assert!(KeyInstallMethod::parse("unknown").is_err());
    }

    #[test]
    fn test_method_display() {
        assert_eq!(KeyInstallMethod::SshCopyId.to_string(), "ssh-copy-id");
        assert_eq!(KeyInstallMethod::Sshpass.to_string(), "sshpass");
    }

    #[test]
    fn test_detect_method_finds_something() {
        // On any dev machine, at least ssh-copy-id (from OpenSSH) should be available.
        // This test just verifies detect_method doesn't panic.
        let _ = detect_method();
    }

    #[test]
    fn test_build_proxy_command() {
        let key_path = Path::new("/tmp/pfsense-key");
        let cmd = build_proxy_command("192.168.1.1", 22, "admin", key_path);
        assert!(cmd.contains("-i /tmp/pfsense-key"));
        assert!(cmd.contains("-p 22"));
        assert!(cmd.contains("-W %h:%p"));
        assert!(cmd.contains("admin@192.168.1.1"));
        assert!(cmd.contains("StrictHostKeyChecking=no"));
    }

    #[test]
    fn test_build_remove_key_command() {
        let key_data = "AAAAC3NzaC1lZDI1NTE5AAAAITest";
        let cmd = build_remove_key_command(key_data);

        assert!(cmd.contains("grep -vF"));
        assert!(cmd.contains(key_data));
        assert!(cmd.contains("authorized_keys.tmp"));
        assert!(cmd.contains("chmod 600"));
        assert!(cmd.contains("if [ -f ~/.ssh/authorized_keys ]"));
    }

    #[test]
    fn test_build_remove_key_command_special_chars() {
        // base64 can contain + / = — must be treated as fixed string, not regex
        let key_data = "AAAA+/Base64Data==";
        let cmd = build_remove_key_command(key_data);
        assert!(cmd.contains(key_data));
        assert!(cmd.contains("-vF")); // fixed-string match
    }

    #[test]
    fn test_build_proxy_command_custom_port() {
        let key_path = Path::new("/keys/fw");
        let cmd = build_proxy_command("10.0.0.1", 2222, "root", key_path);
        assert!(cmd.contains("-p 2222"));
        assert!(cmd.contains("root@10.0.0.1"));
    }
}
