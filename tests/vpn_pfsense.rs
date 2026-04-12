//! Integration tests for `oline vpn` against Docker mock pfSense + wg-client containers.
//!
//! Requires the pfsense-e2e docker-compose setup with the wg-client service.
//! Start: `docker compose -f docker/pfsense-e2e/docker-compose.yml up -d --build --wait`
//!
//! Run: `cargo test --test vpn_pfsense -- --nocapture --ignored`

use std::process::Command;

// ── Constants ─────────────────────────────────────────────────────────────────

/// pfSense mock — SSH port exposed to host
const PF_HOST: &str = "127.0.0.1";
const PF_P: u16 = 2222;
/// Root user on pfSense mock (needed for wg/ip commands)
const PF_ROOT_USER: &str = "root";
const PF_ROOT_PASS: &str = "pfsense";
/// pfSense WAN IP inside the Docker network
const PF_WAN_IP: &str = "10.99.2.168";

/// WireGuard client container — SSH port exposed to host
const WG_CLIENT_HOST: &str = "127.0.0.1";
const WG_CLIENT_P: u16 = 2223;
const WG_CLIENT_USER: &str = "root";
const WG_CLIENT_PASS: &str = "client";

/// VPN config
const VPN_IFACE: &str = "wg0";
const VPN_SERVER_ADDR: &str = "10.99.3.1/24";
const VPN_CLIENT_ADDR: &str = "10.99.3.2/32";
const VPN_P: u16 = 51820;

/// LAN server reachable only via VPN
const INTERNAL_SERVER_IP: &str = "10.99.1.10";
const INTERNAL_SERVER_HTTP_P: u16 = 8080;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn wait_for_ssh(host: &str, port: u16, user: &str, pass: &str) {
    for attempt in 1..=30 {
        let status = Command::new("sshpass")
            .args([
                "-p",
                pass,
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=3",
                "-p",
                &port.to_string(),
                &format!("{}@{}", user, host),
                "echo ok",
            ])
            .output();

        match status {
            Ok(o) if o.status.success() => return,
            _ => {
                if attempt == 30 {
                    panic!("SSH not reachable at {}:{} after 30 attempts", host, port);
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

/// Run a command on a remote host using an SSH key. Returns stdout.
fn ssh_exec_with_key(host: &str, port: u16, user: &str, key: &Path, cmd: &str) -> String {
    let output = Command::new("ssh")
        .args([
            "-i",
            key.to_str().unwrap(),
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
            cmd,
        ])
        .output()
        .expect("failed to run ssh");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        panic!(
            "SSH command `{}` on {}@{}:{} failed.\nstdout: {}\nstderr: {}",
            cmd,
            user,
            host,
            port,
            stdout.trim(),
            stderr.trim()
        );
    }

    stdout
}

use std::path::Path;

// ── Test ──────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires Docker: docker compose -f docker/pfsense-e2e/docker-compose.yml up -d --build --wait"]
fn test_vpn_bootstrap_and_peer_connectivity() {
    // ── 0. Wait for both containers ───────────────────────────────────────────
    println!("[vpn-e2e] Waiting for pfsense-mock SSH...");
    wait_for_ssh(PF_HOST, PF_P, PF_ROOT_USER, PF_ROOT_PASS);

    println!("[vpn-e2e] Waiting for wg-client SSH...");
    wait_for_ssh(
        WG_CLIENT_HOST,
        WG_CLIENT_P,
        WG_CLIENT_USER,
        WG_CLIENT_PASS,
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let secrets = tmp.path();

    // ── 1. Generate SSH key for pfSense VPN ops (root) ───────────────────────
    let pf_privkey = o_line_sdl::crypto::gen_ssh_key();
    let pf_pubkey = pf_privkey.public_key().to_string();
    let pf_key_path = secrets.join("pf-vpn-key");
    o_line_sdl::crypto::save_ssh_key(&pf_privkey, &pf_key_path).unwrap();

    o_line_sdl::firewall::pfsense::install_ssh_key(
        PF_HOST,
        PF_P,
        PF_ROOT_USER,
        PF_ROOT_PASS,
        &pf_pubkey,
    )
    .expect("install pfSense root key");

    // ── 2. Generate SSH key for wg-client ────────────────────────────────────
    let wgc_privkey = o_line_sdl::crypto::gen_ssh_key();
    let wgc_pubkey = wgc_privkey.public_key().to_string();
    let wgc_key_path = secrets.join("wg-client-key");
    o_line_sdl::crypto::save_ssh_key(&wgc_privkey, &wgc_key_path).unwrap();

    o_line_sdl::firewall::pfsense::install_ssh_key(
        WG_CLIENT_HOST,
        WG_CLIENT_P,
        WG_CLIENT_USER,
        WG_CLIENT_PASS,
        &wgc_pubkey,
    )
    .expect("install wg-client key");

    // ── 3. Build FirewallRecord for root@pfSense ──────────────────────────────
    let fw = o_line_sdl::firewall::FirewallRecord::new(
        "pfsense-vpn-e2e",
        PF_HOST,
        PF_P,
        PF_ROOT_USER,
        "pf-vpn-key",
    );

    // ── 4. Check WireGuard available ─────────────────────────────────────────
    let wg_ver = o_line_sdl::vpn::pfsense::check_wg_available(&fw, &pf_key_path)
        .expect("wg --version on pfSense mock");
    println!("[vpn-e2e] WireGuard: {}", wg_ver.trim());

    // ── 5. Generate server keypair + write server config ─────────────────────
    let (server_priv, server_pub) = o_line_sdl::vpn::keygen::generate_wg_keypair();

    let server = o_line_sdl::vpn::WgServer {
        firewall_label: "pfsense-vpn-e2e".into(),
        interface: VPN_IFACE.into(),
        listen_port: VPN_P,
        server_address: VPN_SERVER_ADDR.into(),
        private_key: server_priv,
        public_key: server_pub.clone(),
        wan_endpoint: Some(format!("{}:{}", PF_WAN_IP, VPN_P)),
        peers: vec![],
        created_at: 0,
    };

    let server_conf = o_line_sdl::vpn::keygen::wg_server_conf(&server);
    println!("[vpn-e2e] Writing server config...\n{}", server_conf);

    o_line_sdl::vpn::pfsense::write_wg_config(&fw, &pf_key_path, VPN_IFACE, &server_conf)
        .expect("write_wg_config");

    // ── 6. Start WireGuard on pfSense mock ───────────────────────────────────
    println!("[vpn-e2e] Starting WireGuard interface...");
    o_line_sdl::vpn::pfsense::reload_wg(&fw, &pf_key_path, VPN_IFACE).expect("reload_wg");

    // ── 7. Add firewall pass rule for WireGuard UDP ───────────────────────────
    println!("[vpn-e2e] Adding UDP {} pass rule...", VPN_P);
    o_line_sdl::vpn::pfsense::add_fw_rule(&fw, &pf_key_path, VPN_P).expect("add_fw_rule");

    // ── 8. Verify WireGuard interface is up ───────────────────────────────────
    let status =
        o_line_sdl::vpn::pfsense::wg_status(&fw, &pf_key_path, VPN_IFACE).expect("wg_status");
    println!("[vpn-e2e] WireGuard status:\n{}", status);
    assert!(
        status.contains("interface: wg0") || status.contains("wg0"),
        "Expected wg0 interface in status output"
    );

    // ── 9. Generate peer keypair + hot-add peer ───────────────────────────────
    let (peer_priv, peer_pub) = o_line_sdl::vpn::keygen::generate_wg_keypair();

    o_line_sdl::vpn::pfsense::add_peer_hot(
        &fw,
        &pf_key_path,
        VPN_IFACE,
        &peer_pub,
        VPN_CLIENT_ADDR,
    )
    .expect("add_peer_hot");

    println!(
        "[vpn-e2e] Peer {} hot-added with allowed-ips {}",
        &peer_pub[..16],
        VPN_CLIENT_ADDR
    );

    // ── 10. Generate client config + push to wg-client ───────────────────────
    // Route VPN subnet + LAN subnet through the tunnel
    let allowed_ips = "10.99.3.0/24,10.99.1.0/24";
    let client_conf = o_line_sdl::vpn::keygen::wg_client_conf(
        &peer_priv,
        VPN_CLIENT_ADDR,
        &server_pub,
        &format!("{}:{}", PF_WAN_IP, VPN_P),
        &allowed_ips,
    );
    println!("[vpn-e2e] Client config:\n{}", client_conf);

    let wgc_target = format!("{}@{}:{}", WG_CLIENT_USER, WG_CLIENT_HOST, WG_CLIENT_P);
    o_line_sdl::vpn::pfsense::push_client_conf_with_key(
        &wgc_target,
        VPN_IFACE,
        &client_conf,
        &wgc_key_path,
    )
    .expect("push client conf to wg-client");

    // ── 11. Bring up WireGuard on wg-client ───────────────────────────────────
    println!("[vpn-e2e] Bringing up WireGuard on wg-client...");
    ssh_exec_with_key(
        WG_CLIENT_HOST,
        WG_CLIENT_P,
        WG_CLIENT_USER,
        &wgc_key_path,
        &format!("wg-quick up /root/{}.conf", VPN_IFACE),
    );

    // Wait for handshake
    std::thread::sleep(std::time::Duration::from_secs(2));

    // ── 12. Verify VPN connectivity: ping pfSense VPN IP ─────────────────────
    println!(
        "[vpn-e2e] Pinging pfSense VPN IP ({})...",
        VPN_SERVER_ADDR.split('/').next().unwrap()
    );
    let pf_vpn_ip = VPN_SERVER_ADDR.split('/').next().unwrap();
    let ping_out = ssh_exec_with_key(
        WG_CLIENT_HOST,
        WG_CLIENT_P,
        WG_CLIENT_USER,
        &wgc_key_path,
        &format!("ping -c 3 -W 2 {} && echo PING_OK", pf_vpn_ip),
    );
    assert!(
        ping_out.contains("PING_OK"),
        "VPN ping to pfSense failed: {}",
        ping_out
    );
    println!("[vpn-e2e] VPN ping to pfSense OK");

    // ── 13. Verify LAN access via VPN: HTTP to internal-server ───────────────
    println!(
        "[vpn-e2e] Testing HTTP to internal-server ({}) via VPN...",
        INTERNAL_SERVER_IP
    );
    let http_out = ssh_exec_with_key(
        WG_CLIENT_HOST,
        WG_CLIENT_P,
        WG_CLIENT_USER,
        &wgc_key_path,
        &format!(
            "curl -s --max-time 5 http://{}:{}/",
            INTERNAL_SERVER_IP, INTERNAL_SERVER_HTTP_P
        ),
    );
    assert!(
        http_out.contains("internal-server-ok"),
        "Expected 'internal-server-ok' from internal server via VPN, got: {}",
        http_out
    );
    println!("[vpn-e2e] LAN access via VPN OK: {}", http_out.trim());

    // ── 14. Cleanup ───────────────────────────────────────────────────────────
    println!("[vpn-e2e] Tearing down WireGuard on wg-client...");
    let _ = Command::new("ssh")
        .args([
            "-i",
            wgc_key_path.to_str().unwrap(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-p",
            &WG_CLIENT_P.to_string(),
            &format!("{}@{}", WG_CLIENT_USER, WG_CLIENT_HOST),
            &format!("wg-quick down {}", VPN_IFACE),
        ])
        .output();

    println!("[vpn-e2e] Test PASSED");
}
