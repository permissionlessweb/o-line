//! WireGuard X25519 key generation and config file builders.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use x25519_dalek::{PublicKey, StaticSecret};

use super::WgServer;

/// Generate a WireGuard X25519 keypair.
///
/// Returns `(private_key_base64, public_key_base64)`.
pub fn generate_wg_keypair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    let priv_b64 = BASE64.encode(secret.as_bytes());
    let pub_b64 = BASE64.encode(public.as_bytes());
    (priv_b64, pub_b64)
}

/// Build the WireGuard server configuration file content.
///
/// Includes `[Interface]` section and all `[Peer]` blocks.
pub fn wg_server_conf(server: &WgServer) -> String {
    let mut conf = format!(
        "[Interface]\nAddress = {}\nListenPort = {}\nPrivateKey = {}\n",
        server.server_address, server.listen_port, server.private_key,
    );

    for peer in &server.peers {
        conf.push_str(&format!(
            "\n[Peer]\n# {}\nPublicKey = {}\nAllowedIPs = {}\n",
            peer.name, peer.public_key, peer.peer_address,
        ));
    }

    conf
}

/// Build a WireGuard client configuration file content.
///
/// - `peer_priv_key`: base64 private key for this client
/// - `peer_address`: VPN address for this client (e.g. "10.0.0.2/32")
/// - `server_pub_key`: base64 public key of the server
/// - `server_endpoint`: "host:port" of the server (e.g. "1.2.3.4:51820")
/// - `allowed_ips`: traffic to route through VPN (e.g. "0.0.0.0/0" or "192.168.1.0/24")
pub fn wg_client_conf(
    peer_priv_key: &str,
    peer_address: &str,
    server_pub_key: &str,
    server_endpoint: &str,
    allowed_ips: &str,
) -> String {
    format!(
        "[Interface]\nAddress = {}\nPrivateKey = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
        peer_address, peer_priv_key, server_pub_key, server_endpoint, allowed_ips,
    )
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::WgPeer;

    #[test]
    fn test_generate_wg_keypair_valid_base64() {
        let (priv_b64, pub_b64) = generate_wg_keypair();

        let priv_bytes = BASE64.decode(&priv_b64).expect("priv not valid base64");
        let pub_bytes = BASE64.decode(&pub_b64).expect("pub not valid base64");

        assert_eq!(priv_bytes.len(), 32, "private key must be 32 bytes");
        assert_eq!(pub_bytes.len(), 32, "public key must be 32 bytes");
    }

    #[test]
    fn test_generate_wg_keypair_unique() {
        let (priv1, pub1) = generate_wg_keypair();
        let (priv2, pub2) = generate_wg_keypair();
        assert_ne!(priv1, priv2);
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn test_wg_server_conf_no_peers() {
        let (priv_key, pub_key) = generate_wg_keypair();
        let server = WgServer {
            firewall_label: "fw".into(),
            interface: "wg0".into(),
            listen_port: 51820,
            server_address: "10.0.0.1/24".into(),
            private_key: priv_key.clone(),
            public_key: pub_key,
            wan_endpoint: None,
            peers: vec![],
            created_at: 0,
        };

        let conf = wg_server_conf(&server);
        assert!(conf.contains("[Interface]"));
        assert!(conf.contains("Address = 10.0.0.1/24"));
        assert!(conf.contains("ListenPort = 51820"));
        assert!(conf.contains(&format!("PrivateKey = {}", priv_key)));
        assert!(!conf.contains("[Peer]"));
    }

    #[test]
    fn test_wg_server_conf_with_peer() {
        let (priv_key, pub_key) = generate_wg_keypair();
        let (peer_priv, peer_pub) = generate_wg_keypair();
        let server = WgServer {
            firewall_label: "fw".into(),
            interface: "wg0".into(),
            listen_port: 51820,
            server_address: "10.0.0.1/24".into(),
            private_key: priv_key,
            public_key: pub_key,
            wan_endpoint: None,
            peers: vec![WgPeer {
                name: "laptop".into(),
                private_key: peer_priv,
                public_key: peer_pub.clone(),
                peer_address: "10.0.0.2/32".into(),
                allowed_ips: "192.168.1.0/24".into(),
                pushed_to: None,
                added_at: 0,
            }],
            created_at: 0,
        };

        let conf = wg_server_conf(&server);
        assert!(conf.contains("[Peer]"));
        assert!(conf.contains("# laptop"));
        assert!(conf.contains(&format!("PublicKey = {}", peer_pub)));
        assert!(conf.contains("AllowedIPs = 10.0.0.2/32"));
    }

    #[test]
    fn test_wg_client_conf() {
        let (priv_key, _) = generate_wg_keypair();
        let (_, server_pub) = generate_wg_keypair();

        let conf = wg_client_conf(
            &priv_key,
            "10.0.0.2/32",
            &server_pub,
            "192.168.1.168:51820",
            "192.168.1.0/24",
        );

        assert!(conf.contains("[Interface]"));
        assert!(conf.contains("Address = 10.0.0.2/32"));
        assert!(conf.contains(&format!("PrivateKey = {}", priv_key)));
        assert!(conf.contains("[Peer]"));
        assert!(conf.contains(&format!("PublicKey = {}", server_pub)));
        assert!(conf.contains("Endpoint = 192.168.1.168:51820"));
        assert!(conf.contains("AllowedIPs = 192.168.1.0/24"));
        assert!(conf.contains("PersistentKeepalive = 25"));
    }
}
