use crate::{cli::*, config::*, dns::cloudflare::*, with_examples};

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct DnsArgs {}
    => "../../docs/examples/dns.md"
}

use std::{
    error::Error,
    io::{self, BufRead},
};

// ── Subcommand: dns-update ──
// Manually upsert one or more Cloudflare DNS records — useful when the automatic
// DNS update after deploy failed silently (e.g. the ingress endpoint wasn't ready
// in time) or when a record needs to be manually corrected.
pub async fn cmd_dns_update() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== DNS Update (Cloudflare) ===\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    // Load CF credentials from saved config if available, otherwise prompt.
    let (cf_token, zone_id) = if has_saved_config() {
        let pw =
            rpassword::prompt_password("Enter config password (or Enter to prompt manually): ")?;
        if !pw.is_empty() {
            if let Some(cfg) = load_config(&pw) {
                let t = cfg.val("OLINE_CF_API_TOKEN");
                let z = cfg.val("OLINE_CF_ZONE_ID");
                if !t.is_empty() && !z.is_empty() {
                    (t, z)
                } else {
                    (
                        read_input(&mut lines, "Cloudflare API token", None)?,
                        read_input(&mut lines, "Cloudflare zone ID", None)?,
                    )
                }
            } else {
                (
                    read_input(&mut lines, "Cloudflare API token", None)?,
                    read_input(&mut lines, "Cloudflare zone ID", None)?,
                )
            }
        } else {
            (
                read_input(&mut lines, "Cloudflare API token", None)?,
                read_input(&mut lines, "Cloudflare zone ID", None)?,
            )
        }
    } else {
        (
            read_input(&mut lines, "Cloudflare API token", None)?,
            read_input(&mut lines, "Cloudflare zone ID", None)?,
        )
    };

    if cf_token.is_empty() || zone_id.is_empty() {
        return Err("Cloudflare token and zone ID are required.".into());
    }

    loop {
        let domain = read_input(&mut lines, "Domain to update (or 'q' to quit)", None)?;
        if domain == "q" || domain.is_empty() {
            break;
        }

        tracing::info!("  Record type for {}:", domain);
        tracing::info!("    1. CNAME (HTTP ingress — proxied through Cloudflare)");
        tracing::info!("    2. A (proxied — HTTP/HTTPS via Cloudflare CDN)");
        tracing::info!("    3. A (DNS-only — raw TCP passthrough, e.g. P2P)");
        let rtype = read_input(&mut lines, "Type", Some("1"))?;

        match rtype.as_str() {
            "1" => {
                let target = read_input(
                    &mut lines,
                    "CNAME target (provider ingress hostname, e.g. abc123.ingress.provider.com)",
                    None,
                )?;
                if target.is_empty() {
                    tracing::info!("  Skipped — no target provided.");
                    continue;
                }
                tracing::info!("  Upserting CNAME {} → {}", domain, target);
                match cloudflare_upsert_cname(&cf_token, &zone_id, &domain, &target).await {
                    Ok(_) => tracing::info!("  Done."),
                    Err(e) => tracing::info!("  Error: {}", e),
                }
            }
            "2" | "3" => {
                let proxied = rtype == "2";
                let ip_str = read_input(&mut lines, "IPv4 address", None)?;
                let ip: std::net::Ipv4Addr = ip_str
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid IPv4: {}", ip_str))?;
                let mode = if proxied { "proxied" } else { "DNS-only" };
                tracing::info!("  Upserting A {} → {} ({})", domain, ip, mode);
                match cloudflare_upsert_a(&cf_token, &zone_id, &domain, ip, proxied).await {
                    Ok(_) => tracing::info!("  Done."),
                    Err(e) => tracing::info!("  Error: {}", e),
                }
            }
            _ => {
                tracing::info!("  Unknown type — skipped.");
            }
        }
    }

    Ok(())
}
