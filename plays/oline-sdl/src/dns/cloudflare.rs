use std::error::Error;

use akash_deploy_rs::ServiceEndpoint;
use cloudflare::{
    endpoints::dns::dns::{
        CreateDnsRecord, CreateDnsRecordParams, DeleteDnsRecord, DnsContent, ListDnsRecords,
        ListDnsRecordsParams, UpdateDnsRecord, UpdateDnsRecordParams,
    },
    framework::{
        auth::Credentials,
        client::{async_api::Client as CfClient, ClientConfig as CfClientConfig},
        Environment as CfEnvironment,
    },
};

use crate::akash::endpoint_hostname;

/// Update (or create) a CNAME record via the Cloudflare API crate.
/// Lists ALL record types for `name` so stale records of a different type are
/// replaced rather than leaving a conflicting record that blocks creation.
async fn cloudflare_upsert_cname(
    cf_token: &str,
    zone_id: &str,
    name: &str,
    target: &str,
) -> Result<(), Box<dyn Error>> {
    let credentials = Credentials::UserAuthToken {
        token: cf_token.to_string(),
    };
    let client = CfClient::new(
        credentials,
        CfClientConfig::default(),
        CfEnvironment::Production,
    )
    .map_err(|e| format!("Failed to create Cloudflare client: {}", e))?;

    // List ALL records for this name (no type filter) so we find stale A/AAAA etc.
    let list_resp = client
        .request(&ListDnsRecords {
            zone_identifier: zone_id,
            params: ListDnsRecordsParams {
                name: Some(name.to_string()),
                record_type: None,
                ..Default::default()
            },
        })
        .await
        .map_err(|e| format!("Cloudflare list DNS records failed: {:?}", e))?;

    if let Some(existing) = list_resp.result.first() {
        match &existing.content {
            DnsContent::CNAME { .. } => {
                // Same type — update in place.
                client
                    .request(&UpdateDnsRecord {
                        zone_identifier: zone_id,
                        identifier: &existing.id,
                        params: UpdateDnsRecordParams {
                            name,
                            content: DnsContent::CNAME {
                                content: target.to_string(),
                            },
                            ttl: Some(60),
                            proxied: Some(false),
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare CNAME update failed: {:?}", e))?;
                tracing::info!("    Updated CNAME {} → {}", name, target);
            }
            _ => {
                // Wrong type — delete it then create a fresh CNAME.
                tracing::info!("    Replacing existing record for {} with CNAME", name);
                client
                    .request(&DeleteDnsRecord {
                        zone_identifier: zone_id,
                        identifier: &existing.id,
                    })
                    .await
                    .map_err(|e| format!("Cloudflare delete old record failed: {:?}", e))?;
                client
                    .request(&CreateDnsRecord {
                        zone_identifier: zone_id,
                        params: CreateDnsRecordParams {
                            name,
                            content: DnsContent::CNAME {
                                content: target.to_string(),
                            },
                            ttl: Some(60),
                            proxied: Some(false),
                            priority: None,
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare CNAME create failed: {:?}", e))?;
                tracing::info!(
                    "    Created CNAME {} → {} (replaced old record)",
                    name,
                    target
                );
            }
        }
    } else {
        client
            .request(&CreateDnsRecord {
                zone_identifier: zone_id,
                params: CreateDnsRecordParams {
                    name,
                    content: DnsContent::CNAME {
                        content: target.to_string(),
                    },
                    ttl: Some(60),
                    proxied: Some(false),
                    priority: None,
                },
            })
            .await
            .map_err(|e| format!("Cloudflare CNAME create failed: {:?}", e))?;
        tracing::info!("    Created CNAME {} → {}", name, target);
    }

    Ok(())
}

/// Resolve a hostname to its first IPv4 address.
pub async fn resolve_to_ipv4(hostname: &str) -> Option<std::net::Ipv4Addr> {
    tokio::net::lookup_host(format!("{}:80", hostname))
        .await
        .ok()?
        .find_map(|addr| match addr {
            std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
            _ => None,
        })
}

/// Upsert a Cloudflare DNS A record: `name` → `ip`.
/// Lists ALL record types for `name` so stale CNAMEs are replaced rather than
/// causing a 400 conflict error.
pub async fn cloudflare_upsert_a(
    cf_token: &str,
    zone_id: &str,
    name: &str,
    ip: std::net::Ipv4Addr,
) -> Result<(), Box<dyn Error>> {
    let credentials = Credentials::UserAuthToken {
        token: cf_token.to_string(),
    };
    let client = CfClient::new(
        credentials,
        CfClientConfig::default(),
        CfEnvironment::Production,
    )
    .map_err(|e| format!("Failed to create Cloudflare client: {}", e))?;

    // List ALL records for this name (no type filter) so stale CNAMEs are caught.
    let list_resp = client
        .request(&ListDnsRecords {
            zone_identifier: zone_id,
            params: ListDnsRecordsParams {
                name: Some(name.to_string()),
                record_type: None,
                ..Default::default()
            },
        })
        .await
        .map_err(|e| format!("Cloudflare list DNS records failed: {:?}", e))?;

    if let Some(existing) = list_resp.result.first() {
        match &existing.content {
            DnsContent::A { .. } => {
                // Same type — update in place.
                client
                    .request(&UpdateDnsRecord {
                        zone_identifier: zone_id,
                        identifier: &existing.id,
                        params: UpdateDnsRecordParams {
                            name,
                            content: DnsContent::A { content: ip },
                            ttl: Some(60),
                            proxied: Some(false),
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare A record update failed: {:?}", e))?;
                tracing::info!("    Updated A {} → {}", name, ip);
            }
            _ => {
                // Wrong type (e.g. stale CNAME) — delete then create A record.
                tracing::info!("    Replacing existing record for {} with A", name);
                client
                    .request(&DeleteDnsRecord {
                        zone_identifier: zone_id,
                        identifier: &existing.id,
                    })
                    .await
                    .map_err(|e| format!("Cloudflare delete old record failed: {:?}", e))?;
                client
                    .request(&CreateDnsRecord {
                        zone_identifier: zone_id,
                        params: CreateDnsRecordParams {
                            name,
                            content: DnsContent::A { content: ip },
                            ttl: Some(60),
                            proxied: Some(false),
                            priority: None,
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare A record create failed: {:?}", e))?;
                tracing::info!("    Created A {} → {} (replaced old record)", name, ip);
            }
        }
    } else {
        client
            .request(&CreateDnsRecord {
                zone_identifier: zone_id,
                params: CreateDnsRecordParams {
                    name,
                    content: DnsContent::A { content: ip },
                    ttl: Some(60),
                    proxied: Some(false),
                    priority: None,
                },
            })
            .await
            .map_err(|e| format!("Cloudflare A record create failed: {:?}", e))?;
        tracing::info!("    Created A {} → {}", name, ip);
    }

    Ok(())
}

/// Scan the rendered SDL for `accept:` domains on every service expose and update
/// Cloudflare CNAME records so each accept domain points at the provider-assigned
/// ingress hostname (the URI in the provider status response that is NOT itself
/// one of the accept domains).
///
/// This must run immediately after `deploy_phase_with_selection` returns so the
/// public domain resolves to the new provider before services try to use it.
pub async fn cloudflare_update_accept_domains(
    rendered_sdl: &str,
    endpoints: &[ServiceEndpoint],
    cf_token: &str,
    zone_id: &str,
) {
    let yaml: serde_yaml::Value = match serde_yaml::from_str(rendered_sdl) {
        Ok(y) => y,
        Err(e) => {
            tracing::info!(
                "  Warning: could not parse SDL for Cloudflare DNS update: {}",
                e
            );
            return;
        }
    };

    let services = match yaml.get("services").and_then(|s| s.as_mapping()) {
        Some(s) => s,
        None => return,
    };

    for (svc_key, svc_config) in services {
        let svc_name = match svc_key.as_str() {
            Some(s) => s,
            None => continue,
        };

        // Collect all accept domains across all expose entries for this service.
        let mut accept_domains: Vec<String> = Vec::new();
        if let Some(exposes) = svc_config.get("expose").and_then(|e| e.as_sequence()) {
            for expose in exposes {
                if let Some(arr) = expose.get("accept").and_then(|a| a.as_sequence()) {
                    for v in arr {
                        if let Some(raw) = v.as_str() {
                            // Strip inline YAML comments (e.g. "host # ← note")
                            let domain = raw.split('#').next().unwrap_or(raw).trim();
                            if !domain.is_empty() {
                                accept_domains.push(domain.to_string());
                            }
                        }
                    }
                }
            }
        }

        if accept_domains.is_empty() {
            continue;
        }

        tracing::info!(
            "  [dns] {} — updating {} domain(s): {}",
            svc_name,
            accept_domains.len(),
            accept_domains.join(", ")
        );

        // Build a set for O(1) lookup.
        let accept_set: std::collections::HashSet<&str> =
            accept_domains.iter().map(|s| s.as_str()).collect();

        // Prefer a port-80/443 HTTP ingress endpoint as the CNAME target.
        // If the service uses proto:tcp (NodePort), Akash may assign a random external
        // port instead of 443 — in that case fall through to the A-record path.
        let provider_ingress = endpoints
            .iter()
            .filter(|e| e.service == svc_name && (e.port == 80 || e.port == 443))
            .map(|e| endpoint_hostname(&e.uri))
            .find(|host| !accept_set.contains(*host));

        match provider_ingress {
            Some(ingress) => {
                // HTTP/HTTPS ingress — CNAME each accept domain to the provider hostname.
                tracing::info!("  [dns] {} — ingress hostname: {}", svc_name, ingress);
                for domain in &accept_domains {
                    tracing::info!("  Cloudflare CNAME: {} → {}", domain, ingress);
                    if let Err(e) =
                        cloudflare_upsert_cname(cf_token, zone_id, domain, ingress).await
                    {
                        tracing::info!("  Warning: Cloudflare CNAME failed for {}: {}", domain, e);
                    }
                }
            }
            None => {
                // No HTTP/443 ingress found — service likely uses a NodePort (proto:tcp).
                // CNAMEs can't carry port numbers, so resolve the provider hostname to IPv4
                // and create A records instead.
                tracing::info!(
                    "  [dns] {} — no port-443 ingress found; falling back to A record",
                    svc_name
                );

                // Any endpoint for this service gives us the provider hostname.
                let provider_host = endpoints
                    .iter()
                    .find(|e| e.service == svc_name)
                    .map(|e| endpoint_hostname(&e.uri).to_string());

                let host = match provider_host {
                    Some(h) => h,
                    None => {
                        tracing::info!(
                            "  Warning: no endpoint found for '{}' — skipping DNS",
                            svc_name
                        );
                        continue;
                    }
                };

                // Resolve provider hostname → IPv4.
                let ip = match resolve_to_ipv4(&host).await {
                    Some(ip) => ip,
                    None => {
                        tracing::info!(
                            "  Warning: could not resolve '{}' to IPv4 — skipping A records",
                            host
                        );
                        continue;
                    }
                };

                tracing::info!("  [dns] {} — provider IP: {}", svc_name, ip);

                // Log connection strings for NodePort services (ports not in the A record).
                let node_ports: Vec<u16> = endpoints
                    .iter()
                    .filter(|e| e.service == svc_name && e.port != 80 && e.port != 443)
                    .map(|e| e.port)
                    .collect();
                for domain in &accept_domains {
                    for port in &node_ports {
                        tracing::info!("  [dns] connection: {}:{}", domain, port);
                    }
                }

                for domain in &accept_domains {
                    tracing::info!("  Cloudflare A: {} → {}", domain, ip);
                    if let Err(e) = cloudflare_upsert_a(cf_token, zone_id, domain, ip).await {
                        tracing::info!(
                            "  Warning: Cloudflare A record failed for {}: {}",
                            domain,
                            e
                        );
                    }
                }
            }
        }
    }
}
