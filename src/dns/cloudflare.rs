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

// ── TXT record helpers ────────────────────────────────────────────────────────

/// Upsert a Cloudflare DNS TXT record: `name` → `content`.
/// Any existing TXT record for this name is updated in place; any other record
/// type is deleted first (type conflict) before a new TXT is created.
pub async fn cloudflare_upsert_txt(
    cf_token: &str,
    zone_id: &str,
    name: &str,
    content: &str,
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
            DnsContent::TXT { .. } => {
                client
                    .request(&UpdateDnsRecord {
                        zone_identifier: zone_id,
                        identifier: &existing.id,
                        params: UpdateDnsRecordParams {
                            name,
                            content: DnsContent::TXT {
                                content: content.to_string(),
                            },
                            ttl: Some(60),
                            proxied: Some(false),
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare TXT update failed: {:?}", e))?;
                tracing::info!("    Updated TXT {} = \"{}\"", name, content);
            }
            _ => {
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
                            content: DnsContent::TXT {
                                content: content.to_string(),
                            },
                            ttl: Some(60),
                            proxied: Some(false),
                            priority: None,
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare TXT create failed: {:?}", e))?;
                tracing::info!(
                    "    Created TXT {} = \"{}\" (replaced old record)",
                    name,
                    content
                );
            }
        }
    } else {
        client
            .request(&CreateDnsRecord {
                zone_identifier: zone_id,
                params: CreateDnsRecordParams {
                    name,
                    content: DnsContent::TXT {
                        content: content.to_string(),
                    },
                    ttl: Some(60),
                    proxied: Some(false),
                    priority: None,
                },
            })
            .await
            .map_err(|e| format!("Cloudflare TXT create failed: {:?}", e))?;
        tracing::info!("    Created TXT {} = \"{}\"", name, content);
    }

    Ok(())
}

/// Set a DNSLink TXT record so Cloudflare's IPFS gateway serves `cid` at `domain`.
///
/// Creates two records:
/// - `_dnslink.<domain>` TXT = `"dnslink=/ipfs/<cid>"`
/// - `<domain>` CNAME → `cloudflare-ipfs.com` (Cloudflare's universal IPFS gateway)
///
/// After this call, `https://<domain>` will serve the IPFS CID via Cloudflare's
/// gateway (requires the zone to have IPFS Gateway enabled in Cloudflare settings).
pub async fn cloudflare_set_dnslink(
    cf_token: &str,
    zone_id: &str,
    domain: &str,
    cid: &str,
) -> Result<(), Box<dyn Error>> {
    let dnslink_name = format!("_dnslink.{}", domain);
    let dnslink_value = format!("dnslink=/ipfs/{}", cid);

    tracing::info!("  [dns] Setting DNSLink for {} → /ipfs/{}", domain, cid);

    // _dnslink TXT record (not proxied — TXT records can't be proxied)
    cloudflare_upsert_txt(cf_token, zone_id, &dnslink_name, &dnslink_value).await?;

    // CNAME → Cloudflare IPFS gateway (proxied so CF handles HTTPS)
    cloudflare_upsert_cname(cf_token, zone_id, domain, "cloudflare-ipfs.com").await?;

    tracing::info!(
        "  [dns] DNSLink set: https://{} now serves /ipfs/{}",
        domain,
        cid
    );
    Ok(())
}

use crate::akash::endpoint_hostname;

/// Update (or create) a CNAME record via the Cloudflare API crate.
/// Lists ALL record types for `name` so stale records of a different type are
/// replaced rather than leaving a conflicting record that blocks creation.
pub async fn cloudflare_upsert_cname(
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
                            proxied: Some(true),
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
                            proxied: Some(true),
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
                    proxied: Some(true),
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
///
/// `proxied` controls whether traffic is routed through Cloudflare's proxy:
/// - `true`  → HTTP/HTTPS traffic (Cloudflare terminates TLS, provides CDN/WAF)
/// - `false` → DNS-only (raw TCP passthrough, required for P2P/non-HTTP protocols)
pub async fn cloudflare_upsert_a(
    cf_token: &str,
    zone_id: &str,
    name: &str,
    ip: std::net::Ipv4Addr,
    proxied: bool,
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
                            proxied: Some(proxied),
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare A record update failed: {:?}", e))?;
                tracing::info!("    Updated A {} → {}{}", name, ip, if proxied { "" } else { " (DNS-only)" });
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
                            proxied: Some(proxied),
                            priority: None,
                        },
                    })
                    .await
                    .map_err(|e| format!("Cloudflare A record create failed: {:?}", e))?;
                tracing::info!("    Created A {} → {}{}", name, ip, if proxied { "" } else { " (DNS-only)" });
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
                    proxied: Some(proxied),
                    priority: None,
                },
            })
            .await
            .map_err(|e| format!("Cloudflare A record create failed: {:?}", e))?;
        tracing::info!("    Created A {} → {}{}", name, ip, if proxied { "" } else { " (DNS-only)" });
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
                    match cloudflare_upsert_cname(cf_token, zone_id, domain, ingress).await {
                        Ok(_) => {
                            tracing::info!("  Cf CNAME configured: {} → {}", domain, ingress)
                        }
                        Err(e) => {
                            tracing::info!("  Warning: Cf CNAME failed for {}: {}", domain, e)
                        }
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

                // Find the provider hostname from a NodePort endpoint — must NOT be one of the
                // accept domains (those aren't resolved yet and would cause resolve_to_ipv4 to fail).
                let provider_host = endpoints
                    .iter()
                    .find(|e| {
                        e.service == svc_name && !accept_set.contains(endpoint_hostname(&e.uri))
                    })
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
                    match cloudflare_upsert_a(cf_token, zone_id, domain, ip, true).await {
                        Ok(_) => {
                            tracing::info!("  Cloudflare A configured: {} → {}", domain, ip)
                        }
                        Err(e) => tracing::info!(
                            "  Warning: Cloudflare A record failed for {}: {}",
                            domain,
                            e
                        ),
                    }
                }
            }
        }
    }
}

/// Register DNS-only A records for P2P domains.
///
/// P2P traffic is raw TCP using CometBFT's secret connection handshake — NOT HTTP.
/// Cloudflare proxy MUST be disabled (`proxied: false`) because:
/// 1. CF only proxies HTTP/HTTPS; raw TCP connections get terminated with EOF
/// 2. CometBFT's P2P handshake interprets CF's TLS termination as "auth failure"
/// 3. DNS must resolve to the provider's real IP, not CF's anycast IP
///
/// Each entry is `(domain, internal_port, service_name)`. The function finds the
/// matching `ServiceEndpoint` for each service, resolves the provider hostname to
/// IPv4, and creates (or updates) a DNS-only A record.
pub async fn cloudflare_update_p2p_domains(
    p2p_entries: &[(&str, u16, &str)],
    endpoints: &[akash_deploy_rs::ServiceEndpoint],
    cf_token: &str,
    zone_id: &str,
) {
    for &(domain, internal_port, svc_name) in p2p_entries {
        if domain.is_empty() {
            continue;
        }

        // Find the P2P endpoint for this service by matching internal_port.
        let p2p_ep = endpoints.iter().find(|e| {
            e.service == svc_name && e.internal_port == internal_port
        });

        let ep = match p2p_ep {
            Some(ep) => ep,
            None => {
                tracing::info!(
                    "  [dns] P2P: no endpoint for {} port {} — skipping {}",
                    svc_name, internal_port, domain,
                );
                continue;
            }
        };

        let provider_host = endpoint_hostname(&ep.uri);
        let ip = match resolve_to_ipv4(provider_host).await {
            Some(ip) => ip,
            None => {
                tracing::info!(
                    "  [dns] P2P: cannot resolve {} — skipping {}",
                    provider_host, domain,
                );
                continue;
            }
        };

        tracing::info!(
            "  [dns] P2P: {} → {} (provider: {}, NodePort: {})",
            domain, ip, provider_host, ep.port,
        );

        match cloudflare_upsert_a(cf_token, zone_id, domain, ip, false).await {
            Ok(_) => tracing::info!(
                "  [dns] P2P A record: {} → {} (DNS-only, not proxied)", domain, ip,
            ),
            Err(e) => tracing::info!(
                "  Warning: P2P DNS failed for {}: {}", domain, e,
            ),
        }
    }
}

// ── List / Delete helpers (non-interactive CLI) ───────────────────────────────

/// List all DNS records in a zone, optionally filtered by name.
/// Returns a vec of (id, type, name, content, proxied, ttl) tuples as strings.
pub async fn cloudflare_list_records(
    cf_token: &str,
    zone_id: &str,
    filter_name: Option<&str>,
) -> Result<Vec<(String, String, String, String, bool, u32)>, Box<dyn Error>> {
    let credentials = Credentials::UserAuthToken {
        token: cf_token.to_string(),
    };
    let client = CfClient::new(
        credentials,
        CfClientConfig::default(),
        CfEnvironment::Production,
    )
    .map_err(|e| format!("Failed to create Cloudflare client: {}", e))?;

    let list_resp = client
        .request(&ListDnsRecords {
            zone_identifier: zone_id,
            params: ListDnsRecordsParams {
                name: filter_name.map(|s| s.to_string()),
                record_type: None,
                ..Default::default()
            },
        })
        .await
        .map_err(|e| format!("Cloudflare list DNS records failed: {:?}", e))?;

    let mut results = Vec::new();
    for rec in &list_resp.result {
        let (rtype, content) = match &rec.content {
            DnsContent::A { content } => ("A".to_string(), content.to_string()),
            DnsContent::CNAME { content } => ("CNAME".to_string(), content.clone()),
            DnsContent::TXT { content } => ("TXT".to_string(), content.clone()),
            other => (format!("{:?}", other), format!("{:?}", other)),
        };
        results.push((
            rec.id.clone(),
            rtype,
            rec.name.clone(),
            content,
            rec.proxied,
            rec.ttl,
        ));
    }
    Ok(results)
}

/// Delete a DNS record by its record ID.
pub async fn cloudflare_delete_by_id(
    cf_token: &str,
    zone_id: &str,
    record_id: &str,
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

    client
        .request(&DeleteDnsRecord {
            zone_identifier: zone_id,
            identifier: record_id,
        })
        .await
        .map_err(|e| format!("Cloudflare delete record failed: {:?}", e))?;

    Ok(())
}

/// Delete all DNS records matching a given name (and optionally type).
/// Returns the count of records deleted.
pub async fn cloudflare_delete_by_name(
    cf_token: &str,
    zone_id: &str,
    name: &str,
) -> Result<usize, Box<dyn Error>> {
    let records = cloudflare_list_records(cf_token, zone_id, Some(name)).await?;
    let count = records.len();
    for (id, rtype, rname, _, _, _) in &records {
        tracing::info!("  Deleting {} {} (id: {})", rtype, rname, id);
        cloudflare_delete_by_id(cf_token, zone_id, id).await?;
    }
    Ok(count)
}
