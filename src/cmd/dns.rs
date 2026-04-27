use crate::{cli::*, config::*, dns::cloudflare::*, keys::{KeyEntry, KeyStore}, with_examples};
use std::{
    error::Error,
    io::{self, BufRead},
};

with_examples! {
    #[derive(clap::Args, Debug)]
    pub struct DnsArgs {
        #[command(subcommand)]
        pub cmd: Option<DnsSubcommand>
    }
    => "../../docs/examples/dns.md"
}

#[derive(clap::Subcommand, Debug)]
pub enum DnsSubcommand {
    /// Interactive DNS record editor (legacy)
    Update,
    /// List DNS records (optionally filtered by name)
    List {
        /// Filter by record name (e.g. "permissionless.money")
        #[arg(long)]
        name: Option<String>,
        /// Cloudflare API token (auto-resolved from key store if omitted)
        #[arg(long)]
        token: Option<String>,
        /// Cloudflare zone ID (auto-resolved from key store if omitted)
        #[arg(long)]
        zone: Option<String>,
    },
    /// Upsert a TXT record
    SetTxt {
        /// Record name (e.g. "_dnslink.permissionless.money")
        name: String,
        /// TXT content value
        content: String,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        zone: Option<String>,
    },
    /// Upsert a CNAME record (proxied by default)
    SetCname {
        /// Record name (e.g. "permissionless.money")
        name: String,
        /// CNAME target (e.g. "abc.ingress.provider.com")
        target: String,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        zone: Option<String>,
    },
    /// Upsert an A record
    SetA {
        /// Record name (e.g. "p2p.permissionless.money")
        name: String,
        /// IPv4 address
        ip: String,
        /// DNS-only mode (disables Cloudflare proxy)
        #[arg(long)]
        dns_only: bool,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        zone: Option<String>,
    },
    /// Delete DNS records by name
    Delete {
        /// Record name to delete (all matching records removed)
        name: String,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        zone: Option<String>,
    },
    /// Enable Cloudflare Web3 IPFS gateway for a domain (free, one-time setup)
    #[command(name = "web3-enable")]
    Web3Enable {
        /// Domain to enable Web3 IPFS gateway for
        name: String,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        zone: Option<String>,
    },
    /// List Web3 IPFS gateway hostnames
    #[command(name = "web3-list")]
    Web3List {
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        zone: Option<String>,
    },
    /// Full IPFS publish: Web3 gateway + DNSLink + CNAME (one command)
    Publish {
        /// Domain to publish to
        domain: String,
        /// IPFS CID
        cid: String,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        zone: Option<String>,
    },
    /// Manage encrypted credential keys (add, list, remove)
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum KeysAction {
    /// Add a new domain credential set
    Add {
        /// Label (e.g. "permissionless.money")
        label: String,
        /// Domain patterns (comma-separated, e.g. "permissionless.money,*.permissionless.money")
        #[arg(long)]
        domains: String,
        /// Cloudflare API token
        #[arg(long)]
        cf_token: String,
        /// Cloudflare zone ID
        #[arg(long)]
        cf_zone: String,
        /// Optional Akash mnemonic (stored encrypted alongside CF creds)
        #[arg(long)]
        mnemonic: Option<String>,
    },
    /// List all stored credential labels and their domains
    List,
    /// Remove a credential set by label
    Remove {
        /// Label to remove
        label: String,
    },
    /// Look up which credential set matches a given domain
    Resolve {
        /// Domain to look up
        domain: String,
    },
}

/// Resolve CF credentials: CLI flags > key store (by domain) > env vars > error.
fn resolve_cf_creds(
    token_flag: &Option<String>,
    zone_flag: &Option<String>,
    domain_hint: Option<&str>,
) -> Result<(String, String), Box<dyn Error>> {
    // 1. Explicit flags always win
    if let (Some(t), Some(z)) = (token_flag, zone_flag) {
        if !t.is_empty() && !z.is_empty() {
            return Ok((t.clone(), z.clone()));
        }
    }

    // 2. Try key store lookup by domain
    if let Some(domain) = domain_hint {
        if let Ok(password) = get_keystore_password() {
            let store = KeyStore::open(KeyStore::default_path(), &password);
            if let Ok(Some(entry)) = store.resolve(domain) {
                tracing::info!("  [keys] Resolved credentials via '{}' for {}", entry.label, domain);
                return Ok((entry.cf_api_token, entry.cf_zone_id));
            }
        }
    }

    // 3. Fall back to env vars
    let token = token_flag
        .clone()
        .or_else(|| std::env::var("OLINE_CF_API_TOKEN").ok().filter(|s| !s.is_empty()))
        .ok_or("Cloudflare API token required: --token, OLINE_CF_API_TOKEN, or add to key store")?;
    let zone = zone_flag
        .clone()
        .or_else(|| std::env::var("OLINE_CF_ZONE_ID").ok().filter(|s| !s.is_empty()))
        .ok_or("Cloudflare zone ID required: --zone, OLINE_CF_ZONE_ID, or add to key store")?;
    Ok((token, zone))
}

/// Get the key store password from OLINE_PASSWORD env var or prompt.
fn get_keystore_password() -> Result<String, Box<dyn Error>> {
    if let Ok(pw) = std::env::var("OLINE_PASSWORD") {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }
    if std::env::var("OLINE_NON_INTERACTIVE").is_ok() {
        return Err("OLINE_NON_INTERACTIVE requires OLINE_PASSWORD for key store access".into());
    }
    Ok(rpassword::prompt_password("Key store password: ")?)
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn cmd_dns(args: &DnsArgs) -> Result<(), Box<dyn Error>> {
    match &args.cmd {
        None | Some(DnsSubcommand::Update) => cmd_dns_update().await,
        Some(DnsSubcommand::List { name, token, zone }) => {
            let (t, z) = resolve_cf_creds(token, zone, name.as_deref())?;
            let records = cloudflare_list_records(&t, &z, name.as_deref()).await?;
            if records.is_empty() {
                println!("No records found.");
            } else {
                println!("{:<40} {:<8} {:<50} {:<8} {}", "NAME", "TYPE", "CONTENT", "PROXIED", "TTL");
                println!("{:-<120}", "");
                for (_id, rtype, rname, content, proxied, ttl) in &records {
                    let content_display = if content.len() > 47 {
                        format!("{}...", &content[..47])
                    } else {
                        content.clone()
                    };
                    println!("{:<40} {:<8} {:<50} {:<8} {}", rname, rtype, content_display, proxied, ttl);
                }
            }
            Ok(())
        }
        Some(DnsSubcommand::SetTxt { name, content, token, zone }) => {
            let (t, z) = resolve_cf_creds(token, zone, Some(name))?;
            println!("Upserting TXT {} = \"{}\"", name, content);
            cloudflare_upsert_txt(&t, &z, name, content).await?;
            println!("Done.");
            Ok(())
        }
        Some(DnsSubcommand::SetCname { name, target, token, zone }) => {
            let (t, z) = resolve_cf_creds(token, zone, Some(name))?;
            println!("Upserting CNAME {} -> {}", name, target);
            cloudflare_upsert_cname(&t, &z, name, target).await?;
            println!("Done.");
            Ok(())
        }
        Some(DnsSubcommand::SetA { name, ip, dns_only, token, zone }) => {
            let (t, z) = resolve_cf_creds(token, zone, Some(name))?;
            let ip_addr: std::net::Ipv4Addr = ip.parse()
                .map_err(|_| format!("Invalid IPv4: {}", ip))?;
            let proxied = !dns_only;
            let mode = if proxied { "proxied" } else { "DNS-only" };
            println!("Upserting A {} -> {} ({})", name, ip, mode);
            cloudflare_upsert_a(&t, &z, name, ip_addr, proxied).await?;
            println!("Done.");
            Ok(())
        }
        Some(DnsSubcommand::Delete { name, token, zone }) => {
            let (t, z) = resolve_cf_creds(token, zone, Some(name))?;
            let count = cloudflare_delete_by_name(&t, &z, name).await?;
            println!("Deleted {} record(s) for {}.", count, name);
            Ok(())
        }
        Some(DnsSubcommand::Web3Enable { name, token, zone }) => {
            let (t, z) = resolve_cf_creds(token, zone, Some(name))?;
            println!("Enabling Web3 IPFS gateway for {}", name);
            cloudflare_create_web3_hostname(&t, &z, name).await?;
            println!("Done. CNAME {} to cloudflare-ipfs.com and set DNSLink TXT.", name);
            Ok(())
        }
        Some(DnsSubcommand::Web3List { token, zone }) => {
            let (t, z) = resolve_cf_creds(token, zone, None)?;
            let hostnames = cloudflare_list_web3_hostnames(&t, &z).await?;
            if hostnames.is_empty() {
                println!("No Web3 hostnames configured.");
            } else {
                println!("{:<40} {:<12} {}", "HOSTNAME", "STATUS", "ID");
                println!("{:-<70}", "");
                for (id, name, status) in &hostnames {
                    println!("{:<40} {:<12} {}", name, status, id);
                }
            }
            Ok(())
        }
        Some(DnsSubcommand::Publish { domain, cid, token, zone }) => {
            let (t, z) = resolve_cf_creds(token, zone, Some(domain))?;
            println!("Publishing IPFS site: {} -> {}", domain, cid);
            cloudflare_publish_ipfs_site(&t, &z, domain, cid).await?;
            Ok(())
        }
        Some(DnsSubcommand::Keys { action }) => cmd_dns_keys(action).await,
    }
}

// ── Key management ────────────────────────────────────────────────────────────

async fn cmd_dns_keys(action: &KeysAction) -> Result<(), Box<dyn Error>> {
    match action {
        KeysAction::Add { label, domains, cf_token, cf_zone, mnemonic } => {
            let password = get_keystore_password()?;
            let store = KeyStore::open(KeyStore::default_path(), &password);
            let domain_list: Vec<String> = domains
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let mut entry = KeyEntry::new(
                label.clone(),
                domain_list.clone(),
                cf_token.clone(),
                cf_zone.clone(),
            );
            if let Some(m) = mnemonic {
                entry.mnemonic = m.clone();
            }
            store.add(entry)?;
            println!("Added key '{}' for domains: {}", label, domain_list.join(", "));
            Ok(())
        }
        KeysAction::List => {
            let password = get_keystore_password()?;
            let store = KeyStore::open(KeyStore::default_path(), &password);
            let entries = store.load()?;
            if entries.is_empty() {
                println!("No keys stored. Use 'oline dns keys add' to add credentials.");
                return Ok(());
            }
            println!("{:<25} {:<50} {}", "LABEL", "DOMAINS", "HAS_MNEMONIC");
            println!("{:-<90}", "");
            for e in &entries {
                let has_mn = if e.mnemonic.is_empty() { "no" } else { "yes" };
                println!("{:<25} {:<50} {}", e.label, e.domains.join(", "), has_mn);
            }
            Ok(())
        }
        KeysAction::Remove { label } => {
            let password = get_keystore_password()?;
            let store = KeyStore::open(KeyStore::default_path(), &password);
            let count = store.remove(label)?;
            if count > 0 {
                println!("Removed {} key(s) with label '{}'.", count, label);
            } else {
                println!("No key found with label '{}'.", label);
            }
            Ok(())
        }
        KeysAction::Resolve { domain } => {
            let password = get_keystore_password()?;
            let store = KeyStore::open(KeyStore::default_path(), &password);
            match store.resolve(domain)? {
                Some(entry) => {
                    let zlen = entry.cf_zone_id.len();
                    let tlen = entry.cf_api_token.len();
                    println!("Match: '{}' (domains: {})", entry.label, entry.domains.join(", "));
                    println!("  CF zone:  {}...{}", &entry.cf_zone_id[..4.min(zlen)], &entry.cf_zone_id[zlen.saturating_sub(4)..]);
                    println!("  CF token: {}...{}", &entry.cf_api_token[..4.min(tlen)], &entry.cf_api_token[tlen.saturating_sub(4)..]);
                    if !entry.mnemonic.is_empty() {
                        println!("  Mnemonic: (encrypted, present)");
                    }
                }
                None => println!("No matching key found for '{}'.", domain),
            }
            Ok(())
        }
    }
}

// ── Legacy interactive update (preserved as 'oline dns update') ───────────────

async fn cmd_dns_update() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== DNS Update (Cloudflare) ===\n");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

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
        tracing::info!("    1. CNAME (HTTP ingress -- proxied through Cloudflare)");
        tracing::info!("    2. A (proxied -- HTTP/HTTPS via Cloudflare CDN)");
        tracing::info!("    3. A (DNS-only -- raw TCP passthrough, e.g. P2P)");
        let rtype = read_input(&mut lines, "Type", Some("1"))?;

        match rtype.as_str() {
            "1" => {
                let target = read_input(
                    &mut lines,
                    "CNAME target (provider ingress hostname, e.g. abc123.ingress.provider.com)",
                    None,
                )?;
                if target.is_empty() {
                    tracing::info!("  Skipped -- no target provided.");
                    continue;
                }
                tracing::info!("  Upserting CNAME {} -> {}", domain, target);
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
                tracing::info!("  Upserting A {} -> {} ({})", domain, ip, mode);
                match cloudflare_upsert_a(&cf_token, &zone_id, &domain, ip, proxied).await {
                    Ok(_) => tracing::info!("  Done."),
                    Err(e) => tracing::info!("  Error: {}", e),
                }
            }
            _ => {
                tracing::info!("  Unknown type -- skipped.");
            }
        }
    }

    Ok(())
}
