use akash_deploy_rs::AkashBackend as _;
use clap::{Parser, Subcommand};
use o_line_sdl::{
    self,
    cli::*,
    cmd_bootstrap_private, cmd_dns, cmd_endpoints, cmd_firewall, cmd_generate_sdl,
    cmd_init, cmd_manage, cmd_node, cmd_providers, cmd_refresh,
    cmd_registry, cmd_relayer, cmd_sites, cmd_test_grpc, cmd_test_s3, cmd_testnet_deploy, cmd_vpn,
    config::{build_config_from_env, collect_config, *},
    crypto::encrypt_mnemonic,
    deployer::OLineDeployer,
    runtime::OLineRuntime,
    tui::TracingSwitch,
    workflow::{step::{DeployPhase, OLineStep}, OLineWorkflow},
    BootstrapArgs, DeployArgs, DnsArgs, EncryptArgs, EndpointsArgs, FirewallArgs, InitArgs,
    ManageArgs, NodeArgs, ProvidersArgs, RefreshArgs, RegistryArgs, RelayerArgs, SdlArgs,
    SitesArgs, TestGrpcArgs, TestS3Args, TestnetDeployArgs, VpnArgs,
};
use o_line_sdl::cmd::console::{ConsoleArgs, cmd_console};
use std::{
    error::Error,
    io::{self, BufRead},
    sync::LazyLock,
};

/// Global tracing writer switch: stdout by default, channel when TUI is active.
static TRACING_SWITCH: LazyLock<TracingSwitch> = LazyLock::new(TracingSwitch::new);

/// O-Line: Akash deployment orchestrator for Terp Network validator infrastructure.
#[derive(Parser, Debug)]
#[command(name = "oline", about = "validator deployment orchestrator", version)]
#[command(subcommand_required = true, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt mnemonic and store in .env
    Encrypt(EncryptArgs),
    /// Probe Akash RPC/gRPC endpoints and save the fastest to .env
    Endpoints(EndpointsArgs),
    /// Full automated deployment (phases A → B → C → E)
    Deploy(DeployArgs),
    /// Render SDL templates without broadcasting
    #[command(alias = "generate-sdl")]
    Sdl(SdlArgs),
    /// Collect deployment config and write deploy-config.json
    Init(InitArgs),
    /// View and manage active deployments
    Manage(ManageArgs),
    /// Test S3/MinIO bucket connectivity
    #[command(name = "test-s3")]
    TestS3(TestS3Args),
    /// Test gRPC-Web endpoint health
    #[command(name = "test-grpc")]
    TestGrpc(TestGrpcArgs),
    /// Upsert Cloudflare DNS records
    #[command(alias = "dns-update")]
    Dns(DnsArgs),
    /// Bootstrap a private validator node with peers + snapshot
    #[command(alias = "bootstrap-private")]
    Bootstrap(BootstrapArgs),
    /// Deploy and manage IPFS static websites via MinIO-IPFS on Akash
    Sites(SitesArgs),
    /// SSH-based node management: push env updates, run scripts, check health
    Refresh(RefreshArgs),
    /// Deploy and manage a dedicated Akash full node
    Node(NodeArgs),
    /// Manage pfSense firewall SSH keys and connectivity
    Firewall(FirewallArgs),
    /// Manage a Cosmos IBC relayer (binary hot-swap, config reload, key install)
    Relayer(RelayerArgs),
    /// Provision and manage WireGuard VPN on pfSense
    Vpn(VpnArgs),
    /// Manage trusted Akash providers (saved to ~/.config/oline/trusted-providers.json)
    Providers(ProvidersArgs),
    /// Embedded OCI container registry (serve, import, list)
    Registry(RegistryArgs),
    /// Bootstrap a fresh testnet on Akash with validator, faucet, and full sentry array
    #[command(name = "testnet-deploy")]
    TestnetDeploy(TestnetDeployArgs),
    /// Interact with Akash Console API (deployments, providers, leases, etc.)
    Console(ConsoleArgs),
}

// ── Subcommand: deploy --sdl <path> (step 1: create deployment + list bids) ──
async fn cmd_deploy_sdl(sdl_path: &str) -> Result<(), Box<dyn Error>> {
    use o_line_sdl::config::substitute_template_raw;

    let (deployer, rendered, vars, label) = init_sdl_deploy(sdl_path).await?;

    let (state, bids) = deployer
        .deploy_phase_until_bids(&rendered, &vars, &label)
        .await
        .map_err(|e| format!("Deployment failed: {}", e))?;

    let dseq = state.dseq.unwrap_or(0);

    // Print bids as structured output for LLM/script consumption
    println!("DSEQ={}", dseq);
    println!("BIDS={}", bids.len());
    for (i, bid) in bids.iter().enumerate() {
        let price_akt = bid.price as f64 / 1_000_000.0;
        // Query provider info for context
        let info = deployer.client.query_provider_info(&bid.provider).await.ok().flatten();
        let host = info.as_ref().map(|i| i.host_uri.as_str()).unwrap_or("unknown");
        let email = info.as_ref().map(|i| i.email.as_str()).unwrap_or("");
        let website = info.as_ref().map(|i| i.website.as_str()).unwrap_or("");

        println!("BID[{}] provider={} price={} price_akt={:.6} host={} email={} website={}",
            i, bid.provider, bid.price, price_akt, host, email, website);
    }
    println!();
    println!("To select a provider, run:");
    println!("  oline deploy --sdl {} --select {} <PROVIDER_ADDRESS>", sdl_path, dseq);

    Ok(())
}

// ── Subcommand: deploy --sdl <path> --select <dseq> <provider> (step 2: complete) ──
async fn cmd_deploy_sdl_select(sdl_path: &str, dseq: u64, provider: &str) -> Result<(), Box<dyn Error>> {
    use o_line_sdl::config::substitute_template_raw;
    use akash_deploy_rs::{DeploymentState, DeploymentWorkflow, Step};

    let (deployer, rendered, vars, label) = init_sdl_deploy(sdl_path).await?;

    // Rebuild state with the existing dseq and SDL
    let rendered_sdl = substitute_template_raw(&rendered, &vars)
        .map_err(|e| format!("SDL substitution failed: {}", e))?;

    let mut state = DeploymentState::new(&label, deployer.client.address())
        .with_sdl(&rendered_sdl)
        .with_label(&label);
    state.dseq = Some(dseq);

    // Add synthetic bid so select_provider validation passes
    state.bids.push(akash_deploy_rs::Bid {
        provider: provider.to_string(),
        price: 0,
        price_denom: String::new(),
        resources: akash_deploy_rs::Resources {
            cpu_millicores: 0,
            memory_bytes: 0,
            storage_bytes: 0,
            gpu_count: 0,
        },
    });

    // Select the provider
    DeploymentWorkflow::<akash_deploy_rs::AkashClient>::select_provider(&mut state, provider)?;

    // Complete the deployment (lease + manifest + endpoints)
    let endpoints = deployer
        .deploy_phase_complete(&mut state, &label)
        .await
        .map_err(|e| format!("Deployment failed: {}", e))?;

    println!("DSEQ={}", dseq);
    println!("PROVIDER={}", provider);
    for ep in &endpoints {
        println!("ENDPOINT={} port={} internal_port={} service={}", ep.uri, ep.port, ep.internal_port, ep.service);
    }
    println!("DEPLOY_COMPLETE=true");

    Ok(())
}

/// Shared init for both deploy --sdl steps: load env, render SDL, create deployer.
async fn init_sdl_deploy(sdl_path: &str) -> Result<(OLineDeployer, String, std::collections::HashMap<String, String>, String), Box<dyn Error>> {
    use o_line_sdl::config::substitute_template_raw;

    tracing::info!("=== Deploy SDL: {} ===", sdl_path);

    let raw_sdl = std::fs::read_to_string(sdl_path)
        .map_err(|e| format!("Cannot read SDL {}: {}", sdl_path, e))?;

    load_dotenv("OLINE_ENCRYPTED_MNEMONIC");

    // Build vars from TOML config + env vars
    let config_for_vars = build_config_from_env(String::new());
    let vars: std::collections::HashMap<String, String> = config_for_vars
        .to_sdl_vars()
        .into_iter()
        .chain(std::env::vars())
        .collect();

    let rendered = substitute_template_raw(&raw_sdl, &vars)
        .map_err(|e| format!("SDL template substitution failed: {}", e))?;

    tracing::info!("  Rendered SDL ({} bytes)", rendered.len());

    let non_interactive = std::env::var("OLINE_NON_INTERACTIVE").is_ok();
    let mnemonic = if non_interactive {
        let p = std::env::var("OLINE_PASSWORD").unwrap_or_else(|_| "oline-test".to_string());
        if let Some(raw) = std::env::var("OLINE_MNEMONIC").ok().filter(|s| !s.trim().is_empty()) {
            raw.trim().to_string()
        } else {
            use o_line_sdl::crypto::decrypt_mnemonic;
            let blob = read_encrypted_mnemonic_from_env()
                .map_err(|_| "OLINE_NON_INTERACTIVE requires OLINE_MNEMONIC or OLINE_ENCRYPTED_MNEMONIC")?;
            decrypt_mnemonic(&blob, &p)
                .map_err(|e| format!("Failed to decrypt mnemonic: {}", e))?
        }
    } else {
        unlock_mnemonic()?.0
    };

    let config = build_config_from_env(mnemonic);
    let password = std::env::var("OLINE_PASSWORD").unwrap_or_default();
    let deployer = OLineDeployer::new(config, password).await?;

    let label = std::path::Path::new(sdl_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("custom-sdl")
        .to_string();

    Ok((deployer, rendered, vars, label))
}

// ── Subcommand: deploy ──
async fn cmd_deploy(raw: bool, parallel: bool, provider_selections: Option<std::collections::HashMap<String, String>>) -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Welcome to O-Line Deployer ===\n");
    if parallel {
        tracing::info!("  Strategy: parallel (all phases deployed before snapshot sync wait)");
    } else {
        tracing::info!("  Strategy: sequential (one phase at a time)");
    }

    // Non-interactive mode: read mnemonic + password from env vars (no TTY needed).
    // Set OLINE_NON_INTERACTIVE=1 + OLINE_MNEMONIC=<words> + OLINE_PASSWORD=<pw> to
    // run oline deploy fully unattended (CI / local integration tests).
    // Also forced when --select is used (two-step flow).
    let non_interactive = provider_selections.is_some()
        || std::env::var("OLINE_NON_INTERACTIVE").is_ok();

    let (mnemonic, password) = if non_interactive {
        let p = std::env::var("OLINE_PASSWORD").unwrap_or_else(|_| "oline-test".to_string());
        let m = if let Some(raw) = std::env::var("OLINE_MNEMONIC")
            .ok()
            .filter(|s| !s.trim().is_empty())
        {
            raw.trim().to_string()
        } else {
            // Fall back to encrypted mnemonic + OLINE_PASSWORD
            use o_line_sdl::crypto::decrypt_mnemonic;
            let blob = read_encrypted_mnemonic_from_env()
                .map_err(|_| "OLINE_NON_INTERACTIVE requires OLINE_MNEMONIC or OLINE_ENCRYPTED_MNEMONIC")?;
            decrypt_mnemonic(&blob, &p)
                .map_err(|e| format!("Failed to decrypt mnemonic: {}. Check OLINE_PASSWORD.", e))?
        };
        (m, p)
    } else if raw {
        let m = rpassword::prompt_password("Enter mnemonic: ")?;
        if m.trim().is_empty() {
            return Err("Mnemonic cannot be empty.".into());
        }
        let password = rpassword::prompt_password("Enter a password (for config encryption): ")?;
        (m.trim().to_string(), password)
    } else {
        unlock_mnemonic()?
    };

    // Non-interactive: build config from env vars + FD defaults (no prompting).
    let config = if non_interactive {
        build_config_from_env(mnemonic)
    } else {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();
        let cfg = collect_config(&password, mnemonic, &mut lines).await?;
        drop(lines);
        cfg
    };

    let deployer = OLineDeployer::new(config, password)
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    deployer
        .preflight_check()
        .await
        .map_err(|e| -> Box<dyn Error> { e.into() })?;

    if parallel {
        // Parallel path: deploy all phases up-front, then distribute snapshot.
        // HD-derived accounts are required for parallel deployment — concurrent
        // MsgCreateDeployment broadcasts from a single account cause sequence
        // conflicts.  Default to 4 children × 5 AKT if not explicitly set.
        use o_line_sdl::sessions::{FundingMethod, OLineSession, OLineSessionStore};
        let funding = match FundingMethod::from_env() {
            FundingMethod::Master => {
                tracing::info!("  Parallel mode: defaulting to direct (single-signer batch).");
                tracing::info!("  Override with OLINE_FUNDING_METHOD=hd:<count>:<amount_uakt> or direct");
                FundingMethod::Direct
            }
            other => other,
        };
        let session = OLineSession::new(
            funding,
            &deployer.client.address().to_string(),
            &deployer.config.val("OLINE_CHAIN_ID"),
        );
        let session_store = OLineSessionStore::new();
        let mut workflow =
            OLineWorkflow::new_with_session(deployer, OLineStep::FundChildAccounts, session, session_store);

        // Set pre-selected providers for two-step flow (--select a=<addr> ...)
        if let Some(ref sels) = provider_selections {
            workflow.ctx.provider_selections = sels.clone();
        }

        if non_interactive {
            // Non-interactive: run entire workflow headless, no TUI.
            workflow
                .run_headless()
                .await
                .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        } else {
            // ── Phase 1: Interactive (normal terminal) ──
            // Run steps that need stdin: FundChildAccounts → DeployAllUnits → SelectAllProviders
            let stdin2 = io::stdin();
            let mut lines2 = stdin2.lock().lines();
            loop {
                workflow
                    .advance(&mut lines2)
                    .await
                    .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
                if matches!(
                    workflow.step,
                    OLineStep::UpdateAllDns | OLineStep::Complete
                ) {
                    break;
                }
            }
            drop(lines2); // release stdin lock before entering TUI

            if matches!(workflow.step, OLineStep::Complete) {
                // Workflow finished during interactive phase (user aborted).
                return Ok(());
            }

            // ── Phase 2: Automated (split-pane TUI) ──
            // Redirect tracing to channel, build TUI, drive workflow as pinned local future.
            let (deploy_tx, deploy_rx) = tokio::sync::mpsc::unbounded_channel();
            TRACING_SWITCH.activate(deploy_tx);

            // Populate provider host URIs so TUI log targets can build WS URLs
            // without requiring the trusted provider store.
            for phase in [DeployPhase::SpecialTeams, DeployPhase::Tackles, DeployPhase::Forwards, DeployPhase::Relayer] {
                let provider_addr = workflow.ctx.state(phase)
                    .and_then(|s| s.selected_provider.clone());
                if let Some(addr) = provider_addr {
                    if !workflow.ctx.provider_hosts.contains_key(&addr) {
                        if let Ok(Some(info)) = workflow.ctx.deployer.client.query_provider_info(&addr).await {
                            workflow.ctx.provider_hosts.insert(addr, info.host_uri.clone());
                        }
                    }
                }
            }

            let controller = o_line_sdl::tui::TuiController::from_context(&workflow.ctx);
            let controller_for_ssh = controller.clone();
            let password_for_ssh = workflow.ctx.deployer.password.clone();

            let workflow_fut = async move {
                if let Err(e) = workflow.run_headless().await {
                    tracing::error!("Deploy workflow failed: {}", e);
                }
                // Populate SSH targets from NodeRecords written during deploy.
                controller_for_ssh
                    .load_ssh_targets_from_nodes(&password_for_ssh, &[])
                    .await;
            };

            o_line_sdl::tui::run_deploy_tui(controller, deploy_rx, workflow_fut).await?;
            TRACING_SWITCH.deactivate();
        }
        Ok(())
    } else {
        // Sequential path (legacy): one phase at a time via OLineRuntime.
        let mut runtime = OLineRuntime::new();
        runtime.add_workflow("main", deployer);
        let stdin2 = io::stdin();
        let mut lines2 = stdin2.lock().lines();
        runtime
            .run_single(&mut lines2)
            .await
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })
    }
}

// ── Subcommand: encrypt ──
pub fn cmd_encrypt() -> Result<(), Box<dyn Error>> {
    tracing::info!("=== Encrypt Mnemonic ===\n");
    let mnemonic = rpassword::prompt_password("Enter mnemonic: ")?;
    if mnemonic.trim().is_empty() {
        return Err("Mnemonic cannot be empty.".into());
    }
    let password = rpassword::prompt_password("Enter password: ")?;
    if password.is_empty() {
        return Err("Password cannot be empty.".into());
    }
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        return Err("Passwords do not match.".into());
    }
    let blob = encrypt_mnemonic(mnemonic.trim(), &password)?;
    write_encrypted_mnemonic_to_env(&blob)?;
    tracing::info!("\nEncrypted mnemonic written to .env");
    tracing::info!("You can now run `oline deploy` to deploy using your encrypted mnemonic.");
    Ok(())
}

// ── Main ──
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(TRACING_SWITCH.clone())
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    load_dotenv(
        &std::env::var("OLINE_ENV_KEY_NAME").unwrap_or_else(|_| "OLINE_ENCRYPTED_MNEMONIC".into()),
    );

    let cli = Cli::parse();
    match cli.command {
        Commands::Endpoints(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_endpoints(&a).await
        }
        Commands::Encrypt(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_encrypt()
        }
        Commands::Deploy(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            if let Some(ref sdl_path) = a.sdl {
                if let Some(ref select_args) = a.select {
                    let dseq: u64 = select_args[0].parse()
                        .map_err(|_| format!("Invalid DSEQ: {}", select_args[0]))?;
                    let provider = &select_args[1];
                    cmd_deploy_sdl_select(sdl_path, dseq, provider).await
                } else {
                    cmd_deploy_sdl(sdl_path).await
                }
            } else {
                // Parse --select for parallel mode: a=<provider> b=<provider> ...
                let provider_selections = if let Some(ref select_args) = a.select {
                    let mut map = std::collections::HashMap::new();
                    for arg in select_args {
                        if let Some((phase, provider)) = arg.split_once('=') {
                            let key = phase.to_lowercase();
                            if !["a", "b", "c", "e"].contains(&key.as_str()) {
                                return Err(format!(
                                    "Invalid phase key '{}'. Use a, b, c, or e.", key
                                ).into());
                            }
                            map.insert(key, provider.to_string());
                        } else {
                            return Err(format!(
                                "Invalid --select format '{}'. Use phase=provider (e.g. a=akash1...)", arg
                            ).into());
                        }
                    }
                    Some(map)
                } else {
                    None
                };
                cmd_deploy(a.raw, !a.sequential, provider_selections).await
            }
        }
        Commands::Sdl(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_generate_sdl(a.output.as_deref(), a.load_config.as_deref()).await
        }
        Commands::Init(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_init(&a).await
        }
        Commands::Manage(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_manage(&a).await
        }
        Commands::TestS3(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_test_s3().await
        }
        Commands::TestGrpc(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_test_grpc(a.domain).await
        }
        Commands::Dns(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_dns(&a).await
        }
        Commands::Bootstrap(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_bootstrap_private(a).await
        }
        Commands::Sites(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_sites(&a).await
        }
        Commands::Refresh(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_refresh(&a).await
        }
        Commands::Node(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_node(&a).await
        }
        Commands::Firewall(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_firewall(&a).await
        }
        Commands::Relayer(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_relayer(&a).await
        }
        Commands::Vpn(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_vpn(&a).await
        }
        Commands::Providers(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_providers(&a).await.map_err(|e| {
                Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
                    as Box<dyn Error>
            })
        }
        Commands::Registry(a) => cmd_registry(&a).await,
        Commands::TestnetDeploy(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_testnet_deploy(&a).await
        }
        Commands::Console(a) => cmd_console(a).await,
    }
}


