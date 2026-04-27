use clap::{Parser, Subcommand};
use o_line_sdl::{
    self,
    cmd::{
        authz::{cmd_authz, AuthzArgs},
        console::{cmd_console, ConsoleArgs},
        deploy::*,
        sdl::*,
    },
    cmd_bootstrap_private, cmd_dns, cmd_endpoints, cmd_generate_sdl, cmd_init, cmd_manage,
    cmd_node, cmd_providers, cmd_proxy, cmd_refresh, cmd_registry, cmd_relayer, cmd_sites,
    cmd_test_grpc, cmd_test_s3, cmd_testnet_deploy, cmd_vpn,
    config::*,
    crypto::cmd_encrypt,
    BootstrapArgs, DeployArgs, DnsArgs, EncryptArgs, EndpointsArgs, InitArgs, ManageArgs, NodeArgs,
    ProvidersArgs, ProxyArgs, RefreshArgs, RegistryArgs, RelayerArgs, SdlArgs, SitesArgs,
    TestGrpcArgs, TestS3Args, TestnetDeployArgs, VpnArgs,
};
use std::error::Error;
use tracing_subscriber::fmt;

/// O-Line: Akash deployment orchestrator for Terp Network validator infrastructure.
#[derive(Parser, Debug)]
#[command(name = "oline", about = "validator deployment orchestrator", version)]
#[command(subcommand_required = true, arg_required_else_help = true)]
struct Cli {
    /// Config profile to use (mainnet, testnet, local)
    #[arg(
        long,
        short = 'p',
        global = true,
        default_value = "mainnet",
        env = "OLINE_PROFILE"
    )]
    profile: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt mnemonic and store in ~/.oline/config.enc
    Encrypt(EncryptArgs),
    /// Probe Akash RPC/gRPC endpoints and save the fastest to ~/.oline/config.toml
    Endpoints(EndpointsArgs),
    /// Full automated deployment (phases A → B → C → E)
    Deploy(DeployArgs),
    /// Render SDL templates without broadcasting
    #[command(alias = "generate-sdl")]
    Sdl(SdlArgs),
    /// Collect deployment config and write ~/.oline/deploy-config.json
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
    // /// Manage pfSense firewall SSH keys and connectivity
    // Firewall(FirewallArgs),
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
    /// Deploy and manage the provider-proxy-node (specialty infrastructure)
    Proxy(ProxyArgs),
    /// Interact with Akash Console API (deployments, providers, leases, etc.)
    Console(ConsoleArgs),
    /// Manage AuthZ + FeeGrant delegation for passwordless deployments
    Authz(AuthzArgs),
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
        .with_span_events(fmt::format::FmtSpan::FULL)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    load_dotenv();

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
                    let dseq: u64 = select_args[0]
                        .parse()
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
                                    "Invalid phase key '{}'. Use a, b, c, or e.",
                                    key
                                )
                                .into());
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
                cmd_deploy(a.raw, !a.sequential, provider_selections, &cli.profile).await
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
        // Commands::Firewall(a) => {
        //     if a.print_examples_if_requested() {
        //         return Ok(());
        //     }
        //     cmd_firewall(&a).await
        // }
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
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                )) as Box<dyn Error>
            })
        }
        Commands::Registry(a) => cmd_registry(&a).await,
        Commands::Proxy(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_proxy(&a).await
        }
        Commands::TestnetDeploy(a) => {
            if a.print_examples_if_requested() {
                return Ok(());
            }
            cmd_testnet_deploy(&a).await
        }
        Commands::Console(a) => cmd_console(a).await,
        Commands::Authz(a) => cmd_authz(&a, &cli.profile).await,
    }
}
