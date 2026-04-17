use std::sync::LazyLock;

pub mod accounts;
pub mod akash;
pub mod cli;
pub mod cmd;
pub mod config;
pub mod crypto;
pub mod deployer;
pub mod dns;
pub mod error;
pub mod firewall;
#[cfg(feature = "interface")]
pub mod interface;
pub mod nodes;
pub mod providers;
pub mod registry;
pub mod runtime;
pub mod sessions;
pub mod sites;
pub mod snapshots;
pub mod templates;
pub mod testing;
pub mod tui;
pub mod vpn;
pub mod workflow;

pub use cmd::{
    deploy::{
        cmd_bootstrap_private,cmd_manage,cmd_manage_deployments,BootstrapArgs,DeployArgs,
        EncryptArgs,ManageArgs,ManageSubcommand,
    },
    dns::{cmd_dns_update,DnsArgs},
    endpoints::{cmd_endpoints,EndpointsArgs},
    firewall::{cmd_firewall,FirewallArgs},
    init::{cmd_init,InitArgs},
    node::{cmd_node,NodeArgs},
    providers::{cmd_providers,ProvidersArgs},
    refresh::{cmd_refresh,RefreshArgs},
    registry::{cmd_registry,RegistryArgs},
    relayer::{cmd_relayer,RelayerArgs},
    sdl::{cmd_generate_sdl,SdlArgs},
    sites::{cmd_sites,SitesArgs},
    test::{cmd_test_grpc,cmd_test_s3,TestGrpcArgs,TestS3Args},
    testnet::{cmd_testnet_deploy,TestnetDeployArgs},
    vpn::{cmd_vpn,VpnArgs},
};

pub const MAX_RETRIES: u16 = 30;
pub static FIELD_DESCRIPTORS: LazyLock<Vec<config::Fd>> = LazyLock::new(|| {
    [
        DEFAULT_ND,
        NETWORKING_FD,
        SNAPSHOT_FD,
        MINIO_FD,
        SITES_FD,
        SPECIAL_TEAMS_FD,
        LR_TACKLES_FD,
        LR_FFD,
        RELAYER_FD,
        ARGUS_FD,
        REGISTRY_FD,
    ]
    .iter()
    .flat_map(|group| group.iter().cloned())
    .collect()
});

pub const DEFAULT_ND: &[config::Fd] = define_fields![
    "OMNIBUS_IMAGE","Node container image","ghcr.io/terpnetwork/terp-core:v5.1.1-oline",false,
    "SDL_DIR","SDL Templates folder","templates/sdls/oline",false,
    "OLINE_BINARY","Cosmos daemon binary name","terpd",false,
    "OLINE_CHAIN_ID","Chain ID","morocco-1",false,
    "OLINE_CHAIN_JSON","Chain JSON URL","",false,
    "GENESIS_URL","Genesis JSON download URL (overrides chain preset)","",false,
    "OLINE_ADDRBOOK_URL","Address book URL","https://anode.team/Terp/main/addrbook.json",false,
    "OLINE_RPC_ENDPOINT","RPC endpoint","https://rpc-akash.ecostake.com:443",false,
    "OLINE_GRPC_ENDPOINT","gRPC endpoint","https://akash.lavenderfive.com:443",false,
    "OLINE_REST_ENDPOINT","REST (gRPC-Gateway) endpoint","https://api.akashnet.net:443",false,
    "OLINE_VALIDATOR_PEER_ID","Private validator peer id","",false,
    "OLINE_PERSISTENT_PEERS","Default persistent peers (id@host:port,...)","5bf887027701d3b8c4d95c0ba898cc8bf6d166ff@188.165.194.110:26676,58e01ab84eb931a82a024324520021d2e075ec67@185.16.39.125:29656,fafb76ea47967a229d092d7ffb0d9957a4254667@94.130.138.48:33656,6f3677c65945ddb6946cbdaa6ec74b4cfec737f8@65.108.232.168:37656,06a68cd28f6b57768c950af7f2ba37b4d8bd7f5e@142.132.248.253:65532,3e04cc80b4647c9ff652d75b0cb12cb6fc36f5d4@46.4.23.120:13656,c8f6b5ad4048bc667cbe8465176046222d770735@46.46.119.150:26656,f2e0f122b681d84b70711770d34ad92a784e0405@167.235.14.83:656,5ba3e8458f584edfe5434186af74f846190d5475@213.133.100.93:16056,b04c5acab1c821b95f26662d8ebb7ccd4a39e97f@65.108.120.161:34657",false,
    "OLINE_ENTRYPOINT_URL","Bootstrap entrypoint script URL","https://raw.githubusercontent.com/permissionlessweb/o-line/refs/heads/feat/mvp/plays/audible/oline-entrypoint.sh",false,
    "OLINE_SYNC_METHOD","Sync method for B/C nodes (snapshot or statesync)","statesync",false,
    "FAUCET_D","Faucet domain for testnet (e.g. faucet.terp.network)","",false,
];

pub const NETWORKING_FD: &[config::Fd] = define_fields![
    "OLINE_CF_API_TOKEN","Cloudflare API token (press Enter to skip)","",true,
    "OLINE_CF_ZONE_ID","Cloudflare zone ID (press Enter to skip)","",false,
    "SSH_P","SSH/SFTP port for cert delivery","22",false,
];

pub const SNAPSHOT_FD: &[config::Fd] = define_fields![
    "OLINE_SNAP_PATH","S3 snapshot path","snapshots/terpnetwork",false,
    "OLINE_SNAP_TIME","Snapshot schedule time","00:00:00",false,
    "OLINE_SNAP_FULL_URL","priority snapshot url. superceeds OLINE_SNAP_STATE_URL & OLINE_SNAP_BASE_URL if present","",false,
    "OLINE_SNAP_SAVE_FORMAT","Snapshot save format","tar.gz",false,
    "OLINE_SNAP_RETAIN","Snapshot retention period","2 days",false,
    "OLINE_SNAP_KEEP_LAST","Minimum snapshots to keep","2",false,
    "OLINE_SNAP_DOWNLOAD_DOMAIN","Private snapshot domain (internal minio,sets SNAPSHOT_JSON)","",false,
    "STATESYNC_RPC_SERVERS","Statesync RPC servers (comma-separated)","https://terp.rpc.m.anode.team:443,https://terp.rpc.m.anode.team:443",false,
    "STATESYNC_TRUST_HEIGHT","Statesync trust height","",false,
    "STATESYNC_TRUST_HASH","Statesync trust hash","",false,
    "STATESYNC_TRUST_PERIOD","Statesync trust period","168h",false,
];

pub const MINIO_FD: &[config::Fd] = define_fields![
    "MINIO_IPFS_IMAGE","MinIO-IPFS image","minio/minio:latest",false,
    "OLINE_AUTOPIN_INTERVAL","IPFS auto-pin interval (seconds)","300",false,
];

pub const SITES_FD: &[config::Fd] = define_fields![
    "SITES_GATEWAY_DOMAIN","Sites IPFS gateway domain (e.g. sites.terp.network)","",false,
    "SITES_S3_DOMAIN","Sites S3 upload domain (e.g. s3-sites.terp.network)","",false,
    "SITES_CONSOLE_DOMAIN","Sites MinIO console domain (e.g. console-sites.terp.network)","",false,
];

pub const SPECIAL_TEAMS_FD: &[config::Fd] = define_fields![
    // Snapshot node — nginx TLS upstream ports + server_name domains
    "RPC_D_SNAP","Snapshot RPC domain (nginx server_name,e.g. statesync.example.com)","",false,
    "RPC_P_SNAP","Snapshot RPC upstream port (cosmos RPC,e.g. 26657)","26657",false,
    "P2P_D_SNAP","Snapshot P2P domain (e.g. statesync-peer.example.com)","",false,
    "P2P_P_SNAP","Snapshot P2P port (cosmos P2P,e.g. 26656)","26656",false,
    "API_D_SNAP","Snapshot API domain (optional,leave blank to skip)","",false,
    "API_P_SNAP","Snapshot API upstream port (e.g. 1317)","1317",false,
    "GRPC_D_SNAP","Snapshot gRPC domain (optional,leave blank to skip)","",false,
    "GRPC_P_SNAP","Snapshot gRPC port (cosmos native,e.g. 9090)","9090",false,
    // Seed node — nginx TLS upstream ports + server_name domains
    "RPC_D_SEED","Seed RPC domain (nginx server_name,e.g. seed.example.com)","",false,
    "RPC_P_SEED","Seed RPC upstream port (cosmos RPC,e.g. 26657)","26657",false,
    "P2P_D_SEED","Seed P2P domain (e.g. seed.example.com)","",false,
    "P2P_P_SEED","Seed P2P port (cosmos P2P,e.g. 26656)","26656",false,
    "API_D_SEED","Seed API domain (optional,leave blank to skip)","",false,
    "API_P_SEED","Seed API upstream port (e.g. 1317)","1317",false,
    "GRPC_D_SEED","Seed gRPC domain (optional,leave blank to skip)","",false,
    "GRPC_P_SEED","Seed gRPC port (cosmos native,e.g. 9090)","9090",false,
];
pub const LR_TACKLES_FD: &[config::Fd] = define_fields![
    // Left tackle — ports and nginx domains
    "P2P_P_TL","Left tackle P2P port (e.g. 26656)","26656",false,
    "RPC_P_TL","Left tackle RPC port (e.g. 26657)","26657",false,
    "API_P_TL","Left tackle API port (e.g. 1317)","1317",false,
    "GRPC_P_TL","Left tackle gRPC port (e.g. 9090)","9090",false,
    "RPC_D_TL","Left tackle RPC domain (nginx server_name)","",false,
    "API_D_TL","Left tackle API domain (optional)","",false,
    "P2P_D_TL","Left tackle P2P domain (optional)","",false,
    "GRPC_D_TL","Left tackle gRPC domain (optional)","",false,
    // Right tackle
    "P2P_P_TR","Right tackle P2P port","26656",false,
    "RPC_P_TR","Right tackle RPC port","26657",false,
    "API_P_TR","Right tackle API port","1317",false,
    "GRPC_P_TR","Right tackle gRPC port","9090",false,
    "RPC_D_TR","Right tackle RPC domain (optional)","",false,
    "API_D_TR","Right tackle API domain (optional)","",false,
    "P2P_D_TR","Right tackle P2P domain (optional)","",false,
    "GRPC_D_TR","Right tackle gRPC domain (optional)","",false,
];
pub const LR_FFD: &[config::Fd] = define_fields![
    // Left forward — ports and nginx domains
    "P2P_P_FL","Left forward P2P port","26656",false,
    "RPC_P_FL","Left forward RPC port","26657",false,
    "API_P_FL","Left forward API port","1317",false,
    "GRPC_P_FL","Left forward gRPC port","9090",false,
    "RPC_D_FL","Left forward RPC domain (nginx server_name)","",false,
    "API_D_FL","Left forward API domain (optional)","",false,
    "P2P_D_FL","Left forward P2P domain (optional)","",false,
    "GRPC_D_FL","Left forward gRPC domain (optional)","",false,
    // Right forward
    "P2P_P_FR","Right forward P2P port","26656",false,
    "RPC_P_FR","Right forward RPC port","26657",false,
    "API_P_FR","Right forward API port","1317",false,
    "GRPC_P_FR","Right forward gRPC port","9090",false,
    "RPC_D_FR","Right forward RPC domain (optional)","",false,
    "API_D_FR","Right forward API domain (optional)","",false,
    "P2P_D_FR","Right forward P2P domain (optional)","",false,
    "GRPC_D_FR","Right forward gRPC domain (optional)","",false,
];
pub const RELAYER_FD: &[config::Fd] = define_fields![
    "RLY_IMAGE","Relayer Docker image","ghcr.io/permissionlessweb/rly-docker:latest",false,
    "RLY_KEY_NAME","Relayer key name","relayer_key",false,
    "RLY_REMOTE_CHAIN_ID","Remote chain ID (e.g. cosmoshub-4)","",false,
    "RLY_API_D","Relayer REST API domain (Akash HTTPS ingress)","",false,
    "RLY_KEY_TERP","Terp relayer key mnemonic","",true,
    "RLY_KEY_REMOTE","Remote chain relayer key mnemonic","",true,
    "RELAYER_ENTRYPOINT","Relayer entrypoint script URL","",false,
];

pub const ARGUS_FD: &[config::Fd] = define_fields![
    // ── Cosmos node ──────────────────────────────────────────────────────────
    "ARGUS_NODE_MONIKER","Argus node moniker","",false,
    "ARGUS_NODE_SEEDS","Argus node seed peers (id@host:port,...)","",false,
    "ARGUS_NODE_PERSISTENT_PEERS","Argus node persistent peers (id@host:port,...)","",false,
    // ── Argus service ────────────────────────────────────────────────────────
    "ARGUS_IMAGE","Argus Docker image","ghcr.io/permissionlessweb/argus:latest",false,
    "ARGUS_ENTRYPOINT_URL","Argus entrypoint script URL","",false,
    "ARGUS_API_D","Argus REST API domain (Akash HTTPS ingress)","",false,
    "ARGUS_BECH32_PREFIX","Chain bech32 prefix (e.g. terp)","terp",false,
    // ── PostgreSQL ───────────────────────────────────────────────────────────
    "ARGUS_DB_USER","PostgreSQL username","argus",false,
    "ARGUS_DB_PASSWORD","PostgreSQL password","",true,
    "ARGUS_DB_DATA_NAME","PostgreSQL data database name","argus_data",false,
    "ARGUS_DB_ACCOUNTS_NAME","PostgreSQL accounts database name","argus_accounts",false,
];

pub const REGISTRY_FD: &[config::Fd] = define_fields![
    "OLINE_REGISTRY_URL","Public registry URL (providers pull from here)","",false,
    "OLINE_REGISTRY_P","Local registry listen port","5000",false,
    "OLINE_REGISTRY_USERNAME","Registry basic auth username","oline",false,
    "OLINE_REGISTRY_PASSWORD","Registry basic auth password","",true,
    "OLINE_REGISTRY_DIR","Registry storage directory","",false,
];
