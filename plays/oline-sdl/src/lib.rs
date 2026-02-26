use std::sync::LazyLock;

pub mod akash;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod error;
pub mod snapshots;

pub const MAX_RETRIES: u16 = 30;
pub static FIELD_DESCRIPTORS: LazyLock<Vec<config::Fd>> = LazyLock::new(|| {
    [
        DEFAULT_ND,
        NETWORKING_FD,
        SNAPSHOT_FD,
        MINIO_FD,
        SPECIAL_TEAMS_FD,
        LR_TACKLES_FD,
        LR_FORWARD_FD,
    ]
    .iter()
    .flat_map(|group| group.iter().cloned())
    .collect()
});

pub const DEFAULT_ND: &[config::Fd] = define_fields![
    "default"/"omnibus_image"=> "OMNIBUS_IMAGE","Omnibus Image","ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic",false,
    "default"/"sdl_dir"=> "SDL_DIR","SDL Templates folder","sdls",false,
    "chain"/"chain_id"=> "OLINE_CHAIN_ID","Chain ID","",false,
    "network"/ "rpc_endpoint"=> "OLINE_RPC_ENDPOINT","RPC endpoint","https://rpc.akashnet.net:443",   false,
    "network"/ "grpc_endpoint"=> "OLINE_GRPC_ENDPOINT","gRPC endpoint","https://grpc.akashnet.net:443",  false,
    "validator"/"peer_id"=> "OLINE_VALIDATOR_PEER_ID","Private validator peer id","",false,
    "ssh"/"pubkey"=> "SSH_PUBKEY","ssh pubkey","",false,
];

pub const NETWORKING_FD: &[config::Fd] = define_fields![
    "cloudflare" / "api_token"         => "OLINE_CF_API_TOKEN",             "Cloudflare API token (press Enter to skip)",     "",                               true,
    "cloudflare" / "zone_id"           => "OLINE_CF_ZONE_ID",               "Cloudflare zone ID (press Enter to skip)",       "",                               false,
    "cloudflare" / "tls_config_url"    => "TLS_CONFIG_URL",                 "TLS config URL",                                 "",                               false,
    "cloudflare" / "entrypoint_url"    => "ENTRYPOINT_URL",                 "Entrypoint URL",                                 "",                               false,
];

pub const SNAPSHOT_FD: &[config::Fd] = define_fields![
    "snapshot"   / "path"              => "OLINE_SNAPSHOT_PATH",            "S3 snapshot path",                               "snapshots/terpnetwork",          false,
    "snapshot"   / "time"              => "OLINE_SNAPSHOT_TIME",            "Snapshot schedule time",                         "00:00:00",                       false,
    "snapshot"   / "state_url"         => "OLINE_SNAPSHOT_STATE_URL",       "Snapshot state url",                             "https://server-4.itrocket.net/mainnet/terp/.current_state.json",false,
    "snapshot"   / "base_url"         => "OLINE_SNAPSHOT_BASE_URL",        "Snapshot base url",                             "https://server-4.itrocket.net/mainnet/terp/",false,
    "snapshot"   / "save_format"       => "OLINE_SNAPSHOT_SAVE_FORMAT",     "Snapshot save format",                           "tar.gz",                         false,
    "snapshot"   / "retain"            => "OLINE_SNAPSHOT_RETAIN",          "Snapshot retention period",                      "2 days",                         false,
    "snapshot"   / "keep_last"         => "OLINE_SNAPSHOT_KEEP_LAST",       "Minimum snapshots to keep",                      "2",                              false,
    "snapshot"   / "download_domain"   => "OLINE_SNAPSHOT_DOWNLOAD_DOMAIN", "Snapshot download domain",                       "",                               false,
];

pub const MINIO_FD: &[config::Fd] = define_fields![
    "minio"      / "image"             => "MINIO_IPFS_IMAGE",         "MinIO-IPFS image",                               "minio/minio:latest",             false,
    "minio"      / "s3_bucket"         => "OLINE_S3_BUCKET",                "S3 bucket name",                                 "terp-snapshots",                 false,
    "minio"      / "autopin_interval"  => "OLINE_AUTOPIN_INTERVAL",         "IPFS auto-pin interval (seconds)",               "300",                            false,
];

pub const SPECIAL_TEAMS_FD: &[config::Fd] = define_fields![];
pub const LR_TACKLES_FD: &[config::Fd] = define_fields![];
pub const LR_FORWARD_FD: &[config::Fd] = define_fields![];
