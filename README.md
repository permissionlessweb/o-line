# TERP O-Line - Run Terp Network Nodes on Akash

Make deploying Terp Network nodes onto [Akash](//github.com/akash-network/node)
easy and standardized.

The goal is to have a simple way to launch with a variety of different bootstrapping options.

1. ["normal" boostrap](#shortcuts) - using `fastsync`.
1. [Hand-made snapshots](#snapshot-restore)
1. [The new `state-sync` mechanism](#statesync).

Configuration is achieved using environment variables, with shortcuts available for common setups. Every aspect of the node configuration can be achieved in this way.

Additional features are included to make running a node as simple as possible

1. [Chain configuration can be sourced from a remote JSON file](#chain-configuration)
1. [Genesis file can be downloaded and unzipped in various ways](#chain-configuration)
1. [Private keys can be backed up and restored](#private-key-backuprestore) from any S3 compatible storage provider, such as Sia or Storj via [Filebase](https://filebase.com/).
1. [Snapshots of a nodes data directory](#snapshot-backup) can be created at a certain time or day and uploaded to an S3 storage provider

## Generic image (binary downloaded at runtime)

O-line has a generic base image which can download the required binary at runtime. This is useful for chain upgrades, testnets, or using a different version than O-Line primarily supports.

This generic image provides the O-line scripts and configuration helpers, and nothing else. Set the `BINARY_URL` environment variable to a `.zip`, `.tar` or `.tar.gz` URL, and configure `PROJECT`, `PROJECT_DIR` and `PROJECT_BIN`. Alternatively provide a [Chain Registry](https://github.com/cosmos/chain-registry) `CHAIN_JSON` to configure everything automatically (where data is available).

Image URL: `ghcr.io/terp-network/o-line:v0.0.4-generic`

```yaml
services:
  node:
    image: ghcr.io/terpnetwork/o-line:v0.0.4-generic
    env:
      - MONIKER=my-moniker-1
      - CHAIN_JSON=https://raw.githubusercontent.com/cosmos/chain-registry/refs/heads/master/terpnetwork/chain.json
      - BINARY_ZIP_PATH=terp_core_linux_amd64
```

More information on the generic image can be found at [/generic](./generic/), and configuration is detailed in depth below.

## Networks (pre-built images)

The available docker images can be found [here](https://github.com/terpnetwork/o-line/pkgs/container/o-line).  They are
tagged with the form `$COSMOS_OMNIBUS_VERSION-$PROJECT-$PROJECT_VERSION`.

|Project|Version|Image| |
|---|---|---|---|
|[terp-network](https://github.com/terpnetwork/terp-core)|`v4.2.2`|`terpnetwork/o-line:v0.0.4`|[Example](./terpnetwork)|

## Example configurations

Optional configuration options are commented out so you can easily enable them, and the node can be configured further using the docs below.

### Running on Akash

See the `deploy.yml` example file in each chain directory which details the minimum configuration required. Use the [configuration options below](#configuration) to add functionality. Note the commented out persistent storage configuration if needed.

### Running locally/any docker host

See the `docker-compose.yml` example file in each chain directory to run each node using `docker-compose up`.

## Snapshots

O-Line can [import chain snapshots](#snapshot-restore) from almost any location.

Appropriate snapshot configuration is included in most example configurations in the O-Line repository. Check the project directories for more information.

## Examples

See the [_examples](./_examples) directory for some common setups, including:

- [Statesync](./_examples/statesync)
- [Load Balanced RPC Nodes](./_examples/load-balanced-rpc-nodes)
- [Validator and TMKMS](./_examples/validator-and-tmkms)
- [Validator and Public Sentries](./_examples/validator-and-public-sentries)
- [Validator with Private Sentries](./_examples/validator-and-private-sentries)
- [Snapshot Backup](./_examples/snapshot_backup)

## Configuration

Cosmos blockchains can be configured entirely using environment variables instead of the config files.
Every chain has its own prefix, but the format of the configuration is the same.

For example to configure the `seeds` option in the `p2p` section of `config.toml`, for the Akash blockchain:

```
TERP_P2P_SEEDS=id@node:26656
```

The namespace for each of the supported chains in the cosmos omnibus can be found in the `README` in each project directory.

The omnibus images allow some specific variables and shortcuts to configure extra functionality, detailed below.

### Chain configuration

Chain config can be sourced from a `chain.json` file [as seen in the Cosmos Chain Registry](https://github.com/cosmos/chain-registry).

|Variable|Description|Default|Examples|
|---|---|---|---|
|`CHAIN_JSON`|URL to a `chain.json` file detailing the chain meta| |`https://raw.githubusercontent.com/terpnetwork/networks/main/mainnet/morocco-1/genesis.json`
|`CHAIN_ID`|The cosmos chain ID| |`akashnet-2`
|`GENESIS_URL`|URL to the genesis file in `.gz`, `.tar.gz`, or `.zip` format. Can be set by CHAIN_JSON| |`https://raw.githubusercontent.com/terp/net/main/mainnet/genesis.json`
|`DOWNLOAD_GENESIS`|Force download of genesis file. If unset the node will only download if the genesis file is missing| |`1`|
|`VALIDATE_GENESIS`|Set to 1 to enable validation of genesis file|`0`|`1`

### P2P

Peer information can be provided manually, or obtained automatically from the following sources:

- `CHAIN_JSON` URL with peer information included.
- [Polkachu's live peers](https://www.polkachu.com/live_peers).
- Any `ADDRBOOK_URL` where the `config/addrbook.json` file is hosted.

See [Cosmos docs](https://docs.tendermint.com/master/nodes/configuration.html#p2p-settings) for more information.

|Variable|Description|Default|Examples|
|---|---|---|---|
|`P2P_SEEDS`|Seed nodes. Can be set by CHAIN_JSON or GENESIS_URL| |`id@node:26656`|
|`P2P_PERSISTENT_PEERS`|Persistent peers. Can be set by CHAIN_JSON or GENESIS_URL| |`id@node:26656`|
|`ADDRBOOK_URL`|URL to an addrbook.json file| |`https://server-3.itrocket.net/mainnet/terp/addrbook.json`

### Private key backup/restore

On boot, the container can restore a private key from any S3 storage provider. If this is configured and the key doesn't exist in S3 yet, it will be uploaded from the node.

This allows for a persistent node ID and validator key on Akash's ephemeral storage.

[Filebase](https://filebase.com/) is a great way to use S3 with decentralised hosting such as Sia.

The `node_key.json` and `priv_validator_key.json` are both backed up, and can be encrypted with a password.

|Variable|Description|Default|Examples|
|---|---|---|---|
|`S3_KEY`|S3 access key| | |
|`S3_SECRET`|S3 secret key| | |
|`S3_HOST`|The S3 API host|`https://s3.filebase.com`|`https://s3.us-east-1.amazonaws.com`|
|`STORJ_ACCESS_GRANT`|DCS Storj Access Grant token (replaces `S3_KEY`, `S3_SECRET`, `S3_HOST`| | |
|`KEY_PATH`|Bucket and directory to backup/restore to| |`bucket/nodes/node_1`|
|`KEY_PASSWORD`|An optional password to encrypt your private keys. Shouldn't be optional| | |

### Statesync

Some shortcuts for enabling statesync. Statesync requires 2x nodes with snapshots enabled.

<!-- Statesync nodes can also be sourced from [Polkachu's Statesync service](https://www.polkachu.com/state_sync) automatically. -->

[See an example](_examples/statesync) of a statesync deployment.

|Variable|Description|Default|Examples|
|---|---|---|---|
|`STATESYNC_SNAPSHOT_INTERVAL`|Take a snapshot to provide statesync every X blocks| |`500`|
|`STATESYNC_ENABLE`|Enabling statesyncing from a node. Default `true` if `STATESYNC_RPC_SERVERS` is set| | |
|`STATESYNC_RPC_SERVERS`|Comma separated list of RPC nodes with snapshots enabled| |`ip:26657,ip2:26657`|
|`STATESYNC_TRUSTED_NODE`|A trusted node to obtain trust height and hash from. Defaults to the first `STATESYNC_RPC_SERVERS` if set| |`ip:26657`|
|`STATESYNC_TRUST_PERIOD`|Trust period for the statesync snapshot|`168h0m0s`| |
|`STATESYNC_TRUST_HEIGHT`|Obtained from `STATESYNC_TRUSTED_NODE`| | |
|`STATESYNC_TRUST_HASH`|Obtained from `STATESYNC_TRUSTED_NODE`| | |

### Snapshot restore

The node `data` directory can be restored from a `.tar`, `.tar.gz` or `.lz4` file stored on a public URL.
The file can be obtained from the following sources:

- Direct URL to the archive file
- Base URL file listing, where the archive matches a given pattern.
- [snapshot.json](#snapshot-backup) generated by [O-Line Snapshot backup](#snapshot-backup) feature.
<!-- - ChainLayer's [Quicksync snapshots](https://quicksync.io/) described by a JSON file.
- Polkachu's [snapshot service](https://www.polkachu.com/tendermint_snapshots), fully automatically. -->

Note that snapshots will be restored in-process, without downloading the snapshot to disk first. This saves disk space but is slower to extract, and could be made configurable in the future.

|Variable|Description|Default|Examples|
|---|---|---|---|
|`DOWNLOAD_SNAPSHOT`|Force bootstrapping from snapshot. If unset the node will only restore a snapshot if the `data` contents are missing| |`1`|
|`SNAPSHOT_URL`|A URL to a `.tar`, `.tar.gz` or `.lz4` file| |`http://135.181.60.250/akash/akashnet-2_2021-06-16.tar`|
|`SNAPSHOT_BASE_URL`|A base URL to a directory containing backup files| |`http://135.181.60.250/akash`|
|`SNAPSHOT_JSON`|A URL to a `snapshot.json` as detailed in [Snapshot backup](#snapshot-backup)| |`https://cosmos-snapshots.s3.filebase.com/akash/pruned/snapshot.json`|
|`SNAPSHOT_FORMAT`|The format of the snapshot file|`tar.gz`|`tar`/`tar.zst`|
|`SNAPSHOT_PATTERN`|The pattern of the file in the `SNAPSHOT_BASE_URL`|`$CHAIN_ID.*$SNAPSHOT_FORMAT`|`foobar.*tar.gz`|
|`SNAPSHOT_DATA_PATH`|The path to the data directory within the archive| |`snapshot/data`|
|`SNAPSHOT_WASM_PATH`|The path to the wasm directory within the archive, if exists outside of data| |`snapshot/wasm`|
|`SNAPSHOT_PRUNING`|Type of snapshot to download, e.g. `archive`, `pruned`, `default`.|`pruned`|`archive`|
|`SNAPSHOT_QUICKSYNC`|A URL to a Quicksync JSON file describing their snapshots. Also see `SNAPSHOT_PRUNING`| |`https://quicksync.io/terra.json`|

### Snapshot backup

O-Line includes a script to automatically snapshot a node and upload the resulting archive to any S3 compatible service like [Filebase](https://filebase.com/).
At a specified time (or day), the script will shut down the tendermint server, create an archive of the `data` directory and upload it.
Snapshots older than a specified time can also be deleted. Finally a JSON metadata file is created listing the current snapshots. The server is then restarted and monitored.

[See an example](_examples/snapshot_backup) of a snapshot node deployment.

|Variable|Description|Default|Examples|
|---|---|---|---|
|`S3_KEY`|S3 access key| | |
|`S3_SECRET`|S3 secret key| | |
|`S3_HOST`|The S3 API host|`https://s3.filebase.com`|`s3.us-east-1.amazonaws.com`|
|`STORJ_ACCESS_GRANT`|DCS Storj Access Grant token (replaces `S3_KEY`, `S3_SECRET`, `S3_HOST`)| | |
|`STORJ_UPLINK_ARGS`|DCS Storj Uplink arguments|`-p 4 --progress=false`|`-p 4 --parallelism-chunk-size 256M --progress=false`|
|`SNAPSHOT_PATH`|The S3 path to upload snapshots to, including the bucket| |`cosmos-snapshots/akash`|
|`SNAPSHOT_PREFIX`|The prefix for the snapshot filename|`$CHAIN_ID`|`snapshot`|
|`SNAPSHOT_TIME`|The time the snapshot will run|`00:00:00`|`09:00:00`|
|`SNAPSHOT_DAY`|The numeric day of the week the snapshot will run (Monday = 1)|`*`|`7`|
|`SNAPSHOT_DIR`|The directory on disk to snapshot|`$PROJECT_ROOT/data`|`/root/.akash`|
|`SNAPSHOT_CMD`|The command to run the server|`$START_CMD`|`akash start --someflag`|
|`SNAPSHOT_RETAIN`|How long to retain snapshots for (0 to disable)|`2 days`|`1 week`|
|`SNAPSHOT_METADATA`|Whether to create a snapshot.json metadata file|`1`|`0`|
|`SNAPSHOT_METADATA_URL`|The URL snapshots will be served from (for snapshot.json)| |`https://cosmos-snapshots.s3.filebase.com/akash`|
|`SNAPSHOT_SAVE_FORMAT`|Overrides value from `SNAPSHOT_FORMAT`.|`tar.gz`|`tar` (no compression)/`tar.zst` (use [zstd](https://github.com/facebook/zstd))|

When `SNAPSHOT_SAVE_FORMAT` is set to `tar.zst`, [additional variables can be set](https://github.com/facebook/zstd/tree/v1.5.2/programs#passing-parameters-through-environment-variables):
- `ZSTD_CLEVEL` - Compression level, default `3`
- `ZSTD_NBTHREADS` - No. of threads, default `1`, `0` = detected no. of cpu cores

### Binary download

The node binary can be downloaded at runtime when using the [Generic image](#generic-image-binary-downloaded-at-runtime). All configuration can be sourced from `CHAIN_JSON` if the attributes are available, or configured manually. You will need to set `PROJECT`, `PROJECT_BIN` and `PROJECT_DIR` if these can't be sourced from `CHAIN_JSON`.

|Variable|Description|Default|Examples|
|---|---|---|---|
|`BINARY_URL`|URL to the binary (or `zip`, `tar`, `tar.gz`)| | |
|`BINARY_ZIP_PATH`|Path to the binary in the archive. Can be left blank if correctly named in root| | |
|`PROJECT`|Name of the project, informs other variables| | |
|`PROJECT_BIN`|Binary name|`$PROJECT`|`terpd`|
|`PROJECT_DIR`|Name of project directory|`.$PROJECT_BIN`|`.terp`|

<!-- ### Polkachu Services

[Polkachu](https://polkachu.com/) validator provides various Cosmos chain services that can be automatically enabled using environment variables.

|Variable|Description|Default|Examples|
|---|---|---|---|
|`POLKACHU_CHAIN_ID`| Polkachu API chain-id if it differs from Chain Registry naming convention.| |`cryptocom`
|`P2P_POLKACHU`|Import [Polkachu's](https://www.polkachu.com/seeds) seed node if available| |`1`|
|`STATESYNC_POLKACHU`|Import [Polkachu's](https://www.polkachu.com/state_sync) statesync addresses if available| |`1`| -->

### Cosmovisor

[Cosmovisor](https://docs.cosmos.network/main/tooling/cosmovisor) can be downloaded at runtime to automatically manage chain upgrades. You should be familiar with how Cosmovisor works before using this feature.

|Variable|Description|Default|Examples|
|---|---|---|---|
|`COSMOVISOR_ENABLED`|Enable Cosmovisor binary download and support| |`1`|
|`COSMOVISOR_VERSION`|Version of Cosmovisor to download|`1.5.0`| |
|`COSMOVISOR_URL`|Alternative full URL to Cosmovisor binary tar.gz| | |

### Shortcuts

See [Cosmos docs](https://docs.tendermint.com/master/nodes/configuration.html) for more information

|Variable|Description|Default|Examples|
|---|---|---|---|
|`FASTSYNC_VERSION`|The fastsync version| |`v0`|
|`MINIMUM_GAS_PRICES`|Minimum gas prices| |`0.025uthiol`|
|`PRUNING`|How much of the chain to prune| |`nothing`|
|`PRUNING_CUSTOM`|custom pruning options| |`1`|
|`DEBUG`|Set to `1` to output all environment variables on boot. Set to `2` to debug shell scripts.| |`1`, `2`|

## Contributing

### Creating New ghcr.io image:
```sh
git tag v0.0.4 && git push --tags
```

<!-- Adding a new chain is easy:

- Ideally source or setup a `chain.json` to provide a single source of truth for chain info
- Add a project directory based on the existing projects
- Update the [github workflow](https://github.com/terpnetwork/o-line/blob/master/.github/workflows/publish.yaml) to create an image for your chain

Submit a PR or an issue if you want to see any specific chains. -->
