# Snapshot backup

The snapshot script will shutdown the node for as long as the archive and upload process takes, 
so use a dedicated node for creating snapshots.



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
<!-- |`SNAPSHOT_QUICKSYNC`|A URL to a Quicksync JSON file describing their snapshots. Also see `SNAPSHOT_PRUNING`| |`https://quicksync.io/terra.json`| -->

### Snapshot backup

O-Line includes a script to automatically snapshot a node and upload the resulting archive to any S3 compatible service like [Filebase](https://filebase.com/).
At a specified time (or day), the script will shut down the tendermint server, create an archive of the `data` directory and upload it.
Snapshots older than a specified time can also be deleted. Finally a JSON metadata file is created listing the current snapshots. The server is then restarted and monitored.

#### Using Caddy 

#### Using Rsync 

[See an example](_examples/snapshot_backup) of a snapshot node deployment.