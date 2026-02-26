# minio-ipfs

MinIO object storage + Kubo IPFS gateway in a single container, managed by s6-overlay v3. Built from source.

Designed for O-Line validator infrastructure on Akash — receives snapshots via S3 API, serves them over HTTP and IPFS.

## Security model

| Path | Access | Auth |
|------|--------|------|
| S3 API `:9000` GET | Public | Anonymous download via `mc anonymous set download` |
| S3 API `:9000` PUT/DELETE | Private | Requires `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` |
| Console `:9001` | Private | Requires `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` |
| IPFS gateway `:8081` | Public | Read-only |
| IPFS swarm `:4001` | Public | P2P protocol |

Anonymous download is configured automatically at startup by `init-minio-bucket`.

## Quickstart

```bash
docker run -d --name minio-ipfs \
  -e MINIO_ROOT_USER=myaccesskey \
  -e MINIO_ROOT_PASSWORD=mysecretkey \
  -e MINIO_BUCKET=snapshots \
  -p 9000:9000 -p 9001:9001 -p 8081:8081 \
  -v minio_data:/data/minio \
  -v ipfs_data:/data/ipfs \
  ghcr.io/permissionlessweb/minio-ipfs:v0.0.6
```

Upload a file (authenticated):
```bash
mc alias set remote http://localhost:9000 myaccesskey mysecretkey
mc cp snapshot.tar.gz remote/snapshots/
```

Download anonymously:
```bash
curl -O http://localhost:9000/snapshots/snapshot.tar.gz
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MINIO_ROOT_USER` | `minioadmin` | MinIO admin username (S3 access key) |
| `MINIO_ROOT_PASSWORD` | `minioadmin` | MinIO admin password (S3 secret key) |
| `MINIO_BUCKET` | `snapshots` | Bucket created on first startup |
| `MINIO_ENABLED` | `true` | Set `false` to disable MinIO entirely |
| `MINIO_PORT` | `9000` | S3 API listen port |
| `MINIO_CONSOLE_PORT` | `9001` | Web console listen port |
| `IPFS_GATEWAY_PORT` | `8081` | IPFS HTTP gateway port |
| `IPFS_PROFILE` | `server` | Kubo init profile (`server`, `lowpower`) |
| `AUTOPIN_INTERVAL` | `300` | Seconds between auto-pin scans of the bucket |
| `AUTOPIN_PATTERNS` | `*.tar.gz,*.tar.zst,*.tar.lz4,*.tar.xz` | Glob patterns to auto-pin from MinIO |
| `PUID` | `1000` | Run-as user ID |
| `PGID` | `1000` | Run-as group ID |

## Ports

| Port | Service | Public |
|------|---------|--------|
| 9000 | MinIO S3 API | Yes (anonymous GET, authenticated PUT) |
| 9001 | MinIO console | Yes (login required) |
| 8081 | IPFS HTTP gateway | Yes (read-only) |
| 4001 | IPFS swarm (P2P) | Optional |

## Volumes

| Mount | Purpose |
|-------|---------|
| `/data/minio` | MinIO object storage |
| `/data/ipfs` | Kubo IPFS repo (blocks, config, keys) |

## IPFS pinning

Files matching `AUTOPIN_PATTERNS` are automatically pinned to IPFS when they appear in the MinIO bucket. The `svc-autopin` service polls every `AUTOPIN_INTERVAL` seconds, downloads new or changed objects, and pins them.

Manual pin:
```bash
docker exec minio-ipfs ipfs-pin /data/minio/snapshots/snapshot.tar.gz
```

List pinned content:
```bash
docker exec minio-ipfs ipfs pin ls --type=recursive
```

## Build from source

MinIO and `mc` are compiled from source in the Dockerfile (requires Go 1.24+):

```bash
docker build -t minio-ipfs:latest .
```

Override versions at build time:
```bash
docker build \
  --build-arg MINIO_VERSION=RELEASE.2025-10-15T17-29-55Z \
  --build-arg MC_VERSION=RELEASE.2025-08-13T08-35-41Z \
  -t minio-ipfs:latest .
```

## s6-overlay service tree

```
user
 ├── init-permissions      (oneshot)  Set PUID/PGID ownership
 ├── init-ipfs             (oneshot)  Initialize Kubo repo
 │    └── depends: init-permissions
 ├── init-minio            (oneshot)  Prepare /data/minio
 │    └── depends: init-permissions
 ├── svc-ipfs              (longrun)  Kubo daemon
 │    └── depends: init-ipfs
 ├── svc-minio             (longrun)  MinIO server
 │    └── depends: init-minio
 ├── init-minio-bucket     (oneshot)  Create bucket + set anonymous download
 │    └── depends: svc-minio
 └── svc-autopin           (longrun)  Poll bucket, pin to IPFS
      └── depends: init-minio-bucket
```

## Testing

```bash
E2E_IMAGE=minio-ipfs:latest ./e2e-test.sh
```

## Akash deployment

This image runs as part of O-Line's `a.kickoff-special-teams.yml` SDL. The snapshot node writes to MinIO via `MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD` (passed as `S3_KEY`/`S3_SECRET` in the SDL). Anonymous download is enabled for public snapshot serving.

Ports mapped in SDL:
- `9001 -> 80` (console via `snapshots.terp.network`)
- `9000 -> 9000` (S3 API)
- `8081 -> 8081` (IPFS gateway)
- `4001 -> 4001` (IPFS swarm)
