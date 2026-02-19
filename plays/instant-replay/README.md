# Instant Replay: minio-ipfs snapshot file server

A standalone Docker image combining  minio and **Kubo/IPFS** (content pinning + gateway) into a single lightweight container managed by **s6-overlay v3**.

Designed for O-Line validator infrastructure on Akash — serves as the dedicated snapshot receive/serve endpoint.

## Quickstart

```bash
# testing functionality (requires oline to be installed)
E2E_IMAGE=minio-ipfs:latest ./e2e-test.sh
```

### docker compose

```bash
cp .env.example .env
# Edit .env with your S3 credentials
docker compose up -d
```

### docker run

```bash
docker run -d \
  --name minio-ipfs \
  --cap-add SYS_ADMIN \
  --cap-add MKNOD \
  --device /dev/fuse:/dev/fuse \
  --security-opt apparmor:unconfined \
  -e S3_BUCKET=my-bucket \
  -e S3_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID=your-key \
  -e AWS_SECRET_ACCESS_KEY=your-secret \
  -p 8080:8080 \
  -p 8081:8081 \
  -v ipfs_data:/data/ipfs \
  -v fb_config:/config \
  minio-ipfs:latest
```

Then open `http://localhost:8080` — default login is `admin` / `admin`.

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `S3_BUCKET` | _(empty)_ | Yes | S3 bucket name to mount at `/srv` |
| `S3_REGION` | `us-east-1` | No | AWS region or S3-compatible region |
| `S3_ENDPOINT_URL` | _(empty)_ | For non-AWS | Custom endpoint (Filebase, R2, MinIO) |
| `AWS_ACCESS_KEY_ID` | _(empty)_ | Yes | S3 access key |
| `AWS_SECRET_ACCESS_KEY` | _(empty)_ | Yes | S3 secret key |
| `S3FS_EXTRA_OPTS` | _(empty)_ | No | Extra s3fs mount options (comma-separated) |
| `FB_PORT` | `8080` | No | Filebrowser listen port |
| `IPFS_GATEWAY_PORT` | `8081` | No | IPFS HTTP gateway port |
| `IPFS_PROFILE` | `server` | No | Kubo init profile (`server`, `lowpower`) |
| `PUID` | `1000` | No | Run-as user ID |
| `PGID` | `1000` | No | Run-as group ID |

## S3 Bucket Policies

### Public read policy (for serving snapshots)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

### IAM write-only policy (for the API keys)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }
  ]
}
```

## IPFS Pinning

### Pin a file from inside the container

```bash
docker exec minio-ipfs ipfs-pin /srv/snapshot.tar.gz
```

Output:

```
CID: QmXyz...
Gateway URLs:
  Local:  http://localhost:8081/ipfs/QmXyz...
  IPFS:   https://ipfs.io/ipfs/QmXyz...
  Dweb:   https://dweb.link/ipfs/QmXyz...
```

### List pinned content

```bash
docker exec minio-ipfs ipfs pin ls --type=recursive
```

## Performance & Caching

s3fs-fuse tuning is configured in `init-s3mount`:

- `max_stat_cache_size=10000` — cache up to 10k directory entries
- `stat_cache_expire=60` — refresh cached entries every 60 seconds
- `use_path_request_style` — required for S3-compatible providers
- `retries=3` — retry failed operations 3 times

For additional tuning, use `S3FS_EXTRA_OPTS`:

```bash
S3FS_EXTRA_OPTS="kernel_cache,parallel_count=10,multipart_size=64"
```

## Security

- **Change `admin:admin` immediately** — the default Filebrowser credentials must be changed on first login
- **Never expose port 5001** — the IPFS API allows arbitrary file access; keep it internal only
- **Credentials at runtime** — S3 credentials are written to `/etc/passwd-s3fs` (chmod 600) at container start, never baked into the image
- **Non-root services** — the container starts as root for FUSE mount capability, then drops to the `app` user (configurable via `PUID`/`PGID`) for running Filebrowser and IPFS

## Custom Commands & Auto-Pinning

### Adding scripts

Drop scripts into the container or mount them:

```bash
docker cp my-script.sh minio-ipfs:/usr/local/bin/
docker exec minio-ipfs chmod +x /usr/local/bin/my-script.sh
```

### Watcher-based auto-pin (inotifywait)

Note: s3fs does not generate standard inotify events. For auto-pinning S3-uploaded files, use a cron-based approach:

```bash
# Cron job: pin new files every 5 minutes
*/5 * * * * find /srv -newer /tmp/.last-pin -type f -exec ipfs-pin {} \; && touch /tmp/.last-pin
```

## Ports

| Port | Service | Public? |
|------|---------|---------|
| 8080 | Filebrowser web UI | Yes (auth-gated) |
| 8081 | IPFS HTTP Gateway | Yes (read-only) |
| 5001 | IPFS API | No (internal only) |
| 4001 | IPFS Swarm (P2P) | Optional |

## Volumes

| Mount | Purpose | Persistent? |
|-------|---------|-------------|
| `/data/ipfs` | Kubo IPFS repo (blocks, config, keys) | Yes |
| `/config` | Filebrowser database + settings | Yes |
| `/srv` | S3 mount point (managed by s3fs) | No volume needed |

## Akash Deployment

This image is designed to run alongside O-Line validator infrastructure on Akash. When deploying via SDL:

- Map ports 8080 (Filebrowser) and 8081 (IPFS gateway) as HTTP services
- Pass S3 credentials via Akash environment variables
- Use persistent storage for `/data/ipfs` and `/config` volumes
- Ensure the compute profile includes FUSE capabilities (`SYS_ADMIN`)

## RESEARCH

- <https://flysystem.thephpleague.com/docs/adapter/aws-s3-v3/>
- <https://filebrowser.readthedocs.io/en/latest/configuration/storage.html>
