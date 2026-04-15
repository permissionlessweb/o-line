# Bootstrap: MinIO-IPFS Node (oline-a-minio-ipfs)

Phase A — S3-compatible snapshot storage + IPFS gateway.
No SSH needed for bootstrap (stateless container, env vars sufficient).
S3 credentials (`MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`) injected at deploy time.

## Trigger condition
Phase A deploy complete.

## Steps

### 1. Verify S3 connectivity
```
oline test-s3 --episode $EID --host $MINIO_INTERNAL_HOST --key $S3_KEY --secret $S3_SECRET
```
Performs: PUT test-object → GET → DELETE. Verifies MinIO is ready before snapshot node
tries to write snapshots.

Internal Akash service address: `oline-a-minio-ipfs:9000`
(shared within the same Akash deployment manifest — no public exposure needed for S3).

### 2. Create snapshot bucket (if not exists)
```
oline s3-bucket-init --episode $EID --bucket $MINIO_BUCKET
```
Creates the bucket defined by first path segment of `OLINE_SNAP_PATH`.
MinIO auto-creates on first write, so this step is optional/idempotent.

### 3. Update DNS for public download domain (optional)
```
oline update-dns --episode $EID --node minio
```
Creates CNAME for `OLINE_SNAP_DOWNLOAD_DOMAIN` → provider hostname.
Only needed if external users should download snapshots directly.

## Outputs written to session state
```json
{
  "minio_ready": true,
  "minio_internal_host": "oline-a-minio-ipfs:9000",
  "snapshot_download_url": "https://<OLINE_SNAP_DOWNLOAD_DOMAIN>"
}
```

## Notes
- MinIO port 9000 is NOT globally exposed — Akash service-to-service only
- Port 9001 (console) and 8081 (IPFS gateway) ARE globally exposed
- `AUTOPIN_INTERVAL` controls how often IPFS pins new snapshot files
- Persistent storage: `minio-data` (50 Gi) + `ipfs-data` (100 Gi) on beta3 class
