# O-Line CLI Reference

Binary: `oline` (package: `o-line-sdl`)

## Commands

| Command | Purpose |
|---------|---------|
| `oline encrypt` | Encrypt mnemonic with AES-256-GCM, store as `OLINE_ENCRYPTED_MNEMONIC` in `.env` |
| `oline endpoints` | Probe Akash RPC/gRPC endpoints, save fastest to `.env` |
| `oline deploy` | Full parallel deployment (phases A->B->C->E) |
| `oline deploy --parallel` | Deploy all phases before snapshot sync (default) |
| `oline deploy --sequential` | Legacy one-phase-at-a-time deployment |
| `oline deploy --raw` | Enter mnemonic interactively |
| `oline deploy --sdl <path>` | Deploy raw SDL file (create + list bids) |
| `oline deploy --sdl <path> --select <DSEQ> <PROVIDER>` | Select provider for pending deployment |
| `oline sdl` | Render SDL templates without broadcasting |
| `oline sdl -o <dir>` | Write rendered SDLs to directory |
| `oline sdl --load-config <path>` | Load deploy-config.json instead of prompting |
| `oline init` | Collect config interactively -> `deploy-config.json` |
| `oline manage status` | View active deployments |
| `oline manage logs <dseq>` | Stream provider logs via WebSocket |
| `oline manage close --all` | Close all deployments |
| `oline manage close <DSEQ...>` | Close specific deployments |
| `oline manage drain` | Return child account funds to master |
| `oline manage tui` | Ratatui terminal UI |
| `oline manage sync` | Sync deployment state |
| `oline dns update` | Upsert Cloudflare DNS records |
| `oline dns list` | List DNS records |
| `oline dns set-txt <name> <value>` | Set TXT record |
| `oline dns set-cname <name> <target>` | Set CNAME record |
| `oline dns set-a <name> <ip>` | Set A record |
| `oline dns delete <name>` | Delete DNS record |
| `oline dns keys add <domain>` | Add encrypted DNS credentials |
| `oline dns keys list` | List stored DNS keys |
| `oline dns keys remove <domain>` | Remove DNS key |
| `oline dns keys resolve <domain>` | Test which key matches a domain |
| `oline bootstrap` | Bootstrap private validator + snapshot |
| `oline bootstrap --local` | Local mode (no SSH) |
| `oline bootstrap -y --host <ip>` | Non-interactive with flags |
| `oline sites deploy` | Deploy MinIO-IPFS container to Akash |
| `oline sites upload <domain> <dir>` | S3 PUT files (AWS Sig V4) |
| `oline sites publish <domain> <cid>` | Set DNSLink TXT + CNAME |
| `oline sites list` | List hosted sites |
| `oline refresh run <name>` | Push env vars + run command on node |
| `oline refresh add` | Register node in encrypted store |
| `oline refresh list` | Show saved nodes |
| `oline refresh status` | Poll RPC health for all nodes |
| `oline refresh remove` | Remove saved node |
| `oline node deploy` | Deploy dedicated Akash full node |
| `oline node status` | Check node status |
| `oline node close` | Close node deployment |
| `oline firewall` | pfSense SSH key management |
| `oline relayer` | IBC relayer hot-swap, config reload, key install |
| `oline vpn` | WireGuard VPN on pfSense |
| `oline providers` | Manage trusted providers (~/.config/oline/trusted-providers.json) |
| `oline registry` | Embedded OCI container registry (serve, import, list) |
| `oline testnet-deploy` | Bootstrap fresh testnet on Akash |
| `oline console` | Interact with Akash Console API |
| `oline test-s3` | Test S3/MinIO connectivity |
| `oline test-grpc` | Test gRPC-Web endpoint health |

## Non-Interactive Mode

```bash
OLINE_NON_INTERACTIVE=1 \
OLINE_MNEMONIC="word1 word2 ... word24" \
OLINE_PASSWORD=mypassword \
OLINE_AUTO_SELECT=1 \
  oline deploy
```

For `deploy --sdl`, provide `OLINE_MNEMONIC` or `OLINE_ENCRYPTED_MNEMONIC`.

## Provider Selection (--select)

For `--sdl`: `--select <DSEQ> <PROVIDER_ADDRESS>`

For `--parallel`: `--select a=<PROVIDER> b=<PROVIDER> c=<PROVIDER> [e=<PROVIDER>]`

Phase keys: a (snapshot+seed), b (tackles), c (forwards), e (relayer).

## Regenerate This Reference

```bash
OLINE_BIN=./target/release/oline bash scripts/docs/gen-docs.sh
```
