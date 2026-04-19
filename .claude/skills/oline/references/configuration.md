# O-Line Configuration

## Environment Variables

### Core
| Variable | Description |
|----------|-------------|
| `OLINE_PASSWORD` | Encryption password for config, keys, sessions |
| `OLINE_ENCRYPTED_MNEMONIC` | Encrypted mnemonic (written by `oline encrypt`) |
| `OLINE_MNEMONIC` | Raw mnemonic (bypasses prompt) |
| `OLINE_NON_INTERACTIVE` | Skip all prompts (`1`) |
| `OLINE_AUTO_SELECT` | Auto-select cheapest provider |
| `OLINE_CHAIN_ID` | Akash chain ID (e.g. `akashnet-2`) |
| `OLINE_RPC_ENDPOINT` | Akash RPC |
| `OLINE_GRPC_ENDPOINT` | Akash gRPC |

### Deployment
| Variable | Description |
|----------|-------------|
| `OLINE_FUNDING_METHOD` | `master` / `direct` / `hd:N:AMOUNT` |
| `SDL_DIR` | SDL template directory (default: `templates/sdls/`) |
| `OLINE_SNAPSHOT_FULL_URL` | Snapshot URL |
| `OLINE_ENTRYPOINT_URL` | Bootstrap entrypoint script URL |
| `GENESIS_URL` | Genesis file URL (must be in .env AND SDL templates) |
| `OLINE_TEST_STOP_AFTER_DEPLOY` | Stop after DeployAllUnits (testing) |

### DNS
| Variable | Description |
|----------|-------------|
| `OLINE_CF_API_TOKEN` | Cloudflare API token |
| `OLINE_CF_ZONE_ID` | Cloudflare zone ID |

### Network
| Variable | Description |
|----------|-------------|
| `SECRETS_PATH` | SSH key + cert storage dir (default `.`) |
| `SSH_PORT` | SSH port on deployed node (default `22`) |
| `P2P_EXT_PORT` | Actual Akash NodePort for P2P (may differ from SDL) |

## DNS KeyStore

Encrypted credentials at `~/.oline/keys.enc`. Resolution order:
1. CLI flags (`--token`, `--zone`)
2. KeyStore lookup (longest-suffix match, wildcards supported)
3. Env vars
