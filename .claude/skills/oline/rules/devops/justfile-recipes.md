# Justfile Recipes

O-line uses a modular justfile structure with imports from `scripts/just/*.just`.

## Recipe Files

| File | Purpose |
|------|---------|
| `scripts/just/akash.just` | Akash dev cluster management |
| `scripts/just/build.just` | Build and publish commands |
| `scripts/just/firewall.just` | pfSense firewall recipes |
| `scripts/just/helpers.just` | Common helper recipes |
| `scripts/just/localterp.just` | local-terp container lifecycle |
| `scripts/just/minio.just` | MinIO-IPFS recipes |
| `scripts/just/relayer.just` | IBC relayer recipes |
| `scripts/just/remote.just` | Remote sync and deploy recipes |
| `scripts/just/team.just` | Team management scripts |
| `scripts/just/vpn.just` | WireGuard VPN recipes |
| `scripts/just/testing.just` | Test runner recipes |
| `scripts/just/testing/akash.just` | Akash E2E tests |
| `scripts/just/testing/courier.just` | Courier tests |
| `scripts/just/testing/firewall.just` | Firewall tests |
| `scripts/just/testing/registry.just` | Registry tests |
| `scripts/just/testing/sites.just` | Sites tests |
| `scripts/just/testing/ssh.just` | SSH tests |
| `scripts/just/testing/testnet.just` | Testnet tests |
| `scripts/just/testing/vpn.just` | VPN tests |

## Key Recipes

```bash
# Local testing
just start-localterp [nowait]    # Start local-terp container
just e2e                         # Single-node E2E test
just e2e-multi                   # Phase A multi-node test
just e2e-network [omnibus=...]   # Full local network test
just e2e-akash-parallel          # Akash parallel deploy E2E

# Akash dev cluster
just akash-setup                 # One-time genesis init (requires Kind)
just akash-start                 # Start Akash node
just akash-wait                  # Wait + print JSON endpoints
just akash-stop                  # Stop cluster
just akash-clean                 # Remove all state

# Build & publish
just publish-oline-image         # Multi-arch amd64+arm64 Docker build

# Remote
just sync-client user@host[:port]  # SSH-multiplexed repo sync + install

# Firewall
just pfsense-connect             # Full pfSense bootstrap
just tunnel up/down/add/remove/test/list  # SOCKS proxy + pinned tunnels

# Documentation
just gen-docs                    # Regenerate CLI reference
```
