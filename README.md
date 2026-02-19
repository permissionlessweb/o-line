# O-Line Playbook

Useful scripts & configurations for setting up public RPC nodes.

## What's Included?

- **[0-line](./playbook/oline-sdl/README.md):** Sentry node array deployment workflow to minimize surface area of home validators connected to public networks.
- **[Flea Flicker](./playbook/flea-flicker/README.md):** RPC,API,GRPC,SEED reverse proxy configuration & guide.
- **[Instant Replay](./playbook/instant-replay/README.md):** minio-ipfs storage layer for distribution of node snapshots
- **[Scrimmage](./playbook/scrimmage/README.md):** deterministic test scenarios

## TODO

- add bootstrapping of indexer support
- PIR: private information retrieval indexer
- add archive node bootstrapping support
- utitize load-balancing for frontward facing rpcs (need templatize lb-deploy.yaml)
- tmkms step by step
- special teams: vpn oline for oline
- special taems: ephemeral deployments (rotate service provider & location)

## Disclaimer

This is educational purposes. Dont use this in production envrionment, or if you do be certain you know what you are doing and dont expect it to work as intended just because this awesome github exists.
