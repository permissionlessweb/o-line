# O-Line Playbook

Useful scripts & configurations for setting up public RPC nodes.

## What's Included?

- **[0-line](./playbook/oline-sdl/README.md):** Sentry node array deployment workflow to minimize surface area of home validators connected to public networks.
- **[Flea Flicker](./playbook/flea-flicker/README.md):** RPC,API,GRPC,SEED reverse proxy configuration & guide.
- **[Instant Replay](./playbook/instant-replay/README.md):** minio-ipfs storage layer for distribution of node snapshots
- **[Scrimmage](./playbook/scrimmage/README.md):** deterministic test scenarios

## TODO

- cicd
- retrieve env variables:
  - validator-peer id + ip: (check local node)
- add bootstrapping of indexer & relayer services (replaces second special teams nodes)
- ~~configure tls/https for all nodes~~
- load-balancing for frontward facing rpcs (need templatize lb-deploy.yaml)
- PIR: private information retrieval indexer
- tmkms step by step
- special teams: vpn oline for oline
- special taems: ephemeral deployments (rotate service provider & location)
- agent skill for creating variabalized SDL's, and wiring into scripts

## Disclaimer

This is educational purposes. Dont use this in production envrionment, or if you do be certain you know what you are doing and dont expect it to work as intended just because this awesome github exists.