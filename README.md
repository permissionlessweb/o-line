# O-Line Playbook

Useful scripts & configurations for setting up public RPC nodes.

## What's Included?

- **[0-line](./playbook/oline-sdl/README.md):** Sentry node array deployment runtime for protecting at home validators.
- **[Reverse Proxy Template](./playbook/flea-flicker/README.md):** RPC,API,GRPC,SEED reverse proxy configuration & guide.
- [**Keep Alive**](./relayer/keepalive/README.md): Relayer service monitoring script, developed by [DAO DAO](https://github.com/DA0-DA0/)

## TODO

- add bootstrapping of indexer support
- add archive node bootstrapping support
- utitize load-balancing for frontward facing rpcs (need templatize lb-deploy.yaml)
- custom node image for ipfs pin on snapshot
- tmkms step by step
- special teams: vpn oline for oline
- special taems: ephemeral deployments (rotate service provider & location)

## Disclaimer

This is educational purposes. Dont use this in production envrionment, or if you do be certain you know what you are doing and dont expect it to work as intended just because this awesome github exists.
