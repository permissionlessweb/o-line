# O-Line Playbook
Useful scripts & configurations for setting up public RPC nodes.

## What's Included?
### Reverse Proxy 
- **Custom Node Images:** Docker image source code for deploying full-nodes, sentry-nodes, indexer & validator setups, *fork of [cosmos-omnibus](https://github.com/akash-network/cosmos-omnibus)*.
- **Nginx Template:** RPC,API,GRPC,SEED reverse proxy configuration & guide.
- **Caddy Template:** RPC,API,GRPC,SEED reverse proxy confugration & guide.

### Relayer
- [**Keep Alive**](./relayer/keepalive/README.md): Relayer service monitoring script, developed by [DAO DAO](https://github.com/DA0-DA0/)

## TODO:
- add bootstrapping of indexer support
- add archive node bootstrapping support 
- custom node image for ipfs pin on snapshot
- tmkms step by step
- special teams: vpm oline for oline 
- special taems: ephemeral deployments (rotate service provider & location)


## Disclaimmer
This is educational purposes. Dont use this in production envrionment, or if you do be certain you know what you are doing and dont expect it to work as intended just because this awesome github exists. 