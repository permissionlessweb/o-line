#!/bin/sh

# ── Settings ──────────────────────────────────────────────────────────────────
minio_ipfs_version     := "v0.0.9"
ghcr_image             := "ghcr.io/permissionlessweb/minio-ipfs"
dh_image               := "docker.io/permissionlessweb/minio-ipfs"

oline_omnibus_version  := "v0.2.0"
ghcr_omnibus           := "ghcr.io/akash-network/cosmos-omnibus"
dh_omnibus             := "docker.io/akash-network/cosmos-omnibus"

# ── Imports ──────────────────────────────────────────────────────────────────
import 'scripts/just/build.just'
import 'scripts/just/minio.just'
import 'scripts/just/localterp.just'
import 'scripts/just/akash.just'
import 'scripts/just/remote.just'
import 'scripts/just/firewall.just'
import 'scripts/just/relayer.just'
import 'scripts/just/team.just'
import 'scripts/just/vpn.just'

# ── Test subcommand ──────────────────────────────────────────────────────────
# All tests live under `just test <name>`. Run `just test list` to see them.
mod test 'scripts/just/testing.just'
