#!/bin/bash
BIND=terpd
SNAPSHOT="${SNAPSHOT:-latest.tar.lz}}"
CHAIN_HOME="${CHAIN_HOME:-$HOME/.terpd-mainnet}"     # ← Change this
pkill -15 $BIND || true && sleep 3
mkdir -p ~/keys_backup_$(date +%Y%m%d)
cp $CHAIN_HOME/config/priv_validator_key.json ~/keys_backup_*/ 2>/dev/null || true
cp $CHAIN_HOME/config/node_key.json         ~/keys_backup_*/ 2>/dev/null1 || true
cp $CHAIN_HOME/data/priv_validator_state.json ~/keys_backup_*/ 2>/dev/null || true
cd $CHAIN_HOME
echo "Extracting snapshot..."
tar -I zstd -xf "$SNAPSHOT"
cp ~/keys_backup_*/priv_validator_key.json config/ 2>/dev/null || true
cp ~/keys_backup_*/node_key.json config/ 2>/dev/null || true
cp ~/keys_backup_*/priv_validator_state.json data/ 2>/dev/null || true
echo "✅ Restore complete. Starting node..."
$BIND start --home $CHAIN_HOME