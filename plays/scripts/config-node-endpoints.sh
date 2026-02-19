#!/bin/bash

read -p "What would you like to do? Press the corresponding button:
1 - Configure RPC node
2 - Configure custom ports
3 - Exit
" ACTION

if [ "$ACTION" == "1" ]; then
    read -p "Enter config directory absolute path: " CONF_PATH

    # Check if the directory exists
    if [ ! -d "$CONF_PATH" ]; then
        echo "Directory $CONF_PATH does not exist."
        exit 1
    fi

    # Update app.toml
        # -e "/^\[grpc-web\]$/,/^\[/ s/^enable-unsafe-cors *=.*/enable-unsafe-cors = \"true\"/" \
        # -e "/^\[api\]$/,/^\[/ s/^enabled-unsafe-cors *=.*/enabled-unsafe-cors = \"true\"/" \
    sed -i \
        -e "s/^pruning *=.*/pruning = \"nothing\"/" \
        -e "/^\[api\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[api\]$/,/^\[/ s/^swagger *=.*/swagger = \"true\"/" \
        -e "/^\[rosetta\]$/,/^\[/ s/^enable *=.*/enable = \"false\"/" \
        -e "/^\[grpc\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[grpc-web\]$/,/^\[/ s/^enable *=.*/enable = \"true\"/" \
        -e "/^\[state-sync\]$/,/^\[/ s/^snapshot-interval *=.*/snapshot-interval = \"1000\"/" \
        -e "/^\[state-sync\]$/,/^\[/ s/^snapshot-keep-recent *=.*/snapshot-keep-recent = \"2\"/" \
        "${CONF_PATH}app.toml"

    # Update config.toml
    sed -i \
        -e "s/^cors_allowed_origins *=.*/cors_allowed_origins = \"[*]\"/" \
        -e "s/^indexer *=.*/indexer = \"kv\"/" \
        -e "s/^prometheus *=.*/prometheus = \"false\"/" \
        -e "s/^filter_peers *=.*/filter_peers = \"true\"/" \
        "${CONF_PATH}config.toml"

elif [ "$ACTION" == "2" ]; then
    read -p "Enter the preferred port: " CONF_PORT
    read -p "Enter config directory absolute path: " CONF_PATH

    # Check if the directory exists
    if [ ! -d "$CONF_PATH" ]; then
        echo "Directory $CONF_PATH does not exist."
        exit 1
    fi

    # Update app.toml
        # -e "/^\[json-rpc\]$/,/^\[/ s%^ws-address *=.*%ws-address = \"127.0.0.1:${CONF_PORT}546\"%" \
    sed -i \
        -e "/^\[api\]$/,/^\[/ s%^address *=.*%address = \"tcp://0.0.0.0:${CONF_PORT}317\"%" \
        -e "/^\[rosetta\]$/,/^\[/ s%^address *=.*%address = \":${CONF_PORT}080\"%" \
        -e "/^\[grpc\]$/,/^\[/ s%^address *=.*%address = \"0.0.0.0:${CONF_PORT}090\"%" \
        -e "/^\[grpc-web\]$/,/^\[/ s%^address *=.*%address = \"0.0.0.0:${CONF_PORT}091\"%" \
        -e "/^\[json-rpc\]$/,/^\[/ s%^address *=.*%address = \"127.0.0.1:${CONF_PORT}545\"%" \
        -e "/^\[json-rpc\]$/,/^\[/ s%^metrics-address *=.*%metrics-address = \"127.0.0.1:${CONF_PORT}065\"%" \
        "${CONF_PATH}app.toml"

    # Update config.toml
    sed -i \
        -e "s%^proxy_app *=.*%proxy_app = \"tcp://127.0.0.1:${CONF_PORT}658\"%" \
        -e "/^\[rpc\]$/,/^\[/ s%^laddr *=.*%laddr = \"tcp://127.0.0.1:${CONF_PORT}657\"%" \
        -e "/^\[rpc\]$/,/^\[/ s%^pprof_laddr *=.*%pprof_laddr = \"localhost:${CONF_PORT}060\"%" \
        -e "/^\[p2p\]$/,/^\[/ s%^laddr *=.*%laddr = \"tcp://0.0.0.0:${CONF_PORT}656\"%" \
        -e "/^\[p2p\]$/,/^\[/ s%^external_address *=.*%external_address = \"$(wget -qO- eth0.me):${CONF_PORT}656\"%" \
        -e "/^\[instrumentation\]$/,/^\[/ s%^prometheus_listen_addr *=.*%prometheus_listen_addr = \":${CONF_PORT}660\"%" \
        "${CONF_PATH}config.toml"
fi