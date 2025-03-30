#!/bin/bash

AKASH_KEY_NAME=test1
AKASH_KEYRING_BACKEND=os
AKASH_NET="https://raw.githubusercontent.com/akash-network/net/main/mainnet"
AKASH_VERSION="$(curl -s https://api.github.com/repos/akash-network/provider/releases/latest | jq -r '.tag_name')"
export AKASH_CHAIN_ID="$(curl -s "$AKASH_NET/chain-id.txt")"
# export AKASH_NODE="$(curl -s "$AKASH_NET/rpc-nodes.txt" | shuf -n 1)"
export AKASH_NODE="https://rpc-akash.ecostake.com:443"
echo $AKASH_NODE $AKASH_CHAIN_ID $AKASH_KEYRING_BACKEND
AKASH_GAS=auto
AKASH_GAS_ADJUSTMENT=1.3
AKASH_GAS_PRICES=0.0025uakt
AKASH_SIGN_MODE=amino-json

PRIVATE_VALIDATOR_ID=abc123xyz987@<your-ip>:26656


# service names 
SERVICES_ARRAY=(
    "oline--special--snapshot"
    "oline--special--seed"
    "oline--tackle--left"
    "oline--tackle--right"
    "oline--forward--left"
    "oline--forward--right"
)
# Log file paths (used to collect node-ids)
LOG_FILES=(
    "a.logs-kickoff-snapshot.json"
    "a.logs-kickoff-seed.json"
    "a.logs-tackle-left.json"
    "a.logs-tackle-right.json"
    "b.logs-forward-left.json"
    "b.logs-forward-right.json"
)

# SDL files to deploy in sequence
SDL_FILES=(
    # Add more SDL files as needed
    "sdls/a.kickoff-special-teams.yml"
    "sdls/b.left-and-right-tackles.yml"
    "sdls/c.left-and-right-forwards.yml"
)

## trusted providers 
TRUSTED_PROVIDERS=(
    "akash1u5cdg7k3gl43mukca4aeultuz8x2j68mgwn28e" # d3akash
    "akash1h4h33c8rv8e084el7e74f7pktz27pmxxt8nl9q" # overclock
    "akash15ksejj7g4su7ljufsg0a8eglvkje94z8qsh68a" # palmito
    "akash1kqzpqqhm39umt06wu8m4hx63v5hefhrfmjf9dj" # leet.haus
    "akash16yrzlu9cgxcf4d7k6qjax5fd3cll05p87qha4m" # dsm.hh
    "akash1efge8vzg376fnnfeyg5v8tdq9sg3elhgy42wvm" # marzrock
    "akash1tweev0k42guyv3a2jtgphmgfrl2h5y2884vh9d" # dcnorse
    "akash18ga02jzaq8cw52anyhzkwta5wygufgu6zsz6xc" # europlots
    "akash17l0f3kf7gv4kmgqjmgc0ksj3em6lqgcc4kl4dg" # pcgameservers
    "akash1ut3m97h62tty06qdq9lds85r34dxe3snjj0xfe" # akashgpu.com
    )

# Deployment info storage
declare -A DEPLOYMENTS
# Structure: DEPLOYMENTS[SDL_FILE]="dseq:oseq:gseq:provider"

function check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check for provider-services
    if ! command -v provider-services &> /dev/null; then
        log_error "provider-services is not installed. Please install it before proceeding: https://akash.network/docs/deployments/akash-cli/installation/"
        exit 1
    fi
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        log_error "jq is not installed. Please install it before proceeding."
        exit 1
    fi
    
    # Check for yq if we need to modify YAML files
    if ! command -v yq &> /dev/null; then
        log_warn "yq is not installed. It might be needed for YAML modifications."
    fi
    
    log_info "All required dependencies are installed."
}

function setup_keys() {
    log_info "Setting up keys..."
    
    SOCK_CHECK=$(provider-services keys list $AKASH_KEY_NAME --output json)
    if [ "$SOCK_CHECK" = "[]" ]; then
        log_info "No key found with name '$AKASH_KEY_NAME', creating key..."
        provider-services keys add $AKASH_KEY_NAME
    else
        log_info "Key '$AKASH_KEY_NAME' already exists."
    fi
    
    # Set account address
    export AKASH_ACCOUNT_ADDRESS="$(provider-services keys show $AKASH_KEY_NAME -a)"
    log_info "Using account address: $AKASH_ACCOUNT_ADDRESS"
    
    ## confirm balance exists 
    log_info "Checking account balance..."
    BALANCE_CHECK=$(provider-services query bank balances --node $AKASH_NODE $AKASH_ACCOUNT_ADDRESS -o json)
    
    AKT_BALANCE=$(echo "$BALANCE_CHECK" | jq -r '.balances[] | select(.denom == "uakt") | .amount // "0"')
    if [ -z "$AKT_BALANCE" ]; then AKT_BALANCE="0"; fi
    
    if [ "$AKT_BALANCE" -gt 0 ]; then
        log_info "Account has $AKT_BALANCE uakt."
    else
        log_error "Account has no uakt. Please fund your account before proceeding."
        exit 1
    fi
}
 
 
## 2. Create Certificate
function setup_certificate() {
    log_info "Setting up certificate..."
    
    # Check if certificate already exists
    CERT_CHECK=$(provider-services query cert list --owner $AKASH_ACCOUNT_ADDRESS --node $AKASH_NODE -o json)
    CERT_COUNT=$(echo "$CERT_CHECK" | jq -r '.certificates | length')
    
    if [ "$CERT_COUNT" -gt 0 ]; then
        log_info "Certificate already exists."
    else
        log_info "Generating new certificate..."
        provider-services tx cert generate client --from $AKASH_KEY_NAME

        log_info "Publishing certificate..."
        provider-services tx cert publish client --from $AKASH_KEY_NAME --fees 5000uakt
    fi
}

function deploy_sdl() {
    STEP=$1
    SDL_FILE=$2
    log_info "Deploying SDL: $SDL_FILE"

    # set snapshot to occur 10 mins from deployment
    if [[ "$STEP" == 1 ]]; then
    SNAPSHOT_TIME=$(date -d "10 minutes" '+%H:%M:%S')
    yq e ".services.oline--special--snapshot.env[] |= sub(\"^SNAPSHOT_TIME=.*\", \"SNAPSHOT_TIME=$SNAPSHOT_TIME\")" -i "$SDL_FILE"
    fi

    log_info "Creating deployment..."
    DEPLOY_OUTPUT=$(provider-services tx deployment create "$SDL_FILE" --from $AKASH_KEY_NAME --fees 5000uakt -y --output json)
    sleep 7

    # Parse deployment info
    AKASH_DSEQ=$(echo "$DEPLOY_OUTPUT" | jq -r '.logs[0].events[] | select(.type == "akash.v1") | .attributes[] | select(.key == "dseq") | .value')
    AKASH_OSEQ=$(echo "$DEPLOY_OUTPUT" | jq -r '.logs[0].events[] | select(.type == "akash.v1") | .attributes[] | select(.key == "oseq") | .value')
    AKASH_GSEQ=$(echo "$DEPLOY_OUTPUT" | jq -r '.logs[0].events[] | select(.type == "akash.v1") | .attributes[] | select(.key == "gseq") | .value')
    
    if [ -z "$AKASH_DSEQ" ]; then
        log_error "Failed to extract DSEQ from deployment output"
        echo "$DEPLOY_OUTPUT" | jq
        exit 1
    fi
    
    log_info "Deployment created with DSEQ: $AKASH_DSEQ, OSEQ: $AKASH_OSEQ, GSEQ: $AKASH_GSEQ"

    # Wait for bids
    log_info "Waiting for bids..."
    sleep 15
    
    # Get bids
    log_info "Fetching bids..."
    BIDS_OUTPUT=$(provider-services query market bid list --owner=$AKASH_ACCOUNT_ADDRESS --node $AKASH_NODE --dseq $AKASH_DSEQ --state=open -o json)
    
    ## determine cheapest bid from trusted providers
    ## monthly cost == (Xuakt) * # of blocks in a month (6.098sec blocks) == (9.84 blocks/min) == (590.4 blocks/hour) == (14169.6 blocks/day) == 425,088 blocks/month
    # Find trusted provider with lowest bid
    log_info "Finding optimal bid from trusted providers..."
    LOWEST_PRICE="999999999999999"
    LOWEST_PROVIDER=""
     for PROVIDER in "${TRUSTED_PROVIDERS[@]}"; do
        log_info "looking for: $PROVIDER"
        # Extract price for this provider
        PROVIDER_PRICE=$(echo "$BIDS_OUTPUT" | jq -r --arg PROVIDER "$PROVIDER" '.bids[] | select(.bid.bid_id.provider == $PROVIDER) | .bid.price.amount')
        
        if [ ! -z "$PROVIDER_PRICE" ] && [ "$PROVIDER_PRICE" != "null" ]; then
            log_info "Found bid from trusted provider $PROVIDER: $PROVIDER_PRICE uakt"
            if $(bc -l <<< "$PROVIDER_PRICE < $LOWEST_PRICE"); then
                LOWEST_PRICE=$PROVIDER_PRICE
                LOWEST_PROVIDER=$PROVIDER
            fi
        fi
    done

    if [ -z "$LOWEST_PROVIDER" ]; then
        log_error "No bids from trusted providers found!"
        echo "$BIDS_OUTPUT" | jq
        exit 1
    fi

    log_info "Selected provider $LOWEST_PROVIDER with price $LOWEST_PRICE uakt"

    ## 3.c Create the lease 
    log_info "Creating lease with provider $LOWEST_PROVIDER..."
    LEASE_OUTPUT=$(provider-services tx market lease create --dseq $AKASH_DSEQ --provider $LOWEST_PROVIDER --from $AKASH_KEY_NAME --fees 5000uakt -y --output json)
    sleep 10

    #### verify lease was created 
    log_info "Verifying lease..."
    LEASE_CHECK=$(provider-services query market lease list --owner $AKASH_ACCOUNT_ADDRESS --node $AKASH_NODE --dseq $AKASH_DSEQ -o json)
    LEASE_STATE=$(echo "$LEASE_CHECK" | jq -r ".leases[0].lease.state")
    
    if [ "$LEASE_STATE" != "active" ]; then
        log_error "Lease is not active, current state: $LEASE_STATE"
        exit 1
    fi

    log_info "Lease created successfully!"

    ## 3.d Send Manifest To Provider
    log_info "Sending manifest to provider..."
    MANIFEST_OUTPUT=$(provider-services send-manifest "$SDL_FILE" --dseq $AKASH_DSEQ --provider $LOWEST_PROVIDER --from $AKASH_KEY_NAME)
    
    log_info "Manifest sent, waiting for deployment to be ready..."
    sleep 20

    ## 4. Confirm the URL & obtain DNS for deployments 
    log_info "Checking lease status..."
    STATUS_OUTPUT=$(provider-services lease-status --dseq $AKASH_DSEQ --from $AKASH_KEY_NAME --provider $LOWEST_PROVIDER -o json)

    ## Collect DNS URI:
    if [[ "$STEP" == 1 ]]; then
    # Kickoff deployment - extract snapshot and seed node URIs
        SNAPSHOT_URI=$(echo "$STATUS_OUTPUT" | jq -r ".services.\"${SERVICES_ARRAY[0]}\".uris[0]")
        SEED_URI=$(echo "$STATUS_OUTPUT" | jq -r ".services.\"${SERVICES_ARRAY[1]}\".uris[0]")

        # snapshot logs
        provider-services lease-logs --dseq "$AKASH_DSEQ" --provider "$LOWEST_PROVIDER" --from "$AKASH_KEY_NAME" --service "${SERVICES_ARRAY[0]}"> "${LOG_FILES[0]}"
        sleep 10
        # seed logs
        provider-services lease-logs --dseq "$AKASH_DSEQ" --provider "$LOWEST_PROVIDER" --from "$AKASH_KEY_NAME" --service "${SERVICES_ARRAY[1]}" > "${LOG_FILES[1]}"
        sleep 10

        # find node-id from logs 
        SNAPSHOT_NODE_ID=$(grep -o 'ID=[^ ]*' "${LOG_FILES[0]}" | cut -d '=' -f2)
        SEED_NODE_ID=$(grep -o 'ID=[^ ]*' "${LOG_FILES[1]}" | cut -d '=' -f2)

        SNAPSHOT_NODE_PEER_ID="$SNAPSHOT_NODE_ID@$SNAPSHOT_URI:443"
        SEED_NODE_PEER_ID="$SEED_NODE_ID@$SEED_URI:443"
        echo "SNAPSHOT_NODE_PEER_ID=$SNAPSHOT_NODE_PEER_ID" >> deployment_uris.env
        echo "SEED_NODE_PEER_ID=$SEED_NODE_PEER_ID" >> deployment_uris.env
        
    elif [[ "$STEP" == 2 ]]; then
    # Tackles deployment - extract both sentry nodes URIs 
        LEFT_TACKLE_URI=$(echo "$STATUS_OUTPUT" | jq -r ".services.\"${SERVICES_ARRAY[2]}\".uris[0]")
        RIGHT_TACKLE_URI=$(echo "$STATUS_OUTPUT" | jq -r ".services.\"${SERVICES_ARRAY[3]}\".uris[0]")

        provider-services lease-logs --dseq "$AKASH_DSEQ" --provider "$LOWEST_PROVIDER" --from "$AKASH_KEY_NAME" --service "${SERVICES_ARRAY[2]}" >  "${LOG_FILES[2]}"
        sleep 5
        provider-services lease-logs --dseq "$AKASH_DSEQ" --provider "$LOWEST_PROVIDER" --from "$AKASH_KEY_NAME" --service "${SERVICES_ARRAY[3]}" >  "${LOG_FILES[3]}"
        sleep 5
        
        # find node-id from logs 
        LEFT_TACKLE_NODE_ID=$(grep -o 'ID=[^ ]*' "${LOG_FILES[2]}" | cut -d '=' -f2)
        RIGHT_TACKLE_NODE_ID=$(grep -o 'ID=[^ ]*' "${LOG_FILES[3]}" | cut -d '=' -f2)

        LEFT_TACKLE_PEER_ID="$LEFT_TACKLE_NODE_ID@$LEFT_TACKLE_URI:443"
        RIGHT_TACKLE_PEER_ID="$RIGHT_TACKLE_NODE_ID@$RIGHT_TACKLE_URI:443"

        echo "LEFT_TACKLE_PEER_ID=$LEFT_TACKLE_PEER_ID" >> deployment_uris.env
        echo "RIGHT_TACKLE_PEER_ID=$RIGHT_TACKLE_PEER_ID" >> deployment_uris.env
        

    elif [[ "$STEP" == 3 ]]; then
    # Forwards deployment - extract both forward public nodes URIs 
        LEFT_FORWARD_URI=$(echo "$STATUS_OUTPUT" | jq -r ".services.\"${SERVICES_ARRAY[4]}\".uris[0]")
        RIGHT_FORWARD_URI=$(echo "$STATUS_OUTPUT" | jq -r ".services.\"${SERVICES_ARRAY[5]}\".uris[0]")

        # get logs
        provider-services lease-logs --dseq "$AKASH_DSEQ" --provider "$LOWEST_PROVIDER" --from "$AKASH_KEY_NAME" --service "${SERVICES_ARRAY[4]}" > "${LOG_FILES[4]}"
        sleep 5
        provider-services lease-logs --dseq "$AKASH_DSEQ" --provider "$LOWEST_PROVIDER" --from "$AKASH_KEY_NAME" --service "${SERVICES_ARRAY[5]}" > "${LOG_FILES[5]}"
        sleep 5

        # find node-id from logs 
        LEFT_FORWARD_NODE_ID=$(grep -o 'ID=[^ ]*' "${LOG_FILES[4]}" | cut -d '=' -f2)
        RIGHT_FORWARD_NODE_ID=$(grep -o 'ID=[^ ]*' "${LOG_FILES[5]}" | cut -d '=' -f2)


        LEFT_FORWARD_PEER_ID="$LEFT_FORWARD_NODE_ID@$LEFT_FORWARD_URI:443"
        RIGHT_FORWARD_PEER_ID="$RIGHT_FORWARD_NODE_ID@$RIGHT_FORWARD_URI:443"
        
        echo "LEFT_FORWARD_PEER_ID=$LEFT_FORWARD_PEER_ID" >> deployment_uris.env
        echo "RIGHT_FORWARD_PEER_ID=$RIGHT_FORWARD_PEER_ID" >> deployment_uris.env
        
    else
    log_error "should never happen"
    exit 1
    fi

    # Store deployment info
    DEPLOYMENTS["$SDL_FILE"]="$AKASH_DSEQ:$AKASH_OSEQ:$AKASH_GSEQ:$LOWEST_PROVIDER"
    log_info "Deployment of $SDL_FILE completed successfully!"
    return 0    
}


function update_sdl_with_node_info() {
    STEP=$1
    log_info "Updating $TARGET_SDL with node info from $LOG_FILE..."

        # Source the saved URIs
    if [ -f "deployment_uris.env" ]; then
        source deployment_uris.env
    else
        log_error "deployment_uris.env file not found!"
        exit 1
    fi


    log_info "Found $NODE_TYPE node ID: $NODE_ID at $HOST:$PORT"

    # Update the target SDL file based on the step 
    if [[ "$STEP" == 1 ]]; then
    # set snapshot as persistent peer 
        yq e ".services.*.env.TERPD_P2P_PERSISTENT_PEERS = \"$SNAPSHOT_NODE_PEER_ID\"" -i "${SDL_FILES[1]}"
    # set validator as private peers
        yq e ".services.*.env.TERPD_P2P_PRIVATE_PEER_IDS = \"$TERPD_P2P_PRIVATE_PEER_IDS\"" -i "${SDL_FILES[1]}"
        yq e ".services.*.env.TERPD_P2P_UNCONDITIONAL_PEER_IDS = \"$TERPD_P2P_PRIVATE_PEER_IDS\"" -i "${SDL_FILES[1]}"
    elif [[ "$STEP" == 2 ]]; then
    # set snapshot as persistent peer
        yq e ".services.*.env.TERPD_P2P_PERSISTENT_PEERS = \"$SNAPSHOT_NODE_PEER_ID\"" -i "${SDL_FILES[2]}"
    # set l/r tackles as private peers 
        yq e ".services.*.env.TERPD_P2P_PRIVATE_PEER_IDS = \"$LEFT_TACKLE_PEER_ID,$RIGHT_TACKLE_PEER_ID\"" -i "${SDL_FILES[2]}"
        yq e ".services.*.env.TERPD_P2P_UNCONDITIONAL_PEER_IDS = \"$LEFT_TACKLE_PEER_ID,$RIGHT_TACKLE_PEER_ID\"" -i "${SDL_FILES[2]}"
    fi

}

# Main execution flow
function main() {
    log_info "Starting Akash deployment process..."

    ## 1. Setup
    check_dependencies
    setup_keys
    setup_certificate

    ## 2. Deploy snapshot & seed node
    deploy_sdl 1 "${SDL_FILES[0]}" 

    ## 3. Prepare SDL: set persistent peer to our snapshot, set private validator peer
    update_sdl_with_node_info 1 

    ## 4. Deploy L/R Tackles 
    deploy_sdl 2 "${SDL_FILES[1]}"

    ## 5. Prepare SDL: add snapshot as persistent peer
    update_sdl_with_node_info 2

    ## 6. Deploy L/R Forwards
    deploy_sdl 3 "${SDL_FILES[2]}"
    
    log_info "All deployments completed successfully!"

    # Print summary of all deployments
    log_info "Deployment Summary:"
    for SDL_FILE in "${!DEPLOYMENTS[@]}"; do
        DEPLOYMENT_INFO=${DEPLOYMENTS["$SDL_FILE"]}
        DSEQ=$(echo "$DEPLOYMENT_INFO" | cut -d':' -f1)
        PROVIDER=$(echo "$DEPLOYMENT_INFO" | cut -d':' -f4)
        
        log_info "$SDL_FILE: DSEQ=$DSEQ, Provider=$PROVIDER"
    done
}


# Helper functions
function log_info() {
    echo -e "\033[0;32m[INFO]\033[0m $1"
}

function log_warn() {
    echo -e "\033[0;33m[WARN]\033[0m $1"
}

function log_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

## more tools
# - closing lease: provider-services tx deployment close --dseq $AKASH_DSEQ  --owner $AKASH_ACCOUNT_ADDRESS --from $AKASH_KEY_NAME
# - updating lease: provider-services tx deployment update deploy.yml --dseq $AKASH_DSEQ --from $AKASH_KEY_NAME

## todo:
## automate cloudflare DNS api update
main
