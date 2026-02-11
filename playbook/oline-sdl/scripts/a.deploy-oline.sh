#!/usr/bin/env bash

## TODO
## - set min-gas-prices in provider services on install 
## - check current provider-service version with latest, update and install if not accurate
## - use test keyring-backend to avoid password

AKASH_KEY_NAME=test1
AKASH_KEYRING_BACKEND=os
AKASH_NET="https://raw.githubusercontent.com/akash-network/net/main/mainnet"
PROVIDER_REPO="https://github.com/akash-network/provider"
AKASH_VERSION="$(curl -s https://api.github.com/repos/akash-network/provider/releases/latest | jq -r '.tag_name')"
AKASH_CHAIN_ID=$(curl -s "$AKASH_NET/chain-id.txt")
AKASH_HOME="$HOME/.akash"
AKASH_CONFIG="$AKASH_HOME/config/app.toml"
export AKASH_CHAIN_ID
export AKASH_NODE="https://rpc-akash.ecostake.com:443"
export AKASH_GAS=auto
export AKASH_GAS_ADJUSTMENT=1.3
export AKASH_GAS_PRICES="0.0025uakt"
echo $AKASH_NODE "$AKASH_CHAIN_ID" "$AKASH_KEYRING_BACKEND" "$AKASH_HOME"

FLAGS="--keyring-backend $AKASH_KEYRING_BACKEND --home $AKASH_HOME"

PS="provider-services"


CURRENT_IP=$(curl -s https://api.ipify.org)DEFAULT_LOADABLE_BUILTINS_PATH
PRIVATE_VALIDATOR_ID=abc123xyz987@${CURRENT_IP}:26656

# service names 
SERVICES_ARRAY=(
    "oline-a-snapshot"
    "oline-a-seed"
    "oline-b-left"
    "oline-b-right"
    "oline-forward-left"
    "oline-forward-right"
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
    "sdls/b.left-and-right-tackle.yml"
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
declare -A DEPLOYMENTS=()
# Structure: DEPLOYMENTS[SDL_FILE]="dseq:oseq:gseq:provider"

function install_provider_services() {
    log_info "Installing akash-provider-services..."

    local os_name=$(uname -s | tr '[:upper:]' '[:lower:]')

    if [[ "$os_name" == "darwin" ]]; then
        # macOS: Install via Homebrew
        log_info "Detected macOS. Installing via Homebrew..."
        brew untap ovrclk/tap 2>/dev/null || true
        brew tap akash-network/tap
        brew install akash-provider-services

    elif [[ "$os_name" == "linux" ]]; then
        # Linux: Build from source
        log_info "Detected Linux. Building from source..."

        # Ensure Go is installed
        if ! command -v go &> /dev/null; then
            log_error "Go is not installed. Please install Go >= 1.21"
            exit 1
        fi

        local go_path="${GOPATH:-$HOME/go}"
        local provider_dir="$go_path/src/github.com/akash-network/provider"

        # Clone or update repo
        if [[ -d "$provider_dir" ]]; then
            cd "$provider_dir" || { log_error "Failed to enter $provider_dir"; exit 1; }
            git fetch --all
        else
            mkdir -p "$provider_dir"
            git clone $PROVIDER_REPO "$provider_dir"
            cd "$provider_dir" || { log_error "Failed to enter $provider_dir"; exit 1; }
        fi


        log_info "Checking out Akash provider version: $AKASH_VERSION"
        git checkout "v$AKASH_VERSION" || { log_error "Failed to checkout v$AKASH_VERSION"; exit 1; }

        # Build and install
        make deps-install
        make install

        log_info "Provider services installed successfully."
    else
        log_error "Unsupported OS: $os_name"
        exit 1
    fi

    # Verify installation
    if ! command -v $PS &> /dev/null; then
        log_error "provider-services binary not found in PATH after installation."
        exit 1
    fi

    log_info "$PS version: $($PS version)"
}

function check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check for provider-services
    if ! command -v $PS &> /dev/null; then
        install_provider_services
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

    # Minimum gas prices update
    perl -i -pe 's/minimum-gas-prices = ""/minimum-gas-prices = "0.0025uakt"/' "$AKASH_CONFIG"
    SOCK_CHECK=$($PS keys list $AKASH_KEY_NAME --output json)
    if [ "$SOCK_CHECK" = "[]" ]; then
        log_info "No key found with name '$AKASH_KEY_NAME', creating key..."
        $PS keys add $AKASH_KEY_NAME
    else
        log_info "Key '$AKASH_KEY_NAME' already exists."
    fi
    
    # Set account address
    AKASH_ACCOUNT_ADDRESS=$($PS keys show $AKASH_KEY_NAME -a)
    log_info "Using account address: $AKASH_ACCOUNT_ADDRESS"
    
    ## confirm balance exists 
    log_info "Checking account balance..."
    BALANCE_CHECK=$($PS query bank balances --node $AKASH_NODE "$AKASH_ACCOUNT_ADDRESS" -o json)
    
    AKT_BALANCE=$(echo "$BALANCE_CHECK" | jq -r '.balances[] | select(.denom == "uakt") | .amount // "0"')
    if [ -z "$AKT_BALANCE" ]; then AKT_BALANCE="0"; fi
    
    if [ "$AKT_BALANCE" -gt 0 ]; then
        log_info "Account $AKASH_ACCOUNT_ADDRESS has $AKT_BALANCE uakt."
    else
        log_error "Account $AKASH_ACCOUNT_ADDRESS has no uakt. Please fund your account before proceeding."
        exit 1
    fi
}
 
 
## 2. Create Certificate
function setup_certificate() {
    log_info "Setting up certificate..."
    
    # Check if certificate already exists
    CERT_CHECK=$($PS query cert list --owner $AKASH_ACCOUNT_ADDRESS --node $AKASH_NODE -o json)
    CERT_COUNT=$(echo "$CERT_CHECK" | jq -r '.certificates | length')
    
    if [ "$CERT_COUNT" -gt 0 ]; then
        log_info "Certificate already exists."
    else
        log_info "Generating new certificate..."
        $PS tx cert generate client --from $AKASH_KEY_NAME

        log_info "Publishing certificate..."
        $PS tx cert publish client --from $AKASH_KEY_NAME --fees 5000uakt
    fi
}
 
function check_existing_deployments() {
  log_info "Checking for existing deployments..."
  
  # Query deployments
  local deployments_json
  deployments_json=$($PS query deployment list --owner "$AKASH_ACCOUNT_ADDRESS" --state active --output json) || {
    log_error "Failed to query deployments"
    return 1
  }

  # Use jq to extract fields safely; handle both direct array and paginated responses
  local dseqs=()
  local created_ats=()
  local states=()
  local jq_output

    jq_output=$(echo "$deployments_json" | jq -r '
        .deployments[]?.deployment |
        "\(.deployment_id.dseq)//\(.deployment_header.created_at)//\(.deployment_header.state)"
    ')

  # Extract all dseqs, created_at, and state using jq, flatten if necessary
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        dseqs+=( "${line%%//*}" )
        local rest="${line#*//}"
        created_ats+=( "${rest%%//*}" )
        rest="${rest#*//}"
        states+=( "$rest" )
    done <<< "$jq_output"
  # Check if any deployments found
  if [[ ${#dseqs[@]} -eq 0 ]]; then
    log_info "No existing deployments found. Continuing..."
    return 0
  fi

  log_info "Found ${#dseqs[@]} existing deployment(s):"

  # Display menu
  local idx=0
  for dseq in "${dseqs[@]}"; do
    printf "%3s. DSEQ=%s | Created=%s | State=%s\n" "$((idx+1))" "$dseq" "${created_ats[$idx]}" "${states[$idx]}"
    ((idx++))
  done

  echo
  echo "Select deployment(s) to close (e.g. 1,3 or 1-3 or all), or press Enter to skip:"
  read -r choices

  # If no input, skip
  if [[ -z "$choices" ]]; then
    log_info "No deployments selected for closure. Continuing..."
    return 0
  fi

  # Normalize and process selections
  local to_close=()
  if [[ "$choices" == "all" ]]; then
    to_close=("${dseqs[@]}")
  else
    # Support ranges (1-3) and commas (1,3,5)
    IFS=',' read -ra parts <<< "$choices"
    for part in "${parts[@]}"; do
      if [[ "$part" =~ ^[0-9]+-[0-9]+$ ]]; then
        # Range like 1-3
        IFS='-' read -ra range <<< "$part"
        local start=${range[0]}
        local end=${range[1]}
        for ((i=start; i<=end; i++)); do
          local array_idx=$((i - 1))
          if [[ $array_idx -ge 0 && $array_idx -lt ${#dseqs[@]} ]]; then
            to_close+=("${dseqs[$array_idx]}")
          else
            log_error "Invalid selection: $i (out of range)"
          fi
        done
      elif [[ "$part" =~ ^[0-9]+$ ]]; then
        # Single number
        local array_idx=$((part - 1))
        if [[ $array_idx -ge 0 && $array_idx -lt ${#dseqs[@]} ]]; then
          to_close+=("${dseqs[$array_idx]}")
        else
          log_error "Invalid selection: $part (out of range)"
        fi
      else
        log_error "Invalid input format: $part"
        return 1
      fi
    done
  fi

  # Remove duplicates
  readarray -t to_close <<< "$(printf '%s\n' "${to_close[@]}" | sort -u)"

  # Close selected deployments
  for dseq in "${to_close[@]}"; do
    log_info "Closing deployment DSEQ=$dseq"
    $PS tx deployment close --dseq "$dseq" --owner "$AKASH_ACCOUNT_ADDRESS" --from "$AKASH_KEY_NAME" --gas auto --gas-adjustment 1.3 --fees 10000uakt \
      -y || {
        log_error "Failed to close DSEQ $dseq"
        continue
      }
    log_info "Closed DSEQ $dseq"
    sleep 6
  done

  log_info "Resuming deployment process..."
}


function wait_for_bids() {
    local dseq=$1
    local owner=$2
    local max_attempts=12
    local wait_time=5
    
    for ((attempt=1; attempt<=max_attempts; attempt++)); do
        local bids_output=$($PS query market bid list --owner=$owner --node $AKASH_NODE --dseq $dseq --state=open -o json)
        local bid_count=$(echo "$bids_output" | jq -r '.bids | length')
        
        if [ "$bid_count" -gt 0 ]; then
            log_info "Received $bid_count bids after $attempt attempts"
            return 0
        fi
        
        log_info "Attempt $attempt/$max_attempts: No bids yet, waiting ${wait_time}s..."
        sleep $wait_time
    done
    
    log_warn "No bids received after $max_attempts attempts"
    return 1
}



function deploy_sdl() {
    STEP=$1
    SDL_FILE=$2
    log_info "Deploying SDL: $SDL_FILE"

    # set snapshot to occur 10 mins from deployment
    if [[ "$STEP" == 1 ]]; then
    SNAPSHOT_TIME=$(printf '%(%H:%M:%S)T' "$(($(date +%s) + 600))")
    yq e ".services.oline-a-snapshot.env[] |= sub(\"^SNAPSHOT_TIME=.*\", \"SNAPSHOT_TIME=$SNAPSHOT_TIME\")" -i "$SDL_FILE"
    fi

    log_info "Creating deployment..."
    DEPLOY_OUTPUT=$($PS tx deployment create "$SDL_FILE" --from $AKASH_KEY_NAME --fees 5000uakt -y --output json)
    sleep 7

    # Parse deployment info
    AKASH_DSEQ=$(echo "$DEPLOY_OUTPUT" | jq -r '.logs[0].events[] | select(.type == "akash.v1") | .attributes[] | select(.key == "dseq") | .value| gsub("\\s+"; "")' | head -n1)
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
    wait_for_bids "$AKASH_DSEQ" "$AKASH_ACCOUNT_ADDRESS"
    
    # Get bids
    log_info "Fetching bids..."
    BIDS_OUTPUT=$($PS query market bid list --owner=$AKASH_ACCOUNT_ADDRESS --node $AKASH_NODE --dseq $AKASH_DSEQ --state=open -o json)
    
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
        
        if [ -n "$PROVIDER_PRICE" ] && [ "$PROVIDER_PRICE" != "null" ]; then
            log_info "Found bid from trusted provider $PROVIDER: $PROVIDER_PRICE uakt"
            # Compare PROVIDER_PRICE and LOWEST_PRICE using bc
            if bc -l <<< "$PROVIDER_PRICE < $LOWEST_PRICE"; then
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
    LEASE_OUTPUT=$($PS tx market lease create --dseq "$AKASH_DSEQ" --provider "$LOWEST_PROVIDER" --from $AKASH_KEY_NAME --fees 5000uakt --gas 1000000 --gas-adjustment 1.3  --fees 25000uakt -y --output json)
    sleep 10

    #### verify lease was created 
    log_info "Verifying lease..."
    LEASE_CHECK=$($PS query market lease list --owner "$AKASH_ACCOUNT_ADDRESS" --node $AKASH_NODE --dseq "$AKASH_DSEQ" -o json)
    LEASE_STATE=$(echo "$LEASE_CHECK" | jq -r ".leases[0].lease.state")
    
    if [ "$LEASE_STATE" != "active" ]; then
        log_error "Lease is not active, current state: $LEASE_STATE"
        exit 1
    fi

    log_info "Lease created successfully!"

    ## 3.d Send Manifest To Provider
    log_info "Sending manifest to provider..."
    MANIFEST_OUTPUT=$($PS send-manifest "$SDL_FILE" --dseq "$AKASH_DSEQ" --provider "$LOWEST_PROVIDER" --from $AKASH_KEY_NAME)
    
    log_info "Manifest sent, waiting for deployment to be ready..."
    sleep 30

    ## 4. Confirm the URL & obtain DNS for deployments 
    log_info "Checking lease status..."
    STATUS_OUTPUT=$($PS lease-status --dseq "$AKASH_DSEQ" --from $AKASH_KEY_NAME --provider "$LOWEST_PROVIDER")
    log_info "lease status: $STATUS_OUTPUT"

    ## Collect DNS URI:
    if [[ "$STEP" == 1 ]]; then
    # Kickoff deployment - extract snapshot and seed node URIs
    get_node_peer_id "${SERVICES_ARRAY[0]}" "SNAPSHOT_NODE_PEER_ID"
    get_node_peer_id "${SERVICES_ARRAY[1]}" "SEED_NODE_PEER_ID"

        
    elif [[ "$STEP" == 2 ]]; then
    # Tackles deployment - extract both sentry nodes URIs 
    get_node_peer_id "${SERVICES_ARRAY[2]}" "LEFT_TACKLE_PEER_ID"
    get_node_peer_id "${SERVICES_ARRAY[3]}" "RIGHT_TACKLE_PEER_ID"

    elif [[ "$STEP" == 3 ]]; then
    # Forwards deployment - extract both forward public nodes URIs
    get_node_peer_id "${SERVICES_ARRAY[4]}" "LEFT_FORWARD_PEER_ID"
    get_node_peer_id "${SERVICES_ARRAY[5]}" "RIGHT_FORWARD_PEER_ID"
    else
    log_error "Invalid step number: $STEP. Expected values are 1, 2, or 3."
    exit 1
    fi

    # Store deployment info
    DEPLOYMENTS["$SDL_FILE"]="$AKASH_DSEQ:$AKASH_OSEQ:$AKASH_GSEQ:$LOWEST_PROVIDER"
    log_info "Deployment of $SDL_FILE completed successfully!"
    return 0    
}


# Reusable function to get peer ID via RPC /status
get_node_peer_id() {
    local service_name=$1
    local env_var_name=$2

    # Try to get URI from service first
    uri=$(echo "$STATUS_OUTPUT" | jq -r ".services.\"$service_name\".uris[0]")
    if [[ -n "$uri" && "$uri" != "null" ]]; then
        uri="http://${uri}:26657"
    else
        # Fallback: use forwarded_ports (find the first TCP port mapped to 26657)
        local forward_entry=$(echo "$STATUS_OUTPUT" | jq -r ".forwarded_ports.\"$service_name\"[] | select(.port == 26657) | .host + \":\" + (.externalPort | tostring)")
        if [[ -z "$forward_entry" || "$forward_entry" == "null" ]]; then
            log_error "Could not retrieve URI or forwarded port for service: $service_name"
            log_error "STATUS_OUTPUT: $STATUS_OUTPUT"
            exit 1
        fi
        uri="http://${forward_entry}"
    fi

    log_info "Using node info $uri..."
    log_info "retriving node-id for '$service_name' from endpoint '$uri' ..."


    # Retry loop for RPC status
    local status_response
    local node_id=""
    local retries=6
  # Step 2: Retry loop to query /status
    for ((i = 1; i <= retries; i++)); do
        # If we have a forward_entry, try both http/https
        if [[ -n "$forward_entry" ]]; then
            for scheme in http https; do
                peer_url="${scheme}://${forward_entry}"
                status_response=$(curl -s -m 5 "${peer_url}/status" || echo "")
                node_id=$(echo "$status_response" | jq -r '.result?.node_info?.id // empty')

                if [[ -n "$node_id" ]]; then
                    # Success: use 443 for HTTPS, 26656 for P2P (but RPC is 26657 → we map to 443 for peer URL)
                    peer_url="${node_id}@${forward_entry%:*}:443"
                    echo "$env_var_name=$peer_url" >> deployment_uris.env
                    log_info "Retrieved $env_var_name=$peer_url"
                    return 0
                fi
            done
        else
            # Try current uri (https first, then fallback below)
            status_response=$(curl -s -m 5 "${uri}/status")
            node_id=$(echo "$status_response" | jq -r '.result?.node_info?.id // empty')

            if [[ -n "$node_id" ]]; then
                # Format as peer@host:443 (standard for seeds)
                peer_url="${node_id}@${uri#https://}:443"
                echo "$env_var_name=$peer_url" >> deployment_uris.env
                log_info "Retrieved $env_var_name=$peer_url"
                return 0
            fi
        fi

        # Back off before retry
        sleep_seconds=$((i * 2))
        log_info "Attempt $i failed, retrying in ${sleep_seconds}s..."
        sleep $sleep_seconds
    done

    # Final failure
    log_error "Failed to retrieve node_info.id from $uri after $retries attempts"
    echo "$status_response" >&2
    exit 1
}



function update_sdl_with_node_info() {
    STEP=$1
    local target_sdl=${2:-"${SDL_FILES[$STEP]}"}
    
    log_info "Updating $target_sdl with node info for step $STEP..."

    # Source the saved URIs
    if [ -f "deployment_uris.env" ]; then
        # shellcheck source=/dev/null
        source deployment_uris.env
    else
        log_error "deployment_uris.env file not found!"
        exit 1
    fi

    # Rest of the function remains the same
    if [[ "$STEP" == 1 ]]; then
        # Set snapshot as persistent peer 
        yq e ".services.*.env.TERPD_P2P_PERSISTENT_PEERS = \"$SNAPSHOT_NODE_PEER_ID\"" -i "${SDL_FILES[1]}"
        # Set validator as private peers
        # Define PRIVATE_PEER_IDS if not already defined
        PRIVATE_PEER_IDS=${PRIVATE_VALIDATOR_ID}
        yq e ".services.*.env.TERPD_P2P_PRIVATE_PEER_IDS = \"$PRIVATE_PEER_IDS\"" -i "${SDL_FILES[1]}"
        yq e ".services.*.env.TERPD_P2P_UNCONDITIONAL_PEER_IDS = \"$PRIVATE_PEER_IDS\"" -i "${SDL_FILES[1]}"
    elif [[ "$STEP" == 2 ]]; then
        # Set snapshot as persistent peer
        yq e ".services.*.env.TERPD_P2P_PERSISTENT_PEERS = \"$SNAPSHOT_NODE_PEER_ID\"" -i "${SDL_FILES[2]}"
        # Set l/r tackles as private peers 
        yq e ".services.*.env.TERPD_P2P_PRIVATE_PEER_IDS = \"$LEFT_TACKLE_PEER_ID,$RIGHT_TACKLE_PEER_ID\"" -i "${SDL_FILES[2]}"
        yq e ".services.*.env.TERPD_P2P_UNCONDITIONAL_PEER_IDS = \"$LEFT_TACKLE_PEER_ID,$RIGHT_TACKLE_PEER_ID\"" -i "${SDL_FILES[2]}"
    else
        log_error "Unsupported step number: $STEP"
        exit 1
    fi

    log_info "Updated $target_sdl with node info successfully"
}



function save_node_info() {
    local key=$1
    local value=$2
    
    # Check if file exists
    if [ ! -f "deployment_uris.env" ]; then
        touch deployment_uris.env
    fi
    
    # Check if key already exists
    if grep -q "^$key=" deployment_uris.env; then
        # Update existing key
        sed -i "s/^$key=.*/$key=$value/" deployment_uris.env
    else
        # Append new key
        echo "$key=$value" >> deployment_uris.env
    fi
}

# Main execution flow
function main() {
    log_info "Starting Akash deployment process..."

    ## 1. Setup
    check_dependencies
    setup_keys
    setup_certificate
    check_existing_deployments

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
        
        log_info "SDL_FILE=$SDL_FILE: DSEQ=$DSEQ, Provider=$PROVIDER"
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
main

## more tools
# - closing lease: $PS tx deployment close --dseq $AKASH_DSEQ  --owner $AKASH_ACCOUNT_ADDRESS --from $AKASH_KEY_NAME
# - updating lease: $PS tx deployment update deploy.yml --dseq $AKASH_DSEQ --from $AKASH_KEY_NAME

## todo:
## automate cloudflare DNS api update
# function update_cloudflare_dns() {
#     local dns_name=$1
#     local target_ip=$2
#     local cf_email=${CLOUDFLARE_EMAIL:-""}
#     local cf_api_key=${CLOUDFLARE_API_KEY:-""}
#     local cf_zone_id=${CLOUDFLARE_ZONE_ID:-""}
    
#     # Check if Cloudflare credentials are set
#     if [[ -z "$cf_email" || -z "$cf_api_key" || -z "$cf_zone_id" ]]; then
#         log_warn "Cloudflare credentials not set. Skipping DNS update."
#         log_warn "Set CLOUDFLARE_EMAIL, CLOUDFLARE_API_KEY, and CLOUDFLARE_ZONE_ID environment variables to enable."
#         return 1
#     fi
    
#     log_info "Updating Cloudflare DNS: $dns_name -> $target_ip"
    
#     # First, get the record ID if it exists
#     record_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$cf_zone_id/dns_records?type=A&name=$dns_name" \
#         -H "X-Auth-Email: $cf_email" \
#         -H "X-Auth-Key: $cf_api_key" \
#         -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
    
#     if [[ -n "$record_id" ]]; then
#         # Update existing record
#         update_response=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$cf_zone_id/dns_records/$record_id" \
#             -H "X-Auth-Email: $cf_email" \
#             -H "X-Auth-Key: $cf_api_key" \
#             -H "Content-Type: application/json" \
#             --data "{\"type\":\"A\",\"name\":\"$dns_name\",\"content\":\"$target_ip\",\"ttl\":120,\"proxied\":false}")
            
#         success=$(echo "$update_response" | jq -r '.success')
#         if [[ "$success" == "true" ]]; then
#             log_info "DNS record updated successfully: $dns_name -> $target_ip"
#         else
#             error=$(echo "$update_response" | jq -r '.errors[0].message')
#             log_error "Failed to update DNS record: $error"
#         fi
#     else
#         # Create new record
#         create_response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$cf_zone_id/dns_records" \
#             -H "X-Auth-Email: $cf_email" \
#             -H "X-Auth-Key: $cf_api_key" \
#             -H "Content-Type: application/json" \
#             --data "{\"type\":\"A\",\"name\":\"$dns_name\",\"content\":\"$target_ip\",\"ttl\":120,\"proxied\":false}")
            
#         success=$(echo "$create_response" | jq -r '.success')
#         if [[ "$success" == "true" ]]; then
#             log_info "DNS record created successfully: $dns_name -> $target_ip"
#         else
#             error=$(echo "$create_response" | jq -r '.errors[0].message')
#             log_error "Failed to create DNS record: $error"
#         fi
#     fi
# }