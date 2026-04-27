//! `oline authz` — manage AuthZ + FeeGrant delegation for passwordless deployments.

use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use akash_deploy_rs::{
    authz_msg_type_urls, broadcast_multi_signer, build_authz_grant_msgs,
    build_authz_revoke_msgs, build_feegrant_msg, build_feegrant_revoke_msg,
    AkashClient, AuthzConfig, KeySigner, SignerEntry,
};
use clap::Subcommand;

use crate::accounts::child_address;
use crate::authz::{
    generate_deployer_mnemonic, has_authz_setup, load_authz_state, load_deployer_mnemonic,
    remove_authz_files, save_authz_state, write_deployer_key,
};
use crate::cli::unlock_mnemonic;
use crate::config::build_config_from_env;

#[derive(clap::Args, Debug)]
pub struct AuthzArgs {
    #[command(subcommand)]
    pub command: AuthzSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum AuthzSubcommand {
    /// One-time setup: generate deployer wallet, broadcast AuthZ + FeeGrant grants
    Setup {
        /// Grant expiration in days (default: 365)
        #[arg(long, default_value_t = 365)]
        expiration_days: u32,
        /// Fee spend limit in uAKT (default: 10_000_000 = 10 AKT)
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
        /// Re-broadcast grants even if they already exist on-chain
        #[arg(long)]
        renew: bool,
    },
    /// Query on-chain grant status
    Status,
    /// Revoke all grants and remove deployer key
    Revoke,
}

pub async fn cmd_authz(
    args: &AuthzArgs,
    profile: &str,
) -> Result<(), Box<dyn Error>> {
    match &args.command {
        AuthzSubcommand::Setup {
            expiration_days,
            fee_limit,
            renew,
        } => cmd_authz_setup(profile, *expiration_days, *fee_limit, *renew).await,
        AuthzSubcommand::Status => cmd_authz_status().await,
        AuthzSubcommand::Revoke => cmd_authz_revoke(profile).await,
    }
}

async fn cmd_authz_setup(
    profile: &str,
    expiration_days: u32,
    fee_limit: u64,
    renew: bool,
) -> Result<(), Box<dyn Error>> {
    // If already configured and not renewing, reuse existing deployer
    let existing = load_authz_state();
    if has_authz_setup() && !renew {
        let state = existing.as_ref().unwrap();
        eprintln!("AuthZ delegation already configured.");
        eprintln!("  Granter: {}", state.granter_address);
        eprintln!("  Grantee: {}", state.grantee_address);
        eprintln!("Use --renew to re-broadcast grants with fresh expiration.");
        return Ok(());
    }

    // 1. Decrypt master mnemonic (password required this one time)
    eprintln!("=== AuthZ Setup{} ===", if renew { " (renew)" } else { "" });
    eprintln!("Decrypting master mnemonic (password required once)...");
    let (master_mnemonic, _password) = unlock_mnemonic()?;

    // 2. Build config and connect to chain
    let config = build_config_from_env(master_mnemonic.clone(), Some(profile));
    let rpc = config.val("OLINE_RPC_ENDPOINT");
    let grpc = config.val("OLINE_GRPC_ENDPOINT");

    let master_client = AkashClient::new_from_mnemonic(&master_mnemonic, &rpc, &grpc)
        .await
        .map_err(|e| format!("failed to connect with master wallet: {}", e))?;
    let granter_address = master_client.address();

    // 3. Deployer wallet: reuse existing if renewing, generate new otherwise
    let (deployer_mnemonic, grantee_address) = if renew {
        if let Some(ref state) = existing {
            let m = load_deployer_mnemonic()
                .map_err(|e| format!("cannot renew without existing deployer key: {}", e))?;
            eprintln!("Reusing existing deployer wallet for renewal.");
            (m, state.grantee_address.clone())
        } else {
            return Err("--renew requires an existing authz configuration".into());
        }
    } else {
        let m = generate_deployer_mnemonic();
        let signer = KeySigner::new_mnemonic_str(&m, None)
            .map_err(|e| format!("failed to create deployer signer: {}", e))?;
        let addr = child_address(&signer, "akash");
        (m, addr)
    };

    eprintln!("Granter (master):   {}", granter_address);
    eprintln!("Grantee (deployer): {}", grantee_address);

    // 4. Build and broadcast grant messages
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiration = now + (expiration_days as u64 * 86400);

    let mut all_msgs =
        build_authz_grant_msgs(&granter_address, &grantee_address, Some(expiration));
    let feegrant_msg = build_feegrant_msg(
        &granter_address,
        &grantee_address,
        Some(fee_limit),
        Some(expiration),
    );
    all_msgs.push(feegrant_msg);

    // Include 1 uAKT bank send to create grantee's on-chain account in the same tx.
    // Without this, the grantee account doesn't exist on-chain and tx simulation fails.
    if !renew {
        let dust_msg = akash_deploy_rs::build_bank_send_msg(
            &granter_address,
            &grantee_address,
            1,
            "uakt",
        );
        all_msgs.push(dust_msg);
    }

    let msg_count = all_msgs.len();
    eprintln!(
        "Broadcasting {} messages ({} AuthZ + 1 FeeGrant{})...",
        msg_count,
        authz_msg_type_urls().len(),
        if !renew { " + 1 account fund" } else { "" },
    );

    let master_signer = KeySigner::new_mnemonic_str(&master_mnemonic, None)
        .map_err(|e| format!("failed to create master signer: {}", e))?;

    let querier = &master_client.signing_client().querier;
    let chain_id = querier.chain_config.chain_id.as_str();

    let acct = querier
        .base_account(master_client.address_ref())
        .await
        .map_err(|e| format!("failed to query master account: {}", e))?;

    let result = broadcast_multi_signer(
        querier,
        chain_id,
        vec![SignerEntry {
            signer: &master_signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages: all_msgs,
        }],
        1.5,
        Duration::from_secs(60),
    )
    .await
    .map_err(|e| format!("grant tx failed: {}", e))?;

    eprintln!(
        "Grants confirmed: hash={}, height={}",
        result.hash, result.height
    );

    // 5. Save deployer key (unencrypted, 0600 permissions)
    let key_path = write_deployer_key(&deployer_mnemonic)?;
    eprintln!("Deployer key saved: {}", key_path.display());

    // 7. Save authz config metadata
    let authz_config = AuthzConfig {
        granter_address: granter_address.clone(),
        grantee_address: grantee_address.clone(),
        msg_types: authz_msg_type_urls(),
        expiration: Some(expiration),
        fee_spend_limit: Some(fee_limit),
        created_at: now,
    };
    save_authz_state(&authz_config)?;

    // 8. Summary
    eprintln!();
    eprintln!("=== AuthZ Setup Complete ===");
    eprintln!("Granter:     {}", granter_address);
    eprintln!("Grantee:     {}", grantee_address);
    eprintln!(
        "Expiration:  {} days ({} UTC)",
        expiration_days,
        chrono::DateTime::from_timestamp(expiration as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M")
    );
    eprintln!(
        "Fee limit:   {} uAKT ({:.2} AKT)",
        fee_limit,
        fee_limit as f64 / 1_000_000.0
    );
    eprintln!("Msg types:   {}", authz_config.msg_types.len());
    for url in &authz_config.msg_types {
        eprintln!("  - {}", url);
    }
    eprintln!();
    eprintln!("Deployments will now use the deployer wallet (no password required).");

    Ok(())
}

async fn cmd_authz_status() -> Result<(), Box<dyn Error>> {
    let state = match load_authz_state() {
        Some(s) => s,
        None => {
            eprintln!("No AuthZ delegation configured.");
            eprintln!("Run `oline authz setup` to create one.");
            return Ok(());
        }
    };

    eprintln!("=== AuthZ Delegation Status ===");
    eprintln!("Granter:  {}", state.granter_address);
    eprintln!("Grantee:  {}", state.grantee_address);

    if state.is_expired() {
        eprintln!("Status:   EXPIRED (use `oline authz setup --renew` to refresh)");
    } else {
        eprintln!("Status:   ACTIVE");
    }

    if let Some(exp) = state.expiration {
        let dt = chrono::DateTime::from_timestamp(exp as i64, 0).unwrap_or_default();
        eprintln!("Expires:  {} UTC", dt.format("%Y-%m-%d %H:%M"));
    } else {
        eprintln!("Expires:  never");
    }

    if let Some(limit) = state.fee_spend_limit {
        eprintln!(
            "Fee limit: {} uAKT ({:.2} AKT)",
            limit,
            limit as f64 / 1_000_000.0
        );
    }

    eprintln!("Msg types: {}", state.msg_types.len());
    for url in &state.msg_types {
        eprintln!("  - {}", url);
    }

    let has_key = crate::config::oline_deployer_key_path().exists();
    eprintln!(
        "Deployer key: {}",
        if has_key { "present" } else { "MISSING" }
    );

    Ok(())
}

async fn cmd_authz_revoke(profile: &str) -> Result<(), Box<dyn Error>> {
    let state = match load_authz_state() {
        Some(s) => s,
        None => {
            eprintln!("No AuthZ delegation configured. Nothing to revoke.");
            return Ok(());
        }
    };

    eprintln!("=== AuthZ Revoke ===");
    eprintln!("Decrypting master mnemonic to sign revocation...");
    let (master_mnemonic, _password) = unlock_mnemonic()?;

    let config = build_config_from_env(master_mnemonic.clone(), Some(profile));
    let rpc = config.val("OLINE_RPC_ENDPOINT");
    let grpc = config.val("OLINE_GRPC_ENDPOINT");

    let master_client = AkashClient::new_from_mnemonic(&master_mnemonic, &rpc, &grpc)
        .await
        .map_err(|e| format!("failed to connect with master wallet: {}", e))?;

    let mut all_msgs =
        build_authz_revoke_msgs(&state.granter_address, &state.grantee_address);
    let feegrant_revoke =
        build_feegrant_revoke_msg(&state.granter_address, &state.grantee_address);
    all_msgs.push(feegrant_revoke);

    let msg_count = all_msgs.len();
    eprintln!(
        "Broadcasting {} revoke messages ({} AuthZ + 1 FeeGrant)...",
        msg_count,
        msg_count - 1
    );

    let master_signer = KeySigner::new_mnemonic_str(&master_mnemonic, None)
        .map_err(|e| format!("failed to create master signer: {}", e))?;

    let querier = &master_client.signing_client().querier;
    let chain_id = querier.chain_config.chain_id.as_str();

    let acct = querier
        .base_account(master_client.address_ref())
        .await
        .map_err(|e| format!("failed to query master account: {}", e))?;

    let result = broadcast_multi_signer(
        querier,
        chain_id,
        vec![SignerEntry {
            signer: &master_signer,
            account_number: acct.account_number,
            sequence: acct.sequence,
            messages: all_msgs,
        }],
        1.5,
        Duration::from_secs(60),
    )
    .await;

    match result {
        Ok(tx) => {
            eprintln!("Tx confirmed: hash={}, height={}", tx.hash, tx.height);
        }
        Err(e) => {
            eprintln!("Warning: revoke tx failed: {}", e);
            eprintln!("Grants may already be expired or revoked.");
        }
    }

    remove_authz_files()?;
    eprintln!("Deployer key and authz config removed.");
    eprintln!("=== AuthZ Revoke Complete ===");

    Ok(())
}
