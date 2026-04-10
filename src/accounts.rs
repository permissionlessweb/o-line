/// HD key derivation helpers for parallel deployment.
///
/// Child accounts are derived at BIP44 `m/44'/118'/0'/0/{index}` from the
/// master mnemonic.  In v1, all deployments still use the master account since
/// `AkashClient` bundles connection + signer and can only be constructed from a
/// mnemonic.  Future work: expose `AkashClient::new_with_signer` upstream or
/// add per-unit mnemonic support to `OLineConfig`.
use akash_deploy_rs::{DeployError, KeySigner};
use bech32::{ToBase32, Variant};
use bip32::DerivationPath;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::str::FromStr;

/// Derive a child `KeySigner` at BIP44 `m/44'/118'/0'/0/{index}`.
///
/// Returns a signer whose signing key corresponds to the Nth HD child account.
/// All N signers are derived locally (no network) from a single mnemonic, which
/// enables batch signing workflows where multiple accounts share one broadcast
/// pipeline rather than instantiating a separate client per account.
pub fn derive_child_signer(mnemonic: &str, index: u32) -> Result<KeySigner, DeployError> {
    let path = DerivationPath::from_str(&format!("m/44'/118'/0'/0/{}", index))
        .map_err(|e| DeployError::Signer(format!("Invalid derivation path: {}", e)))?;
    KeySigner::new_mnemonic_str(mnemonic, Some(&path))
        .map_err(|e| DeployError::Signer(format!("Failed to derive child signer {}: {}", index, e)))
}

/// Derive the bech32 Cosmos address for a `KeySigner`.
///
/// Uses the standard Cosmos address derivation:
///   compressed_pubkey(33 bytes) → SHA256 → RIPEMD160(20 bytes) → bech32(prefix)
///
/// This matches the derivation used by the Cosmos SDK and `terpd keys add`.
pub fn child_address(signer: &KeySigner, prefix: &str) -> String {
    // bip32::XPrv::public_key() → XPub::to_bytes() → [u8; 33] compressed secp256k1
    let pub_bytes = signer.key.public_key().to_bytes();
    let sha256 = Sha256::digest(pub_bytes);
    let ripemd = Ripemd160::digest(sha256);
    bech32::encode(prefix, ripemd.to_base32(), Variant::Bech32)
        .expect("bech32 encoding should never fail for valid prefix")
}

/// Derive the bech32 address for HD index `index` directly from a mnemonic string.
///
/// Convenience wrapper around [`derive_child_signer`] + [`child_address`].
pub fn child_address_str(
    mnemonic: &str,
    index: u32,
    prefix: &str,
) -> Result<String, akash_deploy_rs::DeployError> {
    let signer = derive_child_signer(mnemonic, index)?;
    Ok(child_address(&signer, prefix))
}
