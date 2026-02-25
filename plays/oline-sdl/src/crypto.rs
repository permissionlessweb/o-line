use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use openssh::SessionBuilder;
use rand::RngCore;
use ssh_key::LineEnding;
use std::{error::Error, path::PathBuf};

pub const SALT_LEN: usize = 16; // AES-256-GCM fixed
pub const NONCE_LEN: usize = 12; // AES-256-GCM fixed
pub const S3_SECRET: usize = 40;
pub const S3_KEY: usize = 24;

pub fn gen_ssh_key() -> ssh_key::PrivateKey {
    use ssh_key::rand_core::OsRng;
    ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap()
}
pub fn save_ssh_key(k: ssh_key::PrivateKey, path: PathBuf) {
    let k = k.to_openssh(LineEnding::LF).unwrap();
    std::fs::write(&path, k).expect("Failed to save SSH private key");
}
// forms ssh://[user@]hostname[:port] from deployment
pub fn ssh_dest_path(ssh_port: &str, uri: &str) -> String {
    format!("{}@{}:{}", "root", uri, ssh_port)
}

/// sends reusable wildcard cert & privkey to node
pub async fn send_cert_sftp(
    dest: &str,
    cert: &Vec<u8>,
    privkey: &Vec<u8>,
    ssh_path: &PathBuf,
) -> Result<(), Box<dyn Error>> {
    use openssh_sftp_client::Sftp;
    // define ssh key to use for session
    let sftp = Sftp::from_session(
        SessionBuilder::default()
            .keyfile(ssh_path)
            .connect_mux(dest)
            .await?,
        Default::default(),
    )
    .await?;
    let path = PathBuf::new();

    // write cert to node
    sftp.options()
        .write(true)
        .create_new(true)
        .open(&path)
        .await?
        .write(&cert)
        .await?;
    // write privkey to node
    sftp.options()
        .write(true)
        .create_new(true)
        .open(&path)
        .await?
        .write(&privkey)
        .await?;

    // return pubkey
    Ok(())
}

/// Generate a random alphanumeric credential string of the given length.
pub fn generate_credential(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

pub fn encrypt_mnemonic(mnemonic: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let mut salt = [0u8; SALT_LEN];
    let mut key = [0u8; 32];

    rand::thread_rng().fill_bytes(&mut salt);
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Failed to create cipher: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, mnemonic.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&blob))
}

pub fn decrypt_mnemonic(encrypted_b64: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let blob = BASE64
        .decode(encrypted_b64)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    if blob.len() < SALT_LEN + NONCE_LEN + 1 {
        return Err("Encrypted data too short".into());
    }

    let (salt, nonce_bytes, ciphertext) = (
        &blob[..SALT_LEN],
        &blob[SALT_LEN..SALT_LEN + NONCE_LEN],
        &blob[SALT_LEN + NONCE_LEN..],
    );

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Failed to create cipher: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed — wrong password or corrupted data")?;

    String::from_utf8(plaintext)
        .map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e).into())
}
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hex::encode(hash)
}
