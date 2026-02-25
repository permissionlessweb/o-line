//! core cli commands

use std::{
    error::Error,
    io::{self, Write},
};

use crate::{
    config::{days_to_date, read_encrypted_mnemonic_from_env},
    crypto::decrypt_mnemonic,
    FIELD_DESCRIPTORS,
};

// ── Secret redaction ──
pub fn redact_if_secret(env_var: &str, value: &str) -> String {
    let is_secret = FIELD_DESCRIPTORS
        .iter()
        .find(|fd| fd.ev == env_var)
        .map(|fd| fd.s)
        .unwrap_or(false);

    if is_secret {
        if value.len() <= 4 {
            "****".to_string()
        } else {
            format!("{}...{}", &value[..2], &value[value.len() - 2..])
        }
    } else {
        value.to_string()
    }
}

// ── Interactive helpers ──
pub fn prompt_continue(
    lines: &mut io::Lines<io::StdinLock<'_>>,
    question: &str,
) -> Result<bool, io::Error> {
    print!("  {} [Y/n]: ", question);
    io::stdout().flush()?;
    let answer = lines.next().unwrap_or(Ok(String::new()))?;
    let answer = answer.trim().to_lowercase();
    Ok(answer.is_empty() || answer == "y" || answer == "yes")
}

pub fn read_input(
    lines: &mut io::Lines<io::StdinLock<'_>>,
    prompt: &str,
    default: Option<&str>,
) -> Result<String, io::Error> {
    if let Some(def) = default {
        // Show default as a dim placeholder on the input line
        tracing::info!("  {}", prompt);
        print!("  \x1b[2m{}\x1b[0m > ", def);
    } else {
        print!("  {}: ", prompt);
    }
    io::stdout().flush()?;
    let input = lines.next().unwrap_or(Ok(String::new()))?;
    let input = input.trim().to_string();
    if input.is_empty() {
        if let Some(def) = default {
            return Ok(def.to_string());
        }
    }
    Ok(input)
}

/// Like `read_input` but hides the typed value (for secrets).
pub fn read_secret_input(prompt: &str, default: Option<&str>) -> Result<String, Box<dyn Error>> {
    let display = if let Some(def) = default {
        // Show prompt, then placeholder hint (rpassword hides typed input)
        tracing::info!("  {}", prompt);
        format!("  \x1b[2m{}\x1b[0m > ", def)
    } else {
        format!("  {}: ", prompt)
    };
    let input = rpassword::prompt_password(&display)?;
    let input = input.trim().to_string();
    if input.is_empty() {
        if let Some(def) = default {
            return Ok(def.to_string());
        }
    }
    Ok(input)
}

pub fn prompt_s3_creds(
    lines: &mut io::Lines<io::StdinLock<'_>>,
) -> Result<(String, String, String, String), Box<dyn Error>> {
    let s3_key = read_secret_input("S3 access key", None)?;
    let s3_secret = read_secret_input("S3 secret key", None)?;
    let s3_host = read_input(lines, "S3 host", Some("https://s3.filebase.com"))?;
    let snapshot_path = read_input(
        lines,
        "S3 snapshot path (bucket/path)",
        Some("snapshots/terpnetwork"),
    )?;
    Ok((s3_key, s3_secret, s3_host, snapshot_path))
}

pub fn urlencoded(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

pub fn unlock_mnemonic() -> Result<(String, String), Box<dyn Error>> {
    let blob = read_encrypted_mnemonic_from_env()?;
    let password = rpassword::prompt_password("Enter password: ")?;
    let mnemonic = decrypt_mnemonic(&blob, &password)?;
    tracing::info!("Mnemonic decrypted successfully.\n");
    Ok((mnemonic, password))
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}
pub fn chrono_format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "-".to_string();
    }
    // Simple UTC timestamp formatting without chrono dependency
    let secs = ts;
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let mins = (rem % 3600) / 60;

    // Rough date from epoch (good enough for display)
    // 1970-01-01 + days
    let (year, month, day) = days_to_date(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}Z",
        year, month, day, hours, mins
    )
}
