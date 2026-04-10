/// HD session management for parallel deployments.
///
/// Tracks funding strategy, derived accounts, and per-phase deployment state
/// across the lifecycle of a multi-node deploy.
///
/// Storage layout:
/// ```text
/// ~/.oline/sessions/
///   oline-20260310-abc123/
///     session.json
/// ```
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

/// How deployment accounts are funded — expandable enum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum FundingMethod {
    /// Use master mnemonic account directly (backward compatible).
    Master,
    /// Derive N child accounts at BIP44 m/44'/118'/0'/0/{index}.
    /// Fund each child from master via bank_send.
    HdDerived {
        count: u32,
        amount_per_child: u64,
        act_amount_per_child: u64,
    },
    /// Deploy all units from the master account in a single batch tx.
    /// No child account derivation or funding — all MsgCreateDeployment
    /// messages are signed by the master signer in one transaction.
    /// Lease creation is sequential (each tx increments sequence).
    Direct,
}

impl FundingMethod {
    /// Parse from env var `OLINE_FUNDING_METHOD`.
    ///
    /// - `"master"` or unset → `Master`
    /// - `"hd:<count>:<amount>"` → `HdDerived { count, amount_per_child }`
    pub fn from_env() -> Self {
        let val = std::env::var("OLINE_FUNDING_METHOD").unwrap_or_default();
        Self::parse(&val)
    }

    /// Parse a funding method string.
    pub fn parse(s: &str) -> Self {
        let s = s.trim().to_lowercase();
        if s == "direct" {
            return FundingMethod::Direct;
        }
        if s.starts_with("hd:") {
            let parts: Vec<&str> = s.splitn(4, ':').collect();
            if parts.len() >= 3 {
                if let (Ok(count), Ok(amount)) = (parts[1].parse(), parts[2].parse()) {
                    let act_amount = if parts.len() == 4 {
                        parts[3].parse().unwrap_or(amount)
                    } else {
                        amount // backward compatible: same as AKT amount
                    };
                    return FundingMethod::HdDerived {
                        count,
                        amount_per_child: amount,
                        act_amount_per_child: act_amount,
                    };
                }
            }
        }
        FundingMethod::Master
    }
}

/// A funded HD-derived account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntry {
    pub hd_index: u32,
    pub address: String,
    pub funded: bool,
    pub funded_amount: u64,
    #[serde(default)]
    pub act_funded_amount: u64,
    pub assigned_to: Option<String>,
}

/// A recorded deployment within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentEntry {
    pub phase: String,
    pub dseq: u64,
    pub account_index: u32,
    pub label: String,
    pub provider: Option<String>,
    pub endpoints: Vec<String>,
}

/// Session state for a deployment run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OLineSession {
    pub id: String,
    pub funding: FundingMethod,
    pub master_address: String,
    pub chain_id: String,
    pub accounts: Vec<AccountEntry>,
    pub deployments: Vec<DeploymentEntry>,
    pub ssh_key_path: String,
    pub created_at: u64,
    pub updated_at: u64,
}

impl OLineSession {
    /// Create a new session with a unique timestamp-based ID.
    pub fn new(funding: FundingMethod, master_address: &str, chain_id: &str) -> Self {
        let now = now_secs();
        let hex = format!("{:x}", now);
        let short_id = &hex[..6.min(hex.len())];
        let id = format!("oline-{}-{}", date_stamp(now), short_id);
        Self {
            id,
            funding,
            master_address: master_address.to_string(),
            chain_id: chain_id.to_string(),
            accounts: Vec::new(),
            deployments: Vec::new(),
            ssh_key_path: String::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Touch the `updated_at` timestamp.
    pub fn touch(&mut self) {
        self.updated_at = now_secs();
    }
}

/// File-backed session store under `~/.oline/sessions/`.
pub struct OLineSessionStore {
    base_dir: PathBuf,
}

impl OLineSessionStore {
    /// Create a store at the default location (`~/.oline/sessions/`).
    pub fn new() -> Self {
        let base = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".oline")
            .join("sessions");
        Self { base_dir: base }
    }

    /// Create a store at a custom base directory (useful for tests).
    pub fn with_dir(dir: PathBuf) -> Self {
        Self { base_dir: dir }
    }

    /// Save a session to disk.
    pub fn save(&self, session: &OLineSession) -> Result<(), String> {
        let dir = self.base_dir.join(&session.id);
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create session dir {:?}: {}", dir, e))?;
        let path = dir.join("session.json");
        let json = serde_json::to_string_pretty(session)
            .map_err(|e| format!("Failed to serialize session: {}", e))?;
        fs::write(&path, json)
            .map_err(|e| format!("Failed to write {:?}: {}", path, e))?;
        Ok(())
    }

    /// Load a session by ID.
    pub fn load(&self, id: &str) -> Result<OLineSession, String> {
        let path = self.base_dir.join(id).join("session.json");
        let data = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {:?}: {}", path, e))?;
        serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse session JSON: {}", e))
    }

    /// List all session IDs (sorted by name, newest last).
    pub fn list(&self) -> Result<Vec<String>, String> {
        if !self.base_dir.exists() {
            return Ok(Vec::new());
        }
        let mut ids: Vec<String> = fs::read_dir(&self.base_dir)
            .map_err(|e| format!("Failed to read sessions dir: {}", e))?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                if entry.path().join("session.json").exists() {
                    Some(entry.file_name().to_string_lossy().to_string())
                } else {
                    None
                }
            })
            .collect();
        ids.sort();
        Ok(ids)
    }

    /// Load the most recently created session, if any.
    pub fn latest(&self) -> Result<Option<OLineSession>, String> {
        let ids = self.list()?;
        match ids.last() {
            Some(id) => self.load(id).map(Some),
            None => Ok(None),
        }
    }

    /// Delete a session directory.
    pub fn delete(&self, id: &str) -> Result<(), String> {
        let dir = self.base_dir.join(id);
        if dir.exists() {
            fs::remove_dir_all(&dir)
                .map_err(|e| format!("Failed to delete session {:?}: {}", dir, e))?;
        }
        Ok(())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn date_stamp(epoch_secs: u64) -> String {
    let days = epoch_secs / 86400;
    let (y, m, d) = crate::config::days_to_date(days);
    format!("{:04}{:02}{:02}", y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_funding_method_parse() {
        assert_eq!(FundingMethod::parse("master"), FundingMethod::Master);
        assert_eq!(FundingMethod::parse(""), FundingMethod::Master);
        assert_eq!(FundingMethod::parse("MASTER"), FundingMethod::Master);
        assert_eq!(FundingMethod::parse("direct"), FundingMethod::Direct);
        assert_eq!(FundingMethod::parse("DIRECT"), FundingMethod::Direct);
        assert_eq!(FundingMethod::parse("  Direct  "), FundingMethod::Direct);
        assert_eq!(
            FundingMethod::parse("hd:4:5000000"),
            FundingMethod::HdDerived {
                count: 4,
                amount_per_child: 5_000_000,
                act_amount_per_child: 5_000_000,
            }
        );
        // 4-part format with explicit ACT amount
        assert_eq!(
            FundingMethod::parse("hd:4:5000000:10000000"),
            FundingMethod::HdDerived {
                count: 4,
                amount_per_child: 5_000_000,
                act_amount_per_child: 10_000_000,
            }
        );
        // Invalid format falls back to Master
        assert_eq!(FundingMethod::parse("hd:bad"), FundingMethod::Master);
        assert_eq!(FundingMethod::parse("hd:4:"), FundingMethod::Master);
    }

    #[test]
    fn test_session_serde_roundtrip() {
        let mut session = OLineSession::new(
            FundingMethod::HdDerived {
                count: 3,
                amount_per_child: 1_000_000,
                act_amount_per_child: 1_000_000,
            },
            "akash1abc123",
            "morocco-1",
        );
        session.accounts.push(AccountEntry {
            hd_index: 0,
            address: "akash1child0".into(),
            funded: true,
            funded_amount: 1_000_000,
            act_funded_amount: 1_000_000,
            assigned_to: Some("phase-a".into()),
        });
        session.deployments.push(DeploymentEntry {
            phase: "special-teams".into(),
            dseq: 12345,
            account_index: 0,
            label: "oline-phase-a".into(),
            provider: Some("provider1".into()),
            endpoints: vec!["snapshot:26657".into()],
        });

        let json = serde_json::to_string_pretty(&session).unwrap();
        let restored: OLineSession = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.id, session.id);
        assert_eq!(restored.master_address, "akash1abc123");
        assert_eq!(restored.chain_id, "morocco-1");
        assert_eq!(restored.accounts.len(), 1);
        assert_eq!(restored.accounts[0].address, "akash1child0");
        assert_eq!(restored.deployments.len(), 1);
        assert_eq!(restored.deployments[0].dseq, 12345);
    }

    #[test]
    fn test_session_store_save_load_list_delete() {
        let tmp = std::env::temp_dir().join("oline-test-sessions");
        let _ = fs::remove_dir_all(&tmp);
        let store = OLineSessionStore::with_dir(tmp.clone());

        // Empty list
        assert_eq!(store.list().unwrap(), Vec::<String>::new());

        // Save
        let session = OLineSession::new(FundingMethod::Master, "akash1test", "test-1");
        let id = session.id.clone();
        store.save(&session).unwrap();

        // List
        let ids = store.list().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], id);

        // Load
        let loaded = store.load(&id).unwrap();
        assert_eq!(loaded.master_address, "akash1test");

        // Latest
        let latest = store.latest().unwrap().unwrap();
        assert_eq!(latest.id, id);

        // Delete
        store.delete(&id).unwrap();
        assert_eq!(store.list().unwrap().len(), 0);

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_funding_method_serde_tagged() {
        let master_json = serde_json::to_string(&FundingMethod::Master).unwrap();
        assert!(master_json.contains("\"type\":\"Master\""));

        let direct_json = serde_json::to_string(&FundingMethod::Direct).unwrap();
        assert!(direct_json.contains("\"type\":\"Direct\""));
        let restored_direct: FundingMethod = serde_json::from_str(&direct_json).unwrap();
        assert_eq!(restored_direct, FundingMethod::Direct);

        let hd = FundingMethod::HdDerived {
            count: 2,
            amount_per_child: 500_000,
            act_amount_per_child: 500_000,
        };
        let hd_json = serde_json::to_string(&hd).unwrap();
        assert!(hd_json.contains("\"type\":\"HdDerived\""));
        assert!(hd_json.contains("\"count\":2"));

        let restored: FundingMethod = serde_json::from_str(&hd_json).unwrap();
        assert_eq!(restored, hd);
    }

    #[test]
    fn test_session_new_id_format() {
        let session = OLineSession::new(FundingMethod::Master, "akash1x", "chain-1");
        assert!(session.id.starts_with("oline-"));
        assert!(session.created_at > 0);
        assert_eq!(session.created_at, session.updated_at);
    }

    #[test]
    fn test_session_touch() {
        let mut session = OLineSession::new(FundingMethod::Master, "akash1x", "chain-1");
        let original = session.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.touch();
        // updated_at uses second precision, so it may or may not have changed
        // in 10ms. Just verify it didn't go backwards.
        assert!(session.updated_at >= original);
    }
}
