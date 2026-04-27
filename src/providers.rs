/// Trusted provider store — a single global JSON file at
/// `~/.config/oline/trusted-providers.json` that persists preferred Akash
/// providers across all oline sessions and projects.
///
/// When a bid arrives from a trusted provider, oline selects it automatically
/// (cheapest among trusted) instead of falling back to cheapest-overall. This
/// lets operators curate a list of reliable providers they've verified in
/// practice, rather than relying solely on price.
use akash_deploy_rs::Bid;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrustedProvider {
    /// Bech32 Akash provider address (akash1...).
    pub address: String,
    /// HTTPS host URI reported by the provider (e.g. `https://provider.xyz:8443`).
    pub host_uri: String,
    /// Optional human-readable alias (e.g. `"mycloud"`, `"prod-eu"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Free-form notes (region, tier, reason for trusting, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Unix epoch seconds when this entry was added.
    pub added_at: u64,
}

impl TrustedProvider {
    pub fn new(address: impl Into<String>, host_uri: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            host_uri: host_uri.into(),
            alias: None,
            notes: None,
            added_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// The label to display: alias if set, otherwise first 16 chars of address.
    pub fn display_name(&self) -> &str {
        self.alias
            .as_deref()
            .unwrap_or_else(|| &self.address[..self.address.len().min(20)])
    }
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// Plain-JSON store at `~/.config/oline/trusted-providers.json`.
///
/// Provider addresses are public information — no encryption needed. The file
/// is shared across all oline projects and sessions on the same machine.
pub struct TrustedProviderStore {
    path: PathBuf,
}

impl TrustedProviderStore {
    pub fn open(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Default path: `~/.config/oline/trusted-providers.json`
    /// Falls back to `$XDG_CONFIG_HOME/oline/...` if set.
    pub fn default_path() -> PathBuf {
        let config_base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                PathBuf::from(home).join(".config")
            });
        config_base.join("oline").join("trusted-providers.json")
    }

    /// Load all trusted providers. Returns empty vec if the file doesn't exist.
    pub fn load(&self) -> Vec<TrustedProvider> {
        if !self.path.exists() {
            return vec![];
        }
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist the provider list to disk.
    pub fn save(&self, providers: &[TrustedProvider]) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(providers)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    /// Add a provider (replaces existing entry for the same address).
    pub fn add(&self, provider: TrustedProvider) -> Result<(), Box<dyn std::error::Error>> {
        let mut providers = self.load();
        providers.retain(|p| p.address != provider.address);
        providers.push(provider);
        self.save(&providers)
    }

    /// Remove by address or alias. Returns number of entries removed.
    pub fn remove(&self, query: &str) -> Result<usize, Box<dyn std::error::Error>> {
        let mut providers = self.load();
        let before = providers.len();
        providers.retain(|p| {
            p.address != query && p.alias.as_deref() != Some(query)
        });
        let removed = before - providers.len();
        if removed > 0 {
            self.save(&providers)?;
        }
        Ok(removed)
    }

    /// Returns true if the address is in the trusted list.
    pub fn is_trusted(&self, address: &str) -> bool {
        self.load().iter().any(|p| p.address == address)
    }

    /// Find a trusted provider entry by address or alias.
    pub fn find(&self, query: &str) -> Option<TrustedProvider> {
        self.load()
            .into_iter()
            .find(|p| p.address == query || p.alias.as_deref() == Some(query))
    }

    // ── Bid selection ─────────────────────────────────────────────────────────

    /// Select the best provider address from a set of bids using the trusted list.
    ///
    /// Priority:
    ///   1. Cheapest bid from a trusted provider (if any trusted provider is bidding)
    ///   2. `None` — caller falls back to cheapest-overall
    pub fn select_from_bids(&self, bids: &[Bid]) -> Option<String> {
        let trusted = self.load();
        if trusted.is_empty() {
            return None;
        }
        let trusted_addrs: std::collections::HashSet<&str> =
            trusted.iter().map(|p| p.address.as_str()).collect();

        bids.iter()
            .filter(|b| trusted_addrs.contains(b.provider.as_str()))
            .min_by_key(|b| b.price)
            .map(|b| {
                let alias = trusted
                    .iter()
                    .find(|p| p.address == b.provider)
                    .and_then(|p| p.alias.as_deref());
                tracing::info!(
                    "  [trusted] {} ({}) bids {} uakt/block — selected.",
                    alias.unwrap_or(&b.provider[..b.provider.len().min(20)]),
                    b.provider,
                    b.price
                );
                b.provider.clone()
            })
    }

    /// Returns the subset of bids that come from trusted providers.
    pub fn trusted_bids<'a>(&self, bids: &'a [Bid]) -> Vec<&'a Bid> {
        let trusted = self.load();
        let addrs: std::collections::HashSet<&str> =
            trusted.iter().map(|p| p.address.as_str()).collect();
        bids.iter().filter(|b| addrs.contains(b.provider.as_str())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use akash_deploy_rs::Resources;

    fn make_bid(provider: &str, price: u64) -> Bid {
        Bid {
            provider: provider.to_string(),
            price,
            price_denom: "uakt".to_string(),
            resources: Resources::default(),
        }
    }

    fn store_with_providers(providers: &[(&str, &str)]) -> (TrustedProviderStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trusted-providers.json");
        let store = TrustedProviderStore::open(&path);
        for (address, host_uri) in providers {
            store.add(TrustedProvider::new(*address, *host_uri)).expect("add provider");
        }
        (store, dir)
    }

    #[test]
    fn test_select_from_bids_empty_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trusted-providers.json");
        let store = TrustedProviderStore::open(&path);

        let bids = vec![make_bid("akash1provider1", 100)];
        assert_eq!(store.select_from_bids(&bids), None);
    }

    #[test]
    fn test_select_from_bids_no_trusted_bidding() {
        let (store, _dir) = store_with_providers(&[
            ("akash1trusted1", "https://trusted1.example.com:8443"),
        ]);

        let bids = vec![
            make_bid("akash1other1", 50),
            make_bid("akash1other2", 200),
        ];
        assert_eq!(store.select_from_bids(&bids), None);
    }

    #[test]
    fn test_select_from_bids_single_match() {
        let (store, _dir) = store_with_providers(&[
            ("akash1trusted1", "https://trusted1.example.com:8443"),
        ]);

        let bids = vec![
            make_bid("akash1other1", 50),
            make_bid("akash1trusted1", 150),
        ];
        assert_eq!(
            store.select_from_bids(&bids),
            Some("akash1trusted1".to_string())
        );
    }

    #[test]
    fn test_select_from_bids_cheapest_trusted() {
        let (store, _dir) = store_with_providers(&[
            ("akash1trusted1", "https://trusted1.example.com:8443"),
            ("akash1trusted2", "https://trusted2.example.com:8443"),
        ]);

        let bids = vec![
            make_bid("akash1trusted1", 300),
            make_bid("akash1trusted2", 100),
            make_bid("akash1other1", 50),
        ];
        assert_eq!(
            store.select_from_bids(&bids),
            Some("akash1trusted2".to_string())
        );
    }

    #[test]
    fn test_select_from_bids_ignores_untrusted_cheaper() {
        let (store, _dir) = store_with_providers(&[
            ("akash1trusted1", "https://trusted1.example.com:8443"),
        ]);

        let bids = vec![
            make_bid("akash1untrusted_cheap", 10),
            make_bid("akash1trusted1", 500),
        ];
        // Untrusted provider is cheaper, but we must return the trusted one.
        assert_eq!(
            store.select_from_bids(&bids),
            Some("akash1trusted1".to_string())
        );
    }

    #[test]
    fn test_trusted_bids_filter() {
        let (store, _dir) = store_with_providers(&[
            ("akash1trusted1", "https://trusted1.example.com:8443"),
            ("akash1trusted2", "https://trusted2.example.com:8443"),
        ]);

        let bids = vec![
            make_bid("akash1trusted1", 100),
            make_bid("akash1untrusted1", 50),
            make_bid("akash1trusted2", 200),
            make_bid("akash1untrusted2", 75),
        ];
        let trusted = store.trusted_bids(&bids);
        assert_eq!(trusted.len(), 2);
        let providers: Vec<&str> = trusted.iter().map(|b| b.provider.as_str()).collect();
        assert!(providers.contains(&"akash1trusted1"));
        assert!(providers.contains(&"akash1trusted2"));
        assert!(!providers.contains(&"akash1untrusted1"));
        assert!(!providers.contains(&"akash1untrusted2"));
    }
}
