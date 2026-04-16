//! Resource manifest — defines what the courier needs to fetch.
//!
//! Each resource has a name (filename on disk), source URL, and whether
//! it's required (courier aborts if a required fetch fails).

use serde::{Deserialize, Serialize};

/// A single resource to fetch from the public internet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    /// Filename on disk (e.g. "chain.json", "addrbook.json", "snapshot.tar.lz4")
    pub name: String,
    /// Source URL
    pub url: String,
    /// If true, courier aborts on fetch failure
    pub required: bool,
    /// Expected SHA-256 hex digest (optional — skip verification if empty)
    pub sha256: String,
}

/// The complete manifest of resources to fetch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub resources: Vec<Resource>,
}

impl Manifest {
    /// Build manifest from environment variables.
    ///
    /// Each `COURIER_RESOURCE_<N>` env var is a pipe-delimited string:
    ///   `name|url|required|sha256`
    ///
    /// Example:
    ///   `COURIER_RESOURCE_0=chain.json|https://raw.githubusercontent.com/.../chain.json|true|`
    ///   `COURIER_RESOURCE_1=addrbook.json|https://...addrbook.json|false|`
    ///   `COURIER_RESOURCE_2=snapshot.tar.lz4|https://server.itrocket.net/.../snap.tar.lz4|true|`
    ///
    /// Well-known env vars are also checked as shortcuts:
    ///   `CHAIN_JSON_URL`, `ADDRBOOK_URL`, `GENESIS_URL`, `SNAPSHOT_URL`,
    ///   `WASMVM_URL`, `ENTRYPOINT_URL`
    pub fn from_env() -> Self {
        let mut resources = Vec::new();

        // ── Well-known shortcuts ──
        let shortcuts = [
            ("CHAIN_JSON_URL", "chain.json", true),
            ("ADDRBOOK_URL", "addrbook.json", false),
            ("GENESIS_URL", "genesis.json", false),
            ("SNAPSHOT_URL", "snapshot.tar.lz4", true),
            ("WASMVM_URL", "libwasmvm.x86_64.so", false),
            ("ENTRYPOINT_URL", "entrypoint.sh", false),
        ];

        for (env_key, default_name, required) in shortcuts {
            if let Ok(url) = std::env::var(env_key) {
                if !url.is_empty() {
                    // Derive filename from URL if it looks like a direct file link,
                    // otherwise use the default name.
                    let name = url_filename(&url).unwrap_or_else(|| default_name.to_string());
                    resources.push(Resource {
                        name,
                        url,
                        required,
                        sha256: String::new(),
                    });
                }
            }
        }

        // ── Numbered resources (COURIER_RESOURCE_0, _1, _2, ...) ──
        for i in 0..64 {
            let key = format!("COURIER_RESOURCE_{}", i);
            if let Ok(val) = std::env::var(&key) {
                if let Some(r) = parse_resource_env(&val) {
                    resources.push(r);
                }
            }
        }

        // ── JSON manifest from COURIER_MANIFEST env var ──
        if let Ok(json) = std::env::var("COURIER_MANIFEST") {
            if let Ok(m) = serde_json::from_str::<Manifest>(&json) {
                resources.extend(m.resources);
            }
        }

        // ── JSON manifest from file ──
        if let Ok(path) = std::env::var("COURIER_MANIFEST_FILE") {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(m) = serde_json::from_str::<Manifest>(&contents) {
                    resources.extend(m.resources);
                }
            }
        }

        // Dedup by name (first wins)
        let mut seen = std::collections::HashSet::new();
        resources.retain(|r| seen.insert(r.name.clone()));

        Self { resources }
    }
}

/// Parse `name|url|required|sha256` into a Resource.
fn parse_resource_env(val: &str) -> Option<Resource> {
    let parts: Vec<&str> = val.splitn(4, '|').collect();
    if parts.len() < 2 {
        return None;
    }
    Some(Resource {
        name: parts[0].to_string(),
        url: parts[1].to_string(),
        required: parts.get(2).map(|s| *s == "true").unwrap_or(false),
        sha256: parts.get(3).map(|s| s.to_string()).unwrap_or_default(),
    })
}

/// Extract filename from URL path. Returns None for bare domains.
fn url_filename(url: &str) -> Option<String> {
    let path = url.split('?').next()?;
    let segment = path.rsplit('/').next()?;
    if segment.is_empty() || !segment.contains('.') {
        None
    } else {
        Some(segment.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resource_basic() {
        let r = parse_resource_env("chain.json|https://example.com/chain.json|true|abc123").unwrap();
        assert_eq!(r.name, "chain.json");
        assert_eq!(r.url, "https://example.com/chain.json");
        assert!(r.required);
        assert_eq!(r.sha256, "abc123");
    }

    #[test]
    fn parse_resource_minimal() {
        let r = parse_resource_env("file.txt|https://example.com/file.txt").unwrap();
        assert_eq!(r.name, "file.txt");
        assert!(!r.required);
        assert!(r.sha256.is_empty());
    }

    #[test]
    fn url_filename_extracts() {
        assert_eq!(url_filename("https://example.com/path/to/chain.json"), Some("chain.json".into()));
        assert_eq!(url_filename("https://example.com/"), None);
        assert_eq!(url_filename("https://example.com/file.tar.lz4?token=abc"), Some("file.tar.lz4".into()));
    }
}
