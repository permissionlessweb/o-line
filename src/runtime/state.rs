use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

/// Global runtime state written atomically to `oline-state.json`.
///
/// `seq` is a monotonically-increasing write counter.  Every call to
/// `StateFile::write()` increments `seq` and renames a temp file over the
/// target path — `rename(2)` is atomic on POSIX filesystems, so concurrent
/// writers (parallel workflow tasks) cannot produce a torn read.  No file
/// locking is required.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeState {
    /// Global write counter — incremented on every write.
    pub seq: u64,
    /// Per-workflow records keyed by workflow ID (e.g. `"main"`, `"phase-a"`).
    pub workflows: HashMap<String, WorkflowRecord>,
}

/// Point-in-time snapshot of a single workflow's progress.
///
/// Written after every step so the state file always reflects the live
/// position of each workflow.  Fields are intentionally plain strings so
/// the JSON is human-readable without needing to import internal types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRecord {
    /// Stable workflow identifier — matches the key in `RuntimeState::workflows`.
    pub id: String,
    /// Debug representation of the current `OLineStep` (e.g. `"WaitPeer { target: Snapshot, .. }"`).
    pub step: String,
    /// `"pending"` | `"running"` | `"complete"` | `"failed: <reason>"`
    pub status: String,
    /// DSEQ for each deployed phase, populated as `Deploy` steps complete.
    /// Keys match `DeployPhase::key()`: `"special-teams"`, `"tackles"`, etc.
    #[serde(default)]
    pub phase_dseqs: HashMap<String, u64>,
    /// Resolved peer IDs (`"id@host:port"`), populated as `WaitPeer` steps complete.
    /// Keys match `PeerTarget::key()`: `"snapshot"`, `"seed"`, `"left-tackle"`, etc.
    #[serde(default)]
    pub peer_ids: HashMap<String, String>,
    /// Unix timestamp (seconds) when this workflow was first registered.
    pub started_at: u64,
    /// Unix timestamp (seconds) of the most recent state write.
    pub updated_at: u64,
}

impl WorkflowRecord {
    /// Create a new record in `"pending"` status.
    pub fn new(id: impl Into<String>) -> Self {
        let now = now_secs();
        Self {
            id: id.into(),
            step: "pending".into(),
            status: "pending".into(),
            phase_dseqs: HashMap::new(),
            peer_ids: HashMap::new(),
            started_at: now,
            updated_at: now,
        }
    }

    /// Transition to `"running"` at the given step name.
    pub fn at_step(&mut self, step: impl Into<String>) {
        self.step = step.into();
        self.status = "running".into();
        self.updated_at = now_secs();
    }

    /// Mark the workflow as successfully complete.
    pub fn complete(&mut self) {
        self.step = "Complete".into();
        self.status = "complete".into();
        self.updated_at = now_secs();
    }

    /// Mark the workflow as failed with a human-readable reason.
    pub fn failed(&mut self, reason: impl AsRef<str>) {
        self.status = format!("failed: {}", reason.as_ref());
        self.updated_at = now_secs();
    }
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Handle for the shared `oline-state.json` file.
///
/// All writes go through `write()` which atomically replaces the file via
/// a `.json.tmp` sibling and `rename(2)`.  Readers always see a complete,
/// consistent JSON object — never a partial write.
pub struct StateFile {
    path: PathBuf,
}

impl StateFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Default location: `./oline-state.json` in the working directory.
    pub fn default_path() -> PathBuf {
        PathBuf::from("oline-state.json")
    }

    /// Read the current state.
    /// Returns `RuntimeState::default()` if the file is missing or corrupt.
    pub async fn read(&self) -> RuntimeState {
        match tokio::fs::read_to_string(&self.path).await {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => RuntimeState::default(),
        }
    }

    /// Increment `seq`, serialize to a `.tmp` sibling, then rename it over
    /// the target path.  Atomic on POSIX — safe for concurrent workflow tasks.
    pub async fn write(&self, mut state: RuntimeState) -> std::io::Result<()> {
        state.seq += 1;
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let tmp = self.path.with_extension("json.tmp");
        tokio::fs::write(&tmp, &json).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        Ok(())
    }

    /// Convenience: read current state, update one workflow record, write back.
    pub async fn update_workflow(&self, record: WorkflowRecord) -> std::io::Result<()> {
        let mut state = self.read().await;
        state.workflows.insert(record.id.clone(), record);
        self.write(state).await
    }
}
