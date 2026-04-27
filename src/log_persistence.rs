//! Async file-backed log persister.
//!
//! Receives `(service_name, line)` tuples via an mpsc channel and appends
//! each line with an ISO-8601 timestamp to `~/.oline/logs/{session_id}/{service}.log`.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use tokio::sync::mpsc;

use crate::config::oline_config_dir;

/// A single persist-worthy log line.
pub struct PersistLine {
    pub service: String,
    pub text: String,
}

/// Async log persister that writes to per-service log files.
pub struct LogPersister {
    dir: PathBuf,
    writers: HashMap<String, BufWriter<File>>,
}

impl LogPersister {
    /// Create a new persister for the given session.
    ///
    /// Log files are written to `~/.oline/logs/{session_id}/`.
    pub fn new(session_id: &str) -> std::io::Result<Self> {
        Self::new_at(log_dir().join(session_id))
    }

    /// Create a new persister writing to an explicit directory.
    pub fn new_at(dir: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            writers: HashMap::new(),
        })
    }

    /// Append a timestamped line to the service's log file.
    pub fn write_line(&mut self, service: &str, line: &str) -> std::io::Result<()> {
        let writer = self.writer_for(service)?;
        let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        writeln!(writer, "[{}] {}", ts, line)?;
        writer.flush()?;
        Ok(())
    }

    /// Get or create a BufWriter for the given service.
    fn writer_for(&mut self, service: &str) -> std::io::Result<&mut BufWriter<File>> {
        if !self.writers.contains_key(service) {
            let safe_name = sanitize_filename(service);
            let path = self.dir.join(format!("{}.log", safe_name));
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            self.writers.insert(service.to_string(), BufWriter::new(file));
        }
        Ok(self.writers.get_mut(service).unwrap())
    }

    /// The directory where log files are written.
    pub fn log_path(&self) -> &Path {
        &self.dir
    }
}

/// Root log directory: `~/.oline/logs/`.
pub fn log_dir() -> PathBuf {
    oline_config_dir().join("logs")
}

/// Sanitize a service label for use as a filename.
///
/// Replaces characters that are invalid in filenames with underscores.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}

/// Spawn a background task that drains the persist channel and writes to disk.
///
/// Returns the sender half for producers to clone.
pub fn spawn_persist_task(
    session_id: &str,
) -> Result<mpsc::UnboundedSender<PersistLine>, std::io::Error> {
    let mut persister = LogPersister::new(session_id)?;
    let (tx, mut rx) = mpsc::unbounded_channel::<PersistLine>();

    let log_path = persister.log_path().display().to_string();
    tracing::info!("  Log persistence: {}", log_path);

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = persister.write_line(&msg.service, &msg.text) {
                tracing::warn!("log persist error: {}", e);
            }
        }
    });

    Ok(tx)
}

/// List available log sessions (directories under `~/.oline/logs/`).
pub fn list_sessions() -> Vec<String> {
    let dir = log_dir();
    if !dir.exists() {
        return Vec::new();
    }
    let mut sessions: Vec<String> = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    sessions.sort();
    sessions
}

/// Replay persisted logs for a session to stdout.
pub fn replay_session(session_id: &str, service: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let dir = log_dir().join(session_id);
    if !dir.exists() {
        return Err(format!("no logs found for session '{}'", session_id).into());
    }

    let mut files: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "log").unwrap_or(false))
        .collect();
    files.sort();

    for path in &files {
        let svc = path.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
        if let Some(filter) = service {
            if svc != filter {
                continue;
            }
        }
        let contents = fs::read_to_string(path)?;
        for line in contents.lines() {
            println!("[{}] {}", svc, line);
        }
    }

    Ok(())
}
