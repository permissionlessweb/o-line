//! Switchable tracing writer: routes tracing output to either stdout or an mpsc channel.
//!
//! Install once at startup via `tracing_subscriber::fmt().with_writer(switch.clone())`.
//! Before entering the TUI, call `activate(tx)` to redirect all tracing output into
//! the deploy progress pane.  Call `deactivate()` to restore stdout output.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing_subscriber::fmt::MakeWriter;

/// A `MakeWriter` that toggles between stdout and an mpsc channel.
///
/// The `AtomicBool` check is the hot path — every tracing call reads it.
/// When inactive, writes go to stdout.  When active, writes go to a channel
/// so the TUI deploy pane can display them.
#[derive(Clone)]
pub struct TracingSwitch {
    active: Arc<AtomicBool>,
    tx: Arc<Mutex<Option<mpsc::UnboundedSender<String>>>>,
}

impl TracingSwitch {
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            tx: Arc::new(Mutex::new(None)),
        }
    }

    /// Start capturing tracing output into `tx` instead of stdout.
    pub fn activate(&self, tx: mpsc::UnboundedSender<String>) {
        *self.tx.lock().unwrap() = Some(tx);
        self.active.store(true, Ordering::Release);
    }

    /// Stop capturing — revert to stdout.
    pub fn deactivate(&self) {
        self.active.store(false, Ordering::Release);
        *self.tx.lock().unwrap() = None;
    }
}

impl<'a> MakeWriter<'a> for TracingSwitch {
    type Writer = TracingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        if self.active.load(Ordering::Acquire) {
            let tx = self.tx.lock().unwrap().clone();
            TracingWriter::Channel(ChannelWriter { tx })
        } else {
            TracingWriter::Stdout(io::stdout())
        }
    }
}

/// Writer returned by `TracingSwitch::make_writer`.
pub enum TracingWriter {
    Stdout(io::Stdout),
    Channel(ChannelWriter),
}

/// Buffers a single tracing event, then sends the complete line to the channel on flush/drop.
pub struct ChannelWriter {
    tx: Option<mpsc::UnboundedSender<String>>,
}

impl io::Write for TracingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TracingWriter::Stdout(w) => w.write(buf),
            TracingWriter::Channel(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TracingWriter::Stdout(w) => w.flush(),
            TracingWriter::Channel(w) => w.flush(),
        }
    }
}

impl io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(ref tx) = self.tx {
            let text = String::from_utf8_lossy(buf);
            // tracing-subscriber writes each event as a single write call ending with \n.
            // Split on newlines so each line is a separate entry in the deploy pane.
            for line in text.lines() {
                if !line.is_empty() {
                    let _ = tx.send(line.to_string());
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
