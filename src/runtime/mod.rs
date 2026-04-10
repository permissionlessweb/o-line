pub mod events;
pub mod state;

use crate::{
    deployer::OLineDeployer,
    workflow::{step::OLineStep, OLineWorkflow, StepResult},
};
use akash_deploy_rs::DeployError;
use events::WorkflowEvent;
use state::{StateFile, WorkflowRecord};
use std::io::{Lines, StdinLock};
use tokio::sync::broadcast;

/// A named workflow slot managed by [`OLineRuntime`].
pub struct WorkflowHandle {
    /// Stable identifier — the key in `oline-state.json` and in event payloads.
    pub id: String,
    /// The underlying step-machine.
    pub workflow: OLineWorkflow,
    /// In-memory record, kept in sync with the state file after each step.
    pub record: WorkflowRecord,
}

impl WorkflowHandle {
    pub fn new(id: impl Into<String>, deployer: OLineDeployer) -> Self {
        let id = id.into();
        Self {
            record: WorkflowRecord::new(&id),
            workflow: OLineWorkflow::new(deployer),
            id,
        }
    }
}

/// Multi-workflow orchestrator.
///
/// # State file
/// `oline-state.json` is written atomically after **every** step via
/// `rename(2)`.  The global `seq` counter increments on each write so readers
/// always see a complete, consistent snapshot — no locking needed.
///
/// # Parallel groups
/// [`OLineStep::parallel_group()`] returns a `u64` bitmask.  Steps sharing any
/// bit belong to the same parallel group and _may_ run concurrently.  The
/// scheduler uses this to dispatch SSH operations (cert pushes, peer waits)
/// for multiple nodes simultaneously while keeping `Deploy` steps sequential.
///
/// # Multi-workflow dispatch
/// Register workflows with [`add_workflow`](Self::add_workflow).
/// [`run_single`](Self::run_single) drives one workflow to completion with full
/// state and event tracking.  Parallel multi-workflow execution (Phase B
/// starting the moment Phase A emits `PeerReady`) will be added in a future
/// iteration using the [`subscribe`](Self::subscribe) event bus.
pub struct OLineRuntime {
    /// Active workflow slots, dispatched in insertion order.
    pub handles: Vec<WorkflowHandle>,
    /// Path to `oline-state.json`.
    pub state_file: StateFile,
    /// Broadcast channel — every `WorkflowEvent` is sent here.
    /// Subscribers receive all subsequent events; past events are not replayed.
    pub events: broadcast::Sender<WorkflowEvent>,
}

impl Default for OLineRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl OLineRuntime {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            handles: Vec::new(),
            state_file: StateFile::new(StateFile::default_path()),
            events: tx,
        }
    }

    /// Register a named workflow.  Workflows are dispatched in insertion order.
    pub fn add_workflow(&mut self, id: impl Into<String>, deployer: OLineDeployer) {
        self.handles.push(WorkflowHandle::new(id, deployer));
    }

    /// Subscribe to the event bus.
    ///
    /// Each subscriber receives a clone of every subsequent `WorkflowEvent`.
    /// Use this to build dependency gates (e.g. wait for `PeerReady` before
    /// starting Phase B) or to drive a live status display.
    pub fn subscribe(&self) -> broadcast::Receiver<WorkflowEvent> {
        self.events.subscribe()
    }

    /// Drive the first registered workflow to completion.
    ///
    /// After each step:
    /// - `oline-state.json` is updated atomically.
    /// - `StepStarted` / `StepComplete` events are broadcast.
    /// - `PeerReady` and `EndpointsUp` events are emitted when the step
    ///   populates peer IDs or endpoints in the workflow context.
    pub async fn run_single(
        &mut self,
        lines: &mut Lines<StdinLock<'_>>,
    ) -> Result<(), DeployError> {
        if self.handles.is_empty() {
            return Ok(());
        }
        let id = self.handles[0].id.clone();

        loop {
            let step = self.handles[0].workflow.step.clone();

            // Log parallel group hint for observability
            let group = step.parallel_group();
            if group != 0 {
                tracing::debug!("[{}] step {:?} — parallel-group 0x{:02x}", id, step, group);
            }

            // Update state: StepStarted
            self.handles[0].record.at_step(format!("{:?}", step));
            let _ = self.events.send(WorkflowEvent::StepStarted {
                workflow: id.clone(),
                step: step.clone(),
            });
            self.state_file
                .update_workflow(self.handles[0].record.clone())
                .await
                .ok();

            // Advance one step
            match self.handles[0].workflow.advance(lines).await? {
                StepResult::Continue => {
                    let _ = self.events.send(WorkflowEvent::StepComplete {
                        workflow: id.clone(),
                        step: step.clone(),
                    });
                    self.emit_context_events(&id, &step);
                }
                StepResult::Complete => {
                    self.handles[0].record.complete();
                    let _ = self.events.send(WorkflowEvent::WorkflowDone {
                        workflow: id.clone(),
                    });
                    self.state_file
                        .update_workflow(self.handles[0].record.clone())
                        .await
                        .ok();
                    break;
                }
                StepResult::Failed(reason) => {
                    self.handles[0].record.failed(&reason);
                    let _ = self.events.send(WorkflowEvent::WorkflowFailed {
                        workflow: id.clone(),
                        reason: reason.clone(),
                    });
                    self.state_file
                        .update_workflow(self.handles[0].record.clone())
                        .await
                        .ok();
                    return Err(DeployError::InvalidState(reason));
                }
            }
        }
        Ok(())
    }

    /// After a step completes, inspect the workflow context and emit domain-level
    /// events for any newly-populated peer IDs or service endpoints.
    fn emit_context_events(&self, workflow_id: &str, completed_step: &OLineStep) {
        let ctx = &self.handles[0].workflow.ctx;

        // Emit PeerReady after every WaitPeer step that resolves a non-empty ID.
        if let OLineStep::WaitPeer { target, .. } = completed_step {
            let peer = ctx.peer(target.clone());
            if !peer.is_empty() {
                let _ = self.events.send(WorkflowEvent::PeerReady {
                    workflow: workflow_id.to_string(),
                    target: target.clone(),
                    peer_id: peer.to_string(),
                });
            }
        }

        // Emit EndpointsUp after every Deploy step that populates endpoints.
        if let OLineStep::Deploy(phase) = completed_step {
            let endpoints = ctx.endpoints(phase.clone()).to_vec();
            if !endpoints.is_empty() {
                let _ = self.events.send(WorkflowEvent::EndpointsUp {
                    workflow: workflow_id.to_string(),
                    phase: phase.clone(),
                    endpoints,
                });
            }
        }
    }
}
