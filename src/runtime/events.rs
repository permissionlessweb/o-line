use crate::workflow::step::{DeployPhase, OLineStep, PeerTarget};
use akash_deploy_rs::ServiceEndpoint;

/// Events emitted by workflows for inter-workflow coordination and observability.
///
/// The runtime broadcasts these on a `tokio::sync::broadcast` channel.
/// Subscribers (other workflows waiting on peer IDs, the `oline manage` display
/// loop) receive every event in emission order via `OLineRuntime::subscribe()`.
///
/// ## Dependency gate pattern
/// A Phase B workflow subscribes and blocks at its `Deploy(Tackles)` step until
/// it receives `PeerReady { target: PeerTarget::Snapshot, .. }` from Phase A.
/// The bit-wise `OLineStep::parallel_group()` mask tells the runtime which steps
/// _within_ a workflow are safe to run concurrently (e.g. cert pushes to
/// snapshot + seed).
#[derive(Debug, Clone)]
pub enum WorkflowEvent {
    /// A step has begun executing.
    StepStarted { workflow: String, step: OLineStep },
    /// A step completed successfully; the workflow has advanced to the next step.
    StepComplete { workflow: String, step: OLineStep },
    /// A peer ID became available — downstream workflows waiting on this target
    /// should apply it to their context and unblock.
    PeerReady {
        workflow: String,
        target: PeerTarget,
        peer_id: String,
    },
    /// A phase deployment finished and its service endpoints are live.
    EndpointsUp {
        workflow: String,
        phase: DeployPhase,
        endpoints: Vec<ServiceEndpoint>,
    },
    /// The workflow reached `OLineStep::Complete` successfully.
    WorkflowDone { workflow: String },
    /// The workflow encountered an unrecoverable error.
    WorkflowFailed { workflow: String, reason: String },
}

/// Discriminant-only version of `WorkflowEvent`, useful for dep-gate checks
/// and event filter registration without carrying owned payload data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventKind {
    StepStarted,
    StepComplete,
    /// Peer target key, e.g. `"snapshot"`, `"seed"`.
    PeerReady(String),
    /// Phase key, e.g. `"special-teams"`, `"tackles"`.
    EndpointsUp(String),
    WorkflowDone,
    WorkflowFailed,
}

impl WorkflowEvent {
    pub fn kind(&self) -> EventKind {
        match self {
            Self::StepStarted { .. } => EventKind::StepStarted,
            Self::StepComplete { .. } => EventKind::StepComplete,
            Self::PeerReady { target, .. } => EventKind::PeerReady(target.key().into()),
            Self::EndpointsUp { phase, .. } => EventKind::EndpointsUp(phase.key().into()),
            Self::WorkflowDone { .. } => EventKind::WorkflowDone,
            Self::WorkflowFailed { .. } => EventKind::WorkflowFailed,
        }
    }

    pub fn workflow_id(&self) -> &str {
        match self {
            Self::StepStarted { workflow, .. } => workflow,
            Self::StepComplete { workflow, .. } => workflow,
            Self::PeerReady { workflow, .. } => workflow,
            Self::EndpointsUp { workflow, .. } => workflow,
            Self::WorkflowDone { workflow } => workflow,
            Self::WorkflowFailed { workflow, .. } => workflow,
        }
    }
}
