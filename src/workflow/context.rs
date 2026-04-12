use crate::{
    crypto::PreStartFile,
    deployer::OLineDeployer,
    sessions::{OLineSession, OLineSessionStore},
    workflow::step::{DeployPhase, PeerTarget},
};
use akash_deploy_rs::{DeploymentState, ServiceEndpoint};
use std::{collections::HashMap, fmt, path::PathBuf};

/// Outcome of a phase deployment attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum PhaseResult {
    /// Not yet attempted.
    Pending,
    /// Successfully deployed.
    Deployed,
    /// User chose to skip this phase.
    Skipped,
    /// Deployment failed with an error message.
    Failed(String),
}

impl fmt::Display for PhaseResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhaseResult::Pending => write!(f, "--"),
            PhaseResult::Deployed => write!(f, "DEPLOYED"),
            PhaseResult::Skipped => write!(f, "SKIPPED"),
            PhaseResult::Failed(_) => write!(f, "FAILED"),
        }
    }
}

/// Per-unit state for parallel deployment.
///
/// Each deployment unit (snapshot, seed, minio, left-tackle, right-tackle,
/// left-forward, right-forward, relayer) gets its own deployer (child account)
/// and accumulates its own SDL vars and live endpoints.
pub struct UnitState {
    /// Human-readable name for logs ("snapshot", "left-tackle", etc.)
    pub name: &'static str,
    /// BIP44 HD account index used for the child signer.
    pub hd_index: u32,
    /// Deployer instance — owns the child signer and Akash client connection.
    pub deployer: OLineDeployer,
    /// SDL template variables resolved for this unit's deployment.
    pub vars: HashMap<String, String>,
    /// Live service endpoints populated after `SelectAllProviders` completes.
    pub endpoints: Vec<ServiceEndpoint>,
}

/// All mutable state accumulated across deployment steps.
///
/// Phase states and endpoints are stored in fixed-size arrays indexed by
/// `DeployPhase::idx()`; peer IDs are stored in a fixed-size array indexed
/// by `PeerTarget::idx()`. Accessor methods provide a single consistent
/// interface — use `state()`, `endpoints()`, `service_endpoints()`, and
/// `peer()` rather than reaching into the arrays directly.
///
/// `OLineContext::all_keys()` returns every logical field name so tooling and
/// diagnostics always have a complete picture of the context.
pub struct OLineContext {
    /// Akash client, signer, config, and deployment store.
    pub deployer: OLineDeployer,

    // ── Session tracking ───────────────────────────────────────────────────────
    /// Deployment session state (accounts, deployments, funding strategy).
    pub session: OLineSession,
    /// File-backed session persistence.
    pub session_store: OLineSessionStore,

    // ── SSH ───────────────────────────────────────────────────────────────────
    // Generated once during Deploy(SpecialTeams).
    pub ssh_key_path: PathBuf,
    pub ssh_privkey_pem: String,

    // ── Pre-start file delivery ───────────────────────────────────────────────
    // Files to push to each node before signaling bootstrap start.
    // Populated in Deploy(SpecialTeams) from config/env (e.g. local snapshot path).
    // Empty in production (nodes download snapshot themselves).
    pub pre_start_files: Vec<PreStartFile>,

    // ── Phase A SDL vars ──────────────────────────────────────────────────────
    // Needed by UpdateDns(SpecialTeams), SignalStart steps, and print_summary.
    pub a_vars: HashMap<String, String>,

    // ── Derived Phase A values ────────────────────────────────────────────────
    // Computed once in Deploy(SpecialTeams), used by Deploy(Tackles/Forwards).
    pub statesync_rpc: String,

    // ── Per-phase deployment result [DeployPhase::idx()] ──────────────────────
    phase_results: [PhaseResult; DeployPhase::COUNT],

    // ── Per-phase deployment state [DeployPhase::idx()] ───────────────────────
    phase_states: [Option<DeploymentState>; DeployPhase::COUNT],

    // ── Per-phase service endpoints [DeployPhase::idx()] ─────────────────────
    phase_endpoints: [Vec<ServiceEndpoint>; DeployPhase::COUNT],

    // ── Per-peer node IDs [PeerTarget::idx()] ────────────────────────────────
    // Format: "id@host:port". Empty string = not yet resolved.
    peer_ids: [String; PeerTarget::COUNT],

    // ── Provider host URIs (address → host_uri) ──────────────────────────────
    // Populated during provider selection so TUI can build WebSocket URLs
    // without requiring the trusted provider store.
    pub provider_hosts: HashMap<String, String>,

    // ── Parallel deployment path ──────────────────────────────────────────────
    // Populated by FundChildAccounts; each entry owns a child deployer + vars.
    pub units: Vec<UnitState>,

    // ── Early bootstrap tracking ──────────────────────────────────────────────
    // Set to true when Phase A is signaled during deploy_all_units so that
    // wait_snapshot_ready does not re-signal (which would launch a second process).
    pub phase_a_bootstrapped: bool,
}

impl OLineContext {
    pub fn new(deployer: OLineDeployer) -> Self {
        use crate::sessions::FundingMethod;
        let session = OLineSession::new(
            FundingMethod::from_env(),
            &deployer.client.address().to_string(),
            "",
        );
        Self {
            deployer,
            session,
            session_store: OLineSessionStore::new(),
            ssh_key_path: PathBuf::new(),
            ssh_privkey_pem: String::new(),
            pre_start_files: Vec::new(),
            a_vars: HashMap::new(),
            statesync_rpc: String::new(),
            phase_results: [
                PhaseResult::Pending,
                PhaseResult::Pending,
                PhaseResult::Pending,
                PhaseResult::Pending,
            ],
            phase_states: [None, None, None, None],
            phase_endpoints: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            peer_ids: [String::new(), String::new(), String::new(), String::new()],
            provider_hosts: HashMap::new(),
            units: Vec::new(),
            phase_a_bootstrapped: false,
        }
    }

    /// Create a context with an explicit session and store.
    pub fn new_with_session(
        deployer: OLineDeployer,
        session: OLineSession,
        session_store: OLineSessionStore,
    ) -> Self {
        Self {
            deployer,
            session,
            session_store,
            ssh_key_path: PathBuf::new(),
            ssh_privkey_pem: String::new(),
            pre_start_files: Vec::new(),
            a_vars: HashMap::new(),
            statesync_rpc: String::new(),
            phase_results: [
                PhaseResult::Pending,
                PhaseResult::Pending,
                PhaseResult::Pending,
                PhaseResult::Pending,
            ],
            phase_states: [None, None, None, None],
            phase_endpoints: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            peer_ids: [String::new(), String::new(), String::new(), String::new()],
            provider_hosts: HashMap::new(),
            units: Vec::new(),
            phase_a_bootstrapped: false,
        }
    }

    // ── Phase state accessors ─────────────────────────────────────────────────

    /// Deployment state for a phase (`None` if not yet deployed).
    pub fn state(&self, phase: DeployPhase) -> Option<&DeploymentState> {
        self.phase_states[phase.idx()].as_ref()
    }

    /// Store deployment state for a phase (called at end of each Deploy step).
    pub fn set_state(&mut self, phase: DeployPhase, state: DeploymentState) {
        self.phase_states[phase.idx()] = Some(state);
    }

    // ── Phase result accessors ──────────────────────────────────────────────

    /// Deployment result for a phase.
    pub fn phase_result(&self, phase: &DeployPhase) -> &PhaseResult {
        &self.phase_results[phase.idx()]
    }

    /// Store a deployment result for a phase.
    pub fn set_phase_result(&mut self, phase: DeployPhase, result: PhaseResult) {
        self.phase_results[phase.idx()] = result;
    }

    /// Returns `true` if the phase was successfully deployed.
    pub fn phase_deployed(&self, phase: &DeployPhase) -> bool {
        self.phase_results[phase.idx()] == PhaseResult::Deployed
    }

    // ── Endpoint accessors ────────────────────────────────────────────────────

    /// All service endpoints for a phase.
    pub fn endpoints(&self, phase: DeployPhase) -> &[ServiceEndpoint] {
        &self.phase_endpoints[phase.idx()]
    }

    /// Filter endpoints for a specific service name within a phase.
    ///
    /// Returns an owned Vec; callers receive a snapshot free of borrow conflicts.
    pub fn service_endpoints(&self, phase: DeployPhase, service: &str) -> Vec<ServiceEndpoint> {
        self.phase_endpoints[phase.idx()]
            .iter()
            .filter(|e| e.service == service)
            .cloned()
            .collect()
    }

    /// Store all endpoints for a phase (called at end of each Deploy step).
    pub fn set_endpoints(&mut self, phase: DeployPhase, endpoints: Vec<ServiceEndpoint>) {
        self.phase_endpoints[phase.idx()] = endpoints;
    }

    // ── Peer ID accessors ─────────────────────────────────────────────────────

    /// Peer ID string (`"id@host:port"`) for a node; empty if not yet resolved.
    pub fn peer(&self, target: PeerTarget) -> &str {
        &self.peer_ids[target.idx()]
    }

    /// Store a resolved peer ID (called at end of each WaitPeer step).
    pub fn set_peer(&mut self, target: PeerTarget, id: String) {
        self.peer_ids[target.idx()] = id;
    }

    // ── Per-unit deployer lookup ────────────────────────────────────────────

    /// Returns the child deployer for phase index `i` if HD units exist,
    /// otherwise falls back to the master deployer.
    pub fn phase_deployer(&self, phase_index: usize) -> &OLineDeployer {
        self.units
            .get(phase_index)
            .map(|u| &u.deployer)
            .unwrap_or(&self.deployer)
    }

    // ── Diagnostics ───────────────────────────────────────────────────────────

    /// Every logical field key in this context, in declaration order.
    ///
    /// Useful for structured logging, debugging, and verifying that all
    /// expected context values have been populated before a step runs.
    pub fn all_keys() -> &'static [&'static str] {
        &[
            // SSH
            "ssh_key_path",
            "ssh_privkey_pem",
            // Pre-start files
            "pre_start_files",
            // Phase A vars & derived
            "a_vars",
            "statesync_rpc",
            // Per-phase state (keyed by DeployPhase::key())
            "state:special-teams",
            "state:tackles",
            "state:forwards",
            "state:relayer",
            // Per-phase endpoints (keyed by DeployPhase::key())
            "endpoints:special-teams",
            "endpoints:tackles",
            "endpoints:forwards",
            "endpoints:relayer",
            // Peer IDs (keyed by PeerTarget::key())
            "peer:snapshot",
            "peer:seed",
            "peer:left-tackle",
            "peer:right-tackle",
        ]
    }
}
