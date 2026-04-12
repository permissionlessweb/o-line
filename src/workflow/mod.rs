pub mod context;
pub mod phases;
pub mod step;

use crate::deployer::OLineDeployer;
use akash_deploy_rs::DeployError;
use context::{OLineContext, PhaseResult};
use phases::{a, b, c, e, parallel};
use std::io::{BufRead, Lines};
use step::{DeployPhase, NodeTarget, OLineStep, PeerTarget};

pub enum StepResult {
    Continue,
    Complete,
    Failed(String),
}

pub struct OLineWorkflow {
    pub step: OLineStep,
    pub ctx: OLineContext,
}

impl OLineWorkflow {
    pub fn new(deployer: OLineDeployer) -> Self {
        Self {
            step: OLineStep::Deploy(DeployPhase::SpecialTeams),
            ctx: OLineContext::new(deployer),
        }
    }

    /// Create a workflow starting at a specific step.
    ///
    /// Use this to start the parallel deployment path:
    /// ```ignore
    /// OLineWorkflow::new_with_step(deployer, OLineStep::FundChildAccounts)
    /// ```
    pub fn new_with_step(deployer: OLineDeployer, step: OLineStep) -> Self {
        Self {
            step,
            ctx: OLineContext::new(deployer),
        }
    }

    /// Create a workflow with an explicit session and session store.
    pub fn new_with_session(
        deployer: OLineDeployer,
        step: OLineStep,
        session: crate::sessions::OLineSession,
        session_store: crate::sessions::OLineSessionStore,
    ) -> Self {
        Self {
            step,
            ctx: OLineContext::new_with_session(deployer, session, session_store),
        }
    }

    /// Process exactly one step. Each step fn sets `self.step = <next>` before returning `Continue`.
    pub async fn advance(
        &mut self,
        lines: &mut Lines<impl BufRead>,
    ) -> Result<StepResult, DeployError> {
        use OLineStep::*;
        match self.step.clone() {
            // ── Phase A ───────────────────────────────────────────────────────
            Deploy(DeployPhase::SpecialTeams) => a::deploy_special_teams(self, lines).await,
            UpdateDns(DeployPhase::SpecialTeams) => a::update_dns(self).await,
            PushFiles(NodeTarget::Snapshot) => a::push_files_snapshot(self).await,
            SignalStart(NodeTarget::Snapshot) => a::signal_snapshot_start(self).await,
            WaitPeer {
                target: PeerTarget::Snapshot,
                boot_wait_secs,
            } => a::wait_snapshot_peer(self, boot_wait_secs).await,
            PushFiles(NodeTarget::Seed) => a::push_files_seed(self).await,
            SignalStart(NodeTarget::Seed) => a::signal_seed_start(self).await,
            PushFiles(NodeTarget::Minio) => a::push_files_minio(self).await,
            WaitPeer {
                target: PeerTarget::Seed,
                boot_wait_secs,
            } => a::wait_seed_peer(self, boot_wait_secs).await,
            // ── Phase B ───────────────────────────────────────────────────────
            Deploy(DeployPhase::Tackles) => b::deploy_tackles(self, lines).await,
            WaitPeer {
                target: PeerTarget::LeftTackle,
                boot_wait_secs,
            } => b::wait_left_tackle(self, boot_wait_secs).await,
            WaitPeer {
                target: PeerTarget::RightTackle,
                boot_wait_secs,
            } => b::wait_right_tackle(self, boot_wait_secs).await,
            // ── Phase C ───────────────────────────────────────────────────────
            Deploy(DeployPhase::Forwards) => c::deploy_forwards(self, lines).await,
            // ── Phase E ───────────────────────────────────────────────────────
            Deploy(DeployPhase::Relayer) => e::deploy_relayer(self, lines).await,
            UpdateDns(DeployPhase::Relayer) => e::update_dns_relayer(self).await,
            // ── Terminal ──────────────────────────────────────────────────────
            Summary => {
                self.print_summary();
                self.step = Complete;
                Ok(StepResult::Continue)
            }
            Complete => Ok(StepResult::Complete),
            // ── Parallel deployment path ───────────────────────────────────────
            FundChildAccounts => parallel::fund_child_accounts(self).await,
            DeployAllUnits => parallel::deploy_all_units(self, lines).await,
            SelectAllProviders => parallel::select_all_providers(self, lines).await,
            UpdateAllDns => parallel::update_all_dns(self).await,
            WaitSnapshotReady { timeout_secs } => {
                parallel::wait_snapshot_ready(self, timeout_secs).await
            }
            DistributeSnapshot => parallel::distribute_snapshot(self).await,
            SignalAllNodes => parallel::signal_all_nodes(self).await,
            InjectPeers => parallel::inject_peers(self).await,
            WaitAllPeers { boot_wait_secs } => {
                parallel::wait_all_peers(self, boot_wait_secs).await
            }
            // Unreachable combinations (e.g. UpdateDns(Tackles)) are compile-guarded
            // by the phase files only ever setting valid next-step transitions.
            _ => unreachable!("unexpected step combination: {:?}", self.step),
        }
    }

    /// Drive the workflow to completion.
    pub async fn run(&mut self, lines: &mut Lines<impl BufRead>) -> Result<(), DeployError> {
        loop {
            match self.advance(lines).await? {
                StepResult::Continue => {}
                StepResult::Complete => break,
                StepResult::Failed(r) => return Err(DeployError::InvalidState(r)),
            }
        }
        Ok(())
    }

    /// Drive the workflow to completion without stdin.
    ///
    /// Used by the TUI deploy path: after the interactive phase completes,
    /// the remaining automated steps run headless in a background task while
    /// the TUI displays progress.
    pub async fn run_headless(&mut self) -> Result<(), DeployError> {
        let mut lines = std::io::BufReader::new(std::io::empty()).lines();
        self.run(&mut lines).await
    }

    /// Capture the deployment summary as a vec of lines (for TUI display).
    pub fn capture_summary(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.push("=== Deployment Summary ===".to_string());

        let phases: &[(DeployPhase, &str, &str)] = &[
            (DeployPhase::SpecialTeams, "A", "Special Teams"),
            (DeployPhase::Tackles, "B", "Tackles"),
            (DeployPhase::Forwards, "C", "Forwards"),
            (DeployPhase::Relayer, "E", "Relayer"),
        ];

        let mut warnings: Vec<String> = Vec::new();

        for (phase, letter, label) in phases {
            let result = self.ctx.phase_result(phase);
            let dseq_str = self
                .ctx
                .state(phase.clone())
                .and_then(|s| s.dseq)
                .filter(|&d| d > 0)
                .map(|d| format!("  DSEQ: {}", d))
                .unwrap_or_default();
            out.push(format!(
                "  Phase {} ({}):  {}{}",
                letter, label, result, dseq_str,
            ));
            if let PhaseResult::Failed(ref msg) = result {
                warnings.push(format!("Phase {}: {}", letter, msg));
            }
        }

        if !warnings.is_empty() {
            out.push(String::new());
            out.push("  Warnings:".to_string());
            for w in &warnings {
                out.push(format!("    - {}", w));
            }
        }

        let a_vars = &self.ctx.a_vars;
        let get = |k: &str| a_vars.get(k).map(|s| s.as_str()).unwrap_or("");
        out.push("  ┌── Public Endpoints ──────────────────────────────────────────────────".to_string());
        for (label, rpc, api, grpc, p2p, p2p_port) in [
            ("Snapshot", "RPC_D_SNAP", "API_D_SNAP", "GRPC_D_SNAP", "P2P_D_SNAP", "P2P_P_SNAP"),
            ("Seed    ", "RPC_D_SEED", "API_D_SEED", "GRPC_D_SEED", "P2P_D_SEED", "P2P_P_SEED"),
        ] {
            let (rpc_d, api_d, grpc_d, p2p_d, p2p_p) = (get(rpc), get(api), get(grpc), get(p2p), get(p2p_port));
            if !rpc_d.is_empty() { out.push(format!("  │  {} RPC:   https://{}", label, rpc_d)); }
            if !api_d.is_empty() { out.push(format!("  │  {} API:   https://{}", label, api_d)); }
            if !grpc_d.is_empty() { out.push(format!("  │  {} gRPC:  {}", label, grpc_d)); }
            if !p2p_d.is_empty() { out.push(format!("  │  {} P2P:   {}:{}", label, p2p_d, p2p_p)); }
        }
        let metadata_url = get("SNAPSHOT_METADATA_URL");
        let dl_domain = get("SNAPSHOT_DOWNLOAD_DOMAIN");
        if !metadata_url.is_empty() {
            out.push("  │".to_string());
            out.push(format!("  │  Snapshot metadata: {}", metadata_url));
        }
        if !dl_domain.is_empty() {
            out.push(format!("  │  MinIO download:    https://{}", dl_domain));
        }
        out.push("  └──────────────────────────────────────────────────────────────────────".to_string());
        out
    }

    fn print_summary(&self) {
        for line in self.capture_summary() {
            tracing::info!("{}", line);
        }
    }
}
