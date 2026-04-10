/// Target phase for `Deploy` and `UpdateDns` steps.
#[derive(Debug, Clone, PartialEq)]
pub enum DeployPhase {
    SpecialTeams,
    Tackles,
    Forwards,
    Relayer,
}

impl DeployPhase {
    /// Number of phases — matches the array sizes in `OLineContext`.
    pub const COUNT: usize = 4;

    /// All phases in pipeline order, usable for iteration or diagnostics.
    pub const ALL: [DeployPhase; Self::COUNT] = [
        DeployPhase::SpecialTeams,
        DeployPhase::Tackles,
        DeployPhase::Forwards,
        DeployPhase::Relayer,
    ];

    /// Stable lowercase key for use in logs, context maps, and storage.
    pub fn key(&self) -> &'static str {
        match self {
            DeployPhase::SpecialTeams => "special-teams",
            DeployPhase::Tackles => "tackles",
            DeployPhase::Forwards => "forwards",
            DeployPhase::Relayer => "relayer",
        }
    }

    /// Index into the fixed-size arrays in `OLineContext`.
    pub(crate) fn idx(&self) -> usize {
        match self {
            DeployPhase::SpecialTeams => 0,
            DeployPhase::Tackles => 1,
            DeployPhase::Forwards => 2,
            DeployPhase::Relayer => 3,
        }
    }
}

/// Which node receives pre-start file delivery or the verify+signal-start sequence.
#[derive(Debug, Clone, PartialEq)]
pub enum NodeTarget {
    Snapshot,
    Seed,
    Minio,
}

/// Which node's peer ID to poll for.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerTarget {
    Snapshot,
    Seed,
    LeftTackle,
    RightTackle,
}

impl PeerTarget {
    /// Number of tracked peer nodes — matches the array size in `OLineContext`.
    pub const COUNT: usize = 4;

    /// All peer targets in discovery order.
    pub const ALL: [PeerTarget; Self::COUNT] = [
        PeerTarget::Snapshot,
        PeerTarget::Seed,
        PeerTarget::LeftTackle,
        PeerTarget::RightTackle,
    ];

    /// Stable lowercase key for use in logs and context field names.
    pub fn key(&self) -> &'static str {
        match self {
            PeerTarget::Snapshot => "snapshot",
            PeerTarget::Seed => "seed",
            PeerTarget::LeftTackle => "left-tackle",
            PeerTarget::RightTackle => "right-tackle",
        }
    }

    /// Index into the fixed-size peer array in `OLineContext`.
    pub(crate) fn idx(&self) -> usize {
        match self {
            PeerTarget::Snapshot => 0,
            PeerTarget::Seed => 1,
            PeerTarget::LeftTackle => 2,
            PeerTarget::RightTackle => 3,
        }
    }
}

/// One named unit of work in the o-line deployment pipeline.
///
/// Steps that share the same operation across phases are parameterized;
/// supporting enums classify the target so each variant is human-readable
/// and extensible without adding new flat variants.
#[derive(Debug, Clone, PartialEq)]
pub enum OLineStep {
    /// Bid, accept, and wait for services in the phase to become available.
    Deploy(DeployPhase),
    /// Upsert Cloudflare CNAME records for the phase's `accept:` domains.
    UpdateDns(DeployPhase),
    /// Push pre-start files via SFTP/SSH-pipe, plus optional local script overrides.
    PushFiles(NodeTarget),
    /// Verify pre-start file delivery and fire `OLINE_PHASE=start` on the target node.
    SignalStart(NodeTarget),
    /// Optional boot wait then poll `/status` until the node reports its peer ID.
    WaitPeer { target: PeerTarget, boot_wait_secs: u64 },
    /// Print a recap of all DSEQs and public endpoints.
    Summary,
    /// Workflow finished.
    Complete,

    // ── Parallel deployment path ──────────────────────────────────────────────
    // Steps below implement the "all providers rented at once" strategy.
    // Derive child accounts → deploy all units → parallel wait → distribute snapshot.

    /// Derive HD child accounts and fund them from the master account.
    FundChildAccounts,
    /// Broadcast CreateDeployment for all units (snapshot, seed, minio, tackles, forwards).
    DeployAllUnits,
    /// Interactive: user picks a provider for each deployed unit in sequence.
    SelectAllProviders,
    /// Upsert Cloudflare DNS records for all units in parallel.
    UpdateAllDns,
    /// Poll snapshot RPC until the node is fully synced (catching_up = false).
    WaitSnapshotReady { timeout_secs: u64 },
    /// SSH-stream the snapshot archive from the snapshot node to all waiting nodes.
    DistributeSnapshot,
    /// Push TLS certs + fire OLINE_PHASE=start on all units concurrently.
    SignalAllNodes,
    /// SSH-push updated peer env vars to tackles and forwards after peer IDs are known.
    InjectPeers,
    /// Poll all node RPCs concurrently until each reports at least one peer.
    WaitAllPeers { boot_wait_secs: u64 },
}

impl OLineStep {
    /// Bitmask of parallel execution groups this step belongs to.
    ///
    /// - `0` — step must run sequentially (no concurrency with any other step).
    /// - Non-zero — steps sharing **any** bit belong to the same parallel group
    ///   and **may** be dispatched concurrently by the runtime.
    ///
    /// Bit layout:
    ///   Bit 0 (`0x01`) — DNS updates (all phases may update in parallel)
    ///   Bit 1 (`0x02`) — Pre-start file delivery (Snapshot + Seed + MinIO can push together)
    ///   Bit 2 (`0x04`) — Start signals (Snapshot + Seed can signal together)
    ///   Bit 3 (`0x08`) — Phase A peer polling (Snapshot + Seed can wait together)
    ///   Bit 4 (`0x10`) — Phase B peer polling (LeftTackle + RightTackle wait together)
    pub fn parallel_group(&self) -> u64 {
        match self {
            OLineStep::UpdateDns(_) => 1 << 0,
            OLineStep::PushFiles(_) => 1 << 1,
            OLineStep::SignalStart(_) => 1 << 2,
            OLineStep::WaitPeer {
                target: PeerTarget::Snapshot,
                ..
            } => 1 << 3,
            OLineStep::WaitPeer {
                target: PeerTarget::Seed,
                ..
            } => 1 << 3,
            OLineStep::WaitPeer {
                target: PeerTarget::LeftTackle,
                ..
            } => 1 << 4,
            OLineStep::WaitPeer {
                target: PeerTarget::RightTackle,
                ..
            } => 1 << 4,
            // Deploy, Summary, Complete: sequential only
            _ => 0,
        }
    }

    /// Returns `true` if this step can execute concurrently with `other`.
    ///
    /// Both steps must belong to at least one shared parallel group (non-zero
    /// bit overlap).  Steps with group `0` never parallel with anything.
    pub fn can_parallel_with(&self, other: &OLineStep) -> bool {
        let a = self.parallel_group();
        let b = other.parallel_group();
        a != 0 && b != 0 && (a & b) != 0
    }
}
