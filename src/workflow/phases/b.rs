use crate::{
    akash::{build_phase_b_vars, endpoint_hostname},
    cli::prompt_continue,
    deployer::OLineDeployer,
    nodes::register_phase_nodes,
    workflow::context::PhaseResult,
    workflow::{OLineWorkflow, StepResult},
    workflow::step::{DeployPhase, OLineStep, PeerTarget},
};
use akash_deploy_rs::{DeployError, DeploymentRecord, DeploymentStore};
use std::io::{BufRead, Lines, StdinLock};

pub async fn deploy_tackles(
    w: &mut OLineWorkflow,
    lines: &mut Lines<StdinLock<'_>>,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Phase 2: Deploy Left & Right Tackles ──");
    if !prompt_continue(lines, "Deploy b.yml?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?
    {
        tracing::info!("  Skipping Phase B.");
        w.ctx.set_phase_result(DeployPhase::Tackles, PhaseResult::Skipped);
        w.step = OLineStep::Deploy(DeployPhase::Forwards);
        return Ok(StepResult::Continue);
    }

    let b_vars = build_phase_b_vars(
        &w.ctx.deployer.config,
        w.ctx.peer(PeerTarget::Snapshot),
        &w.ctx.statesync_rpc,
    );

    let sdl = match w.ctx.deployer.config.load_sdl("b.yml") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("  Phase B SDL error: {} — skipping.", e);
            w.ctx.set_phase_result(DeployPhase::Tackles, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Deploy(DeployPhase::Forwards);
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deploying...");
    let (b_state, b_endpoints) = match w
        .ctx
        .deployer
        .deploy_phase_with_selection(&sdl, &b_vars, "oline-phase-b", lines)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("  Phase B deploy failed: {} — skipping.", e);
            w.ctx.set_phase_result(DeployPhase::Tackles, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Deploy(DeployPhase::Forwards);
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deployed! DSEQ: {}", b_state.dseq.unwrap_or(0));
    w.ctx
        .deployer
        .deployment_store
        .save(
            &DeploymentRecord::from_state(&b_state, &w.ctx.deployer.password)
                .map_err(|e| DeployError::InvalidState(e.to_string()))?,
        )
        .await
        .ok();

    {
        let ssh_port_internal: u16 = std::env::var("SSH_PORT")
            .unwrap_or_else(|_| "22".into())
            .parse()
            .unwrap_or(22);
        let key_name = w
            .ctx
            .ssh_key_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "oline-ssh-key".into());
        register_phase_nodes(
            &b_endpoints,
            b_state.dseq.unwrap_or(0),
            &[
                ("oline-b-left-node", "Phase B - Left Tackle"),
                ("oline-b-right-node", "Phase B - Right Tackle"),
            ],
            &key_name,
            "B",
            &w.ctx.deployer.password,
            ssh_port_internal,
        );
    }

    w.ctx.set_endpoints(DeployPhase::Tackles, b_endpoints);
    w.ctx.set_state(DeployPhase::Tackles, b_state);
    w.ctx.set_phase_result(DeployPhase::Tackles, PhaseResult::Deployed);

    let boot_wait = std::env::var("OLINE_RPC_INITIAL_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300u64);

    w.step = OLineStep::WaitPeer {
        target: PeerTarget::LeftTackle,
        boot_wait_secs: boot_wait,
    };
    Ok(StepResult::Continue)
}

pub async fn wait_left_tackle(
    w: &mut OLineWorkflow,
    boot_wait_secs: u64,
) -> Result<StepResult, DeployError> {
    if !w.ctx.phase_deployed(&DeployPhase::Tackles) {
        w.step = OLineStep::WaitPeer {
            target: PeerTarget::RightTackle,
            boot_wait_secs: 0,
        };
        return Ok(StepResult::Continue);
    }
    let b_eps = w.ctx.endpoints(DeployPhase::Tackles);
    let left_rpc_url = OLineDeployer::find_endpoint_by_internal_port(b_eps, "oline-b-left-node", 26657)
        .map(|e| e.uri.clone());
    let left_p2p_addr = OLineDeployer::find_endpoint_by_internal_port(b_eps, "oline-b-left-node", 26656)
        .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    let left_tackle_peer = match (left_rpc_url.as_deref(), left_p2p_addr.as_deref()) {
        (Some(rpc), Some(p2p)) => {
            OLineDeployer::extract_peer_id_with_boot_wait(rpc, p2p, boot_wait_secs, 20, 60)
                .await
                .unwrap_or_else(|| {
                    tracing::info!("  Warning: could not fetch left-tackle peer ID.");
                    String::new()
                })
        }
        _ => {
            tracing::info!("  Warning: no endpoints for oline-b-left-node");
            String::new()
        }
    };
    w.ctx.set_peer(PeerTarget::LeftTackle, left_tackle_peer);

    w.step = OLineStep::WaitPeer {
        target: PeerTarget::RightTackle,
        boot_wait_secs: 0,
    };
    Ok(StepResult::Continue)
}

pub async fn wait_right_tackle(
    w: &mut OLineWorkflow,
    _boot_wait_secs: u64,
) -> Result<StepResult, DeployError> {
    if !w.ctx.phase_deployed(&DeployPhase::Tackles) {
        w.step = OLineStep::Deploy(DeployPhase::Forwards);
        return Ok(StepResult::Continue);
    }
    let b_eps = w.ctx.endpoints(DeployPhase::Tackles);
    let right_rpc_url = OLineDeployer::find_endpoint_by_internal_port(b_eps, "oline-b-right-node", 26657)
        .map(|e| e.uri.clone());
    let right_p2p_addr = OLineDeployer::find_endpoint_by_internal_port(b_eps, "oline-b-right-node", 26656)
        .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    let right_tackle_peer = match (right_rpc_url.as_deref(), right_p2p_addr.as_deref()) {
        (Some(rpc), Some(p2p)) => {
            // Right tackle waits 0s — it syncs in parallel with left; left already
            // burned the boot wait, so right is usually ready by the time we query.
            OLineDeployer::extract_peer_id_with_boot_wait(rpc, p2p, 0, 20, 60)
                .await
                .unwrap_or_else(|| {
                    tracing::info!("  Warning: could not fetch right-tackle peer ID.");
                    String::new()
                })
        }
        _ => {
            tracing::info!("  Warning: no endpoints for oline-b-right-node");
            String::new()
        }
    };
    w.ctx.set_peer(PeerTarget::RightTackle, right_tackle_peer);

    tracing::info!("    left_tackle:  {}", w.ctx.peer(PeerTarget::LeftTackle));
    tracing::info!("    right_tackle: {}", w.ctx.peer(PeerTarget::RightTackle));

    w.step = OLineStep::Deploy(DeployPhase::Forwards);
    Ok(StepResult::Continue)
}
