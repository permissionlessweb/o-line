use crate::{
    akash::build_phase_c_vars,
    cli::prompt_continue,
    nodes::register_phase_nodes,
    workflow::context::PhaseResult,
    workflow::{OLineWorkflow, StepResult},
    workflow::step::{DeployPhase, OLineStep, PeerTarget},
};
use akash_deploy_rs::{DeployError, DeploymentRecord, DeploymentStore};
use std::io::{BufRead, Lines};

pub async fn deploy_forwards(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Phase 3: Deploy Left & Right Forwards ──");

    if !w.ctx.phase_deployed(&DeployPhase::Tackles) {
        tracing::warn!("  Note: Phase B was not deployed — forwards will lack tackle peers.");
    }

    if !prompt_continue(lines, "Deploy c.yml?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?
    {
        tracing::info!("  Skipping Phase C.");
        w.ctx.set_phase_result(DeployPhase::Forwards, PhaseResult::Skipped);
        w.step = OLineStep::Deploy(DeployPhase::Relayer);
        return Ok(StepResult::Continue);
    }

    let c_vars = build_phase_c_vars(
        &w.ctx.deployer.config,
        w.ctx.peer(PeerTarget::Seed),
        w.ctx.peer(PeerTarget::Snapshot),
        w.ctx.peer(PeerTarget::LeftTackle),
        w.ctx.peer(PeerTarget::RightTackle),
        &w.ctx.statesync_rpc,
    );

    let sdl = match w.ctx.deployer.config.load_sdl("c.yml") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("  Phase C SDL error: {} — skipping.", e);
            w.ctx.set_phase_result(DeployPhase::Forwards, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Deploy(DeployPhase::Relayer);
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deploying...");
    let (c_state, c_endpoints) = match w
        .ctx
        .deployer
        .deploy_phase_with_selection(&sdl, &c_vars, "oline-phase-c", lines)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("  Phase C deploy failed: {} — skipping.", e);
            w.ctx.set_phase_result(DeployPhase::Forwards, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Deploy(DeployPhase::Relayer);
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deployed! DSEQ: {}", c_state.dseq.unwrap_or(0));
    w.ctx
        .deployer
        .deployment_store
        .save(
            &DeploymentRecord::from_state(&c_state, &w.ctx.deployer.password)
                .map_err(|e| DeployError::InvalidState(e.to_string()))?,
        )
        .await
        .ok();

    {
        let ssh_port_internal: u16 = std::env::var("SSH_P")
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
            &c_endpoints,
            c_state.dseq.unwrap_or(0),
            &[
                ("oline-c-left-node", "Phase C - Left Forward"),
                ("oline-c-right-node", "Phase C - Right Forward"),
            ],
            &key_name,
            "C",
            &w.ctx.deployer.password,
            ssh_port_internal,
        );
    }

    w.ctx.set_state(DeployPhase::Forwards, c_state);
    w.ctx.set_phase_result(DeployPhase::Forwards, PhaseResult::Deployed);

    w.step = OLineStep::Deploy(DeployPhase::Relayer);
    Ok(StepResult::Continue)
}
