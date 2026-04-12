use crate::{
    akash::build_phase_rly_vars,
    cli::prompt_continue,
    dns::cloudflare::cloudflare_update_accept_domains,
    nodes::register_phase_nodes,
    workflow::context::PhaseResult,
    workflow::{OLineWorkflow, StepResult},
    workflow::step::{DeployPhase, OLineStep},
};
use akash_deploy_rs::{DeployError, DeploymentRecord, DeploymentStore};
use std::io::{BufRead, Lines};
use std::path::PathBuf;

pub async fn deploy_relayer(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Phase 5: Deploy IBC Relayer ──");
    if !prompt_continue(lines, "Deploy e.yml?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?
    {
        tracing::info!("  Skipped.");
        w.ctx.set_phase_result(DeployPhase::Relayer, PhaseResult::Skipped);
        w.step = OLineStep::Summary;
        return Ok(StepResult::Continue);
    }

    let e_vars = build_phase_rly_vars(&w.ctx.deployer.config);

    let sdl = match w.ctx.deployer.config.load_sdl("e.yml") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("  Phase E SDL error: {} — skipping.", e);
            w.ctx.set_phase_result(DeployPhase::Relayer, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Summary;
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deploying...");
    let (e_state, e_endpoints) = match w
        .ctx
        .deployer
        .deploy_phase_with_selection(&sdl, &e_vars, "oline-phase-e", lines)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("  Phase E deploy failed: {} — skipping.", e);
            w.ctx.set_phase_result(DeployPhase::Relayer, PhaseResult::Failed(e.to_string()));
            w.step = OLineStep::Summary;
            return Ok(StepResult::Continue);
        }
    };

    tracing::info!("  Deployed! DSEQ: {}", e_state.dseq.unwrap_or(0));
    w.ctx
        .deployer
        .deployment_store
        .save(
            &DeploymentRecord::from_state(&e_state, &w.ctx.deployer.password)
                .map_err(|e| DeployError::InvalidState(e.to_string()))?,
        )
        .await
        .ok();

    // Phase E has its own SSH key — save to disk and register nodes.
    if let Some(privkey_pem) = e_vars.get("SSH_PRIVKEY") {
        let ssh_port_internal: u16 = std::env::var("SSH_P")
            .unwrap_or_else(|_| "22".into())
            .parse()
            .unwrap_or(22);
        let e_key_name = format!("oline-phase-e-key-{}", e_state.dseq.unwrap_or(0));
        let secrets_dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
        let e_key_path = PathBuf::from(&secrets_dir).join(&e_key_name);
        match ssh_key::PrivateKey::from_openssh(privkey_pem.as_bytes()) {
            Ok(k) => {
                if let Err(e) = crate::crypto::save_ssh_key(&k, &e_key_path) {
                    tracing::warn!("  [Phase E] Failed to save SSH key: {}", e);
                } else {
                    let e_services: Vec<String> = e_endpoints
                        .iter()
                        .filter(|ep| ep.internal_port == ssh_port_internal)
                        .map(|ep| ep.service.clone())
                        .collect();
                    let e_svc_pairs: Vec<(&str, String)> = e_services
                        .iter()
                        .map(|svc| (svc.as_str(), format!("Phase E - {}", svc)))
                        .collect();
                    let e_svc_refs: Vec<(&str, &str)> = e_svc_pairs
                        .iter()
                        .map(|(s, l)| (*s, l.as_str()))
                        .collect();
                    register_phase_nodes(
                        &e_endpoints,
                        e_state.dseq.unwrap_or(0),
                        &e_svc_refs,
                        &e_key_name,
                        "E",
                        &w.ctx.deployer.password,
                        ssh_port_internal,
                    );
                }
            }
            Err(e) => tracing::warn!("  [Phase E] Invalid SSH key: {}", e),
        }
    }

    w.ctx.set_endpoints(DeployPhase::Relayer, e_endpoints);
    w.ctx.set_state(DeployPhase::Relayer, e_state);
    w.ctx.set_phase_result(DeployPhase::Relayer, PhaseResult::Deployed);

    w.step = OLineStep::UpdateDns(DeployPhase::Relayer);
    Ok(StepResult::Continue)
}

pub async fn update_dns_relayer(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    if !w.ctx.phase_deployed(&DeployPhase::Relayer) {
        w.step = OLineStep::Summary;
        return Ok(StepResult::Continue);
    }

    let cf_token = w.ctx.deployer.config.val("OLINE_CF_API_TOKEN");
    let cf_zone = w.ctx.deployer.config.val("OLINE_CF_ZONE_ID");

    if !cf_token.is_empty() && !cf_zone.is_empty() {
        let sdl = w.ctx.state(DeployPhase::Relayer).and_then(|s| s.sdl_content.clone());
        if let Some(sdl) = sdl {
            let e_endpoints = w.ctx.endpoints(DeployPhase::Relayer).to_vec();
            cloudflare_update_accept_domains(&sdl, &e_endpoints, &cf_token, &cf_zone).await;
        }
    }

    w.step = OLineStep::Summary;
    Ok(StepResult::Continue)
}
