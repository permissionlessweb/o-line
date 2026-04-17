use crate::{
    akash::{build_phase_a_vars, endpoint_hostname, inject_p2p_nodeport, node_refresh_vars},
    cli::prompt_continue,
    crypto::{
        push_pre_start_files, push_scripts_sftp, verify_files_and_signal_start, FileSource,
        PreStartFile,
    },
    deployer::OLineDeployer,
    dns::cloudflare::{cloudflare_update_accept_domains, cloudflare_update_p2p_domains},
    nodes::register_phase_nodes,
    workflow::step::{DeployPhase, NodeTarget, OLineStep, PeerTarget},
    workflow::{OLineWorkflow, StepResult},
    MAX_RETRIES,
};
use akash_deploy_rs::{AkashBackend, DeployError, DeploymentRecord, DeploymentStore, ProviderAuth};
use std::{
    env::var,
    io::{BufRead, Lines},
};

pub async fn deploy_special_teams(
    w: &mut OLineWorkflow,
    lines: &mut Lines<impl BufRead>,
) -> Result<StepResult, DeployError> {
    tracing::info!("\n── Phase 1: Deploy Snapshot + Seed nodes ──");
    if !prompt_continue(lines, "Deploy Kickoff (Special Teams)?")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?
    {
        tracing::info!("Aborted.");
        w.step = OLineStep::Complete;
        return Ok(StepResult::Complete);
    }

    let secrets_path = var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
    let a_vars = build_phase_a_vars(&w.ctx.deployer.config, &secrets_path)
        .await
        .map_err(|e| DeployError::InvalidState(format!("build_phase_a_vars: {}", e)))?;
    tracing::info!("  Deploying...");
    let sdl = w
        .ctx
        .deployer
        .config
        .load_sdl("a.yml")
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;

    let (a_state, mut a_api) = w
        .ctx
        .deployer
        .deploy_phase_with_selection(&sdl, &a_vars, "oline-phase-a", lines)
        .await?;

    tracing::info!("Deployed! DSEQ: {}", a_state.dseq.unwrap());

    {
        let needs_ingress = |svc: &str| -> bool {
            !a_api.iter().any(|e| {
                e.service == svc && e.internal_port == 0 && (e.port == 443 || e.port == 80)
            })
        };
        let missing: Vec<&str> = ["oline-a-snapshot", "oline-a-seed", "oline-a-minio-ipfs"]
            .iter()
            .copied()
            .filter(|svc| !a_api.iter().any(|e| e.service.as_str() == *svc) || needs_ingress(svc))
            .collect();

        if !missing.is_empty() {
            tracing::info!(
                "  [endpoints] {} service(s) missing from initial query: {} — refreshing from provider API",
                missing.len(),
                missing.join(", ")
            );
            if let (Some(provider_addr), Some(lease_id), Some(jwt)) = (
                a_state.selected_provider.as_deref(),
                a_state.lease_id.as_ref(),
                a_state.jwt_token.as_deref(),
            ) {
                match w
                    .ctx
                    .deployer
                    .client
                    .query_provider_info(provider_addr)
                    .await
                {
                    Ok(Some(info)) => {
                        let auth = ProviderAuth::Jwt {
                            token: jwt.to_string(),
                        };
                        match w
                            .ctx
                            .deployer
                            .client
                            .query_provider_status(&info.host_uri, lease_id, &auth)
                            .await
                        {
                            Ok(status) => {
                                let before = a_api.len();
                                for ep in status.endpoints {
                                    let dup = a_api.iter().any(|e| {
                                        e.service == ep.service
                                            && e.internal_port == ep.internal_port
                                    });
                                    if !dup {
                                        //TODO: create function for service ednpoint to define endport
                                        tracing::info!(
                                            "  [endpoints] {} :{} → NodePort {} ({})",
                                            ep.service,
                                            ep.internal_port,
                                            ep.port,
                                            ep.uri
                                        );
                                        a_api.push(ep);
                                    }
                                }
                                tracing::info!(
                                    "  [endpoints] refreshed: {} → {} total",
                                    before,
                                    a_api.len()
                                );
                            }
                            Err(e) => {
                                tracing::info!("  Warning: provider status query failed: {}", e)
                            }
                        }
                    }
                    Ok(None) => {
                        tracing::info!("  Warning: provider '{}' not found", provider_addr)
                    }
                    Err(e) => tracing::info!("  Warning: could not query provider info: {}", e),
                }
            } else {
                tracing::info!(
                    "  Warning: deployment state missing provider/lease/jwt — cannot refresh endpoints"
                );
            }
        }
    }

    w.ctx
        .deployer
        .deployment_store
        .save(
            &DeploymentRecord::from_state(&a_state, &w.ctx.deployer.password)
                .map_err(|e| DeployError::InvalidState(e.to_string()))?,
        )
        .await
        .ok();

    {
        let ssh_port_internal: u16 = var("SSH_P")
            .unwrap_or_else(|_| "22".into())
            .parse()
            .unwrap_or(22);
        let key_name = format!("{}", a_state.dseq.unwrap());
        register_phase_nodes(
            &a_api,
            a_state.dseq.unwrap_or(0),
            &[
                ("oline-a-snapshot", "Phase A - Snapshot"),
                ("oline-a-seed", "Phase A - Seed"),
                ("oline-a-minio-ipfs", "Phase A - MinIO"),
            ],
            &key_name,
            "A",
            &w.ctx.deployer.password,
            ssh_port_internal,
        );
    }

    let secrets_path = var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
    let ssh_key_path: std::path::PathBuf =
        format!("{}/{}", secrets_path, a_state.dseq.unwrap()).into();
    let ssh_privkey_pem = a_vars
        .get("SSH_PRIVKEY")
        .ok_or_else(|| DeployError::InvalidState("SSH_PRIVKEY missing from phase-A vars".into()))?
        .clone();

    // Save SSH key to disk for subsequent SFTP/SSH steps.
    {
        use crate::crypto::save_ssh_key;
        use ssh_key::PrivateKey;
        let k = PrivateKey::from_openssh(ssh_privkey_pem.as_bytes())
            .map_err(|e| DeployError::InvalidState(format!("Invalid SSH key: {}", e)))?;
        save_ssh_key(&k, &ssh_key_path)
            .map_err(|e| DeployError::InvalidState(format!("save SSH key: {}", e)))?;
    }

    // Build pre_start_files from env: if a local snapshot archive exists, deliver
    // it to each node before signaling bootstrap start.  In production, nodes
    // self-download; the list is empty so push_pre_start_files is a no-op.
    let pre_start_files: Vec<PreStartFile> = {
        let snapshot_path = std::env::var("E2E_SNAP_PATH")
            .or_else(|_| std::env::var("OLINE_PRE_START_SNAP"))
            .ok()
            .map(std::path::PathBuf::from)
            .filter(|p| p.exists());
        let remote_path = std::env::var("SNAPSHOT_SFTP_PATH")
            .unwrap_or_else(|_| "/tmp/snapshot.tar.lz4".into());
        match snapshot_path {
            Some(p) => {
                tracing::info!("  [phase-a] Pre-start snapshot: {:?} → {}", p, remote_path);
                vec![PreStartFile { source: FileSource::Path(p), remote_path }]
            }
            None => {
                tracing::info!("  [phase-a] No local snapshot — nodes will self-download.");
                vec![]
            }
        }
    };

    // Build statesync RPC string for Phase B (cosmos format: "host:port,host:port")
    let snap_rpc_ep =
        OLineDeployer::find_endpoint_by_internal_port(&a_api, "oline-a-snapshot", 26657);
    let seed_rpc_ep = OLineDeployer::find_endpoint_by_internal_port(&a_api, "oline-a-seed", 26657);
    let statesync_rpc = {
        let s = snap_rpc_ep
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port))
            .unwrap_or_default();
        let sd = seed_rpc_ep
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port))
            .unwrap_or_default();
        match (s.is_empty(), sd.is_empty()) {
            (false, false) => format!("{},{}", s, sd),
            (false, true) => s,
            (true, false) => sd,
            (true, true) => String::new(),
        }
    };

    // Print Phase A public endpoints
    {
        let get = |k: &str| a_vars.get(k).map(|s| s.as_str()).unwrap_or("");
        tracing::info!(
            "\n  ┌── Phase A Public Endpoints ──────────────────────────────────────────"
        );
        for (label, rpc, api, grpc, p2p, p2p_port) in [
            (
                "Snapshot",
                "RPC_D_SNAP",
                "API_D_SNAP",
                "GRPC_D_SNAP",
                "P2P_D_SNAP",
                "P2P_P_SNAP",
            ),
            (
                "Seed    ",
                "RPC_D_SEED",
                "API_D_SEED",
                "GRPC_D_SEED",
                "P2P_D_SEED",
                "P2P_P_SEED",
            ),
        ] {
            let (rpc_d, api_d, grpc_d, p2p_d, p2p_p) =
                (get(rpc), get(api), get(grpc), get(p2p), get(p2p_port));
            if !rpc_d.is_empty() {
                tracing::info!("  │  {} RPC:   https://{}", label, rpc_d);
            }
            if !api_d.is_empty() {
                tracing::info!("  │  {} API:   https://{}", label, api_d);
            }
            if !grpc_d.is_empty() {
                tracing::info!("  │  {} gRPC:  {}", label, grpc_d);
            }
            if !p2p_d.is_empty() {
                tracing::info!("  │  {} P2P:   {}:{}", label, p2p_d, p2p_p);
            }
        }
        let metadata_url = get("SNAPSHOT_METADATA_URL");
        let dl_domain = get("SNAPSHOT_DOWNLOAD_DOMAIN");
        if !metadata_url.is_empty() {
            tracing::info!("  │");
            tracing::info!("  │  Snapshot metadata: {}", metadata_url);
        }
        if !dl_domain.is_empty() {
            tracing::info!("  │  MinIO download:    https://{}", dl_domain);
        }
        tracing::info!(
            "  └──────────────────────────────────────────────────────────────────────\n"
        );
    }

    // Populate context
    w.ctx.ssh_key_path = ssh_key_path;
    w.ctx.ssh_privkey_pem = ssh_privkey_pem;
    w.ctx.pre_start_files = pre_start_files;
    w.ctx.a_vars = a_vars;
    w.ctx.statesync_rpc = statesync_rpc;
    w.ctx.set_endpoints(DeployPhase::SpecialTeams, a_api);
    w.ctx.set_state(DeployPhase::SpecialTeams, a_state);
    w.ctx.set_phase_result(
        DeployPhase::SpecialTeams,
        crate::workflow::context::PhaseResult::Deployed,
    );

    w.step = OLineStep::UpdateDns(DeployPhase::SpecialTeams);
    Ok(StepResult::Continue)
}

pub async fn update_dns(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let cf_token = w.ctx.deployer.config.val("OLINE_CF_API_TOKEN");
    let cf_zone = w.ctx.deployer.config.val("OLINE_CF_ZONE_ID");
    if !cf_token.is_empty() && !cf_zone.is_empty() {
        let eps = w.ctx.endpoints(DeployPhase::SpecialTeams).to_vec();

        // HTTP/HTTPS accept domains (proxied through Cloudflare)
        tracing::info!("  Updating Cloudflare DNS for accept domains...");
        let sdl = w
            .ctx
            .state(DeployPhase::SpecialTeams)
            .and_then(|s| s.sdl_content.clone());
        if let Some(sdl) = sdl {
            cloudflare_update_accept_domains(&sdl, &eps, &cf_token, &cf_zone).await;
        }

        // P2P domains: DNS-only A records (NOT proxied — raw TCP for CometBFT P2P)
        let vars = &w.ctx.a_vars;
        let get = |k: &str| vars.get(k).map(|s| s.as_str()).unwrap_or("");
        let snap_p2p: u16 = get("P2P_P_SNAP").parse().unwrap_or(26656);
        let seed_p2p: u16 = get("P2P_P_SEED").parse().unwrap_or(26656);
        let p2p_entries = [
            (get("P2P_D_SNAP"), snap_p2p, "oline-a-snapshot"),
            (get("P2P_D_SEED"), seed_p2p, "oline-a-seed"),
        ];
        cloudflare_update_p2p_domains(&p2p_entries, &eps, &cf_token, &cf_zone).await;
    } else {
        tracing::info!(
            "  Note: Cloudflare DNS not configured — update CNAMEs for accept domains manually."
        );
    }

    w.step = OLineStep::PushFiles(NodeTarget::Snapshot);
    Ok(StepResult::Continue)
}

pub async fn push_files_snapshot(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());
    let nginx_path = var("OLINE_NGINX_PATH").unwrap_or_else(|_| "plays/flea-flicker/nginx".into());

    let snapshot_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-snapshot");
    if snapshot_eps.is_empty() {
        tracing::info!(
            "  Warning: no endpoints found for oline-a-snapshot — skipping file delivery"
        );
    } else {
        tracing::info!("  Delivering pre-start files to snapshot node...");
        push_pre_start_files(
            "phase-a-snapshot",
            &snapshot_eps,
            &w.ctx.ssh_key_path,
            &w.ctx.pre_start_files,
            MAX_RETRIES,
        )
        .await
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;

        if let Err(e) = push_scripts_sftp(
            "phase-a-snapshot",
            &snapshot_eps,
            &w.ctx.ssh_key_path,
            &scripts_path,
            Some(&nginx_path),
        )
        .await
        {
            tracing::info!("  Warning: script upload to snapshot failed: {}", e);
        }
    }

    w.step = OLineStep::SignalStart(NodeTarget::Snapshot);
    Ok(StepResult::Continue)
}

pub async fn signal_snapshot_start(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let snapshot_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-snapshot");
    if snapshot_eps.is_empty() {
        tracing::info!(
            "  Warning: no endpoints found for oline-a-snapshot — skipping verify+start"
        );
    } else {
        let remote_paths: Vec<String> = w.ctx.pre_start_files.iter()
            .map(|f| f.remote_path.clone())
            .collect();
        let mut snapshot_refresh = node_refresh_vars(&w.ctx.a_vars, "SNAP");
        inject_p2p_nodeport(&mut snapshot_refresh, &snapshot_eps, "oline-a-snapshot");
        verify_files_and_signal_start(
            "phase-a-snapshot",
            &snapshot_eps,
            &w.ctx.ssh_key_path,
            &remote_paths,
            &snapshot_refresh,
        )
        .await
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;
    }

    // Print SSH access for all phase-A nodes before the boot wait
    {
        let ssh_port: u16 = var("SSH_P")
            .unwrap_or_else(|_| "22".into())
            .parse()
            .unwrap_or(22);
        tracing::info!("  Phase-A node access (use during boot wait):");
        for (label, service) in [
            ("snapshot", "oline-a-snapshot"),
            ("seed    ", "oline-a-seed"),
            ("minio   ", "oline-a-minio-ipfs"),
        ] {
            if let Some(ep) = w
                .ctx
                .endpoints(DeployPhase::SpecialTeams)
                .iter()
                .find(|e| e.service == service && e.internal_port == ssh_port)
            {
                tracing::info!(
                    "    [{}]  ssh -i {} -o StrictHostKeyChecking=no -p {} root@{}",
                    label,
                    w.ctx.ssh_key_path.display(),
                    ep.port,
                    endpoint_hostname(&ep.uri),
                );
            }
        }
    }

    let boot_wait = var("OLINE_RPC_INITIAL_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120u64);

    w.step = OLineStep::WaitPeer {
        target: PeerTarget::Snapshot,
        boot_wait_secs: boot_wait,
    };
    Ok(StepResult::Continue)
}

pub async fn wait_snapshot_peer(
    w: &mut OLineWorkflow,
    boot_wait_secs: u64,
) -> Result<StepResult, DeployError> {
    let a_eps = w.ctx.endpoints(DeployPhase::SpecialTeams);
    let snap_rpc_url =
        OLineDeployer::find_endpoint_by_internal_port(a_eps, "oline-a-snapshot", 26657)
            .map(|e| format!("http://{}:{}", endpoint_hostname(&e.uri), e.port));
    let snap_p2p_addr =
        OLineDeployer::find_endpoint_by_internal_port(a_eps, "oline-a-snapshot", 26656)
            .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    let snapshot_peer = match (snap_rpc_url.as_deref(), snap_p2p_addr.as_deref()) {
        (Some(rpc), Some(p2p)) => {
            OLineDeployer::extract_peer_id_with_boot_wait(rpc, p2p, boot_wait_secs, 10, 30)
                .await
                .unwrap_or_else(|| {
                    tracing::info!(
                        "  Warning: no RPC/P2P NodePort for snapshot — seed will start without private peer"
                    );
                    String::new()
                })
        }
        _ => {
            tracing::info!(
                "  Warning: no RPC/P2P NodePort for snapshot — seed will start without private peer"
            );
            String::new()
        }
    };
    if !snapshot_peer.is_empty() {
        tracing::info!("  [snapshot] Private peer: {}", snapshot_peer);
    }
    w.ctx.set_peer(PeerTarget::Snapshot, snapshot_peer);

    w.step = OLineStep::PushFiles(NodeTarget::Seed);
    Ok(StepResult::Continue)
}

pub async fn push_files_seed(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let scripts_path = var("OLINE_SCRIPTS_PATH").unwrap_or_else(|_| "plays/audible".into());
    let nginx_path = var("OLINE_NGINX_PATH").unwrap_or_else(|_| "plays/flea-flicker/nginx".into());

    let seed_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-seed");
    if seed_eps.is_empty() {
        tracing::info!("  Warning: no endpoints found for oline-a-seed — skipping file delivery");
    } else {
        tracing::info!("  Delivering pre-start files to seed node...");
        push_pre_start_files(
            "phase-a-seed",
            &seed_eps,
            &w.ctx.ssh_key_path,
            &w.ctx.pre_start_files,
            MAX_RETRIES,
        )
        .await
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;

        if let Err(e) = push_scripts_sftp(
            "phase-a-seed",
            &seed_eps,
            &w.ctx.ssh_key_path,
            &scripts_path,
            Some(&nginx_path),
        )
        .await
        {
            tracing::info!("  Warning: script upload to seed failed: {}", e);
        }
    }

    w.step = OLineStep::SignalStart(NodeTarget::Seed);
    Ok(StepResult::Continue)
}

pub async fn signal_seed_start(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    let seed_eps = w
        .ctx
        .service_endpoints(DeployPhase::SpecialTeams, "oline-a-seed");
    if !seed_eps.is_empty() {
        let snapshot_peer = w.ctx.peer(PeerTarget::Snapshot).to_string();
        let mut seed_refresh = node_refresh_vars(&w.ctx.a_vars, "SEED");
        inject_p2p_nodeport(&mut seed_refresh, &seed_eps, "oline-a-seed");
        if !snapshot_peer.is_empty() {
            // Private peer: don't gossip this ID to the network.
            seed_refresh.insert("TERPD_P2P_PRIVATE_PEER_IDS".into(), snapshot_peer.clone());
            // Persistent peer: always maintain a connection to the snapshot node.
            seed_refresh.insert("TERPD_P2P_PERSISTENT_PEERS".into(), snapshot_peer.clone());
            tracing::info!(
                "  [seed] Injecting snapshot peer (private+persistent): {}",
                snapshot_peer
            );
        }
        let remote_paths: Vec<String> = w.ctx.pre_start_files.iter()
            .map(|f| f.remote_path.clone())
            .collect();
        verify_files_and_signal_start(
            "phase-a-seed",
            &seed_eps,
            &w.ctx.ssh_key_path,
            &remote_paths,
            &seed_refresh,
        )
        .await
        .map_err(|e| DeployError::InvalidState(e.to_string()))?;
    }

    w.step = OLineStep::PushFiles(NodeTarget::Minio);
    Ok(StepResult::Continue)
}

pub async fn push_files_minio(w: &mut OLineWorkflow) -> Result<StepResult, DeployError> {
    // init-nginx on the minio node only installs+starts sshd when
    // SNAPSHOT_DOWNLOAD_DOMAIN is non-empty. Mirror that guard here.
    let snapshot_dl_domain = w
        .ctx
        .a_vars
        .get("OLINE_SNAP_DOWNLOAD_DOMAIN")
        .map(|s| s.as_str())
        .unwrap_or_default();

    if snapshot_dl_domain.is_empty() {
        tracing::info!(
            "  Note: OLINE_SNAP_DOWNLOAD_DOMAIN not set — skipping minio pre-start file delivery."
        );
    } else {
        let minio_endpoints = w
            .ctx
            .service_endpoints(DeployPhase::SpecialTeams, "oline-a-minio-ipfs");
        if minio_endpoints.is_empty() {
            tracing::info!(
                "  Warning: no endpoints found for oline-a-minio-ipfs — skipping file delivery"
            );
        } else {
            tracing::info!("  Delivering pre-start files to minio-ipfs node...");
            let minio_retries: u16 = var("MINIO_SFTP_RETRIES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60);
            push_pre_start_files(
                "phase-a-minio",
                &minio_endpoints,
                &w.ctx.ssh_key_path,
                &w.ctx.pre_start_files,
                minio_retries,
            )
            .await
            .map_err(|e| DeployError::InvalidState(e.to_string()))?;
        }
    }

    let boot_wait = var("OLINE_RPC_INITIAL_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300u64);

    w.step = OLineStep::WaitPeer {
        target: PeerTarget::Seed,
        boot_wait_secs: boot_wait,
    };
    Ok(StepResult::Continue)
}

pub async fn wait_seed_peer(
    w: &mut OLineWorkflow,
    boot_wait_secs: u64,
) -> Result<StepResult, DeployError> {
    let a_eps = w.ctx.endpoints(DeployPhase::SpecialTeams);
    let seed_rpc_url = OLineDeployer::find_endpoint_by_internal_port(a_eps, "oline-a-seed", 26657)
        .map(|e| format!("http://{}:{}", endpoint_hostname(&e.uri), e.port));
    let seed_p2p_addr = OLineDeployer::find_endpoint_by_internal_port(a_eps, "oline-a-seed", 26656)
        .map(|e| format!("{}:{}", endpoint_hostname(&e.uri), e.port));

    let seed_peer = match (seed_rpc_url.as_deref(), seed_p2p_addr.as_deref()) {
        (Some(rpc), Some(p2p)) => {
            OLineDeployer::extract_peer_id_with_boot_wait(rpc, p2p, boot_wait_secs, 20, 60)
                .await
                .unwrap_or_else(|| {
                    tracing::info!(
                        "  Warning: could not fetch seed peer ID — Phase B will use empty peer."
                    );
                    String::new()
                })
        }
        _ => {
            tracing::info!(
                "  Warning: no RPC/P2P endpoints found for oline-a-seed — skipping peer ID"
            );
            String::new()
        }
    };

    tracing::info!("    snapshot_peer: {}", w.ctx.peer(PeerTarget::Snapshot));
    tracing::info!("    seed_peer:     {}", seed_peer);
    w.ctx.set_peer(PeerTarget::Seed, seed_peer);

    w.step = OLineStep::Deploy(DeployPhase::Tackles);
    Ok(StepResult::Continue)
}
