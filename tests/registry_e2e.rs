//! Registry end-to-end test — deploys to a local Akash chain using an image
//! served from the embedded OCI registry.
//!
//! Requires: Docker daemon + ict-rs chain infrastructure.
//!
//! Run via:
//! ```bash
//! just test registry e2e
//! # or directly:
//! cargo test --features testing --test registry_e2e -- --nocapture --ignored --test-threads=1
//! ```

#[cfg(feature = "testing")]
mod e2e {
    use o_line_sdl::{
        config::inject_registry_credentials,
        registry::{import::import_image_direct, server, storage::list_registry_images},
        testing::{CometEventKind, IctAkashNetwork, WsEventStream},
    };
    use std::{
        collections::HashSet,
        env,
        net::TcpListener,
        path::PathBuf,
        process::{Command, Stdio},
        time::Duration,
    };
    use tempfile::TempDir;

    fn pick_free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind port 0");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    fn oline_bin() -> PathBuf {
        env!("CARGO_BIN_EXE_oline").into()
    }

    fn test_sdl_dir() -> PathBuf {
        let manifest = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
        PathBuf::from(manifest).join("tests/fixtures/sdls")
    }

    /// Wait for the registry HTTP endpoint to become available.
    async fn wait_for_registry(port: u16) {
        let url = format!("http://127.0.0.1:{port}/v2/");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();

        for _ in 0..30 {
            if client.get(&url).send().await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("registry did not start on port {port} within 6 seconds");
    }

    /// Full registry → Akash deploy e2e:
    ///
    /// 1. Start registry on random port (no auth)
    /// 2. Direct-import `nginx:alpine`
    /// 3. Start `IctAkashNetwork`
    /// 4. Verify SDL credential injection
    /// 5. Deploy via `oline deploy --parallel` with registry image
    /// 6. Assert: deployment created, bid placed, lease created
    #[tokio::test]
    #[ignore]
    async fn test_registry_deploy_to_akash() {
        let _ = tracing_subscriber::fmt::try_init();

        // ── 1. Start embedded registry on a random port (open, no auth) ──────
        let registry_dir = TempDir::new().unwrap();
        let registry_port = pick_free_port();
        std::env::set_var("OLINE_REGISTRY_DIR", registry_dir.path().to_str().unwrap());

        let _registry_handle = tokio::spawn({
            let port = registry_port;
            async move {
                if let Err(e) = server::serve(port, "", "").await {
                    eprintln!("[registry] server error: {e}");
                }
            }
        });

        wait_for_registry(registry_port).await;
        eprintln!("[test] Registry started on port {registry_port}");

        // ── 2. Direct-import nginx:alpine into registry storage ──────────────
        let pull_status = Command::new("docker")
            .args(["pull", "nginx:alpine"])
            .status()
            .expect("docker pull");
        assert!(pull_status.success(), "docker pull nginx:alpine failed");

        import_image_direct("nginx:alpine", registry_dir.path())
            .await
            .expect("import_image_direct failed");

        let images = list_registry_images(registry_dir.path()).unwrap();
        eprintln!("[test] Registry images: {images:?}");
        assert!(
            images.iter().any(|i| i.contains("nginx")),
            "nginx not found in registry"
        );

        // ── 3. Start local Akash network ─────────────────────────────────────
        let net = IctAkashNetwork::start("registry-e2e")
            .await
            .expect("IctAkashNetwork::start()");

        eprintln!("[test] Network ready.");
        eprintln!("[test]   RPC:           {}", net.rpc());
        eprintln!("[test]   gRPC:          {}", net.grpc());
        eprintln!("[test]   Provider URI:  {}", net.provider_uri());
        eprintln!("[test]   Provider addr: {}", net.provider_address());
        eprintln!("[test]   Chain:         {}", net.chain_id());

        // ── 4. Verify SDL credential injection ───────────────────────────────
        let registry_image = format!("127.0.0.1:{registry_port}/library/nginx:alpine");
        let registry_url = format!("http://127.0.0.1:{registry_port}");

        let sample_sdl = format!(
            r#"version: "2.0"
services:
  web:
    image: {registry_image}
    expose:
      - port: 80
        as: 80
        to:
          - global: true
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 0.1
        memory:
          size: 128Mi
        storage:
          - size: 256Mi
  placement:
    dcloud:
      pricing:
        web:
          denom: uact
          amount: 100
deployment:
  web:
    dcloud:
      profile: web
      count: 1
"#
        );

        let injected = inject_registry_credentials(&sample_sdl, &registry_url, "oline", "pass")
            .expect("inject_registry_credentials");
        eprintln!("[test] Injected SDL:\n{injected}");

        let doc: serde_yaml::Value = serde_yaml::from_str(&injected).unwrap();
        let creds = &doc["services"]["web"]["credentials"];
        assert_eq!(
            creds["host"].as_str().unwrap(),
            format!("127.0.0.1:{registry_port}"),
            "credentials host mismatch"
        );
        assert_eq!(creds["username"].as_str().unwrap(), "oline");
        assert_eq!(creds["password"].as_str().unwrap(), "pass");

        // ── 5. Connect WebSocket and fund deployer ───────────────────────────
        let ws = WsEventStream::connect(net.rpc())
            .await
            .expect("WsEventStream::connect");
        let mut event_rx = ws.subscribe();

        let deployer_client = net.deployer_client().await.expect("deployer client");
        let deployer_addr = deployer_client.address().to_string();

        eprintln!("[test] Funding deployer via faucet (200 AKT)...");
        net.faucet(&deployer_addr, 200_000_000)
            .await
            .expect("faucet: fund deployer");

        let mut owners: HashSet<String> = HashSet::new();
        owners.insert(deployer_addr.clone());

        // ── 6. Spawn oline deploy --parallel with registry image ─────────────
        let sdl_dir = env::var("SDL_DIR")
            .unwrap_or_else(|_| test_sdl_dir().to_string_lossy().to_string());
        let secrets_dir = std::env::temp_dir().join("oline-registry-e2e-secrets");
        let _ = std::fs::create_dir_all(&secrets_dir);
        let clean_cwd = std::env::temp_dir().join("oline-registry-e2e-cwd");
        let _ = std::fs::create_dir_all(&clean_cwd);

        let oline_child = Command::new(oline_bin())
            .args(["deploy", "--parallel"])
            .env_clear()
            .current_dir(&clean_cwd)
            .env("HOME", env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
            .env("PATH", env::var("PATH").unwrap_or_default())
            .env("OLINE_NON_INTERACTIVE", "1")
            .env("OLINE_MNEMONIC", &net.deployer_mnemonic)
            .env("OLINE_PASSWORD", "oline-registry-e2e")
            .env("OLINE_RPC_ENDPOINT", net.rpc())
            .env("OLINE_GRPC_ENDPOINT", net.grpc())
            .env("OLINE_REST_ENDPOINT", "")
            .env("OLINE_CHAIN_ID", net.chain_id())
            .env("OLINE_DENOM", "uakt")
            .env("OMNIBUS_IMAGE", &registry_image)
            .env("SDL_DIR", &sdl_dir)
            .env("OLINE_CF_API_TOKEN", "")
            .env("OLINE_CF_ZONE_ID", "")
            .env("SECRETS_PATH", secrets_dir.to_string_lossy().as_ref())
            .env("OLINE_ENCRYPTED_MNEMONIC", "")
            .env("OLINE_FUNDING_METHOD", "direct")
            .env("OLINE_MAX_BID_WAIT", "20")
            .env("OLINE_TEST_STOP_AFTER_DEPLOY", "1")
            .env("OLINE_REGISTRY_URL", &registry_url)
            .env("OLINE_REGISTRY_USERNAME", "oline")
            .env("OLINE_REGISTRY_PASSWORD", "")
            .env(
                "RUST_LOG",
                "info,akash_deploy_rs=debug,test_provider=debug",
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn oline");

        eprintln!(
            "[test] oline spawned (pid {:?})",
            oline_child.id()
        );

        // ── 7. Collect on-chain events ───────────────────────────────────────
        eprintln!("[test] Collecting on-chain events (300 s budget)...");
        let mut orders = Vec::new();
        let mut bids = Vec::new();
        let mut leases = Vec::new();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
        let mut last_heartbeat = tokio::time::Instant::now();

        let (need_orders, need_bids, need_leases) = (1, 1, 1);

        loop {
            if orders.len() >= need_orders
                && bids.len() >= need_bids
                && leases.len() >= need_leases
            {
                eprintln!("[test] All expected events collected.");
                break;
            }
            if tokio::time::Instant::now() > deadline {
                eprintln!("[test] Event collection timed out.");
                break;
            }

            let sleep = tokio::time::sleep(Duration::from_secs(1));
            tokio::pin!(sleep);

            tokio::select! {
                Ok(ev) = event_rx.recv() => {
                    if ev.kind == CometEventKind::Tx {
                        for (key, val) in &ev.attrs {
                            if key.ends_with(".EventOrderCreated.id.owner") {
                                if owners.contains(val) {
                                    eprintln!("[test] OrderCreated for {val}");
                                    orders.push(val.clone());
                                }
                            }
                            if key.ends_with(".EventBidCreated.id.owner") {
                                if owners.contains(val) {
                                    eprintln!("[test] BidCreated for {val}");
                                    bids.push(val.clone());
                                }
                            }
                            if key.ends_with(".EventLeaseCreated.id.owner") {
                                if owners.contains(val) {
                                    eprintln!("[test] LeaseCreated for {val}");
                                    leases.push(val.clone());
                                }
                            }
                        }
                    }
                }
                _ = &mut sleep => {
                    let now = tokio::time::Instant::now();
                    if now.duration_since(last_heartbeat) > Duration::from_secs(30) {
                        eprintln!(
                            "[test] heartbeat: orders={}, bids={}, leases={}",
                            orders.len(), bids.len(), leases.len()
                        );
                        last_heartbeat = now;
                    }
                }
            }
        }

        // ── 8. Wait for oline to finish ──────────────────────────────────────
        let oline_output = tokio::task::spawn_blocking(move || {
            oline_child.wait_with_output().expect("wait_with_output")
        })
        .await
        .expect("join");

        let combined_output = format!(
            "--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&oline_output.stdout),
            String::from_utf8_lossy(&oline_output.stderr),
        );

        // ── 9. Assert ────────────────────────────────────────────────────────
        assert!(
            !orders.is_empty(),
            "Expected >=1 OrderCreated, got 0.\noline output:\n{combined_output}"
        );
        assert!(
            !bids.is_empty(),
            "Expected >=1 BidCreated, got 0.\noline output:\n{combined_output}"
        );
        assert!(
            !leases.is_empty(),
            "Expected >=1 LeaseCreated, got 0.\noline output:\n{combined_output}"
        );

        eprintln!(
            "[test] PASS: orders={}, bids={}, leases={}",
            orders.len(),
            bids.len(),
            leases.len()
        );

        std::env::remove_var("OLINE_REGISTRY_DIR");
    }
}
