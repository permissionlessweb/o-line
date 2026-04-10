use std::path::Path;
use std::sync::Arc;

use axum::{extract::DefaultBodyLimit, Router};
use container_registry::auth;
use sec::Secret;

use super::storage::ensure_registry_dir;

/// Build and start the OCI registry server.
///
/// Binds to `0.0.0.0:<port>` with HTTP basic auth (username/password).
/// Storage is at `OLINE_REGISTRY_DIR` or `~/.config/oline/registry/`.
pub async fn serve(port: u16, username: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let storage_dir = ensure_registry_dir()?;
    serve_with_dir(port, username, password, &storage_dir).await
}

/// Like [`serve`] but with an explicit storage directory (avoids env var races in tests).
pub async fn serve_with_dir(
    port: u16,
    username: &str,
    password: &str,
    storage_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(storage_dir)?;
    tracing::info!("Registry storage: {}", storage_dir.display());

    // Auth: if password is provided, require it for write and allow anonymous read.
    // If no password, allow anonymous read+write (local dev).
    // Note: Anonymous wrapper is required even for open mode — bare Permissions
    // rejects NoCredentials requests.
    let auth: Arc<dyn auth::AuthProvider> = if password.is_empty() {
        Arc::new(auth::Anonymous::new(
            auth::Permissions::ReadWrite,
            auth::Permissions::ReadWrite,
        ))
    } else {
        let mut users = std::collections::HashMap::new();
        users.insert(username.to_string(), Secret::new(password.to_string()));
        Arc::new(auth::Anonymous::new(auth::Permissions::ReadOnly, users))
    };

    let registry = container_registry::ContainerRegistry::builder()
        .storage(&storage_dir)
        .auth_provider(auth)
        .build()
        .map_err(|e| format!("Failed to init registry: {e}"))?;

    let app = Router::new()
        .merge(registry.make_router())
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024)); // 2 GB

    let bind_addr = format!("0.0.0.0:{port}");
    tracing::info!("OCI registry listening on {bind_addr}");
    if !password.is_empty() {
        tracing::info!("  Auth: username={username}, password=****");
    } else {
        tracing::info!("  Auth: open (no password set)");
    }

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    tracing::info!("Shutting down registry...");
}
