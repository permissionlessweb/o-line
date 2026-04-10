use bollard::Docker;
use std::path::Path;

/// List locally available Docker images.
pub async fn list_local_images() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let docker = Docker::connect_with_local_defaults()?;
    let images = docker
        .list_images(Some(bollard::image::ListImagesOptions::<String> {
            all: false,
            ..Default::default()
        }))
        .await?;

    let mut result = Vec::new();
    for image in images {
        for tag in &image.repo_tags {
            if tag != "<none>:<none>" {
                result.push(tag.clone());
            }
        }
    }
    result.sort();
    Ok(result)
}

/// Import a local Docker image into the registry's filesystem storage.
///
/// Uses `docker save` (via bollard) to export the image as a tar stream,
/// then pushes it to the local registry via the OCI Distribution API.
///
/// The registry must be running at `registry_url` for this to work.
pub async fn import_image(
    image_ref: &str,
    registry_url: &str,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse image_ref into (name, tag)
    let (name, tag) = match image_ref.rsplit_once(':') {
        Some((n, t)) => (n, t),
        None => (image_ref, "latest"),
    };

    // Re-tag for registry
    let docker = Docker::connect_with_local_defaults()?;

    // Strip scheme from registry_url for tagging
    let registry_host = registry_url
        .trim_end_matches('/')
        .strip_prefix("https://")
        .or_else(|| registry_url.strip_prefix("http://"))
        .unwrap_or(registry_url);

    let target_tag = format!("{registry_host}/{name}:{tag}");
    tracing::info!("Tagging {image_ref} as {target_tag}");

    docker
        .tag_image(
            image_ref,
            Some(bollard::image::TagImageOptions {
                repo: &format!("{registry_host}/{name}"),
                tag: &tag.to_string(),
            }),
        )
        .await?;

    // Push to registry
    tracing::info!("Pushing {target_tag} to registry...");

    use bollard::auth::DockerCredentials;
    use futures_util::StreamExt;

    let credentials = if !password.is_empty() {
        Some(DockerCredentials {
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            ..Default::default()
        })
    } else {
        None
    };

    let mut stream = docker.push_image(
        &format!("{registry_host}/{name}"),
        Some(bollard::image::PushImageOptions { tag }),
        credentials,
    );

    while let Some(result) = stream.next().await {
        match result {
            Ok(output) => {
                if let Some(status) = &output.status {
                    tracing::info!("  {status}");
                }
                if let Some(error) = &output.error {
                    return Err(format!("Push error: {error}").into());
                }
            }
            Err(e) => return Err(format!("Push failed: {e}").into()),
        }
    }

    tracing::info!("Successfully imported {image_ref} as {target_tag}");
    Ok(())
}

/// Import a local Docker image directly into registry filesystem storage.
///
/// This method does NOT require the registry server to be running.
/// It exports the image via `docker save`, extracts the layers and manifest,
/// and writes them directly to the registry's storage directory.
pub async fn import_image_direct(
    image_ref: &str,
    storage_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use futures_util::StreamExt;
    use std::io::Read;

    let docker = Docker::connect_with_local_defaults()?;

    // Parse image ref
    let (name, tag) = match image_ref.rsplit_once(':') {
        Some((n, t)) => (n, t),
        None => (image_ref, "latest"),
    };

    // Normalize name: replace '/' with library path if simple name
    let repo_name = if name.contains('/') {
        name.to_string()
    } else {
        format!("library/{name}")
    };

    tracing::info!("Exporting {image_ref} from Docker...");

    // Export image as tar
    let mut tar_bytes = Vec::new();
    let mut stream = docker.export_image(image_ref);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        tar_bytes.extend_from_slice(&chunk);
    }

    tracing::info!("  Exported {} bytes, extracting...", tar_bytes.len());

    // Ensure storage dirs exist
    let blobs_dir = storage_dir.join("blobs");
    let manifests_dir = storage_dir.join("manifests");
    let uploads_dir = storage_dir.join("uploads");
    let tags_dir = storage_dir.join("tags");
    for d in [&blobs_dir, &manifests_dir, &uploads_dir, &tags_dir] {
        std::fs::create_dir_all(d)?;
    }

    // Parse the docker save tar.
    //
    // Docker save produces two formats:
    //   Legacy:  <hash>/layer.tar, <config_hash>.json, manifest.json
    //   OCI:     blobs/sha256/<digest>, manifest.json
    //
    // Store all entries in a single map so we can look up whatever paths
    // the manifest references, regardless of format.
    let mut archive = tar::Archive::new(std::io::Cursor::new(&tar_bytes));
    let mut all_files: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();
        // Skip directory entries
        if entry.header().entry_type().is_dir() {
            continue;
        }
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;
        all_files.insert(path, contents);
    }

    let docker_manifest: serde_json::Value = serde_json::from_slice(
        all_files.get("manifest.json").ok_or("No manifest.json found in Docker image")?,
    )?;
    let manifest_arr = docker_manifest.as_array().ok_or("manifest.json is not an array")?;
    let manifest_entry = manifest_arr
        .first()
        .ok_or("Empty manifest.json")?;

    let config_name = manifest_entry["Config"]
        .as_str()
        .ok_or("No Config in manifest")?;
    let layer_paths: Vec<&str> = manifest_entry["Layers"]
        .as_array()
        .ok_or("No Layers in manifest")?
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    // Write config blob
    let config_data = all_files
        .get(config_name)
        .ok_or_else(|| format!("Config {} not found in tar", config_name))?;
    let config_digest = write_blob(&blobs_dir, config_data)?;
    tracing::info!("  Config: sha256:{config_digest}");

    // Write layer blobs
    let mut oci_layers = Vec::new();
    for layer_path in &layer_paths {
        let layer_data = all_files
            .get(*layer_path)
            .ok_or_else(|| format!("Layer {layer_path} not found in tar"))?;
        let layer_digest = write_blob(&blobs_dir, layer_data)?;
        tracing::info!("  Layer:  sha256:{layer_digest} ({} bytes)", layer_data.len());
        oci_layers.push(serde_json::json!({
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar",
            "size": layer_data.len(),
            "digest": format!("sha256:{layer_digest}")
        }));
    }

    // Build OCI manifest
    let oci_manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_data.len(),
            "digest": format!("sha256:{config_digest}")
        },
        "layers": oci_layers
    });

    let manifest_bytes = serde_json::to_vec_pretty(&oci_manifest)?;
    let manifest_digest = write_blob(&manifests_dir, &manifest_bytes)?;

    // Write tag symlink: tags/<repo>/<image>/<tag> -> ../../../manifests/<digest>
    let (repo_part, image_part) = repo_name.split_once('/').unwrap_or(("library", &repo_name));
    let tag_dir = tags_dir.join(repo_part).join(image_part);
    std::fs::create_dir_all(&tag_dir)?;
    let tag_path = tag_dir.join(tag);
    let manifest_rel = std::path::PathBuf::from("../../../manifests").join(&manifest_digest);

    // Remove existing symlink if present
    let _ = std::fs::remove_file(&tag_path);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&manifest_rel, &tag_path)?;

    tracing::info!("Imported {repo_part}/{image_part}:{tag}");
    tracing::info!("  Manifest: sha256:{manifest_digest}");

    Ok(())
}

/// Write data to a blob file named by its sha256 digest. Returns the hex digest.
fn write_blob(dir: &Path, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest_hex = hex::encode(hasher.finalize());

    let blob_path = dir.join(&digest_hex);
    if !blob_path.exists() {
        std::fs::write(&blob_path, data)?;
    }
    Ok(digest_hex)
}
