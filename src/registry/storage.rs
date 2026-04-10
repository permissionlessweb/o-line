use std::path::PathBuf;

/// Resolve the registry storage directory.
///
/// Priority: `OLINE_REGISTRY_DIR` env var > `~/.config/oline/registry/`
pub fn registry_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("OLINE_REGISTRY_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("oline")
        .join("registry")
}

/// Ensure the storage directory exists and return its path.
pub fn ensure_registry_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = registry_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// List all images (repo/image:tag) available in the registry's filesystem storage.
///
/// Walks the `tags/` subdirectory which has structure: `tags/<repo>/<image>/<tag>`.
pub fn list_registry_images(dir: &std::path::Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let tags_dir = dir.join("tags");
    let mut images = Vec::new();

    if !tags_dir.exists() {
        return Ok(images);
    }

    // tags/<repo>/<image>/<tag>
    for repo_entry in std::fs::read_dir(&tags_dir)? {
        let repo_entry = repo_entry?;
        if !repo_entry.file_type()?.is_dir() {
            continue;
        }
        let repo_name = repo_entry.file_name().to_string_lossy().to_string();
        for image_entry in std::fs::read_dir(repo_entry.path())? {
            let image_entry = image_entry?;
            if !image_entry.file_type()?.is_dir() {
                continue;
            }
            let image_name = image_entry.file_name().to_string_lossy().to_string();
            for tag_entry in std::fs::read_dir(image_entry.path())? {
                let tag_entry = tag_entry?;
                let tag_name = tag_entry.file_name().to_string_lossy().to_string();
                images.push(format!("{}/{}:{}", repo_name, image_name, tag_name));
            }
        }
    }

    images.sort();
    Ok(images)
}
