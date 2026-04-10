use super::storage::{ensure_registry_dir, list_registry_images, registry_dir};
use std::path::PathBuf;
use std::sync::Mutex;
use tempfile::TempDir;

/// Serialize tests that mutate `OLINE_REGISTRY_DIR` so parallel test threads
/// don't race on the shared process-wide env var.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// `registry_dir()` returns the platform config path + `oline/registry/` when
/// `OLINE_REGISTRY_DIR` is unset.
#[test]
fn test_registry_dir_default() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("OLINE_REGISTRY_DIR");
    let dir = registry_dir();
    let expected = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("oline")
        .join("registry");
    assert_eq!(dir, expected);
}

/// `registry_dir()` honours `OLINE_REGISTRY_DIR`.
#[test]
fn test_registry_dir_env_override() {
    let _guard = ENV_LOCK.lock().unwrap();
    let custom = "/tmp/oline-test-custom-registry";
    std::env::set_var("OLINE_REGISTRY_DIR", custom);
    let dir = registry_dir();
    assert_eq!(dir, PathBuf::from(custom));
    std::env::remove_var("OLINE_REGISTRY_DIR");
}

/// `ensure_registry_dir()` creates the directory inside a tempdir and returns
/// the correct path.
#[test]
fn test_ensure_registry_dir() {
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("registry");
    std::env::set_var("OLINE_REGISTRY_DIR", target.to_str().unwrap());
    let result = ensure_registry_dir().unwrap();
    assert_eq!(result, target);
    assert!(target.exists());
    std::env::remove_var("OLINE_REGISTRY_DIR");
}

/// `list_registry_images` on an empty directory returns an empty vec.
#[test]
fn test_list_empty_registry() {
    let tmp = TempDir::new().unwrap();
    let images = list_registry_images(tmp.path()).unwrap();
    assert!(images.is_empty());
}

/// `list_registry_images` discovers the `tags/<repo>/<image>/<tag>` layout.
#[test]
fn test_list_populated_registry() {
    let tmp = TempDir::new().unwrap();
    let tags = tmp.path().join("tags");

    // Create two images: library/nginx:alpine, myorg/myapp:v1.2
    for (repo, image, tag) in [
        ("library", "nginx", "alpine"),
        ("myorg", "myapp", "v1.2"),
    ] {
        let dir = tags.join(repo).join(image).join(tag);
        std::fs::create_dir_all(&dir).unwrap();
    }

    let images = list_registry_images(tmp.path()).unwrap();
    assert_eq!(images.len(), 2);
    assert!(images.contains(&"library/nginx:alpine".to_string()));
    assert!(images.contains(&"myorg/myapp:v1.2".to_string()));
}

/// `inject_registry_credentials` adds a `credentials:` block to services whose
/// `image:` matches the registry host.
#[test]
fn test_inject_credentials_matching() {
    let sdl = r#"
version: "2.0"
services:
  web:
    image: localhost:5000/library/nginx:alpine
    expose:
      - port: 80
"#;

    let result = crate::config::inject_registry_credentials(
        sdl,
        "http://localhost:5000",
        "oline",
        "secret",
    )
    .unwrap();

    let doc: serde_yaml::Value = serde_yaml::from_str(&result).unwrap();
    let creds = &doc["services"]["web"]["credentials"];
    assert_eq!(creds["host"].as_str().unwrap(), "localhost:5000");
    assert_eq!(creds["username"].as_str().unwrap(), "oline");
    assert_eq!(creds["password"].as_str().unwrap(), "secret");
}

/// `inject_registry_credentials` leaves services with non-matching images untouched.
#[test]
fn test_inject_credentials_no_match() {
    let sdl = r#"
version: "2.0"
services:
  web:
    image: docker.io/library/nginx:alpine
    expose:
      - port: 80
"#;

    let result = crate::config::inject_registry_credentials(
        sdl,
        "http://localhost:5000",
        "oline",
        "secret",
    )
    .unwrap();

    let doc: serde_yaml::Value = serde_yaml::from_str(&result).unwrap();
    assert!(doc["services"]["web"].get("credentials").is_none());
}

/// With two services, only the one whose image matches the registry gets credentials.
#[test]
fn test_inject_credentials_mixed() {
    let sdl = r#"
version: "2.0"
services:
  registry-svc:
    image: localhost:5000/library/nginx:alpine
    expose:
      - port: 80
  public-svc:
    image: nginx:alpine
    expose:
      - port: 8080
"#;

    let result = crate::config::inject_registry_credentials(
        sdl,
        "http://localhost:5000",
        "oline",
        "pass",
    )
    .unwrap();

    let doc: serde_yaml::Value = serde_yaml::from_str(&result).unwrap();

    // registry-svc gets credentials
    let creds = &doc["services"]["registry-svc"]["credentials"];
    assert_eq!(creds["host"].as_str().unwrap(), "localhost:5000");
    assert_eq!(creds["username"].as_str().unwrap(), "oline");

    // public-svc does NOT get credentials
    assert!(doc["services"]["public-svc"].get("credentials").is_none());
}
