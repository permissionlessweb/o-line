# Ephemeral SSH Keys Per Deployment Session

## Problem

Currently the SSH key is shared across all deployments:

1. `build_phase_a_vars()` (akash.rs:194) writes the key to
   `{SECRETS_PATH}/oline-parallel-key` — a **static, global path**
2. `ensure_ssh_key_encrypted()` reuses the key if it already exists
3. The parallel workflow (oline.rs:2832) saves a **second copy** to
   `~/.oline/<dseq>` — but this is the same key, just saved again
4. `NodeRecord.key_name` stores just `"oline-parallel-key"` — a single
   hardcoded key name shared by ALL nodes in ALL sessions
5. `oline manage` resolves the key via `SECRETS_PATH` + `key_name` —
   always points to the same global key

**Result**: One key unlocks every node you've ever deployed. No isolation.
No way to rotate per-session. If you lose the key, everything is exposed.

---

## Design

### Core Principle

**One SSH key per deployment session.** The key lives at a deterministic
path derived from the session ID, so there's no need to add a field to
`OLineSession` — we compute the path from the session ID at runtime.

### Key Location Convention

```
~/.oline/sessions/<session-id>/ssh-key
```

Since `OLineSessionStore` already creates `~/.oline/sessions/<session-id>/`
for `session.json`, the SSH key simply goes in the same directory. No
new struct fields needed — the path is always
`sessions_dir / session_id / "ssh-key"`.

### Flow

```
oline deploy
  │
  ├─ 1. Create OLineSession → session.id = "oline-20260511-a1b2c3"
  │
  ├─ 2. Generate fresh Ed25519 SSH key
  │     Save encrypted to ~/.oline/sessions/oline-20260511-a1b2c3/ssh-key
  │
  ├─ 3. build_phase_a_vars() uses session-specific path
  │     key_path = session_dir.join("ssh-key")
  │     Inserts SSH_PUBKEY + SSH_PRIVKEY + SSH_KEY_PATH into vars
  │
  ├─ 4. All phases (B, C, E) receive the same SSH_PUBKEY
  │     Nodes are provisioned with THIS session's public key only
  │
  ├─ 5. NodeRecord.key_name = "<session-id>/ssh-key"
  │     oline manage resolves to ~/.oline/sessions/<session-id>/ssh-key
  │
  ├─ 6. oline manage displays SSH commands with the correct per-session key
  │
  └─ 7. On session close (deployment complete) or purge:
       Delete ~/.oline/sessions/<session-id>/ssh-key
       Keep session.json for historical reference
```

---

## Changes By File

### 1. `src/sessions.rs` — Add helper for SSH key path

```rust
impl OLineSession {
    /// Absolute path to the ephemeral SSH private key for this session.
    /// Convention: ~/.oline/sessions/<session-id>/ssh-key
    pub fn ssh_key_path(&self) -> PathBuf {
        OLineSessionStore::new()
            .base_dir
            .join(&self.id)
            .join("ssh-key")
    }
}
```

No new fields on the struct. The path is derived from `self.id`.

### 2. `src/akash.rs` — Parameterize `build_phase_a_vars`

Currently (line 194):
```rust
let key_path: PathBuf = format!("{}/oline-parallel-key", secrets_path).into();
```

Change to accept `session_key_path: &Path`:
```rust
pub fn build_phase_a_vars(
    config: &DeployConfig,
    password: &str,
    session_key_path: &Path,  // NEW
) -> HashMap<String, String> {
    // ...
    let key_path = session_key_path.to_path_buf();
    let ssh_key = ensure_ssh_key_encrypted(&key_path, password)?;
    // ...
}
```

Same for `build_phase_b_vars`, `build_phase_c_vars`, `build_phase_rly_vars`
— they receive `SSH_PUBKEY` from phase A's vars already, so they don't
need the key path. Only phase A generates the keypair.

### 3. `src/workflow/oline.rs` — Use session-derived key path

Currently (line 2832):
```rust
let ssh_key_path = crate::config::oline_config_dir()
    .join(a_state.dseq.unwrap().to_string());
```

Change to:
```rust
let ssh_key_path = w.ctx.session.ssh_key_path();
```

This replaces both the old `~/.oline/<dseq>` path AND the old
`{SECRETS_PATH}/oline-parallel-key` path with the session-derived path.

Also update line 417 (the non-parallel path):
```rust
// Before:
w.ctx.ssh_key_path = key_path;
// After:
w.ctx.ssh_key_path = w.ctx.session.ssh_key_path();
```

### 4. `src/nodes/mod.rs` — Update `NodeRecord.key_path()`

Currently (line 82):
```rust
pub fn key_path(&self) -> PathBuf {
    let dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
    PathBuf::from(dir).join(&self.key_name)
}
```

Change to resolve relative to `~/.oline/sessions/`:
```rust
pub fn key_path(&self) -> PathBuf {
    // If key_name contains a slash, it's a session-relative path
    // (e.g. "oline-20260511-a1b2c3/ssh-key")
    if self.key_name.contains('/') {
        crate::config::oline_config_dir()
            .join("sessions")
            .join(&self.key_name)
    } else {
        // Legacy: fall back to SECRETS_PATH (shouldn't happen after migration)
        let dir = std::env::var("SECRETS_PATH").unwrap_or_else(|_| ".".into());
        PathBuf::from(dir).join(&self.key_name)
    }
}
```

### 5. NodeRecord key_name — Use session-relative path

Wherever `NodeRecord::new()` is called, change `key_name` from
`"oline-parallel-key"` to `"<session-id>/ssh-key"`:

```rust
// Before:
NodeRecord::new(..., "oline-parallel-key", ...)
// After:
NodeRecord::new(..., format!("{}/ssh-key", session.id), ...)
```

This requires threading `session.id` to the NodeRecord creation sites
(which are already inside the workflow that has access to the session).

### 6. `src/cmd/deploy.rs` — Generate key at session creation

After `OLineSession::new()` (line 339), generate the SSH key:

```rust
let session = OLineSession::new(funding, &address, &chain_id);

// Generate ephemeral SSH key for this session
let ssh_key_path = session.ssh_key_path();
std::fs::create_dir_all(ssh_key_path.parent().unwrap())?;
let ssh_key = crate::crypto::gen_ssh_key();
crate::crypto::save_ssh_key_encrypted(
    &ssh_key,
    &ssh_key_path,
    &deployer.password,
)?;
tracing::info!("Session {} SSH key → {}", session.id, ssh_key_path.display());
```

### 7. `oline manage` — Display session-scoped keys

The TUI already reads `ssh_key_path` from `NodeRecord.key_path()`. After
the `key_path()` change above, it will automatically resolve to the
session-specific key. No TUI changes needed.

Add a session summary line in the TUI header:

```
Session: oline-20260511-a1b2c3
SSH key: ~/.oline/sessions/oline-20260511-a1b2c3/ssh-key
```

### 8. Session Purge — Delete inactive session keys

Add to `OLineSessionStore`:

```rust
impl OLineSessionStore {
    /// Purge SSH keys from sessions that are not the latest.
    /// Keeps session.json for history but removes the private key.
    pub fn purge_inactive_keys(&self) -> Result<Vec<String>, String> {
        let ids = self.list()?;
        let latest = ids.last();
        let mut purged = Vec::new();
        for id in &ids {
            if Some(id.as_str()) == latest.map(|s| s.as_str()) {
                continue; // keep active session's key
            }
            let key_path = self.base_dir.join(id).join("ssh-key");
            if key_path.exists() {
                std::fs::remove_file(&key_path)
                    .map_err(|e| format!("Failed to remove {:?}: {}", key_path, e))?;
                purged.push(id.clone());
            }
        }
        Ok(purged)
    }
}
```

Wire into `oline deploy` post-completion and `oline manage` startup.

---

## Implementation Order

| # | File | Change | Risk |
|---|------|--------|------|
| 1 | `sessions.rs` | Add `ssh_key_path()` helper | Low |
| 2 | `nodes/mod.rs` | Update `key_path()` for session-relative | Low |
| 3 | `akash.rs` | Accept `session_key_path` param in `build_phase_a_vars` | Medium |
| 4 | `workflow/oline.rs` | Replace hardcoded key paths with `session.ssh_key_path()` | Medium |
| 5 | `cmd/deploy.rs` | Generate key at session creation | Medium |
| 6 | NodeRecord callers | Use `<session-id>/ssh-key` as key_name | Low |
| 7 | `sessions.rs` | Add `purge_inactive_keys()` | Low |
| 8 | TUI | Add session/key display to header | Low |

---

## Open Questions

1. **Password caching**: During deployment, we'll decrypt the key multiple
   times (SFTP cert push, health checks, etc.). Should we cache the decrypted
   key in `/tmp` with restrictive permissions, or prompt for password each
   time? → **User confirmed: yes, cache in /tmp**

2. **Key format**: The key file should be the OpenSSH PEM format (same as
   `ensure_ssh_key_encrypted` currently produces). The `ssh -i` command
   expects this format. → **Keep current format**

3. **Parallel vs sequential**: The parallel workflow already generates a key
   per `build_phase_a_vars` call. The sequential workflow reuses a single
   key. Both should use the session-derived path. → **Single path per session**

---

## Not In Scope

- Ansible bootstrapping (deferred)
- HKDF key derivation from DSEQ (nice-to-have optimization, not required
  for first pass — random key generation is simpler and equally secure)
- Multi-session parallel deployment (user confirmed: 1 session = 1 deploy)
- Backward compatibility (nothing was deployed with the old key scheme)
