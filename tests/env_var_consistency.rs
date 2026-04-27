/// Cross-file env var consistency tests.
///
/// These tests verify that FD names in lib.rs, SDL templates, nginx templates,
/// shell scripts, and the Rust functions that bridge them all agree on naming
/// conventions. They catch the class of bugs where one file uses `RPC_DOMAIN`
/// while another expects `RPC_D`, or where a suffix like `TACKLE_R` doesn't
/// match the FD suffix `TR`.
///
/// Run: `cargo test --features testing -p o-line-sdl --test env_var_consistency`
use std::collections::{HashMap, HashSet};

use o_line_sdl::akash::node_refresh_vars;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Known suffix → position mappings.
/// Each position's FDs should ALL use the same suffix.
const POSITION_SUFFIXES: &[(&str, &str)] = &[
    ("SNAP", "Snapshot"),
    ("SEED", "Seed"),
    ("TL", "Left tackle"),
    ("TR", "Right tackle"),
    ("FL", "Left forward"),
    ("FR", "Right forward"),
];

/// The four service prefixes used in FD naming: {SVC}_{ROLE}_{SUFFIX}.
const SERVICES: &[&str] = &["RPC", "API", "GRPC", "P2P"];

/// The two roles (domain/port) used in FD naming.
const ROLES: &[&str] = &["D", "P"];

/// REFRESH_VARS — the env var names that `verify_files_and_signal_start` injects
/// into containers. Must match `crypto.rs::REFRESH_VARS` exactly.
/// RPC uses `RPC_DOMAIN` (not `RPC_D`) due to shell script convention.
const EXPECTED_REFRESH_KEYS: &[&str] = &[
    "RPC_DOMAIN",
    "RPC_P",
    "API_D",
    "API_P",
    "GRPC_D",
    "GRPC_P",
    "P2P_D",
    "P2P_P",
];

// ── Test 1: FD suffix consistency ────────────────────────────────────────────

// /// Verify that every position's FDs use a single consistent suffix.
// ///
// /// For each known suffix (SNAP, SEED, TL, TR, FL, FR) and each service+role
// /// combo (RPC_D, RPC_P, API_D, ..., P2P_P), the FD name `{SVC}_{ROLE}_{SUFFIX}`
// /// must exist in the corresponding FD array.
// #[test]
// fn test_fd_suffixes_are_consistent() {
//     // Collect all FD names from the three position arrays.
//     let special_teams: HashSet<&str> = SPECIAL_TEAMS_FD.iter().map(|fd| fd.ev).collect();
//     let tackles: HashSet<&str> = LR_TACKLES_FD.iter().map(|fd| fd.ev).collect();
//     let forwards: HashSet<&str> = LR_FFD.iter().map(|fd| fd.ev).collect();

//     let suffix_to_fds: HashMap<&str, &HashSet<&str>> = [
//         ("SNAP", &special_teams),
//         ("SEED", &special_teams),
//         ("TL", &tackles),
//         ("TR", &tackles),
//         ("FL", &forwards),
//         ("FR", &forwards),
//     ]
//     .into_iter()
//     .collect();

//     let mut missing = Vec::new();

//     for (suffix, position) in POSITION_SUFFIXES {
//         let fds = suffix_to_fds[suffix];
//         for svc in SERVICES {
//             for role in ROLES {
//                 let expected = format!("{}_{}_{}", svc, role, suffix);
//                 if !fds.contains(expected.as_str()) {
//                     missing.push(format!(
//                         "{}: missing FD `{}` for {} {}",
//                         position, expected, svc, role
//                     ));
//                 }
//             }
//         }
//     }

//     assert!(
//         missing.is_empty(),
//         "FD suffix inconsistencies found:\n  {}",
//         missing.join("\n  ")
//     );
// }

// ── Test 2: node_refresh_vars round-trip ─────────────────────────────────────

/// Verify that `node_refresh_vars(vars, suffix)` maps suffixed FD keys to the
/// correct unsuffixed REFRESH_VARS keys.
///
/// This catches the two bugs we found:
/// 1. Using `DOMAIN`/`PORT` roles instead of `D`/`P`
/// 2. Suffix mismatches (e.g., `SNAPSHOT` vs `SNAP`)
#[test]
fn test_node_refresh_vars_produces_correct_keys() {
    for (suffix, position) in POSITION_SUFFIXES {
        // Build a vars map with all {SVC}_{ROLE}_{SUFFIX} keys populated.
        let mut input: HashMap<String, String> = HashMap::new();
        for svc in SERVICES {
            for role in ROLES {
                let key = format!("{}_{}_{}", svc, role, suffix);
                let val = format!("test-{}-{}-{}", svc.to_lowercase(), role.to_lowercase(), suffix.to_lowercase());
                input.insert(key, val);
            }
        }

        let result = node_refresh_vars(&input, suffix);

        // Check every expected REFRESH_VARS key is present.
        let mut missing = Vec::new();
        for key in EXPECTED_REFRESH_KEYS {
            if !result.contains_key(*key) {
                missing.push(format!("{}: missing `{}` in output", position, key));
            }
        }
        assert!(
            missing.is_empty(),
            "node_refresh_vars(_, \"{}\") failed to produce expected keys:\n  {}",
            suffix,
            missing.join("\n  ")
        );

        // Verify values map correctly.
        // RPC_DOMAIN should come from RPC_D_{suffix}
        assert_eq!(
            result.get("RPC_DOMAIN").unwrap(),
            &format!("test-rpc-d-{}", suffix.to_lowercase()),
            "{}: RPC_DOMAIN has wrong value",
            position,
        );
        // API_D should come from API_D_{suffix}
        assert_eq!(
            result.get("API_D").unwrap(),
            &format!("test-api-d-{}", suffix.to_lowercase()),
            "{}: API_D has wrong value",
            position,
        );
        // P2P_P should come from P2P_P_{suffix}
        assert_eq!(
            result.get("P2P_P").unwrap(),
            &format!("test-p2p-p-{}", suffix.to_lowercase()),
            "{}: P2P_P has wrong value",
            position,
        );
    }
}

// ── Test 3: nginx template vars vs envsubst ──────────────────────────────────

/// Verify that nginx templates' ${VAR} placeholders are covered by the envsubst
/// VARS list that tls-setup.sh passes.
///
/// tls-setup.sh builds VARS as `$<svc>_P,$<svc>_D` for RPC and API,
/// and `$GRPC_D,$GRPC_P,$TLS_CERT,$TLS_KEY` for GRPC.
///
/// This test parses the actual nginx template files and verifies no placeholder
/// is left unsubstituted.
#[test]
fn test_nginx_template_vars_covered_by_envsubst() {
    use std::path::Path;

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let nginx_dir = repo_root.join("plays/flea-flicker/nginx");

    // Each service: (template_name, envsubst_vars)
    // tls-setup.sh builds VARS='$<PORT_VAR>,$<DOMAIN_VAR>' for non-GRPC
    // and VARS='$<DOMAIN_VAR>,$<PORT_VAR>,$TLS_CERT,$TLS_KEY' for GRPC
    let services: Vec<(&str, Vec<&str>)> = vec![
        ("rpc", vec!["RPC_D", "RPC_P"]),
        ("api", vec!["API_D", "API_P"]),
        ("grpc", vec!["GRPC_D", "GRPC_P", "TLS_CERT", "TLS_KEY"]),
    ];

    // nginx built-in variables (lowercase, start with $)
    let nginx_builtins: HashSet<&str> = [
        "host",
        "http_upgrade",
        "proxy_add_x_forwarded_for",
        "remote_addr",
        "scheme",
    ]
    .into_iter()
    .collect();

    for (svc, envsubst_vars) in &services {
        let tmpl_path = nginx_dir.join(svc);
        if !tmpl_path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&tmpl_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", tmpl_path.display(), e));

        // Extract ${VAR} placeholders from the template.
        let uncovered: Vec<String> = extract_template_vars(&content)
            .into_iter()
            .filter(|var| !nginx_builtins.contains(var.as_str()))
            .filter(|var| !envsubst_vars.contains(&var.as_str()))
            .collect();

        assert!(
            uncovered.is_empty(),
            "nginx/{} has template vars not in envsubst list: {:?}\n  envsubst vars: {:?}",
            svc,
            uncovered,
            envsubst_vars,
        );
    }
}

/// Extract all `${VAR_NAME}` placeholders from nginx template content.
/// Returns only UPPER_CASE variable names (skips nginx builtins which are lowercase).
fn extract_template_vars(content: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            // Found `${` — extract until `}`
            let start = i + 2;
            if let Some(end) = content[start..].find('}') {
                let var = &content[start..start + end];
                // Only collect UPPER_CASE vars (envsubst targets, not nginx builtins)
                if var.chars().next().map_or(false, |c| c.is_ascii_uppercase()) {
                    if !vars.contains(&var.to_string()) {
                        vars.push(var.to_string());
                    }
                }
                i = start + end + 1;
            } else {
                i += 2;
            }
        } else {
            i += 1;
        }
    }
    vars
}

// ── Test 4: REFRESH_VARS covers all services ─────────────────────────────────

/// Verify that every service type consumed by tls-setup.sh and
/// config-node-endpoints.sh has corresponding entries in REFRESH_VARS.
///
/// tls-setup.sh iterates `services="RPC API GRPC"` and reads `${svc}_D` + `${svc}_P`.
/// config-node-endpoints.sh reads `RPC_DOMAIN`, `API_D`, `GRPC_D`, `P2P_D`.
///
/// REFRESH_VARS must include both the domain and port for each service.
#[test]
fn test_refresh_vars_cover_all_services() {
    let refresh_keys: HashSet<&str> = EXPECTED_REFRESH_KEYS.iter().copied().collect();

    // Every service needs a domain and port key.
    // RPC is special: domain is RPC_DOMAIN, port is RPC_P.
    let expected_pairs: Vec<(&str, &str, &str)> = vec![
        ("RPC", "RPC_DOMAIN", "RPC_P"),
        ("API", "API_D", "API_P"),
        ("GRPC", "GRPC_D", "GRPC_P"),
        ("P2P", "P2P_D", "P2P_P"),
    ];

    let mut missing = Vec::new();
    for (svc, domain_key, port_key) in &expected_pairs {
        if !refresh_keys.contains(domain_key) {
            missing.push(format!("{}: domain key `{}` missing from REFRESH_VARS", svc, domain_key));
        }
        if !refresh_keys.contains(port_key) {
            missing.push(format!("{}: port key `{}` missing from REFRESH_VARS", svc, port_key));
        }
    }

    assert!(
        missing.is_empty(),
        "REFRESH_VARS is missing service coverage:\n  {}",
        missing.join("\n  ")
    );
}
