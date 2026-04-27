use clap::{Args, Subcommand};
use serde_json::Value;
use std::error::Error;

const DEFAULT_CONSOLE_API: &str = "https://console-api.akash.network";

fn console_api_url() -> String {
    std::env::var("AKASH_CONSOLE_API").unwrap_or_else(|_| DEFAULT_CONSOLE_API.to_string())
}

fn console_api_key() -> Result<String, Box<dyn Error>> {
    std::env::var("AKASH_CONSOLE_API_KEY")
        .map_err(|_| "AKASH_CONSOLE_API_KEY not set. Set it in .env or environment.".into())
}

// ── Top-level args ──

#[derive(Args, Debug)]
pub struct ConsoleArgs {
    #[command(subcommand)]
    pub service: ConsoleService,
}

// ── Service subcommands — each maps to a proto service ──

#[derive(Subcommand, Debug)]
pub enum ConsoleService {
    /// Deployment lifecycle: list, get, create, update, close, deposit
    Deployment(MethodArgs),
    /// Lease management: create, status
    Lease(MethodArgs),
    /// Bid listing
    Bid(MethodArgs),
    /// Provider discovery: list, get, leases graph, JWT
    Provider(MethodArgs),
    /// Network node endpoints
    Network(MethodArgs),
    /// Pricing estimates
    Pricing(MethodArgs),
    /// API key management
    Auth(MethodArgs),
    /// Certificate creation
    Certificate(MethodArgs),
    /// Address balances and transactions
    Address(MethodArgs),
    /// Deployment settings (auto top-up)
    Settings(MethodArgs),
}

#[derive(Args, Debug)]
pub struct MethodArgs {
    /// RPC method name (e.g. ListDeployments, GetProvider, GetNodes)
    pub method: String,
    /// JSON body: inline '{"key":"val"}' or '-' for stdin. Fields used in URL
    /// path templates are extracted automatically; remaining fields become
    /// query params (GET) or JSON body (POST/PUT).
    #[arg(default_value = "{}")]
    pub body: String,
}

// ── Route table: (method_name, http_verb, path) ──

type Route = (&'static str, &'static str, &'static str);

const DEPLOYMENT: &[Route] = &[
    ("ListDeployments",         "GET",    "/v1/deployments"),
    ("GetDeployment",           "GET",    "/v1/deployments/{dseq}"),
    ("GetDeploymentByOwnerDseq","GET",    "/v1/deployments/{owner}/{dseq}"),
    ("CreateDeployment",        "POST",   "/v1/deployments"),
    ("UpdateDeployment",        "PUT",    "/v1/deployments/{dseq}"),
    ("CloseDeployment",         "DELETE",  "/v1/deployments/{dseq}"),
    ("DepositDeployment",       "POST",   "/v1/deployments/{dseq}/deposit"),
    ("ListWithResources",       "GET",    "/v1/deployments/resources"),
    ("GetWeeklyDeploymentCost", "GET",    "/v1/deployments/cost/weekly"),
];

const LEASE: &[Route] = &[
    ("CreateLease",    "POST", "/v1/leases"),
    ("GetLeaseStatus", "GET",  "/v1/leases/{dseq}/{gseq}/{oseq}/{provider}"),
];

const BID: &[Route] = &[
    ("ListBids", "GET", "/v1/bids/{dseq}"),
];

const PROVIDER: &[Route] = &[
    ("ListProviders",                 "GET",  "/v1/providers"),
    ("GetProvider",                   "GET",  "/v1/providers/{address}"),
    ("GetProviderActiveLeasesGraph",  "GET",  "/v1/providers/{address}/leases/graph"),
    ("GetJwtToken",                   "POST", "/v1/providers/jwt"),
];

const NETWORK: &[Route] = &[
    ("GetNodes", "GET", "/v1/networks/{network}"),
];

const PRICING: &[Route] = &[
    ("GetPricing", "POST", "/v1/pricing"),
];

const AUTH: &[Route] = &[
    ("ListApiKeys",  "GET",    "/v1/api-keys"),
    ("CreateApiKey",  "POST",   "/v1/api-keys"),
    ("UpdateApiKey",  "PUT",    "/v1/api-keys/{id}"),
    ("DeleteApiKey",  "DELETE", "/v1/api-keys/{id}"),
    ("GetApiKey",     "GET",    "/v1/api-keys/{id}"),
];

const CERTIFICATE: &[Route] = &[
    ("CreateCertificate", "POST", "/v1/certificates"),
];

const ADDRESS: &[Route] = &[
    ("GetAddress",             "GET", "/v1/addresses/{address}"),
    ("GetAddressTransactions", "GET", "/v1/addresses/{address}/transactions"),
];

const SETTINGS: &[Route] = &[
    ("GetDeploymentSetting",    "GET", "/v1/deployment-settings/{dseq}"),
    ("UpdateDeploymentSetting", "PUT", "/v1/deployment-settings/{dseq}"),
];

// ── Execution ──

pub async fn cmd_console(args: ConsoleArgs) -> Result<(), Box<dyn Error>> {
    let base_url = console_api_url();
    let api_key = console_api_key()?;

    let (routes, ma) = match args.service {
        ConsoleService::Deployment(a)  => (DEPLOYMENT,  a),
        ConsoleService::Lease(a)       => (LEASE,       a),
        ConsoleService::Bid(a)         => (BID,         a),
        ConsoleService::Provider(a)    => (PROVIDER,    a),
        ConsoleService::Network(a)     => (NETWORK,     a),
        ConsoleService::Pricing(a)     => (PRICING,     a),
        ConsoleService::Auth(a)        => (AUTH,        a),
        ConsoleService::Certificate(a) => (CERTIFICATE, a),
        ConsoleService::Address(a)     => (ADDRESS,     a),
        ConsoleService::Settings(a)    => (SETTINGS,    a),
    };

    // Resolve method
    let (_, http_method, path_tpl) = routes
        .iter()
        .find(|(name, _, _)| name.eq_ignore_ascii_case(&ma.method))
        .ok_or_else(|| {
            let avail: Vec<&str> = routes.iter().map(|(n, _, _)| *n).collect();
            format!("Unknown method '{}'. Available:\n  {}", ma.method, avail.join("\n  "))
        })?;

    // Parse body
    let body_str = if ma.body == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        buf
    } else {
        ma.body
    };
    let body: Value = serde_json::from_str(&body_str)?;

    // Interpolate path params from body
    let mut path = format!("{}{}", base_url, path_tpl);
    let mut used_keys = Vec::new();
    if let Some(obj) = body.as_object() {
        for (key, val) in obj {
            let placeholder = format!("{{{}}}", key);
            if path.contains(&placeholder) {
                let s = match val {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    v => v.to_string(),
                };
                path = path.replace(&placeholder, &s);
                used_keys.push(key.clone());
            }
        }
    }

    // Build request
    let client = reqwest::Client::new();
    let mut req = match *http_method {
        "GET" => {
            let mut r = client.get(&path);
            // Remaining body fields → query params
            if let Some(obj) = body.as_object() {
                let qp: Vec<(String, String)> = obj
                    .iter()
                    .filter(|(k, _)| !used_keys.contains(k))
                    .map(|(k, v)| {
                        let s = match v {
                            Value::String(s) => s.clone(),
                            Value::Number(n) => n.to_string(),
                            Value::Bool(b) => b.to_string(),
                            v => v.to_string(),
                        };
                        (k.clone(), s)
                    })
                    .collect();
                if !qp.is_empty() {
                    r = r.query(&qp);
                }
            }
            r
        }
        "POST" => client.post(&path).json(&body),
        "PUT" => client.put(&path).json(&body),
        "DELETE" => client.delete(&path),
        _ => return Err(format!("Unsupported method: {}", http_method).into()),
    };

    // Auth
    req = req.header("x-api-key", &api_key);
    req = req.header("Content-Type", "application/json");

    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;

    if !status.is_success() {
        eprintln!("HTTP {}: {}", status.as_u16(), text);
        std::process::exit(1);
    }

    // Pretty-print
    match serde_json::from_str::<Value>(&text) {
        Ok(json) => println!("{}", serde_json::to_string_pretty(&json)?),
        Err(_) => println!("{}", text),
    }

    Ok(())
}
