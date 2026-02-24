/// Extract the hostname (without scheme or port) from a ServiceEndpoint URI.
/// e.g. "https://abc.provider.com" → "abc.provider.com"
///      "http://host:8080"         → "host"
///      "host:8080"                → "host"
pub fn endpoint_hostname(uri: &str) -> &str {
    let s = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    // Strip port if present
    s.split(':').next().unwrap_or(s)
}
