//! JMS (just my sockets) subscription converter
//!
//! Converts Base64-encoded proxy links to Clash YAML configuration.
//! Supports: SS, VMess, Trojan, VLESS, Hysteria, Hysteria2, SSR

use std::borrow::Cow;
use std::collections::HashMap;

use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Deserialize;
use serde_json;

/// Decode Base64 if the data appears to be encoded
/// Returns decoded string if successful, otherwise returns original
#[allow(dead_code)]
fn decode_base64_if_needed(data: &str) -> Cow<'_, str> {
    let trimmed = data.trim();

    // If it looks like a proxy link already, no decoding needed
    if trimmed.starts_with("ss://")
        || trimmed.starts_with("vmess://")
        || trimmed.starts_with("trojan://")
        || trimmed.starts_with("vless://")
        || trimmed.starts_with("hysteria://")
        || trimmed.starts_with("hysteria2://")
        || trimmed.starts_with("hy2://")
        || trimmed.starts_with("ssr://")
    {
        return Cow::Borrowed(trimmed);
    }

    // Try Base64 decoding (handles missing padding automatically)
    match BASE64.decode(trimmed) {
        Ok(decoded) => {
            // Try to convert to UTF-8
            match String::from_utf8(decoded) {
                Ok(s) => Cow::Owned(s),
                Err(_) => Cow::Borrowed(trimmed),
            }
        }
        Err(_) => Cow::Borrowed(trimmed),
    }
}

/// Decode Base64 userinfo part (method:password or method:password@host:port)
fn decode_base64_user_info(user_info: &str) -> Result<(String, String)> {
    let decoded = BASE64.decode(user_info)?;
    let decoded_str = String::from_utf8(decoded)?;

    // Check if it contains @ (legacy format with embedded host:port)
    if decoded_str.contains('@') {
        let parts: Vec<&str> = decoded_str.splitn(2, '@').collect();
        if parts.len() != 2 {
            bail!("Invalid legacy SS userinfo format");
        }
        let cred_parts: Vec<&str> = parts[0].splitn(2, ':').collect();
        if cred_parts.len() != 2 {
            bail!("Invalid SS credentials format");
        }
        Ok((cred_parts[0].to_string(), cred_parts[1].to_string()))
    } else {
        // SIP002 format: method:password
        let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            bail!("Invalid SS userinfo format");
        }
        Ok((parts[0].to_string(), parts[1].to_string()))
    }
}

/// URL decode a string (handles %XX encoding)
fn urlencoding_decode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            // Invalid escape, keep as is
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

/// Parse SS plugin options from query string
/// Example: plugin=obfs-local;obfs=http;obfs-host=www.google.com
fn parse_ss_plugin_query(plugin_str: &str) -> HashMap<String, String> {
    let mut opts = HashMap::new();
    let decoded = urlencoding_decode(plugin_str);

    for part in decoded.split(';') {
        if let Some((key, value)) = part.split_once('=') {
            opts.insert(key.to_string(), value.to_string());
        } else if !part.is_empty() {
            opts.insert(part.to_string(), String::new());
        }
    }
    opts
}

/// Parse Shadowsocks URL
/// Supports:
/// - SIP002: ss://base64(method:password)@host:port#name
/// - Legacy: ss://base64(method:password@host:port)#name
/// - With plugin: ss://base64(method:password)@host:port/?plugin=...#name
pub fn parse_ss(line: &str) -> Result<HashMap<String, String>> {
    let mut result = HashMap::new();
    result.insert("type".to_string(), "ss".to_string());

    // Parse URL - use custom parsing to handle base64 with = padding
    let line = line.trim();

    // Extract scheme
    if !line.starts_with("ss://") {
        bail!("Invalid scheme for SS: must start with ss://");
    }

    // Get the part after ss://
    let rest = &line[5..];

    // Find the # to separate userinfo@host:port from #name
    let (userinfo_part, name) = if let Some(pos) = rest.find('#') {
        (&rest[..pos], Some(&rest[pos + 1..]))
    } else {
        (rest, None)
    };

    // Find the @ to separate userinfo from host:port
    let (userinfo, host_port_query) = if let Some(pos) = userinfo_part.rfind('@') {
        (&userinfo_part[..pos], Some(&userinfo_part[pos + 1..]))
    } else {
        // Legacy format: host:port is embedded in base64
        (userinfo_part, None)
    };

    // Parse host:port (and optional query)
    let host_string: String;
    let (host, port, query) = if let Some(hpq) = host_port_query {
        // Check for query string
        let (host_port, query) = if let Some(qpos) = hpq.find("/?") {
            (&hpq[..qpos], Some(&hpq[qpos + 2..]))
        } else {
            (hpq, None)
        };

        if let Some(pos) = host_port.rfind(':') {
            let port_str = &host_port[pos + 1..];
            let port: u16 = port_str
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid port: {}", port_str))?;
            (host_port[..pos].to_string(), port, query)
        } else {
            bail!("Invalid SS URL: missing port");
        }
    } else {
        // Legacy format - need to extract host:port from decoded userinfo
        // Decode userinfo first to get method:password@host:port
        let decoded = BASE64.decode(userinfo)?;
        let decoded_str = String::from_utf8(decoded)?;

        // Find @ in decoded string to get host:port
        if let Some(pos) = decoded_str.rfind('@') {
            let host_port = &decoded_str[pos + 1..];
            if let Some(ppos) = host_port.rfind(':') {
                let port_str = &host_port[ppos + 1..];
                let port: u16 = port_str
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid port in legacy format: {}", port_str))?;
                (host_port[..ppos].to_string(), port, None)
            } else {
                bail!("Invalid legacy SS URL: missing port");
            }
        } else {
            bail!("Invalid legacy SS URL: missing host:port in decoded userinfo");
        }
    };
    host_string = host;

    // Decode userinfo to get method and password
    let (method, password) = decode_base64_user_info(userinfo)?;
    result.insert("cipher".to_string(), method);
    result.insert("password".to_string(), password);

    result.insert("server".to_string(), host_string);
    result.insert("port".to_string(), port.to_string());

    // Get name from fragment
    if let Some(n) = name {
        result.insert("name".to_string(), urlencoding_decode(n));
    }

    // Parse plugin query if present
    if let Some(query) = query {
        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                if key == "plugin" {
                    let plugin_opts = parse_ss_plugin_query(value);
                    if let Some(_plugin_name) = plugin_opts.get("obfs-local") {
                        let mut plugin_str =
                            format!("obfs-local;obfs={}", plugin_opts.get("obfs").unwrap_or(&"".to_string()));
                        if let Some(obfs_host) = plugin_opts.get("obfs-host") {
                            plugin_str.push_str(&format!(";obfs-host={}", obfs_host));
                        }
                        result.insert("plugin".to_string(), plugin_str);
                    } else {
                        result.insert("plugin".to_string(), value.to_string());
                    }
                }
            }
        }
    }

    Ok(result)
}

/// VMess JSON structure for deserializing VMess links
/// Reference: https://www.v2ray.com/en/configuration/transport/websocket.html
#[derive(serde::Deserialize, Debug)]
struct VmessJson {
    /// Server address
    add: String,
    /// Alter ID
    aid: Option<u32>,
    /// Host (used for WebSocket host or SNI)
    host: Option<String>,
    /// User UUID
    id: String,
    /// Network type (tcp, ws, grpc, h2, etc.)
    net: Option<String>,
    /// Path (WebSocket path, gRPC service name)
    path: Option<String>,
    /// Proxy name
    ps: Option<String>,
    /// Server port
    port: u16,
    /// Security method (auto, aes-128-gcm, etc.)
    scy: Option<String>,
    /// TLS settings (tls, reality)
    tls: Option<String>,
    /// Protocol version (should be 2)
    v: Option<String>,
    /// gRPC transport type (multi/gun)
    #[serde(rename = "type")]
    transport_type: Option<String>,
}

/// Parse VMess URL
/// Format: vmess://base64-json
pub fn parse_vmess(line: &str) -> Result<HashMap<String, String>> {
    let mut result = HashMap::new();
    result.insert("type".to_string(), "vmess".to_string());

    let line = line.trim();

    // Extract scheme
    if !line.starts_with("vmess://") {
        bail!("Invalid scheme for VMess: must start with vmess://");
    }

    // Get the base64-encoded JSON after vmess://
    let json_b64 = &line[8..];

    // Decode base64
    let json_bytes = BASE64.decode(json_b64)?;
    let json_str = String::from_utf8(json_bytes)?;

    // Parse JSON
    let vmess: VmessJson = serde_json::from_str(&json_str)?;

    // Extract basic fields
    result.insert("server".to_string(), vmess.add);
    result.insert("port".to_string(), vmess.port.to_string());
    result.insert("uuid".to_string(), vmess.id);

    // Name
    if let Some(ps) = vmess.ps {
        if !ps.is_empty() {
            result.insert("name".to_string(), ps);
        }
    }

    // Network type (default: tcp)
    let network = vmess.net.unwrap_or_else(|| "tcp".to_string());
    result.insert("network".to_string(), network.clone());

    // Security/encryption (default: auto)
    if let Some(scy) = vmess.scy {
        result.insert("cipher".to_string(), scy);
    } else {
        result.insert("cipher".to_string(), "auto".to_string());
    }

    // Handle TLS
    let has_tls = vmess.tls.as_ref().map(|t| !t.is_empty()).unwrap_or(false);
    if has_tls {
        result.insert("tls".to_string(), "true".to_string());
    }

    // Handle transport-specific options
    match network.as_str() {
        "ws" => {
            // WebSocket transport
            let mut ws_opts = HashMap::new();
            if let Some(ref host) = vmess.host {
                if !host.is_empty() {
                    ws_opts.insert("Host".to_string(), host.clone());
                }
            }
            if let Some(ref path) = vmess.path {
                if !path.is_empty() {
                    ws_opts.insert("Path".to_string(), path.clone());
                }
            }
            if !ws_opts.is_empty() {
                result.insert("ws-opts".to_string(), serde_json::to_string(&ws_opts)?);
            }
        }
        "grpc" => {
            // gRPC transport
            let mut grpc_opts = HashMap::new();
            if let Some(ref path) = vmess.path {
                if !path.is_empty() {
                    grpc_opts.insert("grpc-service-name".to_string(), path.clone());
                }
            }
            if let Some(ref transport_type) = vmess.transport_type {
                if !transport_type.is_empty() {
                    grpc_opts.insert("grpc-mode".to_string(), transport_type.clone());
                }
            }
            if !grpc_opts.is_empty() {
                result.insert("grpc-opts".to_string(), serde_json::to_string(&grpc_opts)?);
            }
        }
        "h2" => {
            // HTTP/2 transport
            let mut h2_opts = HashMap::new();
            if let Some(ref host) = vmess.host {
                if !host.is_empty() {
                    h2_opts.insert("Host".to_string(), host.clone());
                }
            }
            if let Some(ref path) = vmess.path {
                if !path.is_empty() {
                    h2_opts.insert("Path".to_string(), path.clone());
                }
            }
            if !h2_opts.is_empty() {
                result.insert("h2-opts".to_string(), serde_json::to_string(&h2_opts)?);
            }
        }
        _ => {
            // TCP or others - handle host for SNI
            if let Some(ref host) = vmess.host {
                if !host.is_empty() && has_tls {
                    result.insert("sni".to_string(), host.clone());
                }
            }
        }
    }

    Ok(result)
}

/// Convert JMS subscription data to Clash YAML
/// Parse Trojan URL
/// Format: trojan://password@host:port?params#name
pub fn parse_trojan(line: &str) -> Result<HashMap<String, String>> {
    use url::Url;

    let mut result = HashMap::new();
    result.insert("type".to_string(), "trojan".to_string());

    let line = line.trim();

    // Extract scheme
    if !line.starts_with("trojan://") {
        bail!("Invalid scheme for Trojan: must start with trojan://");
    }

    // Parse using url crate
    let url_str = format!("trojan://{}", &line[9..]); // Re-add scheme for parsing
    let url = Url::parse(&url_str)?;

    let password = url.username();
    // Extract password (username in URL terms)
    if password.is_empty() {
        bail!("Trojan URL missing password");
    }
    result.insert("password".to_string(), urlencoding_decode(password));

    // Extract server and port
    let host = url.host_str().ok_or_else(|| anyhow::anyhow!("Trojan URL missing host"))?;
    let port = url.port().unwrap_or(443);

    result.insert("server".to_string(), host.to_string());
    result.insert("port".to_string(), port.to_string());

    // Default SNI to host
    result.insert("sni".to_string(), host.to_string());

    // Extract name from fragment
    if let Some(name) = url.fragment() {
        result.insert("name".to_string(), urlencoding_decode(name));
    }

    // Parse query parameters
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "sni" => {
                result.insert("sni".to_string(), value.to_string());
            }
            "type" => {
                match value.as_ref() {
                    "ws" => {
                        result.insert("network".to_string(), "ws".to_string());
                    }
                    "grpc" => {
                        result.insert("network".to_string(), "grpc".to_string());
                    }
                    "h2" | "http" => {
                        result.insert("network".to_string(), "h2".to_string());
                    }
                    _ => {}
                }
            }
            "host" => {
                // Could be ws host or sni
                // Store in ws-opts if network is ws
                if result.get("network").map(|s| s.as_str()) == Some("ws") {
                    let mut ws_opts = HashMap::new();
                    ws_opts.insert("Host".to_string(), value.to_string());
                    // Check for path too
                    if let Some(path) = url.query_pairs().find(|(k, _)| k == "path") {
                        ws_opts.insert("Path".to_string(), path.1.to_string());
                    }
                    result.insert("ws-opts".to_string(), serde_json::to_string(&ws_opts)?);
                } else {
                    result.insert("sni".to_string(), value.to_string());
                }
            }
            "path" => {
                // Add path to appropriate opts based on network
                if result.get("network").map(|s| s.as_str()) == Some("ws") {
                    if let Some(ws_opts_str) = result.get("ws-opts") {
                        let mut ws_opts: HashMap<String, String> = serde_json::from_str(ws_opts_str)?;
                        ws_opts.insert("Path".to_string(), value.to_string());
                        result.insert("ws-opts".to_string(), serde_json::to_string(&ws_opts)?);
                    } else {
                        let mut ws_opts = HashMap::new();
                        ws_opts.insert("Path".to_string(), value.to_string());
                        result.insert("ws-opts".to_string(), serde_json::to_string(&ws_opts)?);
                    }
                } else if result.get("network").map(|s| s.as_str()) == Some("h2") {
                    let mut h2_opts = HashMap::new();
                    h2_opts.insert("Path".to_string(), value.to_string());
                    result.insert("h2-opts".to_string(), serde_json::to_string(&h2_opts)?);
                }
            }
            "tls" | "security" => {
                // TLS is enabled by default for Trojan
            }
            _ => {}
        }
    }

    Ok(result)
}
pub fn convert_jms_to_clash(_data: &str) -> Result<String> {
    bail!("not implemented")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64_if_needed_encoded() {
        let encoded = "c3M6Ly9YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS";
        let decoded = decode_base64_if_needed(encoded);
        // Should return original since it's not pure base64
        assert_eq!(decoded, encoded);
    }

    #[test]
    fn test_decode_base64_if_needed_pure_base64() {
        // Standard base64 encoded ss:// link
        let encoded = "c3M6Ly9hZXMtMTI4LWdjbTpwYXNzd29yZEAxLjIuMy40OjQ0MyNUZXN0U1M=";
        let decoded = decode_base64_if_needed(encoded);
        assert!(decoded.contains("ss://"));
    }

    #[test]
    fn test_decode_base64_if_needed_not_encoded() {
        let plain = "ss://aes-128-gcm:password@1.2.3.4:443#TestSS";
        let decoded = decode_base64_if_needed(plain);
        assert_eq!(decoded, plain);
    }

    #[test]
    fn test_parse_ss_sip002() {
        // SIP002 format: ss://base64(method:password)@host:port#name
        let line = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS";
        let result = parse_ss(line).unwrap();
        assert_eq!(result["name"], "TestSS");
        assert_eq!(result["type"], "ss");
        assert_eq!(result["server"], "1.2.3.4");
        assert_eq!(result["port"], "443");
        assert_eq!(result["cipher"], "aes-128-gcm");
        assert_eq!(result["password"], "password");
    }

    #[test]
    fn test_parse_ss_legacy() {
        // Legacy format: ss://base64(method:password@host:port)#name
        let line = "ss://YWVzLTEyOC1nY206cGFzc3dvcmRAMS4yLjMuNDo0NDM=#TestSS2";
        let result = parse_ss(line).unwrap();
        assert_eq!(result["name"], "TestSS2");
        assert_eq!(result["type"], "ss");
    }

    #[test]
    fn test_parse_ss_with_plugin() {
        // With plugin: ss://base64(method:password)@host:port/?plugin=...#name
        let line = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443/?plugin=obfs-local%3bobfs%3dhttp%3bobfs-host%3dwww.google.com#TestPlugin";
        let result = parse_ss(line).unwrap();
        assert_eq!(result["name"], "TestPlugin");
        assert_eq!(result["plugin"], "obfs-local;obfs=http;obfs-host=www.google.com");
    }

    #[test]
    fn test_parse_vmess_basic() {
        // Basic VMess with JSON payload
        // {"add":"1.2.3.4","aid":0,"host":"","id":"uuid","net":"tcp","path":"","ps":"TestVMess","port":443,"scy":"auto","tls":"","v":"2"}
        let json = "eyJhZGQiOiIxLjIuMy40IiwiYWlkIjowLCJob3N0IjoiIiwiaWQiOiJ1dWlkIiwibmV0IjoidGNwIiwicGF0aCI6IiIsInBzIjoiVGVzdFZNZXNzIiwicG9ydCI6NDQzLCJzY3kiOiJhdXRvIiwidGxzIjoiIiwidiI6IjIifQ==";
        let line = format!("vmess://{}", json);
        let result = parse_vmess(&line).unwrap();
        assert_eq!(result["name"], "TestVMess");
        assert_eq!(result["type"], "vmess");
        assert_eq!(result["server"], "1.2.3.4");
        assert_eq!(result["port"], "443");
        assert_eq!(result["uuid"], "uuid");
    }

    #[test]
    fn test_parse_vmess_with_ws() {
        // VMess with WebSocket transport
        let json = "eyJhZGQiOiIxLjIuMy40IiwiYWlkIjowLCJob3N0Ijoid3MuaG9zdC5jb20iLCJpZCI6InV1aWQiLCJuZXQiOiJ3cyIsInBhdGgiOiIvd3MiLCJwcyI6IlRlc3RXUyIsInBvcnQiOjQ0Mywic2N5IjoiYXV0byIsInRscyI6InRscyIsInYiOiIyIn0=";
        let line = format!("vmess://{}", json);
        let result = parse_vmess(&line).unwrap();
        assert_eq!(result["name"], "TestWS");
        assert_eq!(result["network"], "ws");
        assert!(result.get("ws-opts").is_some());
        assert_eq!(result["tls"], "true");
    }

    #[test]
    fn test_parse_vmess_with_grpc() {
        // VMess with gRPC transport
        let json = "eyJhZGQiOiIxLjIuMy40IiwiYWlkIjowLCJpZCI6InV1aWQiLCJuZXQiOiJncnBjIiwicGF0aCI6ImdycGMtcGF0aCIsInBzIjoiVGVzdEdycGMiLCJwb3J0Ijo0NDMsInNjeSI6ImF1dG8iLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoibXVsdGktZ3JwYyIsInYiOiIyIn0=";
        let line = format!("vmess://{}", json);
        let result = parse_vmess(&line).unwrap();
        assert_eq!(result["name"], "TestGrpc");
        assert_eq!(result["network"], "grpc");
        assert!(result.get("grpc-opts").is_some());
    }

    #[test]
    fn test_parse_trojan_basic() {
        let line = "trojan://password123@1.2.3.4:443#TestTrojan";
        let result = parse_trojan(line).unwrap();
        assert_eq!(result["name"], "TestTrojan");
        assert_eq!(result["type"], "trojan");
        assert_eq!(result["server"], "1.2.3.4");
        assert_eq!(result["port"], "443");
        assert_eq!(result["password"], "password123");
        assert_eq!(result["sni"], "1.2.3.4");
    }

    #[test]
    fn test_parse_trojan_with_ws() {
        let line = "trojan://password123@1.2.3.4:443?type=ws&host=ws.host.com&path=/ws#TestTrojanWS";
        let result = parse_trojan(line).unwrap();
        assert_eq!(result["name"], "TestTrojanWS");
        assert!(result.get("ws-opts").is_some());
    }

    #[test]
    fn test_parse_trojan_with_sni() {
        let line = "trojan://password123@1.2.3.4:443?sni=custom.sni.com#TestTrojanSNI";
        let result = parse_trojan(line).unwrap();
        assert_eq!(result["sni"], "custom.sni.com");
    }}
