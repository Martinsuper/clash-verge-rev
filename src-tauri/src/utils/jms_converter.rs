//! JMS (just my sockets) subscription converter
//!
//! Converts Base64-encoded proxy links to Clash YAML configuration.
//! Supports: SS, VMess, Trojan, VLESS, Hysteria, Hysteria2, SSR

use std::borrow::Cow;
use std::collections::HashMap;

use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json;
use serde_yaml_ng::{Mapping, Sequence, Value};

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
#[allow(dead_code)]
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
    /// Server port (can be string or number in VMess JSON)
    #[serde(deserialize_with = "deserialize_port")]
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

/// Custom deserializer for port that accepts both string and number
fn deserialize_port<'de, D>(deserializer: D) -> std::result::Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};

    struct PortVisitor;

    impl<'de> Visitor<'de> for PortVisitor {
        type Value = u16;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a port number or string")
        }

        fn visit_u16<E>(self, v: u16) -> std::result::Result<u16, E>
        where
            E: de::Error,
        {
            Ok(v)
        }

        fn visit_u64<E>(self, v: u64) -> std::result::Result<u16, E>
        where
            E: de::Error,
        {
            if v <= u16::MAX as u64 {
                Ok(v as u16)
            } else {
                Err(E::custom("port number too large"))
            }
        }

        fn visit_str<E>(self, v: &str) -> std::result::Result<u16, E>
        where
            E: de::Error,
        {
            v.parse::<u16>().map_err(E::custom)
        }

        fn visit_string<E>(self, v: String) -> std::result::Result<u16, E>
        where
            E: de::Error,
        {
            v.parse::<u16>().map_err(E::custom)
        }
    }

    deserializer.deserialize_any(PortVisitor)
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

    // Add padding if needed (VMess links often have missing padding)
    let json_b64_padded = if json_b64.len() % 4 != 0 {
        let padding_needed = 4 - (json_b64.len() % 4);
        format!("{}{}", json_b64, "=".repeat(padding_needed))
    } else {
        json_b64.to_string()
    };

    // Decode base64
    let json_bytes = BASE64.decode(&json_b64_padded)?;
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

    // Handle TLS - only enable if tls is not empty and not "none"
    let has_tls = vmess.tls.as_ref()
        .map(|t| !t.is_empty() && t != "none")
        .unwrap_or(false);
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
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Trojan URL missing host"))?;
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
            "type" => match value.as_ref() {
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
            },
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

/// Parse VLESS URL
/// Format: vless://uuid@host:port?params#name
pub fn parse_vless(line: &str) -> Result<HashMap<String, String>> {
    use url::Url;

    let mut result = HashMap::new();
    result.insert("type".to_string(), "vless".to_string());

    let line = line.trim();

    // Extract scheme
    if !line.starts_with("vless://") {
        bail!("Invalid scheme for VLESS: must start with vless://");
    }

    // Parse using url crate
    let url_str = format!("vless://{}", &line[8..]); // Re-add scheme for parsing
    let url = Url::parse(&url_str)?;

    let uuid = url.username();
    // Extract UUID (username in URL terms)
    if uuid.is_empty() {
        bail!("VLESS URL missing UUID");
    }
    result.insert("uuid".to_string(), urlencoding_decode(uuid));

    // Extract server and port
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("VLESS URL missing host"))?;
    let port = url.port().unwrap_or(443);

    result.insert("server".to_string(), host.to_string());
    result.insert("port".to_string(), port.to_string());

    // Extract name from fragment
    if let Some(name) = url.fragment() {
        result.insert("name".to_string(), urlencoding_decode(name));
    }

    // Parse query parameters
    let mut has_tls = false;
    let mut has_reality = false;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "encryption" => {
                // Usually "none" for VLESS
            }
            "flow" => {
                result.insert("flow".to_string(), value.to_string());
            }
            "security" => match value.as_ref() {
                "tls" => {
                    has_tls = true;
                    result.insert("tls".to_string(), "true".to_string());
                }
                "reality" => {
                    has_reality = true;
                    result.insert("tls".to_string(), "true".to_string());
                }
                _ => {}
            },
            "sni" => {
                result.insert("sni".to_string(), value.to_string());
            }
            "fp" | "fingerprint" => {
                result.insert("fingerprint".to_string(), value.to_string());
            }
            "type" => match value.as_ref() {
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
            },
            "host" => {
                // Could be ws host or sni
                if result.get("network").map(|s| s.as_str()) == Some("ws") {
                    let mut ws_opts = HashMap::new();
                    ws_opts.insert("Host".to_string(), value.to_string());
                    // Check for path too
                    if let Some(path) = url.query_pairs().find(|(k, _)| k == "path") {
                        ws_opts.insert("Path".to_string(), path.1.to_string());
                    }
                    result.insert("ws-opts".to_string(), serde_json::to_string(&ws_opts)?);
                } else if !has_tls && !has_reality {
                    // Only use as SNI if no TLS
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
                } else if result.get("network").map(|s| s.as_str()) == Some("grpc") {
                    let mut grpc_opts = HashMap::new();
                    grpc_opts.insert("grpc-service-name".to_string(), value.to_string());
                    result.insert("grpc-opts".to_string(), serde_json::to_string(&grpc_opts)?);
                }
            }
            "pbk" => {
                // Public key for Reality
                if has_reality {
                    let mut reality_opts = HashMap::new();
                    reality_opts.insert("PublicKey".to_string(), value.to_string());
                    if let Some(sid) = url.query_pairs().find(|(k, _)| k == "sid") {
                        reality_opts.insert("ShortID".to_string(), sid.1.to_string());
                    }
                    result.insert("reality-opts".to_string(), serde_json::to_string(&reality_opts)?);
                }
            }
            "sid" => {
                // Short ID for Reality - handled with pbk
            }
            "spx" => {
                // Skip TLS verification
            }
            _ => {}
        }
    }

    // If has TLS but no SNI, default SNI to host
    if (has_tls || has_reality) && !result.contains_key("sni") {
        result.insert("sni".to_string(), host.to_string());
    }

    Ok(result)
}

/// Parse host:port from a string
/// Returns (host, port) or error if parsing fails
#[allow(dead_code)]
fn parse_host_port(host_port: &str) -> Result<(String, u16)> {
    if let Some(pos) = host_port.rfind(':') {
        let port_str = &host_port[pos + 1..];
        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid port: {}", port_str))?;
        Ok((host_port[..pos].to_string(), port))
    } else {
        bail!("Invalid host:port format: missing port");
    }
}

/// Parse Hysteria URL
/// Format: hysteria://host:port?params#name
/// Params: auth, obfs, up/upmbps, down/downmbps, alpn, sni
pub fn parse_hysteria(line: &str) -> Result<HashMap<String, String>> {
    use url::Url;

    let mut result = HashMap::new();
    result.insert("type".to_string(), "hysteria".to_string());

    let line = line.trim();

    // Extract scheme
    if !line.starts_with("hysteria://") {
        bail!("Invalid scheme for Hysteria: must start with hysteria://");
    }

    // Parse using url crate - the line already starts with hysteria://
    let url = Url::parse(line)?;

    // Extract server and port
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Hysteria URL missing host"))?;
    let port = url.port().unwrap_or(443);

    result.insert("server".to_string(), host.to_string());
    result.insert("port".to_string(), port.to_string());

    // Extract name from fragment
    if let Some(name) = url.fragment() {
        result.insert("name".to_string(), urlencoding_decode(name));
    }

    // Parse query parameters
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "auth" => {
                result.insert("auth_str".to_string(), value.to_string());
            }
            "obfs" => {
                result.insert("obfs".to_string(), value.to_string());
            }
            "up" => {
                result.insert("up".to_string(), value.to_string());
            }
            "down" => {
                result.insert("down".to_string(), value.to_string());
            }
            "upmbps" => {
                result.insert("up_mbps".to_string(), value.to_string());
            }
            "downmbps" => {
                result.insert("down_mbps".to_string(), value.to_string());
            }
            "alpn" => {
                result.insert("alpn".to_string(), value.to_string());
            }
            "sni" => {
                result.insert("sni".to_string(), value.to_string());
            }
            _ => {}
        }
    }

    Ok(result)
}

/// Parse Hysteria2 URL
/// Format: hy2://password@host:port?params#name or hysteria2://password@host:port?params#name
/// Params: sni, obfs, obfs-password, insecure (skip-cert-verify)
pub fn parse_hysteria2(line: &str) -> Result<HashMap<String, String>> {
    use url::Url;

    let mut result = HashMap::new();
    result.insert("type".to_string(), "hysteria2".to_string());

    let line = line.trim();

    // Handle both hy2:// and hysteria2:// prefixes - just use the line directly
    // The line already starts with the correct prefix
    let url = Url::parse(line)?;

    // Extract password (username in URL terms)
    let password = url.username();
    if password.is_empty() {
        bail!("Hysteria2 URL missing password");
    }
    result.insert("password".to_string(), urlencoding_decode(password));

    // Extract server and port
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Hysteria2 URL missing host"))?;
    let port = url.port().unwrap_or(443);

    result.insert("server".to_string(), host.to_string());
    result.insert("port".to_string(), port.to_string());

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
            "obfs" => {
                result.insert("obfs".to_string(), value.to_string());
            }
            "obfs-password" => {
                result.insert("obfs-password".to_string(), value.to_string());
            }
            "insecure" => {
                // Convert "1" or "true" to "true"
                if value == "1" || value == "true" {
                    result.insert("skip-cert-verify".to_string(), "true".to_string());
                }
            }
            _ => {}
        }
    }

    // Default SNI to host if not specified
    if !result.contains_key("sni") {
        result.insert("sni".to_string(), host.to_string());
    }

    Ok(result)
}

/// Parse a single proxy line and return the proxy configuration
/// Dispatches to the appropriate parser based on the URL scheme
pub fn parse_proxy_line(line: &str) -> Result<HashMap<String, String>> {
    let line = line.trim();

    // Skip empty lines
    if line.is_empty() {
        bail!("Empty proxy line");
    }

    // Dispatch based on scheme
    if line.starts_with("ss://") {
        parse_ss(line)
    } else if line.starts_with("vmess://") {
        parse_vmess(line)
    } else if line.starts_with("trojan://") {
        parse_trojan(line)
    } else if line.starts_with("vless://") {
        parse_vless(line)
    } else if line.starts_with("hysteria://") {
        parse_hysteria(line)
    } else if line.starts_with("hy2://") || line.starts_with("hysteria2://") {
        parse_hysteria2(line)
    } else if line.starts_with("ssr://") {
        parse_ssr(line)
    } else {
        bail!("Unknown proxy scheme: {}", line.split(':').next().unwrap_or("unknown"));
    }
}

pub fn convert_jms_to_clash(data: &str) -> Result<String> {
    // Step 1: Decode Base64 if needed
    let decoded = decode_base64_if_needed(data);

    // Step 2: Parse each proxy line
    let mut proxies: Sequence = Sequence::new();
    let mut proxy_names: Vec<String> = Vec::new();

    for line in decoded.lines() {
        let line = line.trim();
        // Skip empty lines and comment lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Try to parse the proxy line
        match parse_proxy_line(line) {
            Ok(proxy_map) => {
                // Convert HashMap to serde_yaml_ng::Value::Mapping
                let mut proxy_mapping = Mapping::new();
                for (key, value) in proxy_map {
                    // Handle nested options like ws-opts, grpc-opts, etc.
                    if key.ends_with("-opts") || key == "reality-opts" {
                        // Parse JSON string back to Mapping
                        if let Ok(opts_map) = serde_json::from_str::<HashMap<String, String>>(&value) {
                            let mut opts_mapping = Mapping::new();
                            for (k, v) in opts_map {
                                opts_mapping.insert(Value::String(k), Value::String(v));
                            }
                            proxy_mapping.insert(Value::String(key), Value::Mapping(opts_mapping));
                        } else {
                            proxy_mapping.insert(Value::String(key), Value::String(value));
                        }
                    } else if key == "alpn" {
                        // alpn should be a sequence
                        let alpn_list: Sequence =
                            value.split(',').map(|s| Value::String(s.trim().to_string())).collect();
                        proxy_mapping.insert(Value::String(key), Value::Sequence(alpn_list));
                    } else {
                        proxy_mapping.insert(Value::String(key), Value::String(value));
                    }
                }

                // Get the proxy name for proxy-groups
                let name = proxy_mapping
                    .get(&Value::String("name".to_string()))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unnamed")
                    .to_string();
                proxy_names.push(name);

                proxies.push(Value::Mapping(proxy_mapping));
            }
            Err(e) => {
                // Log the error but continue parsing other proxies
                log::warn!(target: "app", "Failed to parse proxy line '{}': {}", line, e);
            }
        }
    }

    // Step 3: Check if we have any valid proxies
    if proxies.is_empty() {
        bail!("JMS subscription contains no valid proxies");
    }

    // Step 4: Build Clash YAML config
    let mut config = Mapping::new();

    // Add proxies
    config.insert(Value::String("proxies".to_string()), Value::Sequence(proxies));

    // Add proxy-groups
    let mut proxy_groups: Sequence = Sequence::new();

    // Proxy group: select with all proxies + DIRECT
    let mut proxy_group = Mapping::new();
    proxy_group.insert(Value::String("name".to_string()), Value::String("Proxy".to_string()));
    proxy_group.insert(Value::String("type".to_string()), Value::String("select".to_string()));

    let mut group_proxies: Sequence = proxy_names.iter().map(|n| Value::String(n.clone())).collect();
    group_proxies.push(Value::String("DIRECT".to_string()));
    proxy_group.insert(Value::String("proxies".to_string()), Value::Sequence(group_proxies));

    proxy_groups.push(Value::Mapping(proxy_group));

    config.insert(Value::String("proxy-groups".to_string()), Value::Sequence(proxy_groups));

    // Add rules
    let mut rules: Sequence = Sequence::new();
    rules.push(Value::String("MATCH,Proxy".to_string()));
    config.insert(Value::String("rules".to_string()), Value::Sequence(rules));

    // Step 5: Serialize to YAML
    let yaml_str = serde_yaml_ng::to_string(&config)?;

    Ok(yaml_str)
}

/// Parse SSR (ShadowsocksR) URL
/// Format: ssr://base64(server:port:protocol:method:obfs:password_base64/?params)
/// Params: remarks (name, base64 encoded), obfsparam, protoparam, group
pub fn parse_ssr(line: &str) -> Result<HashMap<String, String>> {
    let mut result = HashMap::new();
    result.insert("type".to_string(), "ssr".to_string());

    let line = line.trim();

    // Extract scheme
    if !line.starts_with("ssr://") {
        bail!("Invalid scheme for SSR: must start with ssr://");
    }

    // Get the base64-encoded part after ssr:// (ssr:// = 6 characters)
    let encoded = &line[6..];

    // Decode base64
    let decoded_bytes = BASE64.decode(encoded)?;
    let decoded_str = String::from_utf8(decoded_bytes)?;

    // Find the position of /? to separate the main part from query params
    let (main_part, query_part) = if let Some(pos) = decoded_str.find("/?") {
        (&decoded_str[..pos], Some(&decoded_str[pos + 2..]))
    } else {
        // Try just / without ?
        if let Some(pos) = decoded_str.find('/') {
            (&decoded_str[..pos], Some(&decoded_str[pos + 1..]))
        } else {
            (decoded_str.as_str(), None)
        }
    };

    // Parse main part: server:port:protocol:method:obfs:password_base64
    let parts: Vec<&str> = main_part.split(':').collect();
    if parts.len() < 6 {
        bail!("Invalid SSR URL: not enough parts (expected at least 6)");
    }

    let server = parts[0].to_string();
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port: {}", parts[1]))?;
    let protocol = parts[2].to_string();
    let method = parts[3].to_string();
    let obfs = parts[4].to_string();
    let password_base64 = parts[5];

    // Decode password from base64
    let password_bytes = BASE64.decode(password_base64)?;
    let password = String::from_utf8(password_bytes)?;

    // Fill in basic fields
    result.insert("server".to_string(), server);
    result.insert("port".to_string(), port.to_string());
    result.insert("cipher".to_string(), method);
    result.insert("password".to_string(), password);

    // Additional SSR fields
    result.insert("protocol".to_string(), protocol);
    result.insert("obfs".to_string(), obfs);

    // Parse query parameters
    if let Some(query) = query_part {
        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                match key {
                    "remarks" => {
                        // Remarks are base64 encoded
                        if let Ok(decoded) = BASE64.decode(value) {
                            if let Ok(name) = String::from_utf8(decoded) {
                                result.insert("name".to_string(), name);
                            }
                        }
                    }
                    "obfsparam" => {
                        if !value.is_empty() {
                            if let Ok(decoded) = BASE64.decode(value) {
                                if let Ok(s) = String::from_utf8(decoded) {
                                    result.insert("obfs-param".to_string(), s);
                                }
                            }
                        }
                    }
                    "protoparam" => {
                        if !value.is_empty() {
                            if let Ok(decoded) = BASE64.decode(value) {
                                if let Ok(s) = String::from_utf8(decoded) {
                                    result.insert("protocol-param".to_string(), s);
                                }
                            }
                        }
                    }
                    "group" => {
                        if !value.is_empty() {
                            if let Ok(decoded) = BASE64.decode(value) {
                                if let Ok(s) = String::from_utf8(decoded) {
                                    result.insert("group".to_string(), s);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(result)
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
    }

    #[test]
    fn test_parse_vless_basic() {
        let line = "vless://uuid-1234-5678@1.2.3.4:443?encryption=none#TestVLESS";
        let result = parse_vless(line).unwrap();
        assert_eq!(result["name"], "TestVLESS");
        assert_eq!(result["type"], "vless");
        assert_eq!(result["server"], "1.2.3.4");
        assert_eq!(result["port"], "443");
        assert_eq!(result["uuid"], "uuid-1234-5678");
    }

    #[test]
    fn test_parse_vless_with_flow() {
        let line = "vless://uuid@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=tls#TestVLESSFlow";
        let result = parse_vless(line).unwrap();
        assert_eq!(result["flow"], "xtls-rprx-vision");
        assert_eq!(result["tls"], "true");
    }

    #[test]
    fn test_parse_ssr_basic() {
        // SSR format: ssr://base64(server:port:protocol:method:obfs:password_base64/?params#name)
        let inner = "1.2.3.4:443:origin:aes-128-cfb:plain:YmFzZTY0cGFzc3dvcmQ=/?obfsparam=&protoparam=&remarks=VGVzdFNTUg==&group=";
        let encoded = base64_encode(inner);
        let line = format!("ssr://{}", encoded);
        let result = parse_ssr(&line).unwrap();
        assert_eq!(result["name"], "TestSSR");
        assert_eq!(result["type"], "ssr");
        assert_eq!(result["server"], "1.2.3.4");
        assert_eq!(result["port"], "443");
        assert_eq!(result["cipher"], "aes-128-cfb");
    }

    fn base64_encode(s: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        BASE64.encode(s.as_bytes())
    }

    #[test]
    fn test_parse_vless_with_reality() {
        let line = "vless://uuid@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.google.com&pbk=publickey&sid=shortid&fp=chrome#TestReality";
        let result = parse_vless(line).unwrap();
        assert!(result.get("reality-opts").is_some());
    }

    #[test]
    fn test_parse_hysteria_basic() {
        let line = "hysteria://1.2.3.4:443?auth=authstring&sni=www.google.com#TestHysteria";
        let result = parse_hysteria(line).unwrap();
        assert_eq!(result["name"], "TestHysteria");
        assert_eq!(result["type"], "hysteria");
        assert_eq!(result["server"], "1.2.3.4");
        assert_eq!(result["port"], "443");
        assert_eq!(result["auth_str"], "authstring");
        assert_eq!(result["sni"], "www.google.com");
    }

    #[test]
    fn test_parse_hysteria_with_obfs() {
        let line = "hysteria://1.2.3.4:443?auth=authstring&obfs=obfsstring&sni=www.google.com#TestHysteriaObfs";
        let result = parse_hysteria(line).unwrap();
        assert_eq!(result["obfs"], "obfsstring");
    }

    #[test]
    fn test_parse_hysteria2_hy2() {
        let line = "hy2://password123@1.2.3.4:443#TestHysteria2";
        let result = parse_hysteria2(line).unwrap();
        assert_eq!(result["name"], "TestHysteria2");
        assert_eq!(result["type"], "hysteria2");
        assert_eq!(result["server"], "1.2.3.4");
        assert_eq!(result["port"], "443");
        assert_eq!(result["password"], "password123");
    }

    #[test]
    fn test_parse_hysteria2_full() {
        let line = "hysteria2://password123@1.2.3.4:443?sni=www.google.com#TestHysteria2Full";
        let result = parse_hysteria2(line).unwrap();
        assert_eq!(result["name"], "TestHysteria2Full");
        assert_eq!(result["sni"], "www.google.com");
    }

    #[test]
    fn test_parse_hysteria2_with_obfs() {
        let line =
            "hy2://password123@1.2.3.4:443?sni=www.google.com&obfs=salamander&obfs-password=obfspass#TestHysteria2Obfs";
        let result = parse_hysteria2(line).unwrap();
        assert_eq!(result["obfs"], "salamander");
        assert_eq!(result["obfs-password"], "obfspass");
    }

    #[test]
    fn test_parse_hysteria2_with_insecure() {
        let line = "hy2://password123@1.2.3.4:443?insecure=1#TestHysteria2Insecure";
        let result = parse_hysteria2(line).unwrap();
        assert_eq!(result["skip-cert-verify"], "true");
    }

    #[test]
    fn test_parse_proxy_line_ss() {
        let line = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS";
        let result = parse_proxy_line(line).unwrap();
        assert_eq!(result["type"], "ss");
        assert_eq!(result["name"], "TestSS");
    }

    #[test]
    fn test_parse_proxy_line_vmess() {
        let json = "eyJhZGQiOiIxLjIuMy40IiwiYWlkIjowLCJob3N0IjoiIiwiaWQiOiJ1dWlkIiwibmV0IjoidGNwIiwicGF0aCI6IiIsInBzIjoiVGVzdFZNZXNzIiwicG9ydCI6NDQzLCJzY3kiOiJhdXRvIiwidGxzIjoiIiwidiI6IjIifQ==";
        let line = format!("vmess://{}", json);
        let result = parse_proxy_line(&line).unwrap();
        assert_eq!(result["type"], "vmess");
        assert_eq!(result["name"], "TestVMess");
    }

    #[test]
    fn test_parse_proxy_line_trojan() {
        let line = "trojan://password123@1.2.3.4:443#TestTrojan";
        let result = parse_proxy_line(line).unwrap();
        assert_eq!(result["type"], "trojan");
    }

    #[test]
    fn test_parse_proxy_line_vless() {
        let line = "vless://uuid@1.2.3.4:443#TestVLESS";
        let result = parse_proxy_line(line).unwrap();
        assert_eq!(result["type"], "vless");
    }

    #[test]
    fn test_parse_proxy_line_hysteria() {
        let line = "hysteria://1.2.3.4:443?auth=authstring#TestHysteria";
        let result = parse_proxy_line(line).unwrap();
        assert_eq!(result["type"], "hysteria");
    }

    #[test]
    fn test_parse_proxy_line_hysteria2() {
        let line = "hy2://password123@1.2.3.4:443#TestHysteria2";
        let result = parse_proxy_line(line).unwrap();
        assert_eq!(result["type"], "hysteria2");
    }

    #[test]
    fn test_parse_proxy_line_ssr() {
        let inner = "1.2.3.4:443:origin:aes-128-cfb:plain:YmFzZTY0cGFzc3dvcmQ=/?remarks=VGVzdFNS";
        let encoded = base64_encode(inner);
        let line = format!("ssr://{}", encoded);
        let result = parse_proxy_line(&line).unwrap();
        assert_eq!(result["type"], "ssr");
    }

    #[test]
    fn test_parse_proxy_line_unknown_scheme() {
        let line = "unknown://test";
        let result = parse_proxy_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_proxy_line_empty() {
        let result = parse_proxy_line("");
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_jms_to_clash_single_proxy() {
        // Single SS proxy
        let data = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS";
        let yaml = convert_jms_to_clash(data).unwrap();

        // Verify YAML contains expected fields
        assert!(yaml.contains("proxies:"));
        assert!(yaml.contains("proxy-groups:"));
        assert!(yaml.contains("rules:"));
        assert!(yaml.contains("name: TestSS"));
        assert!(yaml.contains("type: ss"));
        assert!(yaml.contains("server: 1.2.3.4"));
        assert!(yaml.contains("MATCH,Proxy"));
    }

    #[test]
    fn test_convert_jms_to_clash_multiple_proxies() {
        // Multiple proxies with different protocols
        let data = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS\nvmess://eyJhZGQiOiIxLjIuMy40IiwiYWlkIjowLCJob3N0IjoiIiwiaWQiOiJ1dWlkIiwibmV0IjoidGNwIiwicGF0aCI6IiIsInBzIjoiVGVzdFZNZXNzIiwicG9ydCI6NDQzLCJzY3kiOiJhdXRvIiwidGxzIjoiIiwidiI6IjIifQ==\ntrojan://password123@1.2.3.4:443#TestTrojan";
        let yaml = convert_jms_to_clash(data).unwrap();

        // Verify all proxies are in the output
        assert!(yaml.contains("name: TestSS"));
        assert!(yaml.contains("name: TestVMess"));
        assert!(yaml.contains("name: TestTrojan"));
        assert!(yaml.contains("type: ss"));
        assert!(yaml.contains("type: vmess"));
        assert!(yaml.contains("type: trojan"));

        // Verify proxy group contains all proxies
        assert!(yaml.contains("- TestSS"));
        assert!(yaml.contains("- TestVMess"));
        assert!(yaml.contains("- TestTrojan"));
        assert!(yaml.contains("- DIRECT"));
    }

    #[test]
    fn test_convert_jms_to_clash_base64_encoded() {
        // Base64 encoded proxy links
        let inner = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS";
        let encoded = base64_encode(inner);
        let yaml = convert_jms_to_clash(&encoded).unwrap();

        assert!(yaml.contains("name: TestSS"));
    }

    #[test]
    fn test_convert_jms_to_clash_empty() {
        let result = convert_jms_to_clash("");
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_jms_to_clash_invalid_only() {
        // Only invalid proxy lines
        let data = "unknown://test\ninvalid";
        let result = convert_jms_to_clash(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_jms_to_clash_mixed_valid_invalid() {
        // Mix of valid and invalid lines - should succeed with valid ones
        let data = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS\nunknown://invalid\n# comment\nvmess://eyJhZGQiOiIxLjIuMy40IiwiYWlkIjowLCJob3N0IjoiIiwiaWQiOiJ1dWlkIiwibmV0IjoidGNwIiwicGF0aCI6IiIsInBzIjoiVGVzdFZNZXNzIiwicG9ydCI6NDQzLCJzY3kiOiJhdXRvIiwidGxzIjoiIiwidiI6IjIifQ==";
        let yaml = convert_jms_to_clash(data).unwrap();

        assert!(yaml.contains("name: TestSS"));
        assert!(yaml.contains("name: TestVMess"));
        // Invalid lines should not appear
        assert!(!yaml.contains("unknown"));
        assert!(!yaml.contains("invalid"));
    }

    #[test]
    fn test_convert_real_jms_subscription() {
        // Real JMS subscription content (Base64 encoded)
        let encoded_data = "c3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2YUhneU5FczJjRzFUVjI1NVFsUnpSRUF4TURRdU1UWXdMalExTGpFNU5qbzVPVGs0I0pNUy0xMjYzNTQzQGM3NnMxLnBvcnRhYmxlc3VibWFyaW5lcy5jb206OTk5OApzczovL1lXVnpMVEkxTmkxblkyMDZhSGd5TkVzMmNHMVRWMjU1UWxSelJFQXhNRFF1TVRZd0xqUXpMakV3TWpvNU9UazQjSk1TLTEyNjM1NDNAYzc2czIucG9ydGFibGVzdWJtYXJpbmVzLmNvbTo5OTk4CnZtZXNzOi8vZXlKd2N5STZJa3BOVXkweE1qWXpOVFF6UUdNM05uTXpMbkJ2Y25SaFlteGxjM1ZpYldGeWFXNWxjeTVqYjIwNk9UazVPQ0lzSW5CdmNuUWlPaUk1T1RrNElpd2lhV1FpT2lJeE9ESTBNelU0TmkwMFlUWTBMVFE0Tm1FdE9UQTJNaTFsT0RGalptWTRaVFl4TnpjaUxDSmhhV1FpT2pBc0ltNWxkQ0k2SW5SamNDSXNJblI1Y0dVaU9pSnViMjVsSWl3aWRHeHpJam9pYm05dVpTSXNJbUZrWkNJNklqRTVPQzR6TlM0ME5pNHhNeklpZlEKdm1lc3M6Ly9leUp3Y3lJNklrcE5VeTB4TWpZek5UUXpRR00zTm5NMExuQnZjblJoWW14bGMzVmliV0Z5YVc1bGN5NWpiMjA2T1RrNU9DSXNJbkJ2Y25RaU9pSTVPVGs0SWl3aWFXUWlPaUl4T0RJME16VTROaTAwWVRZMExUUTRObUV0T1RBMk1pMWxPREZqWm1ZNFpUWXhOemNpTENKaGFXUWlPakFzSW01bGRDSTZJblJqY0NJc0luUjVjR1VpT2lKdWIyNWxJaXdpZEd4eklqb2libTl1WlNJc0ltRmtaQ0k2SWpJeE1pNDFNQzR5TlRBdU1qUTNJbjAKdm1lc3M6Ly9leUp3Y3lJNklrcE5VeTB4TWpZek5UUXpRR00zTm5NMUxuQnZjblJoWW14bGMzVmliV0Z5YVc1bGN5NWpiMjA2T1RrNU9DSXNJbkJ2Y25RaU9pSTVPVGs0SWl3aWFXUWlPaUl4T0RJME16VTROaTAwWVRZMExUUTRObUV0T1RBMk1pMWxPREZqWm1ZNFpUWXhOemNpTENKaGFXUWlPakFzSW01bGRDSTZJblJqY0NJc0luUjVjR1VpT2lKdWIyNWxJaXdpZEd4eklqb2libTl1WlNJc0ltRmtaQ0k2SWpFMk1pNHlORGd1TnpRdU56Y2lmUQp2bWVzczovL2V5SndjeUk2SWtwTlV5MHhNall6TlRRelFHTTNObk00TURFdWNHOXlkR0ZpYkdWemRXSnRZWEpwYm1WekxtTnZiVG81T1RrNElpd2ljRzl5ZENJNklqazVPVGdpTENKcFpDSTZJakU0TWpRek5UZzJMVFJoTmpRdE5EZzJZUzA1TURZeUxXVTRNV05tWmpobE5qRTNOeUlzSW1GcFpDSTZNQ3dpYm1WMElqb2lkR053SWl3aWRIbHdaU0k2SW01dmJtVWlMQ0owYkhNaU9pSnViMjVsSWl3aVlXUmtJam9pTWpFeUxqVXdMakl5T1M0eE1ETWlmUQ==";

        // Decode the Base64 subscription
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded_data).unwrap();
        let data = String::from_utf8(decoded).unwrap();

        // First test individual VMess parsing
        let vmess_line = "vmess://eyJwcyI6IkpNUy0xMjYzNTQzQGM3NnMzLnBvcnRhYmxlc3VibWFyaW5lcy5jb206OTk5OCIsInBvcnQiOiI5OTk4IiwiaWQiOiIxODI0MzU4Ni00YTY0LTQ4NmEtOTA2Mi1lODFjZmY4ZTYxNzciLCJhaWQiOjAsIm5ldCI6InRjcCIsInR5cGUiOiJub25lIiwidGxzIjoibm9uZSIsImFkZCI6IjE5OC4zNS40Ni4xMzIifQ";
        let vmess_result = parse_vmess(vmess_line);
        println!("VMess parse result: {:?}", vmess_result);

        // Convert to Clash YAML
        let yaml = convert_jms_to_clash(&data).unwrap();

        // Print YAML for debugging
        println!("Generated YAML:\n{}", yaml);

        // Verify the output contains proxies
        assert!(yaml.contains("proxies:"));
        assert!(yaml.contains("proxy-groups:"));
        assert!(yaml.contains("rules:"));

        // Check SS proxies are parsed
        assert!(yaml.contains("type: ss"));
        assert!(yaml.contains("cipher: aes-256-gcm"));
        assert!(yaml.contains("port:"));

        // Check node names
        assert!(yaml.contains("JMS-1263543"));

        // Check proxy group contains DIRECT
        assert!(yaml.contains("- DIRECT"));

        // Verify it's valid YAML by parsing it
        let parsed: serde_yaml_ng::Mapping = serde_yaml_ng::from_str(&yaml).unwrap();

        // Check number of proxies (should have at least 2 SS)
        let proxies = parsed.get(&serde_yaml_ng::Value::String("proxies".to_string()))
            .and_then(|v| v.as_sequence())
            .unwrap();
        assert!(proxies.len() >= 2, "Expected at least 2 proxies");
    }
}
