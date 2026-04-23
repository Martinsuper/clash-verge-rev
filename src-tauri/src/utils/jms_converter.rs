//! JMS (just my sockets) subscription converter
//!
//! Converts Base64-encoded proxy links to Clash YAML configuration.
//! Supports: SS, VMess, Trojan, VLESS, Hysteria, Hysteria2, SSR

use std::borrow::Cow;
use std::collections::HashMap;

use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

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

/// SS plugin options struct
#[allow(dead_code)]
#[derive(Debug, Default)]
struct SsPluginOpts {
    plugin: String,
    opts: HashMap<String, String>,
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
            let port: u16 = port_str.parse().map_err(|_| anyhow::anyhow!("Invalid port: {}", port_str))?;
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
                let port: u16 = port_str.parse().map_err(|_| anyhow::anyhow!("Invalid port in legacy format: {}", port_str))?;
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
                        let mut plugin_str = format!("obfs-local;obfs={}", plugin_opts.get("obfs").unwrap_or(&"".to_string()));
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

/// Convert JMS subscription data to Clash YAML
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
        assert!(result.get("plugin").is_some());
    }
}
