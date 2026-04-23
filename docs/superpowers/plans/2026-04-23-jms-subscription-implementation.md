# JMS Subscription Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add support for JMS (just my sockets) subscription format, converting Base64-encoded proxy links to Clash YAML config.

**Architecture:** Create a standalone `jms_converter.rs` module with protocol parsers for SS, VMess, Trojan, VLESS, Hysteria, Hysteria2, and SSR. Integrate into `PrfItem::from_url` with auto-detection.

**Tech Stack:** Rust, base64, url, serde_yaml_ng, serde_json (all existing dependencies except `url` crate)

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src-tauri/src/utils/jms_converter.rs` | Main converter module with all protocol parsers |
| `src-tauri/src/utils/mod.rs` | Module declaration |
| `src-tauri/src/config/prfitem.rs` | Integration point - call converter when YAML fails |
| `src-tauri/Cargo.toml` | Add `url` dependency |

---

### Task 1: Add URL Crate Dependency

**Files:**
- Modify: `src-tauri/Cargo.toml:87`

- [ ] **Step 1: Add url crate to dependencies**

Add after the `base64` dependency line:

```toml
url = "2.5"
```

- [ ] **Step 2: Verify dependency resolves**

Run: `cd src-tauri && cargo check`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src-tauri/Cargo.toml
git commit -m "chore(deps): add url crate for JMS subscription parsing"
```

---

### Task 2: Create Module Structure

**Files:**
- Create: `src-tauri/src/utils/jms_converter.rs`
- Modify: `src-tauri/src/utils/mod.rs:20`

- [ ] **Step 1: Add module declaration to mod.rs**

Add at end of file:

```rust
pub mod jms_converter;
```

- [ ] **Step 2: Create empty jms_converter.rs with basic structure**

```rust
//! JMS (just my sockets) subscription converter
//!
//! Converts Base64-encoded proxy links to Clash YAML configuration.
//! Supports: SS, VMess, Trojan, VLESS, Hysteria, Hysteria2, SSR

use anyhow::{Result, bail};

/// Convert JMS subscription data to Clash YAML
pub fn convert_jms_to_clash(data: &str) -> Result<String> {
    bail!("not implemented")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder() {
        // Placeholder test - will be replaced with actual tests
        assert!(true);
    }
}
```

- [ ] **Step 3: Verify module compiles**

Run: `cd src-tauri && cargo check`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/utils/mod.rs src-tauri/src/utils/jms_converter.rs
git commit -m "feat: add jms_converter module structure"
```

---

### Task 3: Implement Base64 Decoding Helper

**Files:**
- Modify: `src-tauri/src/utils/jms_converter.rs`

- [ ] **Step 1: Write failing test for base64 decoding**

Add to tests module:

```rust
#[test]
fn test_decode_base64_if_needed_encoded() {
    let encoded = "c3M6Ly9YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS";
    let decoded = decode_base64_if_needed(encoded);
    // Should return original since it's not pure base64
    assert_eq!(decoded, encoded);
}

#[test]
fn test_decode_base64_if_needed_pure_base64() {
    let encoded = "c3M6Ly9YWVzLTEyOC1nY206cGFzc3dvcmQ9QDEuMi4zLjQ6NDQzI1Rlc3RTUw==";
    let decoded = decode_base64_if_needed(encoded);
    assert!(decoded.contains("ss://"));
}

#[test]
fn test_decode_base64_if_needed_not_encoded() {
    let plain = "ss://aes-128-gcm:password@1.2.3.4:443#TestSS";
    let decoded = decode_base64_if_needed(plain);
    assert_eq!(decoded, plain);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test jms_converter::tests::test_decode_base64 --no-fail-fast`
Expected: Tests fail with "function not found"

- [ ] **Step 3: Implement decode_base64_if_needed**

Add imports and function:

```rust
use std::borrow::Cow;

/// Decode Base64 if the data appears to be encoded
/// Returns decoded string if successful, otherwise returns original
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

    // Try Base64 decoding
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    // Add padding if needed
    let mut data_str = trimmed.to_string();
    while data_str.len() % 4 != 0 {
        data_str.push('=');
    }

    match BASE64.decode(&data_str) {
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test jms_converter::tests::test_decode_base64`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/utils/jms_converter.rs
git commit -m "feat: add base64 decoding helper for JMS converter"
```

---

### Task 4: Implement SS (Shadowsocks) Parser

**Files:**
- Modify: `src-tauri/src/utils/jms_converter.rs`

- [ ] **Step 1: Write failing tests for SS parser**

Add to tests module:

```rust
#[test]
fn test_parse_ss_sip002() {
    // SIP002 format: ss://base64(method:password)@host:port#name
    let line = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS";
    let result = parse_ss(line).unwrap();
    assert_eq!(result["name"], "TestSS");
    assert_eq!(result["type"], "ss");
    assert_eq!(result["server"], "1.2.3.4");
    assert_eq!(result["port"], 443);
    assert_eq!(result["cipher"], "aes-128-gcm");
    assert_eq!(result["password"], "password");
}

#[test]
fn test_parse_ss_legacy() {
    // Legacy format: ss://base64(method:password@host:port)#name
    let line = "ss://YWVzLTEyOC1nY206cGFzc3dvcmRA1.2.3.4OjQ0MyM=VGVzdFNTMg==";
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_ss --no-fail-fast`
Expected: Tests fail with "function not found"

- [ ] **Step 3: Implement parse_ss function**

Add URL import and function:

```rust
use url::Url;
use serde_yaml_ng::Mapping;

/// Parse Shadowsocks (SS) proxy link
/// Supports SIP002 format and legacy format
fn parse_ss(line: &str) -> Option<serde_yaml_ng::Value> {
    let line = line.strip_prefix("ss://")?;

    // Extract name from fragment
    let (main, name) = if let Some(pos) = line.find('#') {
        (&line[..pos], urlencoding_decode(&line[pos + 1..]))
    } else {
        (line, "SS Proxy".to_string())
    };

    // Check for plugin in query string
    let (main_without_query, plugin_opts) = if let Some(pos) = main.find('/?') {
        let query = &main[pos + 2..];
        let opts = parse_ss_plugin_query(query);
        (&main[..pos], opts)
    } else {
        (main, None)
    };

    // Split user info and server
    let parts: Vec<&str> = main_without_query.splitn(2, '@').collect();

    if parts.len() == 2 {
        // SIP002 format: base64(method:password)@host:port
        let user_info = parts[0];
        let server_info = parts[1];

        let server_parts: Vec<&str> = server_info.splitn(2, ':').collect();
        if server_parts.len() != 2 {
            return None;
        }

        // Decode user info
        let decoded_user = decode_base64_user_info(user_info);
        let user_parts: Vec<&str> = decoded_user.splitn(2, ':').collect();
        if user_parts.len() != 2 {
            return None;
        }

        let mut map = Mapping::new();
        map.insert("name".into(), name.into());
        map.insert("type".into(), "ss".into());
        map.insert("server".into(), server_parts[0].into());
        map.insert("port".into(), server_parts[1].parse::<u16>().ok()?.into());
        map.insert("cipher".into(), user_parts[0].into());
        map.insert("password".into(), user_parts[1].into());

        if let Some(opts) = plugin_opts {
            map.insert("plugin".into(), opts.plugin.into());
            if let Some(plugin_opts_map) = opts.opts {
                map.insert("plugin-opts".into(), serde_yaml_ng::Value::Mapping(plugin_opts_map));
            }
        }

        Some(serde_yaml_ng::Value::Mapping(map))
    } else {
        // Legacy format: base64(method:password@host:port)#name
        // Try to decode entire string
        let decoded = decode_base64_user_info(main);
        let decoded_parts: Vec<&str> = decoded.splitn(2, '@').collect();
        if decoded_parts.len() != 2 {
            return None;
        }

        let user_parts: Vec<&str> = decoded_parts[0].splitn(2, ':').collect();
        if user_parts.len() != 2 {
            return None;
        }

        let server_parts: Vec<&str> = decoded_parts[1].splitn(2, ':').collect();
        if server_parts.len() != 2 {
            return None;
        }

        let mut map = Mapping::new();
        map.insert("name".into(), name.into());
        map.insert("type".into(), "ss".into());
        map.insert("server".into(), server_parts[0].into());
        map.insert("port".into(), server_parts[1].parse::<u16>().ok()?.into());
        map.insert("cipher".into(), user_parts[0].into());
        map.insert("password".into(), user_parts[1].into());

        Some(serde_yaml_ng::Value::Mapping(map))
    }
}

/// Decode Base64 user info, handling various padding scenarios
fn decode_base64_user_info(data: &str) -> String {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    // Add padding if needed
    let mut data_str = data.to_string();
    while data_str.len() % 4 != 0 {
        data_str.push('=');
    }

    match BASE64.decode(&data_str) {
        Ok(decoded) => String::from_utf8_lossy(&decoded).to_string(),
        Err(_) => data.to_string(),
    }
}

/// URL decode a string
fn urlencoding_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .to_string()
}

/// SS plugin options
struct SsPluginOpts {
    plugin: String,
    opts: Option<Mapping>,
}

/// Parse SS plugin query string
fn parse_ss_plugin_query(query: &str) -> Option<SsPluginOpts> {
    let params: Vec<&str> = query.split('&').collect();
    for param in params {
        if param.starts_with("plugin=") {
            let plugin_str = urlencoding_decode(&param[7..]);
            let parts: Vec<&str> = plugin_str.splitn(2, ';').collect();
            let plugin_name = parts[0];

            let opts = if parts.len() > 1 {
                let opt_parts: Vec<&str> = parts[1].split(';').collect();
                let mut opts_map = Mapping::new();
                for opt in opt_parts {
                    let kv: Vec<&str> = opt.splitn(2, '=').collect();
                    if kv.len() == 2 {
                        opts_map.insert(kv[0].into(), kv[1].into());
                    }
                }
                Some(opts_map)
            } else {
                None
            };

            return Some(SsPluginOpts {
                plugin: plugin_name.to_string(),
                opts,
            });
        }
    }
    None
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_ss`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/utils/jms_converter.rs
git commit -m "feat: implement SS (Shadowsocks) parser for JMS converter"
```

---

### Task 5: Implement VMess Parser

**Files:**
- Modify: `src-tauri/src/utils/jms_converter.rs`

- [ ] **Step 1: Write failing tests for VMess parser**

Add to tests module:

```rust
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
    assert_eq!(result["port"], 443);
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
    assert_eq!(result["tls"], true);
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_vmess --no-fail-fast`
Expected: Tests fail with "function not found"

- [ ] **Step 3: Implement parse_vmess function**

Add function:

```rust
/// VMess JSON structure (partial fields we care about)
#[derive(serde::Deserialize, Default)]
struct VmessJson {
    #[serde(default)]
    v: String,
    #[serde(default)]
    ps: String,              // name
    #[serde(default)]
    add: String,             // server
    #[serde(default, rename = "port")]
    port_json: serde_json::Value, // port (can be string or number)
    #[serde(default)]
    id: String,              // uuid
    #[serde(default, rename = "aid")]
    aid_json: serde_json::Value, // alterId (can be string or number)
    #[serde(default)]
    scy: String,             // cipher
    #[serde(default)]
    net: String,             // network type (tcp/ws/grpc)
    #[serde(rename = "type", default)]
    transport_type: String,  // transport type for grpc
    #[serde(default)]
    host: String,            // host header for ws
    #[serde(default)]
    path: String,            // path for ws/grpc
    #[serde(default)]
    tls: String,             // tls flag
}

/// Parse VMess proxy link
fn parse_vmess(line: &str) -> Option<serde_yaml_ng::Value> {
    let data = line.strip_prefix("vmess://")?.trim();

    // Add padding if needed
    let mut data_str = data.to_string();
    while data_str.len() % 4 != 0 {
        data_str.push('=');
    }

    let decoded = decode_base64_user_info(&data_str);
    let vmess_json: VmessJson = serde_json::from_str(&decoded).ok()?;

    let port = parse_json_number(&vmess_json.port_json)?;
    let alter_id = parse_json_number_or_zero(&vmess_json.aid_json);

    let mut map = Mapping::new();
    map.insert("name".into(), vmess_json.ps.into());
    map.insert("type".into(), "vmess".into());
    map.insert("server".into(), vmess_json.add.into());
    map.insert("port".into(), port.into());
    map.insert("uuid".into(), vmess_json.id.into());
    map.insert("alterId".into(), alter_id.into());
    map.insert("cipher".into(), if vmess_json.scy.is_empty() { "auto" } else { &vmess_json.scy }.into());

    // Network settings
    if !vmess_json.net.is_empty() && vmess_json.net != "tcp" {
        map.insert("network".into(), vmess_json.net.clone().into());

        if vmess_json.net == "ws" {
            let mut ws_opts = Mapping::new();
            if !vmess_json.path.is_empty() {
                ws_opts.insert("path".into(), vmess_json.path.clone().into());
            }
            if !vmess_json.host.is_empty() {
                let mut headers = Mapping::new();
                headers.insert("Host".into(), vmess_json.host.clone().into());
                ws_opts.insert("headers".into(), serde_yaml_ng::Value::Mapping(headers));
            }
            map.insert("ws-opts".into(), serde_yaml_ng::Value::Mapping(ws_opts));
        } else if vmess_json.net == "grpc" {
            let mut grpc_opts = Mapping::new();
            if !vmess_json.path.is_empty() {
                grpc_opts.insert("serviceName".into(), vmess_json.path.clone().into());
            }
            map.insert("grpc-opts".into(), serde_yaml_ng::Value::Mapping(grpc_opts));
        }
    }

    // TLS
    if vmess_json.tls == "tls" {
        map.insert("tls".into(), true.into());
    }

    Some(serde_yaml_ng::Value::Mapping(map))
}

/// Parse JSON number value (can be number or string)
fn parse_json_number(value: &serde_json::Value) -> Option<u16> {
    match value {
        serde_json::Value::Number(n) => n.as_u64().map(|v| v as u16),
        serde_json::Value::String(s) => s.parse::<u16>().ok(),
        _ => None,
    }
}

/// Parse JSON number value, returning 0 if invalid
fn parse_json_number_or_zero(value: &serde_json::Value) -> u16 {
    parse_json_number(value).unwrap_or(0)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_vmess`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/utils/jms_converter.rs
git commit -m "feat: implement VMess parser for JMS converter"
```

---

### Task 6: Implement Trojan Parser

**Files:**
- Modify: `src-tauri/src/utils/jms_converter.rs`

- [ ] **Step 1: Write failing tests for Trojan parser**

Add to tests module:

```rust
#[test]
fn test_parse_trojan_basic() {
    let line = "trojan://password123@1.2.3.4:443#TestTrojan";
    let result = parse_trojan(line).unwrap();
    assert_eq!(result["name"], "TestTrojan");
    assert_eq!(result["type"], "trojan");
    assert_eq!(result["server"], "1.2.3.4");
    assert_eq!(result["port"], 443);
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_trojan --no-fail-fast`
Expected: Tests fail with "function not found"

- [ ] **Step 3: Implement parse_trojan function**

Add function:

```rust
/// Parse Trojan proxy link
fn parse_trojan(line: &str) -> Option<serde_yaml_ng::Value> {
    let url = Url::parse(line).ok()?;
    let host = url.host_str()?.to_string();
    let port = url.port().unwrap_or(443);
    let password = url.username().to_string();
    let name = urlencoding_decode(url.fragment().unwrap_or("Trojan Proxy"));

    let mut map = Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "trojan".into());
    map.insert("server".into(), host.clone().into());
    map.insert("port".into(), port.into());
    map.insert("password".into(), password.into());

    // Default SNI is the host
    let mut sni = host.clone();

    // Parse query parameters
    let mut ws_opts: Option<Mapping> = None;
    for (key, value) in url.query_pairs() {
        match key.as_str() {
            "sni" => sni = value.to_string(),
            "type" if value == "ws" => {
                ws_opts = Some(Mapping::new());
            }
            "host" => {
                if let Some(ref opts) = ws_opts {
                    let mut headers = Mapping::new();
                    headers.insert("Host".into(), value.to_string().into());
                    opts.insert("headers".into(), serde_yaml_ng::Value::Mapping(headers));
                }
            }
            "path" => {
                if let Some(ref opts) = ws_opts {
                    opts.insert("path".into(), value.to_string().into());
                }
            }
            "skip-cert-verify" | "insecure" => {
                if value == "1" || value == "true" {
                    map.insert("skip-cert-verify".into(), true.into());
                }
            }
            _ => {}
        }
    }

    map.insert("sni".into(), sni.into());

    if let Some(opts) = ws_opts {
        map.insert("ws-opts".into(), serde_yaml_ng::Value::Mapping(opts));
        map.insert("network".into(), "ws".into());
    }

    Some(serde_yaml_ng::Value::Mapping(map))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_trojan`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/utils/jms_converter.rs
git commit -m "feat: implement Trojan parser for JMS converter"
```

---

### Task 7: Implement VLESS Parser

**Files:**
- Modify: `src-tauri/src/utils/jms_converter.rs`

- [ ] **Step 1: Write failing tests for VLESS parser**

Add to tests module:

```rust
#[test]
fn test_parse_vless_basic() {
    let line = "vless://uuid-1234-5678@1.2.3.4:443?encryption=none#TestVLESS";
    let result = parse_vless(line).unwrap();
    assert_eq!(result["name"], "TestVLESS");
    assert_eq!(result["type"], "vless");
    assert_eq!(result["server"], "1.2.3.4");
    assert_eq!(result["port"], 443);
    assert_eq!(result["uuid"], "uuid-1234-5678");
}

#[test]
fn test_parse_vless_with_flow() {
    let line = "vless://uuid@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=tls#TestVLESSFlow";
    let result = parse_vless(line).unwrap();
    assert_eq!(result["flow"], "xtls-rprx-vision");
    assert_eq!(result["tls"], true);
}

#[test]
fn test_parse_vless_with_reality() {
    let line = "vless://uuid@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.google.com&pbk=publickey&sid=shortid&fp=chrome#TestReality";
    let result = parse_vless(line).unwrap();
    assert!(result.get("reality-opts").is_some());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_vless --no-fail-fast`
Expected: Tests fail with "function not found"

- [ ] **Step 3: Implement parse_vless function**

Add function:

```rust
/// Parse VLESS proxy link
fn parse_vless(line: &str) -> Option<serde_yaml_ng::Value> {
    let url = Url::parse(line).ok()?;
    let host = url.host_str()?.to_string();
    let port = url.port().unwrap_or(443);
    let uuid = url.username().to_string();
    let name = urlencoding_decode(url.fragment().unwrap_or("VLESS Proxy"));

    let mut map = Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "vless".into());
    map.insert("server".into(), host.clone().into());
    map.insert("port".into(), port.into());
    map.insert("uuid".into(), uuid.into());

    // Parse query parameters
    let mut security = "tls";
    let mut sni = host.clone();
    let mut flow: Option<String> = None;
    let mut ws_opts: Option<Mapping> = None;
    let mut grpc_opts: Option<Mapping> = None;
    let mut reality_opts: Option<Mapping> = None;

    for (key, value) in url.query_pairs() {
        match key.as_str() {
            "encryption" => {
                // Usually "none"
                if value != "none" {
                    map.insert("encryption".into(), value.to_string().into());
                }
            }
            "flow" => flow = Some(value.to_string()),
            "security" => security = value.as_str(),
            "sni" => sni = value.to_string(),
            "type" => {
                match value.as_str() {
                    "ws" => ws_opts = Some(Mapping::new()),
                    "grpc" => grpc_opts = Some(Mapping::new()),
                    _ => {}
                }
            }
            "host" => {
                if let Some(ref opts) = ws_opts {
                    let mut headers = Mapping::new();
                    headers.insert("Host".into(), value.to_string().into());
                    opts.insert("headers".into(), serde_yaml_ng::Value::Mapping(headers));
                }
            }
            "path" => {
                if let Some(ref opts) = ws_opts {
                    opts.insert("path".into(), value.to_string().into());
                }
                if let Some(ref opts) = grpc_opts {
                    opts.insert("serviceName".into(), value.to_string().into());
                }
            }
            "pbk" => {
                // Reality public key
                if reality_opts.is_none() {
                    reality_opts = Some(Mapping::new());
                }
                reality_opts.as_mut()?.insert("public-key".into(), value.to_string().into());
            }
            "sid" => {
                // Reality short id
                if reality_opts.is_none() {
                    reality_opts = Some(Mapping::new());
                }
                reality_opts.as_mut()?.insert("short-id".into(), value.to_string().into());
            }
            "fp" => {
                // Reality fingerprint
                if reality_opts.is_none() {
                    reality_opts = Some(Mapping::new());
                }
                reality_opts.as_mut()?.insert("fingerprint".into(), value.to_string().into());
            }
            "skip-cert-verify" | "insecure" => {
                if value == "1" || value == "true" {
                    map.insert("skip-cert-verify".into(), true.into());
                }
            }
            _ => {}
        }
    }

    // Set flow if present
    if let Some(f) = flow {
        map.insert("flow".into(), f.into());
    }

    // Set TLS/Reality
    if security == "tls" {
        map.insert("tls".into(), true.into());
        map.insert("sni".into(), sni.into());
    } else if security == "reality" {
        map.insert("tls".into(), true.into());
        if let Some(opts) = reality_opts {
            map.insert("reality-opts".into(), serde_yaml_ng::Value::Mapping(opts));
        }
        map.insert("sni".into(), sni.into());
    }

    // Set network options
    if let Some(opts) = ws_opts {
        map.insert("ws-opts".into(), serde_yaml_ng::Value::Mapping(opts));
        map.insert("network".into(), "ws".into());
    }
    if let Some(opts) = grpc_opts {
        map.insert("grpc-opts".into(), serde_yaml_ng::Value::Mapping(opts));
        map.insert("network".into(), "grpc".into());
    }

    Some(serde_yaml_ng::Value::Mapping(map))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_vless`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/utils/jms_converter.rs
git commit -m "feat: implement VLESS parser for JMS converter"
```

---

### Task 8: Implement Hysteria Parser

**Files:**
- Modify: `src-tauri/src/utils/jms_converter.rs`

- [ ] **Step 1: Write failing tests for Hysteria parser**

Add to tests module:

```rust
#[test]
fn test_parse_hysteria_basic() {
    let line = "hysteria://1.2.3.4:443?auth=password123&up=100&down=200#TestHysteria";
    let result = parse_hysteria(line).unwrap();
    assert_eq!(result["name"], "TestHysteria");
    assert_eq!(result["type"], "hysteria");
    assert_eq!(result["server"], "1.2.3.4");
    assert_eq!(result["port"], 443);
    assert_eq!(result["auth_str"], "password123");
}

#[test]
fn test_parse_hysteria_with_obfs() {
    let line = "hysteria://1.2.3.4:443?auth=password&obfs=salamander&upmbps=100&downmbps=200&sni=www.google.com#TestHysteriaObfs";
    let result = parse_hysteria(line).unwrap();
    assert_eq!(result["obfs"], "salamander");
    assert_eq!(result["sni"], "www.google.com");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_hysteria --no-fail-fast`
Expected: Tests fail with "function not found"

- [ ] **Step 3: Implement parse_hysteria function**

Add function:

```rust
/// Parse Hysteria proxy link
fn parse_hysteria(line: &str) -> Option<serde_yaml_ng::Value> {
    let line = line.strip_prefix("hysteria://")?;

    // Parse host:port and parameters
    let (server_part, name) = if let Some(pos) = line.find('#') {
        (&line[..pos], urlencoding_decode(&line[pos + 1..]))
    } else {
        (line, "Hysteria Proxy".to_string())
    };

    let (host_port, query) = if let Some(pos) = server_part.find('?') {
        (&server_part[..pos], &server_part[pos + 1..])
    } else {
        (server_part, "")
    };

    let (host, port) = parse_host_port(host_port)?;

    let mut map = Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "hysteria".into());
    map.insert("server".into(), host.into());
    map.insert("port".into(), port.into());

    // Parse query parameters
    let mut sni = host.clone();
    for param in query.split('&') {
        let kv: Vec<&str> = param.splitn(2, '=').collect();
        if kv.len() != 2 {
            continue;
        }
        match kv[0] {
            "auth" => map.insert("auth_str".into(), kv[1].into()),
            "obfs" => map.insert("obfs".into(), kv[1].into()),
            "up" | "upmbps" => map.insert("upmbps".into(), kv[1].parse::<u16>().ok()?.into()),
            "down" | "downmbps" => map.insert("downmbps".into(), kv[1].parse::<u16>().ok()?.into()),
            "alpn" => {
                let alpn_vals: Vec<&str> = kv[1].split(',').collect();
                map.insert("alpn".into(), serde_yaml_ng::Value::Sequence(
                    alpn_vals.iter().map(|v| v.into()).collect()
                ));
            }
            "sni" => sni = kv[1].to_string(),
            "insecure" | "skip-cert-verify" => {
                if kv[1] == "1" || kv[1] == "true" {
                    map.insert("skip-cert-verify".into(), true.into());
                }
            }
            _ => None,
        };
    }

    map.insert("sni".into(), sni.into());

    Some(serde_yaml_ng::Value::Mapping(map))
}

/// Parse host:port string
fn parse_host_port(s: &str) -> Option<(String, u16)> {
    // Handle IPv6 addresses
    if s.starts_with '[' {
        let end = s.find(']')?;
        let host = s[1..end].to_string();
        let rest = &s[end + 1..];
        let port = if rest.starts_with(':') {
            rest[1..].parse::<u16>().ok()?
        } else {
            443
        };
        return Some((host, port));
    }

    // Handle IPv4 or domain
    let parts: Vec<&str> = s.rsplitn(2, ':').collect();
    if parts.len() == 2 {
        Some((parts[1].to_string(), parts[0].parse::<u16>().ok()?))
    } else {
        Some((s.to_string(), 443))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_hysteria`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/utils/jms_converter.rs
git commit -m "feat: implement Hysteria parser for JMS converter"
```

---

### Task 9: Implement Hysteria2 Parser

**Files:**
- Modify: `src-tauri/src/utils/jms_converter.rs`

- [ ] **Step 1: Write failing tests for Hysteria2 parser**

Add to tests module:

```rust
#[test]
fn test_parse_hysteria2_basic() {
    let line = "hy2://password123@1.2.3.4:443#TestHy2";
    let result = parse_hysteria2(line).unwrap();
    assert_eq!(result["name"], "TestHy2");
    assert_eq!(result["type"], "hysteria2");
    assert_eq!(result["server"], "1.2.3.4");
    assert_eq!(result["port"], 443);
    assert_eq!(result["password"], "password123");
}

#[test]
fn test_parse_hysteria2_with_obfs() {
    let line = "hy2://password@1.2.3.4:443?sni=www.google.com&obfs=salamander&obfs-password=obfspass#TestHy2Obfs";
    let result = parse_hysteria2(line).unwrap();
    assert_eq!(result["sni"], "www.google.com");
    assert_eq!(result["obfs"], "salamander");
    assert_eq!(result["obfs-password"], "obfspass");
}

#[test]
fn test_parse_hysteria2_alt_prefix() {
    let line = "hysteria2://password@1.2.3.4:443#TestHysteria2Alt";
    let result = parse_hysteria2(line).unwrap();
    assert_eq!(result["name"], "TestHysteria2Alt");
    assert_eq!(result["type"], "hysteria2");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_hysteria2 --no-fail-fast`
Expected: Tests fail with "function not found"

- [ ] **Step 3: Implement parse_hysteria2 function**

Add function:

```rust
/// Parse Hysteria2 proxy link (hy2:// or hysteria2://)
fn parse_hysteria2(line: &str) -> Option<serde_yaml_ng::Value> {
    let line = if line.starts_with("hy2://") {
        line.strip_prefix("hy2://")?
    } else if line.starts_with("hysteria2://") {
        line.strip_prefix("hysteria2://")?
    } else {
        return None;
    };

    // Try URL parsing for password@host:port format
    let full_url = if line.contains('@') {
        format!("hy2://{}", line)
    } else {
        return None;
    };

    let url = Url::parse(&full_url).ok()?;
    let host = url.host_str()?.to_string();
    let port = url.port().unwrap_or(443);
    let password = url.username().to_string();
    let name = urlencoding_decode(url.fragment().unwrap_or("Hysteria2 Proxy"));

    let mut map = Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "hysteria2".into());
    map.insert("server".into(), host.clone().into());
    map.insert("port".into(), port.into());
    map.insert("password".into(), password.into());

    // Parse query parameters
    let mut sni = host.clone();
    for (key, value) in url.query_pairs() {
        match key.as_str() {
            "sni" => sni = value.to_string(),
            "obfs" => map.insert("obfs".into(), value.to_string().into()),
            "obfs-password" => map.insert("obfs-password".into(), value.to_string().into()),
            "insecure" | "skip-cert-verify" => {
                if value == "1" || value == "true" {
                    map.insert("skip-cert-verify".into(), true.into());
                }
            }
            _ => None,
        };
    }

    map.insert("sni".into(), sni.into());

    Some(serde_yaml_ng::Value::Mapping(map))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_hysteria2`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/utils/jms_converter.rs
git commit -m "feat: implement Hysteria2 parser for JMS converter"
```

---

### Task 10: Implement SSR Parser

**Files:**
- Modify: `src-tauri/src/utils/jms_converter.rs`

- [ ] **Step 1: Write failing tests for SSR parser**

Add to tests module:

```rust
#[test]
fn test_parse_ssr_basic() {
    // SSR format: ssr://base64(server:port:protocol:method:obfs:password_base64/?params#name)
    // This is a simplified test - actual SSR format is complex
    let inner = "1.2.3.4:443:origin:aes-128-cfb:plain:YmFzZTY0cGFzc3dvcmQ/?obfsparam=&protoparam=&remarks=VGVzdFNTUg==&group=";
    let encoded = base64_encode(inner);
    let line = format!("ssr://{}", encoded);
    let result = parse_ssr(&line).unwrap();
    assert_eq!(result["name"], "TestSSR");
    assert_eq!(result["type"], "ssr");
    assert_eq!(result["server"], "1.2.3.4");
    assert_eq!(result["port"], 443);
    assert_eq!(result["cipher"], "aes-128-cfb");
}

fn base64_encode(s: &str) -> String {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    BASE64.encode(s.as_bytes())
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_ssr --no-fail-fast`
Expected: Tests fail with "function not found"

- [ ] **Step 3: Implement parse_ssr function**

Add function:

```rust
/// Parse SSR (ShadowsocksR) proxy link
fn parse_ssr(line: &str) -> Option<serde_yaml_ng::Value> {
    let data = line.strip_prefix("ssr://")?;

    // Add padding if needed
    let mut data_str = data.to_string();
    while data_str.len() % 4 != 0 {
        data_str.push('=');
    }

    let decoded = decode_base64_user_info(&data_str);

    // Split main part and params
    let (main_part, params_part) = if let Some(pos) = decoded.find('/?') {
        (&decoded[..pos], &decoded[pos + 2..])
    } else {
        (&decoded, "")
    };

    // Parse main: server:port:protocol:method:obfs:password_base64
    let main_parts: Vec<&str> = main_part.split(':').collect();
    if main_parts.len() < 6 {
        return None;
    }

    let server = main_parts[0];
    let port = main_parts[1].parse::<u16>().ok()?;
    let protocol = main_parts[2];
    let cipher = main_parts[3];
    let obfs = main_parts[4];
    let password_b64 = main_parts[5];

    // Decode password
    let password = decode_base64_user_info(password_b64);

    // Parse params for name (remarks)
    let mut name = "SSR Proxy".to_string();
    let mut obfs_param = String::new();
    let mut protocol_param = String::new();

    for param in params_part.split('&') {
        let kv: Vec<&str> = param.splitn(2, '=').collect();
        if kv.len() != 2 {
            continue;
        }
        match kv[0] {
            "remarks" => name = decode_base64_user_info(kv[1]),
            "obfsparam" => obfs_param = decode_base64_user_info(kv[1]),
            "protoparam" => protocol_param = decode_base64_user_info(kv[1]),
            _ => {}
        }
    }

    let mut map = Mapping::new();
    map.insert("name".into(), name.into());
    map.insert("type".into(), "ssr".into());
    map.insert("server".into(), server.into());
    map.insert("port".into(), port.into());
    map.insert("cipher".into(), cipher.into());
    map.insert("password".into(), password.into());
    map.insert("protocol".into(), protocol.into());
    if !obfs_param.is_empty() {
        map.insert("protocol-param".into(), protocol_param.into());
    }
    map.insert("obfs".into(), obfs.into());
    if !obfs_param.is_empty() {
        map.insert("obfs-param".into(), obfs_param.into());
    }

    Some(serde_yaml_ng::Value::Mapping(map))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_ssr`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/utils/jms_converter.rs
git commit -m "feat: implement SSR parser for JMS converter"
```

---

### Task 11: Implement parse_proxy_line Dispatcher

**Files:**
- Modify: `src-tauri/src/utils/jms_converter.rs`

- [ ] **Step 1: Write failing test for parse_proxy_line**

Add to tests module:

```rust
#[test]
fn test_parse_proxy_line_ss() {
    let line = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS";
    let result = parse_proxy_line(line).unwrap();
    assert_eq!(result["type"], "ss");
}

#[test]
fn test_parse_proxy_line_vmess() {
    let json = "eyJhZGQiOiIxLjIuMy40IiwiYWlkIjowLCJwcyI6IlRlc3QiLCJwb3J0Ijo0NDMsImlkIjoidXVpZCIsInYiOiIyIn0=";
    let line = format!("vmess://{}", json);
    let result = parse_proxy_line(&line).unwrap();
    assert_eq!(result["type"], "vmess");
}

#[test]
fn test_parse_proxy_line_invalid() {
    let line = "invalid://not-a-proxy";
    assert!(parse_proxy_line(line).is_none());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_proxy_line --no-fail-fast`
Expected: Tests fail with "function not found"

- [ ] **Step 3: Implement parse_proxy_line function**

Add function:

```rust
/// Parse a single proxy line, dispatching to appropriate parser
fn parse_proxy_line(line: &str) -> Option<serde_yaml_ng::Value> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

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
        None
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test jms_converter::tests::test_parse_proxy_line`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/utils/jms_converter.rs
git commit -m "feat: implement parse_proxy_line dispatcher"
```

---

### Task 12: Implement convert_jms_to_clash Main Function

**Files:**
- Modify: `src-tauri/src/utils/jms_converter.rs`

- [ ] **Step 1: Write failing tests for main converter**

Add to tests module:

```rust
#[test]
fn test_convert_jms_to_clash_single_proxy() {
    let data = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS";
    let yaml = convert_jms_to_clash(data).unwrap();
    assert!(yaml.contains("proxies:"));
    assert!(yaml.contains("proxy-groups:"));
    assert!(yaml.contains("rules:"));
    assert!(yaml.contains("TestSS"));
}

#[test]
fn test_convert_jms_to_clash_base64_subscription() {
    // Simulate a Base64-encoded subscription with multiple proxies
    let proxies = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:443#TestSS\nvmess://eyJhZGQiOiIxLjIuMy40IiwiYWlkIjowLCJwcyI6IlRlc3RWIiwicG9ydCI6NDQzLCJpZCI6InV1aWQiLCJ2IjoiMiJ9";
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let encoded = BASE64.encode(proxies.as_bytes());
    let yaml = convert_jms_to_clash(&encoded).unwrap();
    assert!(yaml.contains("TestSS"));
    assert!(yaml.contains("TestV"));
}

#[test]
fn test_convert_jms_to_clash_empty() {
    let data = "";
    let result = convert_jms_to_clash(data);
    assert!(result.is_err());
}

#[test]
fn test_convert_jms_to_clash_invalid() {
    let data = "not-a-valid-subscription-at-all";
    let result = convert_jms_to_clash(data);
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd src-tauri && cargo test jms_converter::tests::test_convert_jms_to_clash --no-fail-fast`
Expected: Tests fail with "not implemented" error

- [ ] **Step 3: Implement convert_jms_to_clash function**

Replace placeholder implementation with:

```rust
/// Convert JMS subscription data to Clash YAML configuration
pub fn convert_jms_to_clash(data: &str) -> Result<String> {
    // Decode if Base64 encoded
    let decoded = decode_base64_if_needed(data);

    // Parse all proxy lines
    let mut proxies: Vec<serde_yaml_ng::Value> = Vec::new();
    let mut proxy_names: Vec<String> = Vec::new();

    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(proxy) = parse_proxy_line(line) {
            if let Some(name) = proxy.get("name").and_then(|v| v.as_str()) {
                proxy_names.push(name.to_string());
                proxies.push(proxy);
            }
        }
    }

    if proxies.is_empty() {
        bail!("subscription contains no valid proxies");
    }

    // Generate Clash config
    let config = generate_clash_config(proxies, proxy_names);

    // Serialize to YAML
    let yaml = serde_yaml_ng::to_string(&config)?;
    Ok(yaml)
}

/// Generate a basic Clash configuration structure
fn generate_clash_config(
    proxies: Vec<serde_yaml_ng::Value>,
    proxy_names: Vec<String>,
) -> serde_yaml_ng::Mapping {
    let mut config = Mapping::new();

    // Basic settings
    config.insert("port".into(), 7890.into());
    config.insert("socks-port".into(), 7891.into());
    config.insert("allow-lan".into(), true.into());
    config.insert("mode".into(), "rule".into());
    config.insert("log-level".into(), "info".into());
    config.insert("external-controller".into(), "127.0.0.1:9090".into());

    // Proxies
    config.insert("proxies".into(), serde_yaml_ng::Value::Sequence(proxies));

    // Proxy groups - include all proxies plus DIRECT
    let mut group_proxies: Vec<serde_yaml_ng::Value> = proxy_names
        .iter()
        .map(|n| n.into())
        .collect();
    group_proxies.push("DIRECT".into());

    let mut proxy_group = Mapping::new();
    proxy_group.insert("name".into(), "Proxy".into());
    proxy_group.insert("type".into(), "select".into());
    proxy_group.insert("proxies".into(), serde_yaml_ng::Value::Sequence(group_proxies));

    config.insert(
        "proxy-groups".into(),
        serde_yaml_ng::Value::Sequence(vec![serde_yaml_ng::Value::Mapping(proxy_group)]),
    );

    // Rules - simple rule to route everything through Proxy group
    config.insert(
        "rules".into(),
        serde_yaml_ng::Value::Sequence(vec!["MATCH,Proxy".into()]),
    );

    config
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd src-tauri && cargo test jms_converter::tests::test_convert_jms_to_clash`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/utils/jms_converter.rs
git commit -m "feat: implement convert_jms_to_clash main function"
```

---

### Task 13: Integrate JMS Converter into PrfItem::from_url

**Files:**
- Modify: `src-tauri/src/config/prfitem.rs:388-392`

- [ ] **Step 1: Add import for jms_converter**

At the top of prfitem.rs, add to the imports:

```rust
use crate::utils::jms_converter;
```

- [ ] **Step 2: Modify from_url YAML parsing logic**

Locate the YAML parsing section (around line 388) and modify:

```rust
// Original code to replace:
// let yaml = serde_yaml_ng::from_str::<Mapping>(data).context("the remote profile data is invalid yaml")?;
//
// if !yaml.contains_key("proxies") && !yaml.contains_key("proxy-providers") {
//     bail!("profile does not contain `proxies` or `proxy-providers`");
// }

// New code:
let yaml = match serde_yaml_ng::from_str::<Mapping>(data) {
    Ok(y) if y.contains_key("proxies") || y.contains_key("proxy-providers") => y,
    Ok(_) => bail!("profile does not contain `proxies` or `proxy-providers`"),
    Err(_) => {
        // Try JMS format conversion
        match jms_converter::convert_jms_to_clash(data) {
            Ok(converted) => {
                clash_verge_logging::logging!(
                    info,
                    clash_verge_logging::Type::Config,
                    "JMS subscription converted successfully"
                );
                serde_yaml_ng::from_str::<Mapping>(&converted)?
            }
            Err(e) => {
                bail!("the remote profile data is neither valid Clash YAML nor valid JMS format: {}", e)
            }
        }
    }
};
```

- [ ] **Step 3: Verify module compiles**

Run: `cd src-tauri && cargo check`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/config/prfitem.rs
git commit -m "feat: integrate JMS converter into subscription import"
```

---

### Task 14: Run Full Test Suite

**Files:**
- None (verification only)

- [ ] **Step 1: Run all tests**

Run: `cd src-tauri && cargo test jms_converter`
Expected: All tests pass

- [ ] **Step 2: Run full project test suite**

Run: `cd src-tauri && cargo test`
Expected: No new test failures

- [ ] **Step 3: Run cargo clippy**

Run: `cd src-tauri && cargo clippy -- -D warnings`
Expected: No new warnings

---

### Task 15: Integration Test with Real Subscription

**Files:**
- Create: test script (optional, manual verification)

- [ ] **Step 1: Test with provided JMS subscription URL**

Manual verification using the application:
1. Import subscription URL: `https://jmssub.net/members/getsub.php?service=1263543&id=18243586-4a64-486a-9062-e81cff8e6177`
2. Verify subscription is imported successfully
3. Check that proxies appear in the profile

- [ ] **Step 2: Commit final integration**

```bash
git add -A
git commit -m "feat: complete JMS subscription support implementation

- Add jms_converter module with parsers for SS, VMess, Trojan, VLESS, Hysteria, Hysteria2, SSR
- Auto-detect and convert JMS format subscriptions
- Integrate into PrfItem::from_url for seamless import

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Self-Review Checklist

1. **Spec coverage**: Each protocol parser (SS, VMess, Trojan, VLESS, Hysteria, Hysteria2, SSR) has corresponding test and implementation tasks.

2. **Placeholder scan**: No TBD/TODO found. All code steps have actual implementations.

3. **Type consistency**: Function names consistent across tasks. `parse_proxy_line` returns `Option<serde_yaml_ng::Value>`, used by `convert_jms_to_clash`.

---

Plan complete. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?