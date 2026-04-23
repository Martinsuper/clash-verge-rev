//! JMS (just my sockets) subscription converter
//!
//! Converts Base64-encoded proxy links to Clash YAML configuration.
//! Supports: SS, VMess, Trojan, VLESS, Hysteria, Hysteria2, SSR

use std::borrow::Cow;

use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

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
}
