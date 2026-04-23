---
name: jms-subscription-support
description: 支持 JMS（just my sockets）订阅格式导入，将 Base64 编码的代理链接列表转换为 Clash YAML 配置
type: project
---

# JMS 订阅支持设计文档

**日期**: 2026-04-23
**状态**: 设计完成，待实现

## 背景

clash-verge-rev 当前只支持 Clash YAML 格式的订阅。当订阅返回 Base64 编码的代理链接列表（如 `ss://...`, `vmess://...`）时，导入会失败，因为 `PrfItem::from_url` 期望订阅内容必须是包含 `proxies` 或 `proxy-providers` 字段的 YAML 格式。

JMS（just my sockets）是一种常见的订阅格式，返回 Base64 编码的内容，解码后是代理链接列表。

**Why**: 用户需要导入 JMS 格式的订阅链接，如 `https://jmssub.net/members/getsub.php?service=...`
**How to apply**: 在 `PrfItem::from_url` 中添加自动检测和转换逻辑

## 目标

- 支持 JMS 格式订阅的自动识别和转换
- 支持 SS、VMess、Trojan、VLESS、Hysteria、Hysteria2、SSR 共六种协议
- 生成完整的 Clash 配置（包含 proxies、proxy-groups、rules）
- 保持现有 Clash YAML 订阅处理不变

## 实现方案

### 方案选择

选择**独立模块方案**，创建 `src-tauri/src/utils/jms_converter.rs`：

- 模块化，易于维护和测试
- 转换逻辑与订阅处理分离
- 与现有代码结构一致

### 模块结构

```rust
// src-tauri/src/utils/jms_converter.rs

/// 主转换函数
pub fn convert_jms_to_clash(data: &str) -> Result<String>

/// 检测是否为 JMS 格式
fn is_jms_format(data: &str) -> bool

/// Base64 解码（如果需要）
fn decode_base64_if_needed(data: &str) -> Cow<'_, str>

/// 解析单个代理链接
fn parse_proxy_line(line: &str) -> Option<serde_yaml::Value>

/// 各协议解析函数
fn parse_ss(line: &str) -> Option<serde_yaml::Value>
fn parse_vmess(line: &str) -> Option<serde_yaml::Value>
fn parse_trojan(line: &str) -> Option<serde_yaml::Value>
fn parse_vless(line: &str) -> Option<serde_yaml::Value>
fn parse_hysteria(line: &str) -> Option<serde_yaml::Value>
fn parse_hysteria2(line: &str) -> Option<serde_yaml::Value>
fn parse_ssr(line: &str) -> Option<serde_yaml::Value>

/// 生成默认配置结构
fn generate_default_config(proxies: Vec<serde_yaml::Value>) -> ClashConfig
```

### 协议解析详细设计

#### SS (Shadowsocks)

格式变体：
1. `ss://base64(method:password)@host:port#name` (SIP002)
2. `ss://base64(method:password)@host:port/?plugin=...#name` (带插件)
3. `ss://base64(method:password@host:port)#name` (老格式)

提取字段：`name`, `server`, `port`, `cipher`, `password`, `plugin`, `plugin-opts`

#### VMess

格式：`vmess://base64(json_object)`

JSON 结构：
```json
{
  "v": "2",
  "ps": "节点名称",
  "add": "服务器地址",
  "port": "端口",
  "id": "UUID",
  "aid": "alterId",
  "scy": "cipher",
  "net": "network (tcp/ws/grpc/etc)",
  "type": "伪装类型",
  "host": "Host header",
  "path": "WebSocket path",
  "tls": "tls"
}
```

提取字段：`name`, `server`, `port`, `uuid`, `alterId`, `cipher`, `network`, `ws-opts`, `grpc-opts`, `tls`, `skip-cert-verify`

#### Trojan

格式：`trojan://password@host:port?params#name`

常见参数：
- `sni`: Server Name Indication
- `type`: transport type (tcp/ws)
- `host`: WebSocket Host
- `path`: WebSocket path
- `skip-cert-verify`: bool

提取字段：`name`, `server`, `port`, `password`, `sni`, `skip-cert-verify`, `ws-opts`

#### VLESS

格式：`vless://uuid@host:port?params#name`

常见参数：
- `encryption`: none
- `flow`: xtls-rprx-vision
- `security`: tls/reality
- `type`: tcp/ws/grpc
- `host`: WebSocket Host
- `path`: WebSocket path
- `sni`: SNI
- `pbk`: Reality public key
- `sid`: Reality short id
- `fp`: Reality fingerprint

提取字段：`name`, `server`, `port`, `uuid`, `flow`, `tls`, `skip-cert-verify`, `ws-opts`, `grpc-opts`, `reality-opts`

#### Hysteria

格式：`hysteria://host:port?params#name` 或 `hysteria://auth@host:port?params#name`

常见参数：
- `auth`: 认证字符串
- `obfs`: 混淆
- `up`: 上行带宽
- `down`: 下行带宽
- `alpn`: ALPN
- `sni`: SNI

提取字段：`name`, `server`, `port`, `auth`, `auth_str`, `obfs`, `upmbps`, `downmbps`, `alpn`, `sni`, `skip-cert-verify`

#### Hysteria2

格式：`hy2://password@host:port?params#name` 或 `hysteria2://password@host:port?params#name`

常见参数：
- `sni`: SNI
- `obfs`: 混淆类型 (salamander)
- `obfs-password`: 混淆密码
- `insecure`: skip-cert-verify

提取字段：`name`, `server`, `port`, `password`, `sni`, `skip-cert-verify`, `obfs`, `obfs-password`

#### SSR (ShadowsocksR)

格式：`ssr://base64(server:port:protocol:method:obfs:password_base64/?params=...#name)`

解码后结构：`server:port:protocol:method:obfs:password_base64/?obfsparam=...&protoparam=...&remarks=...&group=...`

提取字段：`name`, `server`, `port`, `cipher`, `password`, `protocol`, `protocol-param`, `obfs`, `obfs-param`

### 生成的 Clash 配置结构

```yaml
proxies:
  - name: "节点名称"
    type: ss/vmess/trojan/vless/hysteria/hysteria2/ssr
    server: x.x.x.x
    port: 443
    # ... 协议特定字段

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - "节点1"
      - "节点2"
      - ...
      - DIRECT

rules:
  - MATCH,Proxy
```

### 集成点

修改 `src-tauri/src/config/prfitem.rs` 的 `from_url` 函数（约第388行）：

```rust
// 现有代码：
let yaml = serde_yaml_ng::from_str::<Mapping>(data)
    .context("the remote profile data is invalid yaml")?;

if !yaml.contains_key("proxies") && !yaml.contains_key("proxy-providers") {
    bail!("profile does not contain `proxies` or `proxy-providers`");
}

// 改为：
let yaml = match serde_yaml_ng::from_str::<Mapping>(data) {
    Ok(y) if y.contains_key("proxies") || y.contains_key("proxy-providers") => y,
    Ok(_) => bail!("profile does not contain `proxies` or `proxy-providers`"),
    Err(_) => {
        // 尝试 JMS 格式转换
        match jms_converter::convert_jms_to_clash(data) {
            Ok(converted) => {
                logging!(info, Type::Config, "JMS subscription converted successfully");
                serde_yaml_ng::from_str(&converted)?
            }
            Err(e) => {
                bail!("the remote profile data is neither valid Clash YAML nor valid JMS format: {}", e)
            }
        }
    }
};
```

### 错误处理策略

1. **Base64 解码失败**: 直接尝试解析原始内容（可能未编码）
2. **单个节点解析失败**: 跳过该节点，记录日志，继续解析其他节点
3. **全部节点解析失败**: 返回错误，包含失败原因
4. **空订阅**: 返回明确错误 "subscription contains no valid proxies"

### 测试计划

为每种协议创建单元测试：

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_ss_sip002() { /* 标准 SIP002 格式 */ }
    #[test]
    fn test_parse_ss_with_plugin() { /* 带插件参数 */ }
    #[test]
    fn test_parse_vmess_basic() { /* 基础 VMess */ }
    #[test]
    fn test_parse_vmess_with_ws() { /* WebSocket 传输 */ }
    #[test]
    fn test_parse_vmess_with_grpc() { /* gRPC 传输 */ }
    #[test]
    fn test_parse_trojan_basic() { /* 基础 Trojan */ }
    #[test]
    fn test_parse_trojan_with_ws() { /* WebSocket 传输 */ }
    #[test]
    fn test_parse_vless_basic() { /* 基础 VLESS */ }
    #[test]
    fn test_parse_vless_with_reality() { /* Reality TLS */ }
    #[test]
    fn test_parse_hysteria() { /* Hysteria 协议 */ }
    #[test]
    fn test_parse_hysteria2() { /* Hysteria2 协议 */ }
    #[test]
    fn test_parse_ssr() { /* SSR 协议 */ }
    #[test]
    fn test_base64_decoding() { /* Base64 解码测试 */ }
    #[test]
    fn test_mixed_protocols() { /* 混合协议订阅 */ }
    #[test]
    fn test_empty_subscription() { /* 空订阅错误处理 */ }
    #[test]
    fn test_invalid_node_skipped() { /* 无效节点跳过 */ }
}
```

## 依赖

不需要新增外部依赖。使用现有依赖：
- `base64`: Base64 编解码
- `url`: URL 解析
- `serde_yaml_ng`: YAML 序列化
- `serde_json`: JSON 解析（用于 VMess）

## 文件变更

| 文件 | 操作 |
|------|------|
| `src-tauri/src/utils/jms_converter.rs` | 新建 |
| `src-tauri/src/utils/mod.rs` | 添加 `mod jms_converter;` |
| `src-tauri/src/config/prfitem.rs` | 修改 `from_url` 函数 |

## 风险与注意事项

1. **协议兼容性**: 不同机场可能有不同的链接格式变体，需要实际测试
2. **性能**: Base64 解码和逐行解析对大型订阅（100+节点）的性能影响很小
3. **向后兼容**: 现有 Clash YAML 订阅处理完全不受影响

## 参考

- jwt-clash-convert: https://github.com/Martinsuper/jwt-clash-convert
- Clash Meta 文档: https://wiki.metacubex.one/config/proxies/
- JMS 订阅格式规范