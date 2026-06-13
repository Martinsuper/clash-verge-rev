use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

use crate::config;

/// 创建 HTTP 客户端
fn create_client() -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("创建 HTTP 客户端失败")
}

/// 获取认证头
fn auth_header() -> Result<String> {
    config::get_auth_header()
}

/// API 基础 URL
fn api_base() -> Result<String> {
    config::get_api_base()
}

/// 代理信息
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ProxyInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: Option<String>,
    pub now: Option<String>,
    pub all: Option<Vec<String>>,
    pub delay: Option<u64>,
    pub history: Option<Vec<DelayHistory>>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct DelayHistory {
    pub time: String,
    pub delay: u64,
}

/// 代理列表响应
#[derive(Debug, Deserialize)]
pub struct ProxiesResponse {
    pub proxies: HashMap<String, ProxyInfo>,
}

/// 规则信息
#[derive(Debug, Deserialize)]
pub struct RuleInfo {
    pub r#type: String,
    pub payload: String,
    pub proxy: String,
}

/// 规则列表响应
#[derive(Debug, Deserialize)]
pub struct RulesResponse {
    pub rules: Vec<RuleInfo>,
}

/// 获取所有代理
pub async fn get_proxies() -> Result<ProxiesResponse> {
    let base = api_base()?;
    let secret = auth_header()?;
    let client = create_client()?;

    let resp = client
        .get(format!("{base}/proxies"))
        .header("Authorization", format!("Bearer {secret}"))
        .send()
        .await
        .context("请求 /proxies 失败，请确认 Clash Verge 是否运行")?;

    if !resp.status().is_success() {
        anyhow::bail!("API 请求失败: HTTP {}", resp.status());
    }

    let proxies: ProxiesResponse = resp.json().await.context("解析代理列表失败")?;
    Ok(proxies)
}

/// 切换代理节点
pub async fn select_proxy(group: &str, node: &str) -> Result<()> {
    let base = api_base()?;
    let secret = auth_header()?;
    let client = create_client()?;

    let body = json!({"name": node});

    let resp = client
        .put(format!("{base}/proxies/{group}"))
        .header("Authorization", format!("Bearer {secret}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .context("切换代理节点失败")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("切换代理节点失败 (HTTP {status}): {body}");
    }

    Ok(())
}

/// 测试代理延迟
pub async fn get_delay(proxy: &str, url: &str, timeout: u32) -> Result<u64> {
    let base = api_base()?;
    let secret = auth_header()?;
    let client = create_client()?;

    let resp = client
        .get(format!("{base}/proxies/{proxy}/delay"))
        .header("Authorization", format!("Bearer {secret}"))
        .query(&[("timeout", timeout.to_string()), ("url", url.to_string())])
        .send()
        .await
        .context("测试延迟失败")?;

    if !resp.status().is_success() {
        anyhow::bail!("测试延迟失败: HTTP {}", resp.status());
    }

    let body: Value = resp.json().await.context("解析延迟结果失败")?;
    Ok(body.get("delay").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// 重新加载配置
pub async fn reload_config() -> Result<()> {
    let base = api_base()?;
    let secret = auth_header()?;
    let client = create_client()?;

    let resp = client
        .put(format!("{base}/configs"))
        .header("Authorization", format!("Bearer {secret}"))
        .query(&[("force", "true")])
        .send()
        .await
        .context("重载配置失败")?;

    if !resp.status().is_success() {
        anyhow::bail!("重载配置失败: HTTP {}", resp.status());
    }

    Ok(())
}

/// 获取当前配置
pub async fn get_configs() -> Result<Value> {
    let base = api_base()?;
    let secret = auth_header()?;
    let client = create_client()?;

    let resp = client
        .get(format!("{base}/configs"))
        .header("Authorization", format!("Bearer {secret}"))
        .send()
        .await
        .context("获取配置失败")?;

    if !resp.status().is_success() {
        anyhow::bail!("获取配置失败: HTTP {}", resp.status());
    }

    let body: Value = resp.json().await.context("解析配置失败")?;
    Ok(body)
}

/// 获取规则列表
pub async fn get_rules() -> Result<RulesResponse> {
    let base = api_base()?;
    let secret = auth_header()?;
    let client = create_client()?;

    let resp = client
        .get(format!("{base}/rules"))
        .header("Authorization", format!("Bearer {secret}"))
        .send()
        .await
        .context("获取规则列表失败")?;

    if !resp.status().is_success() {
        anyhow::bail!("获取规则列表失败: HTTP {}", resp.status());
    }

    let rules: RulesResponse = resp.json().await.context("解析规则列表失败")?;
    Ok(rules)
}

/// 获取当前模式
pub async fn get_mode() -> Result<String> {
    let configs = get_configs().await?;
    Ok(configs
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("rule")
        .to_string())
}
