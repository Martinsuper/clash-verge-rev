use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use reqwest::Client;

use crate::config;

/// 更新订阅
pub async fn run(query: Option<&str>, force_all: bool) -> Result<()> {
    let mut profiles = config::read_profiles()?;
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("创建 HTTP 客户端失败")?;

    // 确定要更新的 profile
    let items_to_update: Vec<usize> = if force_all {
        profiles
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.itype.as_deref() == Some("remote"))
            .map(|(i, _)| i)
            .collect()
    } else if let Some(q) = query {
        let idx = profiles
            .items
            .iter()
            .enumerate()
            .find(|(_, item)| item.uid.as_deref() == Some(q) || item.name.as_deref() == Some(q))
            .map(|(i, _)| i);

        match idx {
            Some(i) => vec![i],
            None => anyhow::bail!("未找到订阅: {}", q),
        }
    } else {
        // 无参数：更新当前 profile
        let current = profiles.current.clone();
        match current {
            Some(uid) => {
                let idx = profiles
                    .items
                    .iter()
                    .enumerate()
                    .find(|(_, item)| item.uid.as_deref() == Some(uid.as_str()));
                match idx {
                    Some((i, _)) => vec![i],
                    None => anyhow::bail!("当前订阅不存在: {}", uid),
                }
            }
            None => anyhow::bail!("未设置当前订阅"),
        }
    };

    let total = items_to_update.len();
    let mut success_count = 0;
    let mut fail_count = 0;

    for (idx, item_idx) in items_to_update.iter().enumerate() {
        // Extract values before mutable borrow
        let name = profiles.items[*item_idx]
            .name
            .as_deref()
            .unwrap_or("Unknown")
            .to_string();
        let uid = profiles.items[*item_idx]
            .uid
            .as_deref()
            .unwrap_or("Unknown")
            .to_string();
        let url = match &profiles.items[*item_idx].url {
            Some(u) => u.clone(),
            None => {
                println!("[{}/{}] {} - 跳过（非远程订阅）", idx + 1, total, name);
                continue;
            }
        };

        println!("[{}/{}] 更新 {}...", idx + 1, total, name);

        match update_single(&client, &profiles, &uid, &url).await {
            Ok(()) => {
                // 更新成功，更新时间戳
                if let Some(item) = profiles.items.get_mut(*item_idx) {
                    item.updated = Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    );
                }
                println!("[{}/{}] {} - ✅ 成功", idx + 1, total, name);
                success_count += 1;
            }
            Err(err) => {
                println!("[{}/{}] {} - ❌ 失败: {}", idx + 1, total, name, err);
                fail_count += 1;
            }
        }
    }

    // 保存 profiles
    let _ = config::save_profiles(&profiles);

    println!();
    println!("更新完成: {} 成功, {} 失败", success_count, fail_count);

    if success_count > 0 {
        // 重载配置
        println!("正在重载配置...");
        match crate::api::reload_config().await {
            Ok(_) => println!("✅ 配置已重载"),
            Err(err) => println!("⚠️ 配置重载失败: {} (可稍后手动重载)", err),
        }
    }

    Ok(())
}

/// 更新单个订阅
async fn update_single(client: &Client, profiles: &config::ProfilesData, uid: &str, url: &str) -> Result<()> {
    // 下载订阅内容
    let resp = client
        .get(url)
        .header("User-Agent", "clash-verge-cli/0.1.0")
        .send()
        .await
        .context("下载订阅失败")?;

    if !resp.status().is_success() {
        anyhow::bail!("下载失败: HTTP {}", resp.status());
    }

    let body = resp.text().await.context("读取响应内容失败")?;

    // 处理内容
    let content = process_subscription_content(&body)?;

    // 验证 YAML 格式
    let _: serde_yaml_ng::Value = serde_yaml_ng::from_str(&content).context("订阅内容不是有效的 YAML 格式")?;

    // 保存文件
    let config_dir = config::get_config_dir()?;
    let profiles_dir = config_dir.join("profiles");
    std::fs::create_dir_all(&profiles_dir)?;

    // 查找文件名
    let default_filename = format!("{}.yaml", uid);
    let filename = profiles
        .items
        .iter()
        .find(|item| item.uid.as_deref() == Some(uid))
        .and_then(|item| item.file.as_ref())
        .map(|f| f.as_str())
        .unwrap_or(&default_filename);

    let file_path = profiles_dir.join(filename);
    std::fs::write(&file_path, &content).with_context(|| format!("写入文件失败: {}", file_path.display()))?;

    Ok(())
}

/// 处理订阅内容（Base64 解码、BOM 去除等）
fn process_subscription_content(data: &str) -> Result<String> {
    // 去除 BOM
    let data = data.trim_start_matches('\u{feff}');

    // 检查是否为 Base64 编码
    if is_base64_encoded(data) {
        let decoded = BASE64.decode(data.trim()).context("Base64 解码失败")?;
        let decoded_str = String::from_utf8(decoded).context("解码内容不是有效的 UTF-8")?;
        Ok(decoded_str)
    } else {
        Ok(data.to_string())
    }
}

/// 检查是否为 Base64 编码内容
fn is_base64_encoded(data: &str) -> bool {
    let trimmed = data.trim();

    // 如果看起来已经是代理链接，不需要解码
    if trimmed.starts_with("ss://")
        || trimmed.starts_with("vmess://")
        || trimmed.starts_with("trojan://")
        || trimmed.starts_with("vless://")
        || trimmed.starts_with("hysteria://")
        || trimmed.starts_with("hysteria2://")
        || trimmed.starts_with("hy2://")
        || trimmed.starts_with("ssr://")
    {
        return true;
    }

    // 如果看起来是 YAML，不需要解码
    if trimmed.contains("proxies:") || trimmed.contains("proxy-groups:") {
        return false;
    }

    // 尝试 Base64 解码
    BASE64.decode(trimmed).is_ok()
}
