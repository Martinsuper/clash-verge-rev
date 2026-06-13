use crate::api;
use anyhow::Result;

/// 列出代理节点
pub async fn run(group_filter: Option<&str>, test_delay: bool, json_output: bool) -> Result<()> {
    let proxies = api::get_proxies().await?;

    // 收集所有代理组
    let mut groups: Vec<&api::ProxyInfo> = proxies
        .proxies
        .values()
        .filter(|p| {
            p.all.is_some()
                && matches!(
                    p.proxy_type.as_deref(),
                    Some("Selector" | "URLTest" | "Fallback" | "LoadBalance")
                )
        })
        .collect();

    groups.sort_by_key(|g| g.name.clone());

    if json_output {
        let output: Vec<serde_json::Value> = groups
            .iter()
            .map(|g| {
                serde_json::json!({
                    "group": g.name,
                    "type": g.proxy_type,
                    "current": g.now,
                    "nodes": g.all,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    if groups.is_empty() {
        println!("暂无代理组");
        return Ok(());
    }

    for group in &groups {
        if let Some(filter) = group_filter
            && !group.name.contains(filter)
        {
            continue;
        }

        let group_type = group.proxy_type.as_deref().unwrap_or("Unknown");
        let current = group.now.as_deref().unwrap_or("未选择");

        println!();
        println!("📁 {} ({})", group.name, group_type);
        println!("   当前: {}", current);

        if let Some(nodes) = &group.all {
            if test_delay {
                // 并行测试延迟
                let mut delays = Vec::new();
                for node_name in nodes {
                    match api::get_delay(node_name, "https://www.google.com", 5000).await {
                        Ok(delay) if delay > 0 => delays.push((node_name.clone(), delay)),
                        _ => delays.push((node_name.clone(), 0)),
                    }
                }
                // 按延迟排序
                delays.sort_by_key(|(_, d)| if *d == 0 { u64::MAX } else { *d });

                for (i, (name, delay)) in delays.iter().enumerate() {
                    let is_current = group.now.as_deref() == Some(name.as_str());
                    let marker = if is_current { "▶" } else { " " };
                    let delay_str = if *delay == 0 {
                        "❌".to_string()
                    } else {
                        format!("{}ms", delay)
                    };
                    println!("  {} {:2}. {} [{}]", marker, i + 1, name, delay_str);
                }
            } else {
                for (i, name) in nodes.iter().enumerate() {
                    let is_current = group.now.as_deref() == Some(name.as_str());
                    let marker = if is_current { "▶" } else { " " };
                    println!("  {} {:2}. {}", marker, i + 1, name);
                }
            }
        }
    }

    Ok(())
}
