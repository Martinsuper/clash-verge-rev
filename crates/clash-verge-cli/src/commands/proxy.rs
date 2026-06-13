use crate::api;
use crate::config;
use anyhow::{Context, Result};

/// 切换代理节点
pub async fn run(group: &str, node: &str) -> Result<()> {
    // 验证节点是否存在
    let proxies = api::get_proxies().await?;

    let proxy_group = proxies
        .proxies
        .get(group)
        .with_context(|| format!("代理组 '{}' 不存在", group))?;

    let available_nodes = proxy_group.all.as_ref().context("代理组没有可用节点列表")?;

    if !available_nodes.contains(&node.to_string()) {
        println!("节点 '{}' 不在组 '{}' 中", node, group);
        println!();
        println!("可用节点:");
        for (i, name) in available_nodes.iter().enumerate() {
            let current = if proxy_group.now.as_deref() == Some(name.as_str()) {
                " (当前)"
            } else {
                ""
            };
            println!("  {}. {}{}", i + 1, name, current);
        }
        anyhow::bail!("节点 '{}' 不可用", node);
    }

    // 执行切换
    api::select_proxy(group, node).await?;

    // 保存选择到 profiles.yaml
    save_selection(group, node);

    println!("✅ 已切换: {} -> {}", group, node);
    Ok(())
}

/// 保存代理选择到 profiles.yaml
fn save_selection(group: &str, node: &str) {
    let Ok(mut profiles) = config::read_profiles() else {
        return;
    };

    let current_uid = match &profiles.current {
        Some(uid) => uid.clone(),
        None => return,
    };

    let Some(item) = config::find_profile_mut(&mut profiles, &current_uid) else {
        return;
    };

    // 更新或添加选择
    let existing = item.selected.iter_mut().find(|s| s.name.as_deref() == Some(group));

    if let Some(selected) = existing {
        selected.now = Some(node.to_string());
    } else {
        item.selected.push(config::PrfSelectedData {
            name: Some(group.to_string()),
            now: Some(node.to_string()),
        });
    }

    let _ = config::save_profiles(&profiles);
}
