use crate::api;
use crate::config;
use anyhow::{Context, Result};

/// 规则子命令
pub async fn run(action: &str, payload: Option<&str>, index: Option<usize>) -> Result<()> {
    match action {
        "list" => list_rules().await,
        "add" => {
            let rule = payload.context("请指定规则内容，例如: DOMAIN,example.com,PROXY")?;
            add_rule(rule).await
        }
        "remove" => {
            let idx = index.context("请指定要删除的规则索引")?;
            remove_rule(idx).await
        }
        _ => {
            println!("用法: cv-cli rules <list|add|remove>");
            println!("  list              列出当前规则");
            println!("  add <RULE>        添加规则 (格式: TYPE,PAYLOAD,PROXY)");
            println!("  remove <INDEX>    删除规则 (索引从 0 开始)");
            Ok(())
        }
    }
}

/// 列出规则
async fn list_rules() -> Result<()> {
    let rules = api::get_rules().await?;

    if rules.rules.is_empty() {
        println!("暂无规则");
        return Ok(());
    }

    println!("当前规则 (共 {} 条):", rules.rules.len());
    println!();

    for (i, rule) in rules.rules.iter().enumerate() {
        println!("  {:4}. [{:12}] {} -> {}", i, rule.r#type, rule.payload, rule.proxy);
    }

    Ok(())
}

/// 添加规则
async fn add_rule(rule: &str) -> Result<()> {
    // 解析规则格式: TYPE,PAYLOAD,PROXY
    let parts: Vec<&str> = rule.splitn(3, ',').collect();
    if parts.len() != 3 {
        anyhow::bail!("规则格式错误，应为: TYPE,PAYLOAD,PROXY\n例如: DOMAIN,example.com,PROXY");
    }

    let rule_type = parts[0].trim();
    let payload = parts[1].trim();
    let proxy = parts[2].trim();

    // 查找规则增强文件
    let config_dir = config::get_config_dir()?;
    let profiles_dir = config_dir.join("profiles");

    // 查找当前 profile 的 rules 增强文件
    let profiles = config::read_profiles()?;
    let current_uid = profiles.current.as_ref().context("未设置当前订阅")?;

    let _current_item = config::find_profile(&profiles, current_uid).context("未找到当前订阅")?;

    // 使用通用的 rules 增强文件
    let rules_file = profiles_dir.join("r_rules.yaml");

    if rules_file.exists() {
        let content = std::fs::read_to_string(&rules_file)?;
        let mut doc: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&content).unwrap_or(serde_yaml_ng::Value::Mapping(Default::default()));

        if let Some(mapping) = doc.as_mapping_mut() {
            if let Some(append) = mapping.get_mut("append") {
                if let Some(seq) = append.as_sequence_mut() {
                    seq.push(serde_yaml_ng::Value::String(rule.to_string()));
                }
            } else {
                mapping.insert(
                    serde_yaml_ng::Value::String("append".to_string()),
                    serde_yaml_ng::Value::Sequence(vec![serde_yaml_ng::Value::String(rule.to_string())]),
                );
            }
        }

        let new_content = serde_yaml_ng::to_string(&doc)?;
        std::fs::write(&rules_file, new_content)?;
    } else {
        // 创建新文件
        let content = format!("append:\n  - \"{}\"\n", rule);
        std::fs::write(&rules_file, content)?;
    }

    println!("✅ 已添加规则: {},{},{}", rule_type, payload, proxy);

    // 重载配置
    println!("正在重载配置...");
    match api::reload_config().await {
        Ok(_) => println!("✅ 配置已重载，规则已生效"),
        Err(err) => println!("⚠️ 配置重载失败: {}", err),
    }

    Ok(())
}

/// 删除规则
async fn remove_rule(index: usize) -> Result<()> {
    let config_dir = config::get_config_dir()?;
    let rules_file = config_dir.join("profiles").join("r_rules.yaml");

    if !rules_file.exists() {
        anyhow::bail!("规则增强文件不存在，没有可删除的规则");
    }

    let content = std::fs::read_to_string(&rules_file)?;
    let mut doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(&content).context("规则文件格式错误")?;

    if let Some(mapping) = doc.as_mapping_mut()
        && let Some(append) = mapping.get_mut("append")
        && let Some(seq) = append.as_sequence_mut()
    {
        if index >= seq.len() {
            anyhow::bail!("索引 {} 超出范围 (共 {} 条规则)", index, seq.len());
        }
        let removed = seq.remove(index);
        let removed_str = removed.as_str().unwrap_or("?");
        println!("✅ 已删除规则: {}", removed_str);
    }

    let new_content = serde_yaml_ng::to_string(&doc)?;
    std::fs::write(&rules_file, new_content)?;

    // 重载配置
    println!("正在重载配置...");
    match api::reload_config().await {
        Ok(_) => println!("✅ 配置已重载，规则已更新"),
        Err(err) => println!("⚠️ 配置重载失败: {}", err),
    }

    Ok(())
}
