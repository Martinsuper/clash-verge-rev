use crate::{
    cmd,
    config::{Config, PrfItem, PrfOption, profiles::profiles_draft_update_item_safe},
    core::{CoreManager, handle, tray, validate::ValidationOutcome},
    utils::help::{mask_err, mask_url},
};
use anyhow::{Result, bail};
use clash_verge_logging::{Type, logging, logging_error};
use smartstring::alias::String;
use tauri::Emitter as _;
use tauri_plugin_mihomo::models::ProxyType;

/// 检测当前代理节点是否可用
/// 通过 Clash API 测试代理延迟
async fn check_current_proxy_health() -> bool {
    let mihomo = handle::Handle::mihomo().await;

    // 获取代理组信息
    let Ok(proxies) = mihomo.get_proxies().await else {
        logging!(warn, Type::Config, "[代理健康检测] 无法获取代理信息");
        return false;
    };

    // 找到一个选择器类型的代理组（通常是 "PROXY" 或 "节点选择"）
    let selector_group = proxies.proxies.values().find(|p| {
        p.all.is_some()
            && matches!(
                p.proxy_type,
                ProxyType::Selector | ProxyType::URLTest | ProxyType::Fallback
            )
    });

    let Some(group) = selector_group else {
        logging!(debug, Type::Config, "[代理健康检测] 未找到选择器代理组");
        return true; // 没有选择器组，假设正常
    };

    let current_proxy = group.now.as_ref();
    let Some(proxy_name) = current_proxy else {
        logging!(debug, Type::Config, "[代理健康检测] 未找到当前代理节点");
        return true;
    };

    // 跳过 DIRECT 和 REJECT
    if proxy_name == "DIRECT" || proxy_name == "REJECT" {
        return true;
    }

    // 测试代理延迟
    match mihomo
        .delay_proxy_by_name(proxy_name, "https://www.google.com", 5000)
        .await
    {
        Ok(delay_result) => {
            if delay_result.delay > 0 {
                logging!(
                    info,
                    Type::Config,
                    "[代理健康检测] 代理节点 {} 可用，延迟 {}ms",
                    proxy_name,
                    delay_result.delay
                );
                true
            } else {
                logging!(warn, Type::Config, "[代理健康检测] 代理节点 {} 不可用", proxy_name);
                false
            }
        }
        Err(err) => {
            logging!(
                warn,
                Type::Config,
                "[代理健康检测] 代理节点 {} 检测失败: {:?}",
                proxy_name,
                err
            );
            false
        }
    }
}

/// 尝试切换到可用的代理节点
/// 遍历代理组中的所有节点，找到一个可用的
async fn try_switch_to_available_proxy() -> bool {
    let mihomo = handle::Handle::mihomo().await;

    let Ok(proxies) = mihomo.get_proxies().await else {
        return false;
    };

    // 找到选择器代理组
    let selector_group = proxies.proxies.values().find(|p| {
        p.all.is_some()
            && matches!(
                p.proxy_type,
                ProxyType::Selector | ProxyType::URLTest | ProxyType::Fallback
            )
    });

    let Some(group) = selector_group else {
        return false;
    };

    let group_name = &group.name;
    let all_proxies = group.all.as_deref().unwrap_or(&[]);

    logging!(
        info,
        Type::Config,
        "[代理切换] 尝试在 {} 个节点中查找可用节点",
        all_proxies.len()
    );

    // 遍历所有节点，测试延迟
    for proxy_name in all_proxies.iter().take(10) {
        // 最多测试10个节点
        if proxy_name == "DIRECT" || proxy_name == "REJECT" {
            continue;
        }

        match mihomo
            .delay_proxy_by_name(proxy_name, "https://www.google.com", 3000)
            .await
        {
            Ok(delay_result) if delay_result.delay > 0 => {
                logging!(
                    info,
                    Type::Config,
                    "[代理切换] 找到可用节点: {} (延迟 {}ms)，正在切换...",
                    proxy_name,
                    delay_result.delay
                );

                // 切换到这个节点
                match mihomo.select_node_for_group(group_name, proxy_name).await {
                    Ok(_) => {
                        logging!(info, Type::Config, "[代理切换] 成功切换到 {}", proxy_name);
                        return true;
                    }
                    Err(err) => {
                        logging!(warn, Type::Config, "[代理切换] 切换失败: {:?}", err);
                    }
                }
            }
            _ => {
                // 节点不可用，继续测试下一个
            }
        }
    }

    logging!(warn, Type::Config, "[代理切换] 未找到可用节点");
    false
}

/// 恢复保存的代理选择到 mihomo 内核
/// 订阅更新后配置重载会重置代理组选择，需要从 profile 的 selected 字段恢复
pub async fn restore_selected_proxies_by_uid(uid: &String) {
    let profiles = Config::profiles().await;
    let profiles_arc = profiles.latest_arc();

    let Ok(item) = profiles_arc.get_item(uid) else {
        logging!(warn, Type::Config, "[代理恢复] 未找到 profile {}", uid);
        return;
    };

    let Some(selected_list) = &item.selected else {
        logging!(debug, Type::Config, "[代理恢复] profile {} 无保存的代理选择", uid);
        return;
    };

    if selected_list.is_empty() {
        return;
    }

    logging!(
        info,
        Type::Config,
        "[代理恢复] 开始恢复 {} 个代理组的选择",
        selected_list.len()
    );

    let mihomo = handle::Handle::mihomo().await;
    for selected in selected_list {
        if let (Some(group_name), Some(proxy_name)) = (&selected.name, &selected.now) {
            if group_name.is_empty() || proxy_name.is_empty() {
                continue;
            }
            match mihomo
                .select_node_for_group(group_name.as_str(), proxy_name.as_str())
                .await
            {
                Ok(_) => {
                    logging!(
                        info,
                        Type::Config,
                        "[代理恢复] 恢复成功: {} -> {}",
                        group_name,
                        proxy_name
                    );
                }
                Err(err) => {
                    logging!(
                        warn,
                        Type::Config,
                        "[代理恢复] 恢复失败: {} -> {}, 错误: {:?}",
                        group_name,
                        proxy_name,
                        err
                    );
                }
            }
        }
    }
}

/// 恢复当前 profile 的代理选择
pub async fn restore_selected_proxies() {
    let uid = {
        let profiles = Config::profiles().await;
        profiles.latest_arc().get_current().cloned()
    };

    if let Some(uid) = uid {
        restore_selected_proxies_by_uid(&uid).await;
    }
}

/// Toggle proxy profile
pub async fn toggle_proxy_profile(profile_index: String) {
    logging_error!(
        Type::Config,
        cmd::patch_profiles_config_by_profile_index(profile_index).await
    );
}

pub async fn switch_proxy_node(group_name: &str, proxy_name: &str) {
    match handle::Handle::mihomo()
        .await
        .select_node_for_group(group_name, proxy_name)
        .await
    {
        Ok(_) => {
            logging!(info, Type::Tray, "切换代理成功: {} -> {}", group_name, proxy_name);
            let _ = handle::Handle::app_handle().emit("verge://refresh-proxy-config", ());
            let _ = tray::Tray::global().update_menu().await;
            return;
        }
        Err(err) => {
            logging!(
                error,
                Type::Tray,
                "切换代理失败: {} -> {}, 错误: {:?}",
                group_name,
                proxy_name,
                err
            );
        }
    }

    match handle::Handle::mihomo()
        .await
        .select_node_for_group(group_name, proxy_name)
        .await
    {
        Ok(_) => {
            logging!(info, Type::Tray, "代理切换回退成功: {} -> {}", group_name, proxy_name);
            let _ = tray::Tray::global().update_menu().await;
        }
        Err(err) => {
            logging!(
                error,
                Type::Tray,
                "代理切换最终失败: {} -> {}, 错误: {:?}",
                group_name,
                proxy_name,
                err
            );
        }
    }
}

async fn should_update_profile(uid: &String, ignore_auto_update: bool) -> Result<Option<(String, Option<PrfOption>)>> {
    let profiles = Config::profiles().await;
    let profiles = profiles.latest_arc();
    let item = profiles.get_item(uid)?;
    let is_remote = item.itype.as_ref().is_some_and(|s| s == "remote");

    if !is_remote {
        logging!(info, Type::Config, "[订阅更新] {uid} 不是远程订阅，跳过更新");
        Ok(None)
    } else if item.url.is_none() {
        logging!(warn, Type::Config, "Warning: [订阅更新] {uid} 缺少URL，无法更新");
        bail!("failed to get the profile item url");
    } else if !ignore_auto_update && !item.option.as_ref().and_then(|o| o.allow_auto_update).unwrap_or(true) {
        logging!(info, Type::Config, "[订阅更新] {} 禁止自动更新，跳过更新", uid);
        Ok(None)
    } else {
        logging!(
            info,
            Type::Config,
            "[订阅更新] {} 是远程订阅，URL: {}",
            uid,
            mask_url(
                item.url
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Profile URL is None"))?
            )
        );
        Ok(Some((
            item.url.clone().ok_or_else(|| anyhow::anyhow!("Profile URL is None"))?,
            item.option.clone(),
        )))
    }
}

async fn perform_profile_update(
    uid: &String,
    url: &String,
    opt: Option<&PrfOption>,
    option: Option<&PrfOption>,
    is_mannual_trigger: bool,
) -> Result<bool> {
    logging!(info, Type::Config, "[订阅更新] 开始下载新的订阅内容");

    // 检测代理节点健康状态，如果不可用则尝试切换
    if !check_current_proxy_health().await {
        logging!(
            warn,
            Type::Config,
            "[订阅更新] 当前代理节点不可用，尝试切换到可用节点..."
        );
        if try_switch_to_available_proxy().await {
            logging!(info, Type::Config, "[订阅更新] 已切换到可用代理节点");
        } else {
            logging!(
                warn,
                Type::Config,
                "[订阅更新] 无法切换到可用代理节点，将继续尝试更新订阅"
            );
        }
    }

    let mut merged_opt = PrfOption::merge(opt, option);
    let is_current = {
        let profiles = Config::profiles().await;
        profiles.latest_arc().is_current_profile_index(uid)
    };
    let profiles = Config::profiles().await;
    let profiles_arc = profiles.latest_arc();
    let profile_name = profiles_arc
        .get_name_by_uid(uid)
        .cloned()
        .unwrap_or_else(|| String::from("UnKnown Profile"));

    let mut last_err;

    match PrfItem::from_url(url, None, None, merged_opt.as_ref()).await {
        Ok(mut item) => {
            logging!(info, Type::Config, "[订阅更新] 更新订阅配置成功");
            profiles_draft_update_item_safe(uid, &mut item).await?;
            return Ok(is_current);
        }
        Err(err) => {
            logging!(
                warn,
                Type::Config,
                "Warning: [订阅更新] 正常更新失败: {}，尝试使用Clash代理更新",
                mask_err(&err.to_string())
            );
            last_err = err;
        }
    }

    merged_opt.get_or_insert_with(PrfOption::default).self_proxy = Some(true);
    merged_opt.get_or_insert_with(PrfOption::default).with_proxy = Some(false);

    match PrfItem::from_url(url, None, None, merged_opt.as_ref()).await {
        Ok(mut item) => {
            logging!(info, Type::Config, "[订阅更新] 使用 Clash代理 更新订阅配置成功");
            profiles_draft_update_item_safe(uid, &mut item).await?;
            handle::Handle::notice_message("update_with_clash_proxy", profile_name);
            drop(last_err);
            return Ok(is_current);
        }
        Err(err) => {
            logging!(
                warn,
                Type::Config,
                "Warning: [订阅更新] Clash代理更新失败: {}，尝试使用系统代理更新",
                mask_err(&err.to_string())
            );
            last_err = err;
        }
    }

    merged_opt.get_or_insert_with(PrfOption::default).self_proxy = Some(false);
    merged_opt.get_or_insert_with(PrfOption::default).with_proxy = Some(true);

    match PrfItem::from_url(url, None, None, merged_opt.as_ref()).await {
        Ok(mut item) => {
            logging!(info, Type::Config, "[订阅更新] 使用 系统代理 更新订阅配置成功");
            profiles_draft_update_item_safe(uid, &mut item).await?;
            handle::Handle::notice_message("update_with_clash_proxy", profile_name);
            drop(last_err);
            return Ok(is_current);
        }
        Err(err) => {
            logging!(
                warn,
                Type::Config,
                "Warning: [订阅更新] 系统代理更新失败: {}，所有重试均已失败",
                mask_err(&err.to_string())
            );
            last_err = err;
        }
    }

    if is_mannual_trigger {
        handle::Handle::notice_message("update_failed_even_with_clash", format!("{profile_name} - {last_err}"));
    }
    Ok(is_current)
}

pub async fn update_profile(
    uid: &String,
    option: Option<&PrfOption>,
    auto_refresh: bool,
    ignore_auto_update: bool,
    is_mannual_trigger: bool,
) -> Result<()> {
    logging!(info, Type::Config, "[订阅更新] 开始更新订阅 {}", uid);
    let url_opt = should_update_profile(uid, ignore_auto_update).await?;

    let should_refresh = match url_opt {
        Some((url, opt)) => {
            perform_profile_update(uid, &url, opt.as_ref(), option, is_mannual_trigger).await? && auto_refresh
        }
        None => auto_refresh,
    };

    if should_refresh {
        logging!(info, Type::Config, "[订阅更新] 更新内核配置");
        match CoreManager::global().update_config_with_force(is_mannual_trigger).await {
            Ok(outcome) if outcome.is_valid() => {
                logging!(info, Type::Config, "[订阅更新] 更新成功");
                // 恢复之前保存的代理选择，因为配置重载会重置 mihomo 的代理组选择
                restore_selected_proxies_by_uid(uid).await;
                handle::Handle::refresh_clash();
            }
            Ok(outcome @ (ValidationOutcome::Skipped { .. } | ValidationOutcome::Busy)) if !is_mannual_trigger => {
                logging!(info, Type::Config, "[订阅更新] 本次配置刷新已跳过: {}", outcome);
            }
            Ok(outcome) => {
                let message = outcome.to_string();
                logging!(error, Type::Config, "[订阅更新] 更新失败: {}", message);
                handle::Handle::notice_message("update_failed", message);
            }
            Err(err) => {
                logging!(error, Type::Config, "[订阅更新] 更新失败: {}", err);
                handle::Handle::notice_message("update_failed", format!("{err}"));
                logging!(error, Type::Config, "{err}");
            }
        }
    }

    Ok(())
}

/// 增强配置
pub async fn enhance_profiles() -> Result<ValidationOutcome> {
    let outcome = CoreManager::global().update_config_forced().await?;
    if outcome.is_valid() {
        // 恢复之前保存的代理选择，因为配置重载会重置 mihomo 的代理组选择
        restore_selected_proxies().await;
    }
    Ok(outcome)
}
