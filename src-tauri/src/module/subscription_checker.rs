use crate::{
    config::{Config, IVerge},
    feat,
    process::AsyncHandler,
};
use anyhow::Result;
use clash_verge_logging::{Type, logging, logging_error};
use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex, watch};

const DEFAULT_INTERVAL_MINUTES: u64 = 60;
const MIN_INTERVAL_MINUTES: u64 = 5;
const MAX_INTERVAL_MINUTES: u64 = 1440;
const DEFAULT_TEST_URL: &str = "http://cp.cloudflare.com/generate_204";

#[derive(Clone, Copy, Debug)]
struct SubscriptionCheckerSettings {
    enabled: bool,
    interval_minutes: u64,
}

impl Default for SubscriptionCheckerSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: DEFAULT_INTERVAL_MINUTES,
        }
    }
}

impl SubscriptionCheckerSettings {
    fn from_verge(verge: &IVerge) -> Self {
        let interval = verge
            .subscription_checker_interval_minutes
            .unwrap_or(DEFAULT_INTERVAL_MINUTES)
            .clamp(MIN_INTERVAL_MINUTES, MAX_INTERVAL_MINUTES);

        Self {
            enabled: verge.enable_subscription_checker.unwrap_or(false),
            interval_minutes: interval,
        }
    }
}

pub struct SubscriptionChecker {
    settings: Arc<RwLock<SubscriptionCheckerSettings>>,
    settings_tx: watch::Sender<SubscriptionCheckerSettings>,
    runner_started: AtomicBool,
    exec_lock: Mutex<()>,
}

impl SubscriptionChecker {
    pub fn global() -> &'static Self {
        static INSTANCE: OnceCell<SubscriptionChecker> = OnceCell::new();
        INSTANCE.get_or_init(|| {
            let (tx, _rx) = watch::channel(SubscriptionCheckerSettings::default());
            Self {
                settings: Arc::new(RwLock::new(SubscriptionCheckerSettings::default())),
                settings_tx: tx,
                runner_started: AtomicBool::new(false),
                exec_lock: Mutex::new(()),
            }
        })
    }

    async fn load_settings() -> SubscriptionCheckerSettings {
        let verge = Config::verge().await;
        SubscriptionCheckerSettings::from_verge(&verge.latest_arc())
    }

    pub async fn init(&self) -> Result<()> {
        let settings = Self::load_settings().await;
        {
            *self.settings.write() = settings;
        }
        let _ = self.settings_tx.send(settings);
        self.maybe_start_runner(settings);
        Ok(())
    }

    pub async fn refresh_settings(&self) -> Result<()> {
        let settings = Self::load_settings().await;
        {
            *self.settings.write() = settings;
        }
        let _ = self.settings_tx.send(settings);
        self.maybe_start_runner(settings);
        Ok(())
    }

    fn maybe_start_runner(&self, settings: SubscriptionCheckerSettings) {
        if settings.enabled {
            self.ensure_runner();
        }
    }

    fn ensure_runner(&self) {
        if self.runner_started.swap(true, Ordering::SeqCst) {
            return;
        }

        let mut rx = self.settings_tx.subscribe();
        AsyncHandler::spawn(move || async move {
            Self::run_scheduler(&mut rx).await;
        });
    }

    async fn run_scheduler(rx: &mut watch::Receiver<SubscriptionCheckerSettings>) {
        let mut current = *rx.borrow();
        loop {
            if !current.enabled {
                if rx.changed().await.is_err() {
                    break;
                }
                current = *rx.borrow();
                continue;
            }

            let duration = std::time::Duration::from_secs(current.interval_minutes.saturating_mul(60));
            let sleeper = tokio::time::sleep(duration);
            tokio::pin!(sleeper);

            tokio::select! {
                _ = &mut sleeper => {
                    let _guard = Self::global().exec_lock.lock().await;
                    // Re-check settings after acquiring lock
                    let current_settings = *Self::global().settings.read();
                    if current_settings.enabled {
                        Self::execute_check().await;
                    }
                }
                changed = rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    current = *rx.borrow();
                }
            }
        }
    }

    /// Core check logic: test proxy connectivity and update subscriptions if proxy is unreachable
    async fn execute_check() {
        logging!(info, Type::Timer, "[订阅检查] 开始检查代理连通性");

        // Step 1: Test proxy connectivity
        if !Self::test_proxy().await {
            logging!(warn, Type::Timer, "[订阅检查] 代理连通性测试失败，尝试更新所有远程订阅");

            // Step 2: Update all remote subscriptions
            let updated_count = Self::update_all_remote_subscriptions().await;

            // Step 3: Notify user
            if updated_count > 0 {
                logging!(
                    info,
                    Type::Timer,
                    "[订阅检查] 已自动更新 {} 个远程订阅",
                    updated_count
                );
                Self::refresh_clash_core().await;
                crate::core::handle::Handle::notice_message(
                    "subscription_auto_updated",
                    format!("已自动更新 {} 个订阅", updated_count),
                );
            } else {
                logging!(info, Type::Timer, "[订阅检查] 没有需要更新的远程订阅");
            }
        } else {
            logging!(info, Type::Timer, "[订阅检查] 代理连通性正常，无需更新");
        }
    }

    /// Update all remote profile subscriptions
    async fn update_all_remote_subscriptions() -> usize {
        let profiles = Config::profiles().await;
        let profiles_arc = profiles.latest_arc();
        let items = match profiles_arc.get_items() {
            Some(items) => items.clone(),
            None => return 0,
        };

        let mut updated_count = 0;

        for item in items.iter() {
            // Only update remote profiles
            let is_remote = item.itype.as_ref().is_some_and(|t| t == "remote");
            if !is_remote {
                continue;
            }

            let uid = match &item.uid {
                Some(uid) => uid.clone(),
                None => continue,
            };

            let is_current = profiles_arc.is_current_profile_index(&uid);

            logging!(
                info,
                Type::Timer,
                "[订阅检查] 自动更新订阅: {} (当前: {})",
                uid,
                is_current
            );

            match feat::update_profile(&uid, None, false, true, false).await {
                Ok(_) => {
                    logging!(info, Type::Timer, "[订阅检查] 订阅更新成功: {}", uid);
                    updated_count += 1;
                }
                Err(e) => {
                    logging_error!(Type::Timer, "[订阅检查] 订阅更新失败 {}: {}", uid, e);
                }
            }
        }

        updated_count
    }

    /// Refresh Clash core configuration after subscriptions are updated
    async fn refresh_clash_core() {
        use crate::core::{CoreManager, handle};

        logging!(info, Type::Timer, "[订阅检查] 更新内核配置");
        match CoreManager::global().update_config_with_force(false).await {
            Ok(outcome) if outcome.is_valid() => {
                logging!(info, Type::Timer, "[订阅检查] 内核配置更新成功");
                handle::Handle::refresh_clash();
            }
            Ok(outcome) => {
                let message = outcome.to_string();
                logging!(warn, Type::Timer, "[订阅检查] 内核配置更新跳过: {}", message);
            }
            Err(err) => {
                logging_error!(Type::Timer, "[订阅检查] 内核配置更新失败: {}", err);
                handle::Handle::notice_message("subscription_auto_update_failed", format!("内核配置更新失败: {err}"));
            }
        }
    }

    /// Test proxy connectivity by making a request through the Clash proxy
    /// Returns true if the proxy is working, false otherwise
    async fn test_proxy() -> bool {
        // First check if proxy (system proxy or TUN) is enabled
        // If neither is enabled, the user is not routing traffic through Clash, skip test
        let verge = Config::verge().await;
        let verge_data = verge.latest_arc();
        let proxy_enabled = verge_data.enable_system_proxy.unwrap_or(false) || verge_data.enable_tun_mode.unwrap_or(false);

        if !proxy_enabled {
            logging!(debug, Type::Timer, "[订阅检查] 系统代理和TUN模式均未启用，跳过连通性检查");
            return true; // Not a failure - user is not using the proxy
        }

        // Reuse test_delay which routes through the Clash mixed port when proxy is enabled
        let test_url: smartstring::alias::String = DEFAULT_TEST_URL.into();
        match feat::test_delay(test_url).await {
            Ok(delay) => {
                // test_delay returns 10000 on timeout, <10000 on success
                if delay < 10000 {
                    logging!(info, Type::Timer, "[订阅检查] 代理连通性正常，延迟: {}ms", delay);
                    true
                } else {
                    logging!(warn, Type::Timer, "[订阅检查] 代理连通性测试超时");
                    false
                }
            }
            Err(e) => {
                logging!(warn, Type::Timer, "[订阅检查] 代理连通性测试失败: {}", e);
                false
            }
        }
    }
}
