mod api;
mod commands;
mod config;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cv-cli",
    about = "Clash Verge CLI 工具",
    version,
    after_help = "使用示例:\n  cv-cli list                    # 列出所有代理组\n  cv-cli list PROXY --delay      # 列出 PROXY 组并测试延迟\n  cv-cli switch PROXY node-1     # 切换节点\n  cv-cli update                  # 更新当前订阅\n  cv-cli update --all            # 更新所有订阅\n  cv-cli update my-sub           # 更新指定订阅\n  cv-cli rules list              # 列出规则\n  cv-cli rules add DOMAIN,google.com,PROXY\n  cv-cli rules remove 0          # 删除索引为 0 的规则\n  cv-cli status                  # 查看当前状态"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 列出代理节点
    #[command(alias = "ls")]
    List {
        /// 过滤组名（模糊匹配）
        #[arg(short, long)]
        group: Option<String>,

        /// 测试节点延迟
        #[arg(short, long)]
        delay: bool,

        /// JSON 格式输出
        #[arg(short, long)]
        json: bool,
    },

    /// 切换代理节点
    #[command(alias = "sw")]
    Switch {
        /// 代理组名
        group: String,

        /// 节点名
        node: String,
    },

    /// 更新订阅
    #[command(alias = "up")]
    Update {
        /// 订阅 UID 或名称（不指定则更新当前订阅）
        query: Option<String>,

        /// 更新所有订阅
        #[arg(short, long)]
        all: bool,
    },

    /// 规则管理
    Rules {
        /// 子命令: list / add / remove
        action: String,

        /// 规则内容 (add 时使用，格式: TYPE,PAYLOAD,PROXY)
        #[arg(short, long)]
        rule: Option<String>,

        /// 规则索引 (remove 时使用，从 0 开始)
        #[arg(short, long)]
        index: Option<usize>,
    },

    /// 查看当前状态
    Status,

    /// 测试指定节点延迟
    Test {
        /// 节点名
        proxy: String,

        /// 测试 URL
        #[arg(short, long, default_value = "https://www.google.com")]
        url: String,

        /// 超时时间（毫秒）
        #[arg(short, long, default_value_t = 5000)]
        timeout: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::List { group, delay, json } => {
            commands::list::run(group.as_deref(), delay, json).await?;
        }

        Commands::Switch { group, node } => {
            commands::proxy::run(&group, &node).await?;
        }

        Commands::Update { query, all } => {
            commands::update::run(query.as_deref(), all).await?;
        }

        Commands::Rules { action, rule, index } => {
            commands::rules::run(&action, rule.as_deref(), index).await?;
        }

        Commands::Status => {
            let mode = api::get_mode().await?;
            let proxies = api::get_proxies().await?;

            println!("模式: {}", mode);
            println!();

            // 显示代理组
            let groups: Vec<&api::ProxyInfo> = proxies
                .proxies
                .values()
                .filter(|p| {
                    p.all.is_some() && matches!(p.proxy_type.as_deref(), Some("Selector" | "URLTest" | "Fallback"))
                })
                .collect();

            for group in &groups {
                let current = group.now.as_deref().unwrap_or("未选择");
                println!("📁 {} -> {}", group.name, current);
            }

            // 显示当前订阅信息
            if let Ok(profiles) = config::read_profiles()
                && let Some(current_uid) = &profiles.current
                && let Some(item) = config::find_profile(&profiles, current_uid)
            {
                println!();
                println!("当前订阅: {}", item.name.as_deref().unwrap_or("Unknown"));
                if let Some(updated) = item.updated {
                    format_timestamp(updated);
                }
            }
        }

        Commands::Test { proxy, url, timeout } => {
            print!("测试 {} 延迟...", proxy);
            match api::get_delay(&proxy, &url, timeout).await {
                Ok(delay) if delay > 0 => println!(" {}ms", delay),
                Ok(_) => println!(" 超时"),
                Err(err) => println!(" 失败: {}", err),
            }
        }
    }

    Ok(())
}

fn format_timestamp(secs: u64) {
    // 简单的时间戳格式化 (UTC)
    let days = secs / 86400;
    let remaining = secs % 86400;

    // 从 1970-01-01 开始计算
    let mut year = 1970i64;
    let mut day_of_year = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if day_of_year < days_in_year {
            break;
        }
        day_of_year -= days_in_year;
        year += 1;
    }

    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &md in &month_days {
        if day_of_year < md as u64 {
            break;
        }
        day_of_year -= md as u64;
        month += 1;
    }
    let day = day_of_year + 1;

    let hour = remaining / 3600;
    let minute = (remaining % 3600) / 60;
    let second = remaining % 60;

    println!(
        "更新时间: {}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hour, minute, second
    );
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
