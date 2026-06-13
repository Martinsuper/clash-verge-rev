use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 获取配置目录
pub fn get_config_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CLASH_VERGE_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }

    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").context("HOME not set")?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("io.github.clash-verge-rev.clash-verge-rev"))
    }

    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").context("APPDATA not set")?;
        Ok(PathBuf::from(appdata).join("io.github.clash-verge-rev.clash-verge-rev"))
    }

    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").context("HOME not set")?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("io.github.clash-verge-rev.clash-verge-rev"))
    }
}

/// 从 config.yaml 读取 API secret
pub fn read_secret() -> Result<String> {
    let config_dir = get_config_dir()?;
    let config_path = config_dir.join("config.yaml");
    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("无法读取配置文件: {}", config_path.display()))?;

    let config: serde_yaml_ng::Value = serde_yaml_ng::from_str(&content).context("配置文件格式错误")?;

    config
        .get("secret")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("配置文件中未找到 secret 字段"))
}

/// 从 config.yaml 读取 external-controller 地址
pub fn read_external_controller() -> Result<String> {
    let config_dir = get_config_dir()?;
    let config_path = config_dir.join("config.yaml");
    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("无法读取配置文件: {}", config_path.display()))?;

    let config: serde_yaml_ng::Value = serde_yaml_ng::from_str(&content).context("配置文件格式错误")?;

    let controller = config
        .get("external-controller")
        .and_then(|v| v.as_str())
        .unwrap_or("127.0.0.1:9097");

    Ok(controller.to_string())
}

/// profiles.yaml 中的 profile 条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrfItemData {
    #[serde(rename = "uid")]
    pub uid: Option<String>,
    #[serde(rename = "type")]
    pub itype: Option<String>,
    pub name: Option<String>,
    pub file: Option<String>,
    pub url: Option<String>,
    #[serde(default)]
    pub selected: Vec<PrfSelectedData>,
    pub updated: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrfSelectedData {
    pub name: Option<String>,
    pub now: Option<String>,
}

/// profiles.yaml 结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilesData {
    pub current: Option<String>,
    #[serde(default)]
    pub items: Vec<PrfItemData>,
}

/// 读取 profiles.yaml
pub fn read_profiles() -> Result<ProfilesData> {
    let config_dir = get_config_dir()?;
    let profiles_path = config_dir.join("profiles.yaml");
    let content = std::fs::read_to_string(&profiles_path)
        .with_context(|| format!("无法读取 profiles 文件: {}", profiles_path.display()))?;

    let profiles: ProfilesData = serde_yaml_ng::from_str(&content).context("profiles.yaml 格式错误")?;

    Ok(profiles)
}

/// 保存 profiles.yaml
pub fn save_profiles(profiles: &ProfilesData) -> Result<()> {
    let config_dir = get_config_dir()?;
    let profiles_path = config_dir.join("profiles.yaml");
    let content = serde_yaml_ng::to_string(profiles).context("序列化 profiles 失败")?;
    std::fs::write(&profiles_path, content)
        .with_context(|| format!("无法写入 profiles 文件: {}", profiles_path.display()))?;
    Ok(())
}

/// 根据 uid 或 name 查找 profile
pub fn find_profile<'a>(profiles: &'a ProfilesData, query: &str) -> Option<&'a PrfItemData> {
    profiles
        .items
        .iter()
        .find(|item| item.uid.as_deref() == Some(query) || item.name.as_deref() == Some(query))
}

/// 根据 uid 或 name 查找可变引用
pub fn find_profile_mut<'a>(profiles: &'a mut ProfilesData, query: &str) -> Option<&'a mut PrfItemData> {
    profiles
        .items
        .iter_mut()
        .find(|item| item.uid.as_deref() == Some(query) || item.name.as_deref() == Some(query))
}

/// 构建 API 基础 URL（含认证头）
pub fn get_api_base() -> Result<String> {
    let controller = read_external_controller()?;
    Ok(format!("http://{controller}"))
}

/// 获取认证请求头
pub fn get_auth_header() -> Result<String> {
    read_secret()
}
