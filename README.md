<h1 align="center">
  <img src="./src-tauri/icons/icon.png" alt="Clash" width="128" />
  <br>
  Continuation of <a href="https://github.com/zzzgydi/clash-verge">Clash Verge</a>
  <br>
</h1>

<h3 align="center">
A Clash Meta GUI based on <a href="https://github.com/tauri-apps/tauri">Tauri</a>.
</h3>

<p align="center">
  Languages:
  <a href="./README.md">简体中文</a> ·
  <a href="./docs/README_en.md">English</a> ·
  <a href="./docs/README_es.md">Español</a> ·
  <a href="./docs/README_ru.md">Русский</a> ·
  <a href="./docs/README_ja.md">日本語</a> ·
  <a href="./docs/README_ko.md">한국어</a> ·
  <a href="./docs/README_fa.md">فارسی</a>
</p>

## Preview

| Dark                             | Light                             |
| -------------------------------- | --------------------------------- |
| ![预览](./docs/preview_dark.png) | ![预览](./docs/preview_light.png) |

## Install

请到发布页面下载对应的安装包：[Release page](https://github.com/clash-verge-rev/clash-verge-rev/releases)<br>
Go to the [Release page](https://github.com/clash-verge-rev/clash-verge-rev/releases) to download the corresponding installation package<br>
Supports Windows (x64/x86), Linux (x64/arm64) and macOS 11+ (intel/apple).

#### 我应当怎样选择发行版

| 版本        | 特征                                     | 链接                                                                                   |
| :---------- | :--------------------------------------- | :------------------------------------------------------------------------------------- |
| Stable      | 正式版，高可靠性，适合日常使用。         | [Release](https://github.com/clash-verge-rev/clash-verge-rev/releases)                 |
| Alpha(废弃) | 测试发布流程。                           | [Alpha](https://github.com/clash-verge-rev/clash-verge-rev/releases/tag/alpha)         |
| AutoBuild   | 滚动更新版，适合测试反馈，可能存在缺陷。 | [AutoBuild](https://github.com/clash-verge-rev/clash-verge-rev/releases/tag/autobuild) |

#### 安装说明和常见问题，请到 [文档页](https://clash-verge-rev.github.io/) 查看

### TG 频道: [@clash_verge_rev](https://t.me/clash_verge_re)

---

## Promotion

### ✈️ [狗狗加速 —— 技术流机场 Doggygo VPN](https://verge.dginv.click/#/register?code=oaxsAGo6)

🚀 高性能海外技术流机场，支持免费试用与优惠套餐，全面解锁流媒体及 AI 服务，全球首家采用 **QUIC 协议**。

🎁 使用 **Clash Verge 专属邀请链接** 注册即送 **3 天免费试用**，每日 **1GB 流量**：👉 [点此注册](https://verge.dginv.click/#/register?code=oaxsAGo6)

#### **核心优势：**

- 📱 自研 iOS 客户端（业内"唯一"）技术经得起考验，极大**持续研发**投入
- 🧑‍💻 **12小时真人客服**(顺带解决 Clash Verge 使用问题)
- 💰 优惠套餐每月**仅需 21 元，160G 流量，年付 8 折**
- 🌍 海外团队，无跑路风险，高达 50% 返佣
- ⚙️ **集群负载均衡**设计，**负载监控和随时扩容**，高速专线(兼容老客户端)，极低延迟，无视晚高峰，4K 秒开
- ⚡ 全球首家**Quic 协议机场**，现已上线更快的 Quic 类协议(Clash Verge 客户端最佳搭配)
- 🎬 解锁**流媒体及 主流 AI**

🌐 官网：👉 [https://狗狗加速.com](https://verge.dginv.click/#/register?code=oaxsAGo6)

### 🤖 [GPTKefu —— 与 Crisp 深度整合的 AI 智能客服平台](https://gptkefu.com)

- 🧠 深度理解完整对话上下文 + 图片识别，自动给出专业、精准的回复，告别机械式客服。
- ♾️ **不限回答数量**，无额度焦虑，区别于其他按条计费的 AI 客服产品。
- 💬 售前咨询、售后服务、复杂问题解答，全场景轻松覆盖，真实用户案例已验证效果。
- ⚡ 3 分钟极速接入，零门槛上手，即刻提升客服效率与客户满意度。
- 🎁 高级套餐免费试用 14 天，先体验后付费：👉 [立即试用](https://gptkefu.com)
- 📢 智能客服TG 频道：[@crisp_ai](https://t.me/crisp_ai)

---

## Features

- 基于性能强劲的 Rust 和 Tauri 2 框架
- 内置[Clash.Meta(mihomo)](https://github.com/MetaCubeX/mihomo)内核，并支持切换 `Alpha` 版本内核。
- 简洁美观的用户界面，支持自定义主题颜色、代理组/托盘图标以及 `CSS Injection`。
- 配置文件管理和增强（Merge 和 Script），配置文件语法提示。
- 系统代理和守卫、`TUN(虚拟网卡)` 模式。
- 可视化节点和规则编辑
- WebDav 配置备份和同步
- **命令行工具 (cv-cli)**：支持终端快速操作，详见下方 [命令行工具](#命令行工具)

---

## 命令行工具

Clash Verge Rev 内置了命令行工具 `cv-cli`，让你可以在终端中快速管理代理节点、更新订阅、配置规则等。

### 安装命令行工具

安装 Clash Verge Rev 后，运行以下命令创建全局可用的符号链接：

```bash
# macOS
sudo ln -s "/Applications/Clash Verge.app/Contents/Resources/cv-cli-$(uname -m)-apple-darwin" /usr/local/bin/cv-cli

# Linux
sudo ln -s "$HOME/.config/io.github.clash-verge-rev.clash-verge-rev/cv-cli-$(uname -m)-unknown-linux-gnu" /usr/local/bin/cv-cli

# Windows (PowerShell 管理员模式)
New-Item -ItemType SymbolicLink -Path "$env:USERPROFILE\cv-cli.exe" -Target "$env:LOCALAPPDATA\io.github.clash-verge-rev.clash-verge-rev\cv-cli-x86_64-pc-windows-msvc.exe"
```

验证安装：

```bash
cv-cli --version
cv-cli --help
```

### 快速开始

```bash
# 1. 查看当前状态
cv-cli status

# 2. 列出所有代理组
cv-cli list

# 3. 列出节点并测试延迟
cv-cli list --delay

# 4. 切换代理节点
cv-cli switch PROXY "Best-Node"

# 5. 更新订阅
cv-cli update
```

### 命令参考

| 命令 | 说明 | 示例 |
|------|------|------|
| `cv-cli status` | 查看当前状态（模式、代理组、订阅信息） | `cv-cli status` |
| `cv-cli list` | 列出所有代理组和节点 | `cv-cli list -g PROXY --delay` |
| `cv-cli switch` | 切换代理节点 | `cv-cli switch PROXY node-1` |
| `cv-cli update` | 更新订阅 | `cv-cli update --all` |
| `cv-cli rules list` | 列出当前规则 | `cv-cli rules list` |
| `cv-cli rules add` | 添加规则 | `cv-cli rules add -r "DOMAIN,google.com,PROXY"` |
| `cv-cli rules remove` | 删除规则 | `cv-cli rules remove -i 0` |
| `cv-cli test` | 测试节点延迟 | `cv-cli test node-1 -u https://www.google.com` |

### 常用场景

**列出节点并测试延迟：**

```bash
cv-cli list --delay
```

输出示例：
```
📁 PROXY (Selector)
   当前: node-1
  ▶  1. node-1 [45ms]
     2. node-2 [120ms]
     3. node-3 [❌]
```

**添加规则让特定网站走代理：**

```bash
cv-cli rules add -r "DOMAIN,chat.openai.com,PROXY"
cv-cli rules add -r "DOMAIN-SUFFIX,github.com,PROXY"
```

**自动化更新订阅（可配合 cron 定时任务）：**

```bash
# 每天早上 8 点自动更新订阅
crontab -e
0 8 * * * /usr/local/bin/cv-cli update --all >> /tmp/clash-update.log 2>&1
```

**快速切换工作/家庭模式：**

```bash
# 工作模式：直连
cv-cli switch PROXY DIRECT

# 家庭模式：全部代理
cv-cli switch PROXY "Best-Node"
```

### 完整文档

详细使用教程请参考：[命令行工具使用教程](./docs/cli-tutorial.md)

---

### FAQ

Refer to [Doc FAQ Page](https://clash-verge-rev.github.io/faq/windows.html)

### Donation

[捐助Clash Verge Rev的开发](https://github.com/sponsors/clash-verge-rev)

## Development

See [CONTRIBUTING.md](./CONTRIBUTING.md) for more details.

To run the development server, execute the following commands after all prerequisites for **Tauri** are installed:

```shell
pnpm i
pnpm run prebuild
pnpm dev
```

## Contributions

Issue and PR welcome!

## Acknowledgement

Clash Verge rev was based on or inspired by these projects and so on:

- [zzzgydi/clash-verge](https://github.com/zzzgydi/clash-verge): A Clash GUI based on tauri. Supports Windows, macOS and Linux.
- [tauri-apps/tauri](https://github.com/tauri-apps/tauri): Build smaller, faster, and more secure desktop applications with a web frontend.
- [Dreamacro/clash](https://github.com/Dreamacro/clash): A rule-based tunnel in Go.
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo): A rule-based tunnel in Go.
- [Fndroid/clash_for_windows_pkg](https://github.com/Fndroid/clash_for_windows_pkg): A Windows/macOS GUI based on Clash.
- [vitejs/vite](https://github.com/vitejs/vite): Next generation frontend tooling. It's fast!

## License

GPL-3.0 License. See [License here](./LICENSE) for details.
