<h1 align="center">
  <img src="./src-tauri/icons/icon.png" alt="Clash Verge Rev" width="128" />
  <br>
  Clash Verge Rev
</h1>

<p align="center">
  基于 <a href="https://github.com/tauri-apps/tauri">Tauri 2</a> 的 Clash Meta 图形界面
  <br>
  高性能、跨平台、简洁美观
</p>

<p align="center">
  语言：<a href="./README.md">简体中文</a> · <a href="./docs/README_en.md">English</a>
</p>

---

## 预览

| 深色模式 | 浅色模式 |
| --- | --- |
| ![深色](./docs/preview_dark.png) | ![浅色](./docs/preview_light.png) |

## 安装

前往 [Release 页面](https://github.com/clash-verge-rev/clash-verge-rev/releases) 下载对应平台的安装包。

支持 Windows (x64/x86/ARM64)、Linux (x64/ARM64) 和 macOS 11+ (Intel/Apple Silicon)。

| 版本 | 说明 | 链接 |
| :--- | :--- | :--- |
| Stable | 正式版，适合日常使用 | [下载](https://github.com/clash-verge-rev/clash-verge-rev/releases) |
| AutoBuild | 滚动更新版，适合测试反馈 | [下载](https://github.com/clash-verge-rev/clash-verge-rev/releases/tag/autobuild) |

> 详细安装说明与常见问题请查阅 [文档站点](https://clash-verge-rev.github.io/)

## 功能特性

- 基于 Rust + Tauri 2，内存占用低、启动速度快
- 内置 [Mihomo](https://github.com/MetaCubeX/mihomo) 内核，支持 Alpha 版本切换
- 主题定制：自定义配色、代理组图标、托盘图标、CSS 注入
- 配置增强：Merge、Script 助手，YAML 语法提示
- 系统代理守卫 + TUN 模式（虚拟网卡）
- 可视化编辑：节点编辑器、规则编辑器
- WebDAV 配置同步与备份

## 文档与社区

- 📖 [文档站点](https://clash-verge-rev.github.io/) — 安装指南、FAQ、使用教程
- 💬 Telegram 频道：[@clash_verge_rev](https://t.me/clash_verge_rev)

## 开发

开发环境搭建与贡献指南请查阅 [CONTRIBUTING.md](./CONTRIBUTING.md)。

快速启动：

```shell
pnpm install
pnpm run prebuild
pnpm dev
```

## 贡献与支持

欢迎提交 Issue 和 Pull Request！

如需赞助项目开发，请访问 [GitHub Sponsors](https://github.com/sponsors/clash-verge-rev)。

## 致谢

本项目基于或参考了以下项目：

- [zzzgydi/clash-verge](https://github.com/zzzgydi/clash-verge) — 原 Clash Verge 项目
- [tauri-apps/tauri](https://github.com/tauri-apps/tauri) — 跨平台桌面应用框架
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) — Clash Meta 内核
- [vitejs/vite](https://github.com/vitejs/vite) — 前端构建工具

## 许可证

GPL-3.0 License，详见 [LICENSE](./LICENSE)。