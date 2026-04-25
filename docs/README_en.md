<h1 align="center">
  <img src="../src-tauri/icons/icon.png" alt="Clash Verge Rev" width="128" />
  <br>
  Clash Verge Rev
</h1>

<p align="center">
  A Clash Meta GUI built with <a href="https://github.com/tauri-apps/tauri">Tauri 2</a>
  <br>
  High-performance, cross-platform, and elegant
</p>

<p align="center">
  Languages: <a href="../README.md">简体中文</a> · <a href="./README_en.md">English</a>
</p>

---

## Preview

| Dark Mode | Light Mode |
| --- | --- |
| ![Dark](./preview_dark.png) | ![Light](./preview_light.png) |

## Installation

Download the installer for your platform from the [Release page](https://github.com/clash-verge-rev/clash-verge-rev/releases).

Available for Windows (x64/x86/ARM64), Linux (x64/ARM64), and macOS 11+ (Intel/Apple Silicon).

| Channel | Description | Link |
| :--- | :--- | :--- |
| Stable | Production-ready, recommended for daily use | [Download](https://github.com/clash-verge-rev/clash-verge-rev/releases) |
| AutoBuild | Rolling builds for testing and feedback | [Download](https://github.com/clash-verge-rev/clash-verge-rev/releases/tag/autobuild) |

> For detailed installation guides and troubleshooting, see the [Documentation Site](https://clash-verge-rev.github.io/)

## Features

- Built on Rust + Tauri 2: low memory usage, fast startup
- Bundled [Mihomo](https://github.com/MetaCubeX/mihomo) core with Alpha channel support
- Custom themes: colors, proxy group icons, tray icons, CSS injection
- Profile enhancement: Merge, Script helpers, YAML syntax hints
- System proxy guard + TUN mode (virtual network adapter)
- Visual editors for nodes and rules
- WebDAV sync and backup for configurations

## Documentation & Community

- 📖 [Documentation Site](https://clash-verge-rev.github.io/) — Guides, FAQ, tutorials
- 💬 Telegram Channel: [@clash_verge_rev](https://t.me/clash_verge_rev)

## Development

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and contribution guidelines.

Quick start:

```shell
pnpm install
pnpm run prebuild
pnpm dev
```

## Contributing

Issues and pull requests are welcome!

To support development, visit [GitHub Sponsors](https://github.com/sponsors/clash-verge-rev).

## Acknowledgements

This project builds on or draws inspiration from:

- [zzzgydi/clash-verge](https://github.com/zzzgydi/clash-verge) — Original Clash Verge project
- [tauri-apps/tauri](https://github.com/tauri-apps/tauri) — Cross-platform desktop app framework
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) — Clash Meta core
- [vitejs/vite](https://github.com/vitejs/vite) — Frontend build tool

## License

GPL-3.0 License. See [LICENSE](../LICENSE) for details.