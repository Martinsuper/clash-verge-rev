# Clash Verge CLI (cv-cli) 使用教程

## 一、安装与配置

### 1.1 安装应用

首先正常安装 Clash Verge Rev 应用（DMG 安装包已包含 cv-cli）。

### 1.2 创建全局命令（推荐）

安装完成后，运行以下命令创建全局可用的符号链接：

```bash
# macOS
sudo ln -s "/Applications/Clash Verge.app/Contents/Resources/cv-cli-$(uname -m)-apple-darwin" /usr/local/bin/cv-cli

# 验证安装
cv-cli --version
cv-cli --help
```

### 1.3 直接使用完整路径

如果不想创建符号链接，可以使用完整路径：

```bash
# macOS Intel
"/Applications/Clash Verge.app/Contents/Resources/cv-cli-x86_64-apple-darwin"

# macOS Apple Silicon (M1/M2/M3)
"/Applications/Clash Verge.app/Contents/Resources/cv-cli-aarch64-apple-darwin"

# Linux
~/.config/io.github.clash-verge-rev.clash-verge-rev/cv-cli-x86_64-unknown-linux-gnu

# Windows (PowerShell)
& "$env:LOCALAPPDATA\io.github.clash-verge-rev.clash-verge-rev\cv-cli-x86_64-pc-windows-msvc.exe"
```

### 1.4 自定义配置目录

默认配置目录：
- macOS: `~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/`
- Linux: `~/.config/io.github.clash-verge-rev.clash-verge-rev/`
- Windows: `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev\`

可通过环境变量覆盖：
```bash
export CLASH_VERGE_CONFIG_DIR=/path/to/custom/config
cv-cli list
```

---

## 二、基础命令

### 2.1 查看帮助

```bash
# 查看总帮助
cv-cli --help

# 查看子命令帮助
cv-cli list --help
cv-cli switch --help
cv-cli update --help
cv-cli rules --help
```

### 2.2 查看当前状态

```bash
cv-cli status
```

输出示例：
```
模式：rule

 PROXY -> node-1
📁 AUTO -> node-2
📁 DIRECT -> DIRECT

当前订阅：My Subscription
更新时间：2026-06-13 10:30:00 UTC
```

---

## 三、节点管理

### 3.1 列出所有代理组

```bash
cv-cli list
```

输出示例：
```
📁 PROXY (Selector)
   当前：node-1
     1. node-1
     2. node-2
     3. node-3

📁 AUTO (URLTest)
   当前：auto-node
     1. auto-node
     2. fallback-node
```

### 3.2 过滤特定代理组

```bash
# 只显示包含 "PROXY" 的组
cv-cli list -g PROXY

# 只显示包含 "节点" 的组（模糊匹配）
cv-cli list -g 节点
```

### 3.3 测试节点延迟

```bash
# 列出所有节点并测试延迟
cv-cli list --delay

# 测试特定组的延迟
cv-cli list -g PROXY --delay
```

输出示例：
```
📁 PROXY (Selector)
   当前：node-1
  ▶  1. node-1 [45ms]
     2. node-2 [120ms]
     3. node-3 [❌]
```

### 3.4 JSON 格式输出

```bash
# 用于脚本处理
cv-cli list --json
```

输出示例：
```json
[
  {
    "group": "PROXY",
    "type": "Selector",
    "current": "node-1",
    "nodes": ["node-1", "node-2", "node-3"]
  }
]
```

### 3.5 切换代理节点

```bash
# 切换 PROXY 组的节点到 node-2
cv-cli switch PROXY node-2

# 输出：✅ 已切换：PROXY -> node-2
```

**常用场景**：
```bash
# 切换到直连
cv-cli switch PROXY DIRECT

# 切换到全局代理
cv-cli switch GLOBAL PROXY
```

### 3.6 测试单个节点延迟

```bash
# 测试指定节点到 Google 的延迟
cv-cli test node-1

# 自定义测试 URL
cv-cli test node-1 -u https://www.gstatic.com/generate_204

# 自定义超时时间（毫秒）
cv-cli test node-1 -t 3000
```

---

## 四、订阅管理

### 4.1 更新当前订阅

```bash
# 更新当前激活的订阅
cv-cli update
```

### 4.2 更新指定订阅

```bash
# 通过 UID 更新
cv-cli update R12345

# 通过名称更新
cv-cli update "My Subscription"
```

### 4.3 更新所有订阅

```bash
cv-cli update --all
```

输出示例：
```
[1/3] 更新 Subscription 1...
[1/3] Subscription 1 - ✅ 成功
[2/3] 更新 Subscription 2...
[2/3] Subscription 2 - ✅ 成功
[3/3] 更新 Subscription 3...
[3/3] Subscription 3 - ❌ 失败：下载失败：HTTP 404

更新完成：2 成功，1 失败
正在重载配置...
✅ 配置已重载
```

---

## 五、规则管理

### 5.1 列出当前规则

```bash
cv-cli rules list
```

输出示例：
```
当前规则 (共 156 条):

   0. [DOMAIN-SUFFIX] google.com -> PROXY
   1. [DOMAIN] www.example.com -> DIRECT
   2. [IP-CIDR] 192.168.0.0/16 -> DIRECT
   3. [MATCH] -> PROXY
```

### 5.2 添加规则

```bash
# 添加域名规则
cv-cli rules add -r "DOMAIN,example.com,PROXY"

# 添加域名后缀规则
cv-cli rules add -r "DOMAIN-SUFFIX,google.com,PROXY"

# 添加 IP 规则
cv-cli rules add -r "IP-CIDR,10.0.0.0/8,DIRECT"

# 添加 GEOIP 规则
cv-cli rules add -r "GEOIP,CN,DIRECT"

# 添加进程规则（Windows）
cv-cli rules add -r "PROCESS-NAME,chrome.exe,PROXY"
```

输出：
```
✅ 已添加规则：DOMAIN,example.com,PROXY
正在重载配置...
✅ 配置已重载，规则已生效
```

### 5.3 删除规则

```bash
# 删除索引为 0 的规则
cv-cli rules remove -i 0

# 输出：✅ 已删除规则：DOMAIN,example.com,PROXY
```

### 5.4 常用规则示例

```bash
# 让特定网站走代理
cv-cli rules add -r "DOMAIN,chat.openai.com,PROXY"
cv-cli rules add -r "DOMAIN,www.google.com,PROXY"
cv-cli rules add -r "DOMAIN-SUFFIX,github.com,PROXY"

# 让特定网站直连
cv-cli rules add -r "DOMAIN,www.baidu.com,DIRECT"
cv-cli rules add -r "DOMAIN-SUFFIX,cn,DIRECT"

# 让特定应用走代理
cv-cli rules add -r "PROCESS-NAME,Telegram,PROXY"
```

---

## 六、高级用法

### 6.1 自动化脚本

**自动切换工作/家庭模式**：

```bash
#!/bin/bash
# switch-work.sh - 切换到工作模式（直连国内，代理国外）

echo "切换到工作模式..."
cv-cli switch PROXY DIRECT
cv-cli rules add -r "GEOIP,CN,DIRECT"
cv-cli rules add -r "MATCH,PROXY"
echo "✅ 工作模式已激活"
```

```bash
#!/bin/bash
# switch-home.sh - 切换到家庭模式（全部代理）

echo "切换到家庭模式..."
cv-cli switch PROXY "Home-Node"
cv-cli rules add -r "MATCH,PROXY"
echo "✅ 家庭模式已激活"
```

**定时更新订阅**：

```bash
#!/bin/bash
# auto-update.sh - 自动更新订阅并切换到最优节点

echo "$(date): 开始更新订阅..."
cv-cli update --all

if [ $? -eq 0 ]; then
    echo "订阅更新成功，切换到自动选择模式..."
    cv-cli switch PROXY AUTO
    echo "$(date): 更新完成"
else
    echo "$(date): 更新失败"
    exit 1
fi
```

添加 crontab 定时任务：
```bash
# 每天早上 8 点自动更新订阅
crontab -e
0 8 * * * /path/to/auto-update.sh >> /tmp/clash-update.log 2>&1
```

### 6.2 与其他工具集成

**与 Alfred/Raycast 集成**：

创建 Alfred Workflow 或 Raycast Script Command：

```bash
#!/bin/bash
# Raycast Script Command: 快速切换节点

case "$1" in
  "直连")
    cv-cli switch PROXY DIRECT
    echo "已切换到直连"
    ;;
  "代理")
    cv-cli switch PROXY "Best-Node"
    echo "已切换到代理"
    ;;
  "更新订阅")
    cv-cli update
    echo "订阅已更新"
    ;;
esac
```

**与快捷指令集成（iOS/macOS）**：

通过「运行 Shell 脚本」动作调用：
```bash
/usr/local/bin/cv-cli switch PROXY "$1"
```

### 6.3 监控与告警

**监控代理可用性**：

```bash
#!/bin/bash
# monitor-proxy.sh - 监控代理节点可用性

NODE="Best-Node"
DELAY=$(cv-cli test "$NODE" 2>&1 | grep -o '[0-9]*ms' | grep -o '[0-9]*')

if [ -z "$DELAY" ]; then
    echo "⚠️ 代理节点 $NODE 不可用！"
    # 发送通知（macOS）
    osascript -e 'display notification "代理节点不可用，请检查！" with title "Clash Verge"'
    exit 1
else
    echo "✅ 代理节点 $NODE 延迟：${DELAY}ms"
fi
```

---

## 七、故障排除

### 7.1 常见错误

| 错误信息 | 原因 | 解决方案 |
|---------|------|---------|
| `无法读取配置文件` | 配置目录不存在 | 确保 Clash Verge 已运行过至少一次 |
| `请求 /proxies 失败` | Clash Verge 未运行 | 启动 Clash Verge 应用 |
| `API 请求失败：HTTP 401` | Secret 不匹配 | 检查 config.yaml 中的 secret |
| `代理组不存在` | 组名拼写错误 | 使用 `cv-cli list` 查看正确的组名 |
| `节点不可用` | 节点不在组中 | 使用 `cv-cli list -g 组名` 查看可用节点 |

### 7.2 调试模式

```bash
# 设置调试环境变量
export RUST_LOG=debug
cv-cli list
```

### 7.3 重置配置

```bash
# 如果配置文件损坏，可以删除后重启应用
rm -rf ~/Library/Application\ Support/io.github.clash-verge-rev.clash-verge-rev/
# 然后重新启动 Clash Verge
```

---

## 八、完整命令参考

```
cv-cli                          # 显示帮助
cv-cli --version                # 显示版本

cv-cli status                   # 查看当前状态
cv-cli list                     # 列出所有代理组
cv-cli list -g PROXY            # 过滤特定组
cv-cli list --delay             # 测试延迟
cv-cli list --json              # JSON 输出

cv-cli switch PROXY node-1      # 切换节点
cv-cli test node-1              # 测试延迟
cv-cli test node-1 -u URL       # 自定义测试 URL
cv-cli test node-1 -t 3000      # 自定义超时

cv-cli update                   # 更新当前订阅
cv-cli update UID               # 更新指定订阅
cv-cli update --all             # 更新所有订阅

cv-cli rules list               # 列出规则
cv-cli rules add -r "RULE"      # 添加规则
cv-cli rules remove -i 0        # 删除规则
```

---

## 九、快速开始

**5 分钟上手**：

```bash
# 1. 安装
sudo ln -s "/Applications/Clash Verge.app/Contents/Resources/cv-cli-$(uname -m)-apple-darwin" /usr/local/bin/cv-cli

# 2. 查看当前状态
cv-cli status

# 3. 查看可用节点
cv-cli list

# 4. 切换节点
cv-cli switch PROXY "Best-Node"

# 5. 更新订阅
cv-cli update
```

现在你已经掌握了 cv-cli 的基本使用方法！
