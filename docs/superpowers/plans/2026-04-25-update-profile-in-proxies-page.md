# 代理页面更新订阅功能实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在代理页面 Header 区域添加"更新当前订阅"按钮

**Architecture:** 直接在 proxies.tsx 中添加按钮组件，复用现有 useProfiles hook、updateProfile API、showNotice 服务

**Tech Stack:** React 19 + TypeScript + MUI + TanStack Query

---

## 文件结构

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/locales/zh/proxies.json` | 修改 | 添加中文翻译键 |
| `src/locales/en/proxies.json` | 修改 | 添加英文翻译键 |
| `src/pages/proxies.tsx` | 修改 | 添加更新订阅按钮 |

---

### Task 1: 添加国际化文本

**Files:**
- Modify: `src/locales/zh/proxies.json`
- Modify: `src/locales/en/proxies.json`

- [ ] **Step 1: 添加中文翻译键**

在 `src/locales/zh/proxies.json` 的 `page.actions` 中添加：

```json
{
  "page": {
    "actions": {
      "toggleChain": "链式代理",
      "connect": "连接",
      "disconnect": "断开",
      "connecting": "连接中...",
      "clearChainConfig": "删除链式配置",
      "updateProfile": "更新订阅"
    },
    ...
  },
  "feedback": {
    "notifications": {
      "profile": {
        "updateSuccess": "订阅更新成功",
        "updateFailed": "订阅更新失败: {{message}}"
      },
      ...
    }
  }
}
```

完整修改：在 `page.actions` 中新增 `"updateProfile": "更新订阅"`，在 `feedback.notifications` 中新增 `profile` 子对象。

- [ ] **Step 2: 添加英文翻译键**

在 `src/locales/en/proxies.json` 的 `page.actions` 中添加：

```json
{
  "page": {
    "actions": {
      "toggleChain": "Chain Proxy",
      "connect": "Connect",
      "disconnect": "Disconnect",
      "connecting": "Connecting...",
      "clearChainConfig": "Delete Chain Config",
      "updateProfile": "Update Profile"
    },
    ...
  },
  "feedback": {
    "notifications": {
      "profile": {
        "updateSuccess": "Profile updated successfully",
        "updateFailed": "Failed to update profile: {{message}}"
      },
      ...
    }
  }
}
```

- [ ] **Step 3: 运行国际化脚本生成类型**

```bash
pnpm i18n:types
```

Expected: 成功生成翻译类型文件，新增 `updateProfile`、`updateSuccess`、`updateFailed` 键。

- [ ] **Step 4: Commit**

```bash
git add src/locales
git commit -m "feat(i18n): add update profile translations for proxies page"
```

---

### Task 2: 在代理页面添加更新订阅按钮

**Files:**
- Modify: `src/pages/proxies.tsx`

- [ ] **Step 1: 添加导入**

在 `src/pages/proxies.tsx` 文件顶部添加导入：

```typescript
import { RefreshRounded } from '@mui/icons-material'
import { IconButton } from '@mui/material'
import { updateProfile } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'
import { useProfiles } from '@/hooks/use-profiles'
```

注意：`IconButton` 可能已通过 `ButtonGroup` 或其他组件导入，检查现有导入避免重复。如果 `Button` 已从 `@mui/material` 导入，可以将 `IconButton` 添加到同一导入语句中。

- [ ] **Step 2: 在组件内添加 hooks 和状态**

在 `ProxyPage` 组件内，`const { t } = useTranslation()` 之后添加：

```typescript
const { current, mutateProfiles } = useProfiles()
const [updatingProfile, setUpdatingProfile] = useState(false)
```

需要确保 `useState` 已导入（检查现有导入列表）。

- [ ] **Step 3: 添加更新处理函数**

在 `onToggleChainMode` 函数之后添加：

```typescript
const onUpdateCurrentProfile = useLockFn(async () => {
  if (!current?.uid || updatingProfile) return

  setUpdatingProfile(true)
  try {
    await updateProfile(current.uid, { with_proxy: true })
    showNotice.success('proxies.feedback.notifications.profile.updateSuccess')
    await mutateProfiles()
  } catch (err) {
    showNotice.error('proxies.feedback.notifications.profile.updateFailed', {
      message: String(err),
    })
  } finally {
    setUpdatingProfile(false)
  }
})
```

- [ ] **Step 4: 在 Header 区域添加按钮**

在 `header` prop 的 Box 内，`ProviderButton` 之后添加按钮：

```tsx
header={
  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
    <ProviderButton />

    {current?.uid && (
      <IconButton
        size="small"
        color="inherit"
        title={t('proxies.page.actions.updateProfile')}
        disabled={updatingProfile}
        onClick={onUpdateCurrentProfile}
        sx={{
          animation: updatingProfile
            ? 'spin 1s linear infinite'
            : 'none',
          '@keyframes spin': {
            '0%': { transform: 'rotate(0deg)' },
            '100%': { transform: 'rotate(360deg)' },
          },
        }}
      >
        <RefreshRounded />
      </IconButton>
    )}

    <ButtonGroup size="small">
      ...
    </ButtonGroup>
    ...
  </Box>
}
```

按钮位置应在 `ProviderButton` 和 `ButtonGroup` 之间。

- [ ] **Step 5: Commit**

```bash
git add src/pages/proxies.tsx
git commit -m "feat(proxies): add update current profile button in header"
```

---

### Task 3: 测试功能

- [ ] **Step 1: 启动开发服务器**

```bash
pnpm dev
```

Expected: 开发服务器启动成功。

- [ ] **Step 2: 手动测试功能**

测试要点：
1. 当前有激活订阅时，按钮显示在 Header 区域
2. 点击按钮，按钮显示旋转动画（loading 状态）
3. 更新成功后，显示成功 Toast 提示
4. 更新失败时，显示错误 Toast 提示
5. 无激活订阅时，按钮隐藏

- [ ] **Step 3: 最终提交（如有修改）**

如有任何修复或调整：

```bash
git add -A
git commit -m "fix: resolve issues found during testing"
```

---

## Self-Review Checklist

- [x] Spec coverage: 所有设计文档中的需求已实现
- [x] Placeholder scan: 无 TBD/TODO 占位符
- [x] Type consistency: 翻译键路径一致