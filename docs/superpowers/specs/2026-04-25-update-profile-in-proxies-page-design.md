# 代理页面更新订阅功能设计

## 目标

在代理页面 Header 区域添加"更新当前订阅"按钮，支持一键更新当前激活的订阅配置文件。

## 需求

- **功能**：更新当前激活的订阅
- **位置**：代理页面 Header 区域，作为独立按钮
- **交互**：简单按钮，点击使用订阅配置的代理更新
- **反馈**：Loading 动画 + Toast 提示

## 技术方案

### 实现方式

直接在 `src/pages/proxies.tsx` 中实现，复用现有的：
- `useProfiles` hook 获取当前激活订阅
- `updateProfile` API 更新订阅
- `useLoadingCache` 管理 loading 状态
- `Notice` 服务显示 Toast

### 按钮位置

```
[Mode: Rule▼] [Chain Mode] [Provider Button] [更新订阅]  ← 新按钮
```

放在 Provider Button 之后，与现有按钮保持一致风格。

### 代码变更

**文件：`src/pages/proxies.tsx`**

1. 导入依赖：
   ```typescript
   import { useProfiles } from "@/hooks/use-profiles";
   import { updateProfile } from "@/services/cmds";
   import { useLoadingCache, useSetLoadingCache } from "@/services/states";
   import { Notice } from "@/services/notice";
   import RefreshRounded from "@mui/icons-material/RefreshRounded";
   ```

2. 添加更新逻辑：
   ```typescript
   const profiles = useProfiles();
   const loadingCache = useLoadingCache();
   const setLoadingCache = useSetLoadingCache();
   const currentUid = profiles.current?.uid;

   const onUpdateCurrentProfile = useLockFn(async () => {
     if (!currentUid) return;
     setLoadingCache({ [currentUid]: true });
     try {
       await updateProfile(currentUid, { with_proxy: true });
       Notice.success(t("profiles.page.update.success"));
       await profiles.mutateProfiles();
     } catch (err) {
       Notice.error(t("profiles.page.update.error", { error: err.message }));
     } finally {
       setLoadingCache({ [currentUid]: false });
     }
   });
   ```

3. 在 Header 按钮区域添加：
   ```tsx
   {currentUid && (
     <IconButton
       size="small"
       color="inherit"
       title={t("profiles.page.actions.updateCurrent")}
       disabled={loadingCache[currentUid]}
       onClick={onUpdateCurrentProfile}
     >
       <RefreshRounded />
     </IconButton>
   )}
   ```

**文件：`src/locales/zh-CN.json`**

添加国际化文本：
```json
{
  "profiles": {
    "page": {
      "actions": {
        "updateCurrent": "更新当前订阅"
      },
      "update": {
        "success": "订阅更新成功",
        "error": "订阅更新失败：{{error}}"
      }
    }
  }
}
```

**文件：`src/locales/en-US.json`**

```json
{
  "profiles": {
    "page": {
      "actions": {
        "updateCurrent": "Update Current Profile"
      },
      "update": {
        "success": "Profile updated successfully",
        "error": "Failed to update profile: {{error}}"
      }
    }
  }
}
```

### 边界情况

- 无当前订阅时：按钮不显示
- 更新中：按钮禁用，图标旋转
- 无网络：Toast 提示错误信息
- 更新成功：Toast 成功提示 + 刷新订阅列表

## 涉及文件

| 文件 | 变更 |
|------|------|
| `src/pages/proxies.tsx` | 添加按钮和更新逻辑 |
| `src/locales/zh-CN.json` | 添加中文文案 |
| `src/locales/en-US.json` | 添加英文文案 |

## 测试要点

1. 当前有激活订阅时，按钮显示
2. 点击按钮，订阅更新成功，显示成功 Toast
3. 更新过程中按钮禁用
4. 无激活订阅时，按钮隐藏
5. 更新失败时，显示错误 Toast