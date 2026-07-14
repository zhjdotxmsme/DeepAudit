# 5+/H5+ 权限模型与绕过

## 权限层次

uniapp App-plus 基于 5+ Runtime，权限模型分四层：

1. **系统层**：Android manifest `<uses-permission>` / iOS Info.plist `NSXxxUsageDescription`
2. **Runtime 层**：5+ 引擎允许列表
3. **App 层**：`manifest.json` -&gt; `app-plus.distribute.permissions`
4. **代码层**：`plus.android.requestPermissions()` 运行时申请

## 常见配置错误

### 过度权限申请

```json
{
  "app-plus": {
    "distribute": {
      "android": {
        "permissions": [
          "<uses-permission android:name=\"android.permission.READ_SMS\"/>",       // 短信权限
          "<uses-permission android:name=\"android.permission.READ_CONTACTS\"/>",  // 通讯录
          "<uses-permission android:name=\"android.permission.RECORD_AUDIO\"/>",   // 录音
          "<uses-permission android:name=\"android.permission.CAMERA\"/>",         // 摄像头
          "<uses-permission android:name=\"android.permission.ACCESS_FINE_LOCATION\"/>",  // GPS
          "<uses-permission android:name=\"android.permission.WRITE_EXTERNAL_STORAGE\"/>",// 外部存储写
          "<uses-permission android:name=\"android.permission.REQUEST_INSTALL_PACKAGES\"/>",// 安装 APK
          "<uses-permission android:name=\"android.permission.SYSTEM_ALERT_WINDOW\"/>",// 悬浮窗
          "<uses-permission android:name=\"android.permission.BIND_ACCESSIBILITY_SERVICE\"/>"// 无障碍！
        ]
      }
    }
  }
}
```

**BIND_ACCESSIBILITY_SERVICE** 是最危险的权限：无障碍服务可读取所有屏幕内容 +
模拟点击 → 事实等同于间谍软件能力。市场审核会拒。

### iOS Info.plist 未声明

iOS 若使用敏感权限（相机、相册、位置、通讯录、麦克风）但缺 UsageDescription
键 → 应用商店直接下架。

```xml
<key>NSCameraUsageDescription</key>
<string>需要相机权限用于扫码</string>
<key>NSPhotoLibraryUsageDescription</key>
<string>需要相册权限用于头像</string>
<key>NSLocationWhenInUseUsageDescription</key>
<string>需要位置权限用于附近搜索</string>
```

### 运行时申请缺失

Android 6.0+ 危险权限必须运行时申请：

```js
plus.android.requestPermissions(
  ['android.permission.READ_EXTERNAL_STORAGE'],
  (result) => {
    if (result.granted.length > 0) {
      // 使用
    }
  }
);
```

若直接调用 API 而未申请 → SecurityException 崩溃。

## 权限提权路径

### 1. WebView 泄露原生能力

若 `plus.webview.getWebviewById(id).setStyle({...})` 或 `evalJS` 允许网页调用
`plus.*` → 网页可越权。

修复：
- web-view 只加载受信任 HTTPS 域名
- native bridge 白名单

### 2. 无障碍服务

一旦拿到 accessibility 权限 = 屏幕录像 + 手势模拟 + 银行 App 抓取。任何 App
申请此权限都应严格审视用途。

### 3. 悬浮窗劫持

`SYSTEM_ALERT_WINDOW` 允许 App 在其他 App 之上绘制。攻击者用于 tapjacking：
覆盖真实登录界面，接管密码输入。

## 审计动作

### manifest.json permissions

- [ ] `WRITE_EXTERNAL_STORAGE` 是否真的需要？（Android 10+ 走 Scoped Storage）
- [ ] `REQUEST_INSTALL_PACKAGES` 若非升级流程需要，删除
- [ ] `BIND_ACCESSIBILITY_SERVICE` 必须有充分理由 + 用户显式引导
- [ ] `RECEIVE_BOOT_COMPLETED` 是否用于业务必需
- [ ] 系统级权限 `WRITE_SETTINGS` / `MODIFY_PHONE_STATE` 一般不该出现

### Info.plist

- [ ] 每个使用的权限都有 UsageDescription
- [ ] Description 文案说明"为什么"而非"什么"
- [ ] `NSAppTransportSecurity` 是否禁用 ATS（不该禁）

### 运行时

```bash
grep -rn 'plus.android.requestPermissions\|plus.ios.request' src/
```

- 是否检查 `result.granted` 而非默认信任
- 拒绝后是否有降级路径

## 相关规则

- CWE: CWE-250 (Execution with Unnecessary Privileges)
- CWE: CWE-732 (Incorrect Permission Assignment)
- CWE: CWE-1021 (Improper Restriction of Rendered UI - Tapjacking)
- 内建 pattern: `uniapp_over_permission`
- 参考：Android 权限最佳实践 https://developer.android.com/guide/topics/permissions/overview
