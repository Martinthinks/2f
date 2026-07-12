# Google 2FA 验证码生成器 - 优化版

基于你上传的 `veil-authenticator.zip` 内容和布局重新优化。

## 上传到 GitHub 根目录

至少上传这些文件：

- index.html
- styles.css
- app.js
- favicon.svg
- vercel.json

Vercel 会自动重新部署。

## 支持链接

- https://你的域名/密钥
- https://你的域名/#密钥
- https://你的域名/?key=密钥

推荐给客户发送：

https://你的域名/密钥

## 功能

- 当前浏览器本地生成 TOTP 验证码
- 30 秒自动刷新
- 复制验证码
- 复制完整链接
- 更换密钥
- Cedars8 在线联系样式


## V11 修复

- 修复本地 file:// 预览时点击“生成验证码 / 更换密钥”报错的问题。
- 原因是本地文件环境不允许 `history.replaceState()` 把地址栏改成 `/密钥`。
- 部署到 Vercel / GitHub 后，`/密钥`、`#密钥`、`?key=密钥` 仍然正常支持。


## V12 调整

- 将账户安全提醒中的“2天”改为“1天”。
- 将 Cedars8 在线联系标签调整到第二行显示。
