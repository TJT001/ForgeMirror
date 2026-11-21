# 前端

Vue 3、TypeScript、Vite、Element Plus 加固工作台。

## 已实现

- 上传 APK/AAB、可选 split APK 与多个 device spec JSON。
- Profile、签名模式、AAB universal/split。
- 高级加固选项：内存加载库、签名算法、响应模式、Shell 版本、native 上限、
  授权/事件 URL 与 Token、Core/Text 自解密、`PT_DYNAMIC` 诱饵、section 名表、
  运行时检测、内容密钥内置开关。
- 任务创建、SSE 阶段/进度、取消、产物下载（split/AAB 为 ZIP）。
- 安全事件列表与类型过滤。

## 构建

```bash
npm install
npm run build
npm run dev -- --host 127.0.0.1
```

API 代理见 `vite.config.ts`（默认 `http://localhost:8080`）。
