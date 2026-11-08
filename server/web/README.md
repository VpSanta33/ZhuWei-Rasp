# ZhuWei RASP Console

面向现有 Go API 的 Vue 单页控制台。构建结果通过 `go:embed` 打包进 Server，运行时无需 Node.js、CDN 或独立前端服务。

## 开发

需要 Node.js >=22.12、npm、项目指定版本的 Go。

```bash
cd server/web
npm ci
npm run build
```

另一个终端启动后端：

```bash
cd server
RASP_ADMIN_PASSWORD='设置本机开发密码' go run ./cmd/rasp-server -listen 127.0.0.1:8480
```

然后在 `server/web` 执行 `npm run dev`，访问 `http://127.0.0.1:5173`。`/api` 默认代理到 8480，可用 `RASP_API_URL` 覆盖。前端使用 Hash 路由，嵌入 Go 后刷新深层页面不需要额外的 SPA 回退规则。

## 2026-10 稳定技术基线

直接依赖采用 npm 官方仓库中发布时间早于 2026-11-01 的稳定版本，精确版本与传递依赖通过 `package-lock.json` 锁定：

| 职责 | 方案 |
| --- | --- |
| UI / 组件 | Vue 3.5.44，Composition API、`script setup`、SFC 预编译 |
| 构建 | Vite 8.3.5 / Rolldown，官方 Vue 插件 6.0.10 |
| 类型 | TypeScript 6.0.3 + vue-tsc 3.3.14，严格检查 SFC 和 TS |
| 路由 | Vue Router 5.4.0，懒加载页面、鉴权守卫、URL 筛选条件 |
| 服务端状态 | TanStack Vue Query 5.105.0，缓存、取消请求、刷新、写入后失效 |
| 图标 | 官方更名后的 @lucide/vue 1.66.0，按需打包 |
| 验证 | Playwright 1.64.1，真实 Go API 与隔离数据库 |
| 样式 | 原生 CSS Layers、语义变量、响应式网格、reduced-motion |

选择稳定 Vue 3.5；Vue 3.6 在该截止时间仍是 RC。Vue 类型检查依赖 TypeScript 的 JavaScript API，因此保留 TS 6 工具链；已发布的原生 TS 7 不作为此 SFC 检查链的直接替换。采用纯 SPA 以适配现有 Go 管理后台和单二进制交付。

官方资料：[Vue 发布记录](https://github.com/vuejs/core/releases)、[Vite 8](https://vite.dev/blog/announcing-vite8)、[TypeScript 7 兼容性说明](https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/)、[Vue Router](https://router.vuejs.org/guide/)、[Vue Query](https://tanstack.com/query/latest/docs/framework/vue/overview)。具体 npm 发布时间用于补充官方文档的版本截止日期判断。

## 代码结构与行为

`src/views` 按业务拆分页面；`src/components` 提供弹窗、异步状态、告警表格和详情；`src/lib/api.ts` 统一响应解包、超时、鉴权及错误处理；`types.ts` 定义现有后端的数据协议。

- 所有统计来自真实接口；未接入、无告警、接口错误分别展示实际状态。
- Bearer 凭证保存在当前标签页 sessionStorage；401 清除会话和查询缓存并返回登录，重新登录恢复目标路由。
- 应用凭证默认隐藏；完整接入配置可复制；生产脚本无需 `unsafe-eval`。
- 发布策略、删除应用、加白和全局紧急开关具有明确确认流程。策略会让规则开始阻断时，服务端返回 409 `confirm_required`，前端列出将阻断的规则与在线实例数，要求输入应用名称后携带 `X-Rasp-Confirm` 重新提交。基础策略编辑保留高级字段；未保存的策略离开时提示。
- 导出告警遍历全部匹配分页；CSV 对公式前缀进行转义。组件导出与当前筛选一致，界面标明接口返回上限。
- 原生 dialog + 显式 Tab 循环提供键盘焦点约束（原生 dialog 允许焦点移出到浏览器界面），Escape 关闭和焦点恢复；每个弹窗使用独立标题 id；SVG 趋势提供文本数据表。
- 系统设置展示策略签名密钥 ID 与公钥；实例列表标出拒绝平台策略（验签失败等）的实例；告警详情展示执行线程与“异步任务”标记。
- 前端不展示尚未实现的 CVE、远程卸载或 RBAC 操作。

## 设计系统与多语言

- **令牌**：`src/styles.css` 的 `tokens` 层集中定义颜色、字号、圆角与阴影，组件只引用令牌。主色为企业蓝 `#2563eb`，中性色为 slate 色阶，语义色（成功/警告/危险/信息）各有 `soft/border/text` 三档，图表使用 6 色序列 `--chart-1..6`。
- **字体**：统一使用系统 UI 字体栈（中文回退 PingFang SC / 微软雅黑 / 思源黑体），等宽字体栈用于 IP、版本、路径与代码；字号只用 12/13/14/16/20/24/30 七档，最小 12px，数字使用等宽数字（`.tabular`）。
- **主题**：浅色 / 深色 / 跟随系统，结果写入 `<html data-theme>`，偏好保存在 localStorage（`rasp_theme`）。新增颜色时请同时在 `:root` 与 `:root[data-theme='dark']` 中定义。
- **多语言**：`src/i18n/` 无第三方依赖，`zh-CN.ts` 为默认语言，`en-US.ts` 以其类型为约束——缺少或多出的 key 会导致 `npm run build` 失败。组件中用 `t('模块.键', { 参数 })`；枚举类文案（攻击类型、研判状态、模式）通过 `translated()` 提供可遍历的响应式表。语言偏好保存在 localStorage（`rasp_locale`），并同步 `<html lang>` 与页面标题。
- 顶栏与登录页提供语言和主题切换；CSV 文件名与表头随语言变化。

## 验证与交付

```bash
npm run build                  # 严格类型检查 + 生产构建
npx playwright install chromium # 首次运行浏览器测试时
# 已有其他版本的 Chromium 时可指定：RASP_CHROMIUM_EXECUTABLE=/path/to/chrome-headless-shell npm run test:e2e
npm run test:e2e               # 自动构建并启动隔离 Go Server（端口可用 RASP_E2E_PORT 指定，默认 18480）
cd ..
go vet ./...
go test ./...
go build ./cmd/rasp-server
```

测试在临时目录创建数据库、签名密钥与测试服务，使用真实签名 Agent API 注入测试数据；不会连接已有业务实例。`RASP_SCREENSHOT_DIR=/绝对路径 npm run test:e2e` 可保存桌面与移动端截图。

仓库根目录执行 `./deploy/build.sh` 会先构建前端，再组装 Agent 和内嵌静态资源的 Go 二进制。`dist/` 不提交；干净检出后先构建前端，再执行 Go 测试或构建。
