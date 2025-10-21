# youai-cfworker

一个可部署到 Cloudflare Workers 的轻量代理，提供 OpenAI 兼容的 `/v1/models` 接口，支持：
- 使用手动配置的密钥进行访问控制
- 尝试使用 you.com 账号密码获取可用 AI 模型（实验特性，失败时回退到静态列表）
- Cherry Studio 客户端可将 Worker 的地址作为自定义 API，获取 you.com 里的模型列表

注意：当前版本仅实现获取模型列表（GET /v1/models），用于在客户端中展示和选择模型。对话/补全等接口未实现。

## 快速开始（Cloudflare Workers 部署）

1. 在 Cloudflare Dashboard 中创建一个 Worker
2. 将仓库中的 `worker.js` 文件内容复制到 Worker 的编辑器里
3. 在 Worker 的 Settings -> Variables 中设置如下环境变量：
   - MANUAL_API_KEY：必填。自定义访问密钥，用于客户端鉴权
   - YOU_USERNAME：可选。you.com 登录邮箱/用户名
   - YOU_PASSWORD：可选。you.com 登录密码
   - DYNAMIC_FETCH：可选。设为 `true` 时尝试通过 you.com 账号动态获取模型（可能因风控/CSRF 失败）
   - STATIC_MODELS：可选。JSON 数组字符串，覆盖默认模型列表，例如：
     - `["gpt-4o","claude-3-5-sonnet","llama-3.1-70b-instruct"]`
   - CACHE_TTL_SECONDS：可选。模型列表缓存时间（默认 900 秒）
4. 保存并部署 Worker

## API 使用

- 鉴权方式（任选其一）：
  - `Authorization: Bearer <MANUAL_API_KEY>`
  - `X-API-Key: <MANUAL_API_KEY>`
  - 在查询参数中追加 `?key=<MANUAL_API_KEY>`

- 健康检查：
  - `GET /health` -> `{ "status": "ok" }`

- 获取模型列表（OpenAI 兼容）：
  - `GET /v1/models`
  - 响应示例：
```json
{
  "object": "list",
  "data": [
    { "id": "gpt-4o", "object": "model", "owned_by": "you.com" },
    { "id": "claude-3-5-sonnet", "object": "model", "owned_by": "you.com" }
  ]
}
```

- cURL 示例：
```
curl -H "Authorization: Bearer <MANUAL_API_KEY>" \
  https://<你的-worker-子域>.workers.dev/v1/models
```

## Cherry Studio 客户端配置

1. 打开 Cherry Studio -> 设置 -> 模型/服务商 -> 添加自定义 OpenAI 兼容服务
2. Base URL（基础地址）：
   - 推荐填写：`https://<你的-worker-子域>.workers.dev`
   - 若客户端需要显式 `/v1` 前缀，请改为：`https://<你的-worker-子域>.workers.dev/v1`
3. API Key：填写你在 Worker 中配置的 `MANUAL_API_KEY`
4. 保存后，点击刷新/获取模型列表，应能看到 you.com 模型（或你在 STATIC_MODELS 中自定义的列表）

提示：若无法获取到 you.com 的动态模型（例如因为登录需要额外验证），可在 `STATIC_MODELS` 中手动维护你期望显示的模型列表。

## 工作原理

- 当 `DYNAMIC_FETCH = true` 且提供了 `YOU_USERNAME` 与 `YOU_PASSWORD` 时，Worker 将尝试访问 you.com 相关接口来推断账号可用的模型；
- 若动态获取失败或未启用，则返回默认/静态模型列表；
- 返回格式遵循 OpenAI 的 `/v1/models` 列表规范，便于客户端直接对接；
- 所有 `/v1/*` 接口都需要携带 `MANUAL_API_KEY` 进行鉴权。

## 重要说明

- 本项目不包含 you.com 未公开的正式 API，对 you.com 的访问仅为“尽力而为”的探测；
- 为了稳定使用，建议通过 `STATIC_MODELS` 显式维护你要在客户端展示的模型列表；
- 如需补全/对话等功能，需要进一步开发对应的路由与 you.com 交互逻辑。

## 许可

MIT
