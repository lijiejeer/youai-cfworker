# youai-cfworker

一个可部署到 Cloudflare Workers 的轻量代理，提供 OpenAI 兼容的接口，将 you.com（YouChat）的能力以 OpenAI 兼容的方式暴露给客户端（如 Cherry Studio）。

已实现功能：
- 手动密钥鉴权（Authorization: Bearer <MANUAL_API_KEY> / X-API-Key / ?key=）
- 模型列表：GET /v1/models（最佳努力从 you.com 推断，失败回退到静态列表）
- 对话补全：POST /v1/chat/completions（支持 stream 与非流式）
- 文本补全：POST /v1/completions（内部映射到 chat/completions）

注意：对 you.com 的调用采用“尽力而为”的公共接口探测与推断，并不保证稳定可用。推荐通过 YOU_COOKIE 直接复用你已登录 you.com 的 Cookie，以提升成功率与稳定性。

## 快速开始（Cloudflare Workers 部署）

1. 在 Cloudflare Dashboard 中创建一个 Worker
2. 将仓库中的 `worker.js` 文件内容复制到 Worker 的编辑器里
3. 在 Worker 的 Settings -> Variables 中设置如下环境变量：
   - MANUAL_API_KEY：必填。自定义访问密钥，用于客户端鉴权
   - YOU_COOKIE：可选。直接粘贴 you.com 的 Cookie 字符串（推荐）
   - YOU_USERNAME：可选。you.com 登录邮箱/用户名（当未提供 YOU_COOKIE 时作为降级尝试）
   - YOU_PASSWORD：可选。you.com 登录密码（当未提供 YOU_COOKIE 时作为降级尝试）
   - DYNAMIC_FETCH：可选。设为 `true` 时，`/v1/models` 会尝试从 you.com 动态探测模型
   - STATIC_MODELS：可选。JSON 数组字符串，覆盖默认模型列表，例如：
     - `["gpt-4o","claude-3-5-sonnet","llama-3.1-70b-instruct"]`
   - CACHE_TTL_SECONDS：可选。模型列表缓存时间（默认 900 秒）
4. 保存并部署 Worker

## 鉴权对应值的获取方式

- MANUAL_API_KEY：
  - 自定义任意一串难以猜测的字符串即可，建议长度 32+。
  - 可用命令生成：
    - macOS/Linux: `openssl rand -hex 32`
    - 或 `python - <<'PY'\nimport secrets; print(secrets.token_hex(32))\nPY`

- YOU_COOKIE（推荐）：
  - 用浏览器登录 you.com；
  - 打开浏览器开发者工具（F12）-> Application/存储 -> Cookies -> 选中 https://you.com；
  - 将相关 Cookie 项拼接为一个 `Cookie` 请求头值（或在 Network 面板选中 you.com 的接口请求，右键 Copy -> Copy request headers，从中复制完整的 `Cookie: ...`）；
  - 将上述整段粘贴到 Worker 环境变量 `YOU_COOKIE` 中；
  - 注：Cookie 有有效期，请勿泄露，过期后需重新复制。

- YOU_USERNAME / YOU_PASSWORD（降级方案）：
  - 分别填写你在 you.com 的登录邮箱/用户名与密码；
  - Worker 会尝试“最佳努力”进行登录以获取 Cookie，可能受风控/CSRF 等影响而失败；
  - 若失败，建议改为提供 `YOU_COOKIE`。

## API 使用

- 健康检查：
  - `GET /health` -> `{ "status": "ok" }`

- 鉴权方式（任选其一）：
  - `Authorization: Bearer <MANUAL_API_KEY>`
  - `X-API-Key: <MANUAL_API_KEY>`
  - 在查询参数中追加 `?key=<MANUAL_API_KEY>`

- 获取模型列表（OpenAI 兼容）：
  - `GET /v1/models`

- 对话补全（OpenAI Chat Completions 兼容）：
  - `POST /v1/chat/completions`
  - 请求示例（非流式）：
```bash
curl -s https://<你的-worker-子域>.workers.dev/v1/chat/completions \
  -H "Authorization: Bearer <MANUAL_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "you-chat",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "用中文介绍一下你自己"}
    ],
    "stream": false
  }'
```
  - 请求示例（流式 stream=true）：
```bash
curl -N https://<你的-worker-子域>.workers.dev/v1/chat/completions \
  -H "Authorization: Bearer <MANUAL_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "you-chat",
    "messages": [
      {"role": "user", "content": "Hello, who are you?"}
    ],
    "stream": true
  }'
```

- 文本补全（OpenAI Completions 兼容）：
  - `POST /v1/completions`（内部会映射到 Chat Completions）
  - 请求示例：
```bash
curl -s https://<你的-worker-子域>.workers.dev/v1/completions \
  -H "Authorization: Bearer <MANUAL_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "you-chat",
    "prompt": "Write a haiku about the ocean.",
    "stream": false
  }'
```

## Cherry Studio 客户端配置

1. 打开 Cherry Studio -> 设置 -> 模型/服务商 -> 添加自定义 OpenAI 兼容服务
2. Base URL（基础地址）：
   - 推荐填写：`https://<你的-worker-子域>.workers.dev`
   - 若客户端需要显式 `/v1` 前缀，请改为：`https://<你的-worker-子域>.workers.dev/v1`
3. API Key：填写你在 Worker 中配置的 `MANUAL_API_KEY`
4. 保存后，点击刷新/获取模型列表；如果配置了 `YOU_COOKIE` 或可登录 you.com，应该可以使用 `you-chat` 或你在 `STATIC_MODELS` 中自定义的模型名。

提示：若无法获取到 you.com 的动态模型或对话失败（例如因为登录需要额外验证），建议直接设置 `YOU_COOKIE`；若仍有问题，可在 `STATIC_MODELS` 中手动维护你期望显示的模型列表，并使用 `you-chat` 作为通用模型名。

## 工作原理

- `/v1/models`：当 `DYNAMIC_FETCH = true` 且提供了 `YOU_COOKIE` 或 `YOU_USERNAME`/`YOU_PASSWORD`，会尝试从 you.com 推断可用模型；失败则回退到静态/默认列表；
- `/v1/chat/completions`：将 OpenAI Chat 请求转换为 you.com 的 YouChat 请求（优先 JSON 接口，失败回退到 SSE 流式接口），并以 OpenAI 兼容格式返回；
- `/v1/completions`：将 `prompt` 映射为单轮 Chat，再复用上述逻辑；
- 所有 `/v1/*` 接口都需要携带 `MANUAL_API_KEY` 进行鉴权。

## 重要说明

- 本项目不包含 you.com 未公开的正式 API，对 you.com 的访问仅为“尽力而为”的探测；
- 由于 you.com 侧接口、风控与 Cookie 过期等因素，无法保证长期稳定；
- 为了稳定使用，优先推荐提供 `YOU_COOKIE`，并按需在 `STATIC_MODELS` 中维护你要展示的模型列表；
- 本项目不保存你的凭证或 Cookie，所有信息仅在 Worker 环境变量中使用。

## 许可

MIT
