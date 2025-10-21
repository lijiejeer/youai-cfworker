/*
  Cloudflare Worker for exposing OpenAI-compatible endpoints backed by you.com account context.

  Implemented endpoints:
  - GET  /v1/models               List available models (best-effort from you.com; falls back to static list)
  - POST /v1/chat/completions     Chat completions (non/streaming) via you.com YouChat endpoints (best-effort)
  - POST /v1/completions          Text completions mapped onto chat completions
  - GET  /health                  Health check

  Auth:
  - Manual API key via Authorization: Bearer <MANUAL_API_KEY>, X-API-Key, or ?key=

  Required Env Vars (set in Cloudflare Worker > Settings > Variables):
  - MANUAL_API_KEY        Manually defined API key the client must present

  Optional Env Vars:
  - YOU_USERNAME          you.com 登录邮箱/用户名
  - YOU_PASSWORD          you.com 登录密码
  - YOU_COOKIE            直接粘贴的 you.com Cookie 字符串（优先于用户名与密码，推荐）
  - STATIC_MODELS         JSON 数组字符串，覆盖默认的模型列表（例如: ["gpt-4o","claude-3-5-sonnet"]）
  - DYNAMIC_FETCH         "true" 时尝试通过 you.com 账号动态获取模型（实验特性）
  - CACHE_TTL_SECONDS     缓存模型列表的秒数（默认 900 秒）
*/

const DEFAULT_MODELS = [
  "gpt-4o",
  "gpt-4o-mini",
  "gpt-4.1",
  "gpt-4.1-mini",
  "claude-3-5-sonnet",
  "claude-3-5-haiku",
  "llama-3.1-405b-instruct",
  "llama-3.1-70b-instruct",
  "mistral-large-latest",
  "qwen-2-72b-instruct",
  "you-chat",
];

let cache = {
  models: null,
  ts: 0,
};

export default {
  async fetch(request, env, ctx) {
    try {
      // CORS preflight
      if (request.method === "OPTIONS") {
        return withCors(new Response(null, { status: 204 }), request);
      }

      const url = new URL(request.url);

      // Root route or health check
      if (url.pathname === "/" || url.pathname === "") {
        return withCors(
          json({
            name: "youai-cfworker",
            status: "ok",
            endpoints: [
              "GET /health",
              "GET /v1/models",
              "POST /v1/chat/completions",
              "POST /v1/completions",
            ],
            docs: "https://github.com/",
          }),
          request
        );
      }
      if (url.pathname === "/health") {
        return withCors(json({ status: "ok" }), request);
      }

      // Auth check for API endpoints under /v1
      if (url.pathname.startsWith("/v1")) {
        const authorized = checkAuth(request, env);
        if (!authorized.ok) {
          return withCors(
            json({ error: "unauthorized", message: authorized.message }, 401),
            request
          );
        }
      }

      // OpenAI-compatible: list models
      if (url.pathname === "/v1/models" && request.method === "GET") {
        const models = await getModels(env);
        const data = models.map((id) => ({ id, object: "model", owned_by: "you.com" }));
        return withCors(json({ object: "list", data }), request);
      }

      // OpenAI-compatible: text completions mapped to chat
      if (url.pathname === "/v1/completions" && request.method === "POST") {
        const body = await safeParseJson(request);
        if (!body || (!body.prompt && !Array.isArray(body.prompt))) {
          return withCors(json({ error: "invalid_request", message: "Missing 'prompt'" }, 400), request);
        }
        const prompt = Array.isArray(body.prompt) ? body.prompt.join("\n\n") : String(body.prompt || "");
        const chatBody = {
          model: body.model || "you-chat",
          messages: [
            ...(body.system ? [{ role: "system", content: String(body.system) }] : []),
            { role: "user", content: prompt },
          ],
          stream: !!body.stream,
          temperature: body.temperature,
          top_p: body.top_p,
          max_tokens: body.max_tokens,
        };
        return await handleChatCompletions(chatBody, request, env);
      }

      // OpenAI-compatible: chat completions
      if (url.pathname === "/v1/chat/completions" && request.method === "POST") {
        const body = await safeParseJson(request);
        if (!body || !Array.isArray(body.messages)) {
          return withCors(json({ error: "invalid_request", message: "Missing 'messages' array" }, 400), request);
        }
        return await handleChatCompletions(body, request, env);
      }

      return withCors(json({ error: "not_found" }, 404), request);
    } catch (err) {
      return withCors(json({ error: "internal_error", message: String(err?.message || err) }, 500), request);
    }
  },
};

function checkAuth(request, env) {
  const manualKey = env?.MANUAL_API_KEY;
  if (!manualKey) {
    return { ok: false, message: "MANUAL_API_KEY is not set on the worker" };
  }
  const auth = request.headers.get("authorization");
  const apiKey = request.headers.get("x-api-key") || new URL(request.url).searchParams.get("key");

  if (apiKey && apiKey === manualKey) return { ok: true };

  if (auth && /^Bearer\s+/i.test(auth)) {
    const token = auth.replace(/^Bearer\s+/i, "").trim();
    if (token === manualKey) return { ok: true };
  }
  return { ok: false, message: "Invalid or missing API key" };
}

async function handleChatCompletions(body, request, env) {
  const model = String(body.model || "you-chat");
  const stream = !!body.stream;
  const messages = Array.isArray(body.messages) ? body.messages : [];

  const prompt = buildPromptFromMessages(messages);
  if (!prompt) {
    return withCors(json({ error: "invalid_request", message: "Empty prompt derived from messages" }, 400), request);
  }

  const cookie = await getYouCookie(env);

  if (stream) {
    const id = makeId();
    const created = Math.floor(Date.now() / 1000);

    const { stream: outStream, controller } = makeSSEStream();

    // Start background task to fetch from you.com SSE and pipe to OpenAI SSE format
    const task = (async () => {
      let sentRole = false;
      let contentBuf = "";
      const tokenSender = async (token) => {
        contentBuf += token;
        const chunk = {
          id,
          object: "chat.completion.chunk",
          created,
          model,
          choices: [
            {
              index: 0,
              delta: { ...(sentRole ? {} : { role: "assistant" }), content: token },
              finish_reason: null,
            },
          ],
        };
        sentRole = true;
        controller.enqueue(encodeSSE({ data: JSON.stringify(chunk) }));
      };

      const ok = await tryStreamFromYou(prompt, cookie, tokenSender, model);
      // End
      if (!ok && contentBuf.length === 0) {
        // Fallback single message when streaming failed early
        const fallbackChunk = {
          id,
          object: "chat.completion.chunk",
          created,
          model,
          choices: [
            { index: 0, delta: { ...(sentRole ? {} : { role: "assistant" }), content: "" }, finish_reason: null },
          ],
        };
        controller.enqueue(encodeSSE({ data: JSON.stringify(fallbackChunk) }));
      }
      controller.enqueue(encodeSSE({ data: "[DONE]" }));
      controller.close();
    })();

    const resp = new Response(outStream, {
      status: 200,
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-transform",
        connection: "keep-alive",
        "x-accel-buffering": "no",
      },
    });
    return withCors(resp, request);
  }

  // Non-streaming: try JSON first, then fallback to buffering SSE
  const jsonRes = await tryJsonFromYou(prompt, cookie, model);
  let text = jsonRes?.text || "";
  if (!text) {
    text = await bufferSSEFromYou(prompt, cookie, model);
  }
  const id = makeId();
  const created = Math.floor(Date.now() / 1000);
  const resp = {
    id,
    object: "chat.completion",
    created,
    model,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: text || "" },
        finish_reason: "stop",
      },
    ],
    usage: jsonRes?.usage || undefined,
  };
  return withCors(json(resp), request);
}

function buildPromptFromMessages(messages) {
  if (!messages || !messages.length) return "";
  // Build a simple prompt compatible with generic QA
  const lines = [];
  for (const m of messages) {
    const role = m?.role || "user";
    const content = toText(m?.content);
    if (!content) continue;
    if (role === "system") lines.push(`System: ${content}`);
    else if (role === "assistant") lines.push(`Assistant: ${content}`);
    else lines.push(`User: ${content}`);
  }
  lines.push("Assistant:");
  return lines.join("\n");
}

function toText(content) {
  if (!content) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((p) => (typeof p === "string" ? p : p?.text || p?.content || ""))
      .filter(Boolean)
      .join("\n");
  }
  if (typeof content === "object") return content.text || content.content || "";
  return String(content);
}

async function getModels(env) {
  const ttl = Number(env?.CACHE_TTL_SECONDS || 900) * 1000;
  const now = Date.now();
  if (cache.models && now - cache.ts < ttl) {
    return cache.models;
  }

  // Prefer dynamic fetch when enabled
  if (String(env?.DYNAMIC_FETCH).toLowerCase() === "true") {
    try {
      const dynamic = await tryFetchModelsFromYou(env);
      if (dynamic && dynamic.length) {
        cache.models = dynamic;
        cache.ts = now;
        return dynamic;
      }
    } catch (e) {
      // swallow and fallback
    }
  }

  // STATIC_MODELS (JSON array string) overrides default when provided
  if (env?.STATIC_MODELS) {
    try {
      const parsed = JSON.parse(env.STATIC_MODELS);
      if (Array.isArray(parsed) && parsed.every((m) => typeof m === "string" && m.trim())) {
        cache.models = parsed;
        cache.ts = now;
        return parsed;
      }
    } catch (e) {
      // ignore and fallback to defaults
    }
  }

  cache.models = DEFAULT_MODELS;
  cache.ts = now;
  return DEFAULT_MODELS;
}

async function tryFetchModelsFromYou(env) {
  const username = env?.YOU_USERNAME || env?.YOU_EMAIL;
  const password = env?.YOU_PASSWORD;
  const cookieFromEnv = (env?.YOU_COOKIE || "").trim();

  // If user provides cookie, attempt model endpoints with it
  const publicCandidates = [
    "https://you.com/api/models",
    "https://you.com/api/llm/models",
    "https://you.com/api/llm/providers",
  ];
  if (cookieFromEnv) {
    for (const url of publicCandidates) {
      try {
        const r = await fetch(url, { headers: { ...defaultHeaders(), cookie: cookieFromEnv } });
        if (r.ok) {
          const data = await safeJson(r);
          const models = normalizeModelsFromUnknown(data);
          if (models?.length) return models;
        }
      } catch (_) {}
    }
  }

  if (!username || !password) return null;

  // Try unauthenticated endpoints first
  for (const url of publicCandidates) {
    try {
      const r = await fetch(url, { headers: defaultHeaders() });
      if (r.ok) {
        const data = await safeJson(r);
        const models = normalizeModelsFromUnknown(data);
        if (models?.length) return models;
      }
    } catch (_) {}
  }

  // Attempt credential login (experimental; may fail due to anti-bot/CSRF)
  // 1) Get initial cookies/CSRF if available
  let cookie = await getInitialCookie();

  // 2) Try multiple plausible login endpoints
  const loginBodies = [
    { email: username, password, rememberMe: true },
    { username, password },
  ];
  const loginEndpoints = [
    "https://you.com/api/auth/login",
    "https://you.com/api/login",
  ];
  for (const endpoint of loginEndpoints) {
    for (const body of loginBodies) {
      try {
        const r = await fetch(endpoint, {
          method: "POST",
          headers: { ...defaultHeaders(), "content-type": "application/json", ...(cookie ? { cookie } : {}) },
          body: JSON.stringify(body),
        });
        // Accumulate cookies if set
        const setCookie = r.headers.get("set-cookie");
        if (setCookie) cookie = mergeCookies(cookie, setCookie);
        if (r.ok) break;
      } catch (_) {}
    }
  }

  // 3) After login attempt, try fetching likely model endpoints with cookie
  for (const url of publicCandidates) {
    try {
      const r = await fetch(url, { headers: { ...defaultHeaders(), ...(cookie ? { cookie } : {}) } });
      if (r.ok) {
        const data = await safeJson(r);
        const models = normalizeModelsFromUnknown(data);
        if (models?.length) return models;
      }
    } catch (_) {}
  }

  return null;
}

async function getYouCookie(env) {
  const fromEnv = (env?.YOU_COOKIE || "").trim();
  if (fromEnv) return fromEnv;

  const username = env?.YOU_USERNAME || env?.YOU_EMAIL;
  const password = env?.YOU_PASSWORD;
  if (!username || !password) return ""; // try anonymous access later

  // Best-effort login to obtain cookie
  let cookie = await getInitialCookie();
  const loginBodies = [
    { email: username, password, rememberMe: true },
    { username, password },
  ];
  const loginEndpoints = [
    "https://you.com/api/auth/login",
    "https://you.com/api/login",
  ];
  for (const endpoint of loginEndpoints) {
    for (const body of loginBodies) {
      try {
        const r = await fetch(endpoint, {
          method: "POST",
          headers: { ...defaultHeaders(), "content-type": "application/json", ...(cookie ? { cookie } : {}) },
          body: JSON.stringify(body),
        });
        const setCookie = r.headers.get("set-cookie");
        if (setCookie) cookie = mergeCookies(cookie, setCookie);
        if (r.ok) return cookie;
      } catch (_) {}
    }
  }
  return cookie || "";
}

function normalizeModelsFromUnknown(data) {
  if (!data) return null;
  // 1) If already an array of strings
  if (Array.isArray(data) && data.every((x) => typeof x === "string")) return data;
  // 2) If array of objects with id
  if (Array.isArray(data) && data[0] && typeof data[0] === "object") {
    const ids = data
      .map((x) => x?.id || x?.model || x?.name)
      .filter((x) => typeof x === "string" && x.trim());
    if (ids.length) return ids;
  }
  // 3) Object with models field
  if (typeof data === "object") {
    const fromModels = data.models || data.data || data.available || data.list;
    if (Array.isArray(fromModels)) {
      const ids = fromModels
        .map((x) => (typeof x === "string" ? x : x?.id || x?.model || x?.name))
        .filter((x) => typeof x === "string" && x.trim());
      if (ids.length) return ids;
    }
  }
  return null;
}

async function tryJsonFromYou(prompt, cookie, model) {
  const endpoints = [
    (q) => `https://you.com/api/youchat?query=${encodeURIComponent(q)}`,
    (q) => `https://you.com/api/chat?query=${encodeURIComponent(q)}`,
  ];
  for (const makeUrl of endpoints) {
    try {
      const r = await fetch(makeUrl(prompt), {
        method: "GET",
        headers: { ...defaultHeaders(), accept: "application/json", ...(cookie ? { cookie } : {}) },
      });
      if (!r.ok) continue;
      const data = await safeJson(r);
      if (!data) continue;
      const text = data.answer || data.response || data.message || data.output || data.text || "";
      if (typeof text === "string" && text.trim()) {
        return { text, raw: data };
      }
    } catch (_) {}
  }
  return null;
}

async function bufferSSEFromYou(prompt, cookie, model) {
  let collected = "";
  await tryStreamFromYou(
    prompt,
    cookie,
    async (token) => {
      collected += token;
    },
    model
  );
  return collected;
}

async function tryStreamFromYou(prompt, cookie, onToken, model) {
  const candidates = [
    (q) => {
      const u = new URL("https://you.com/api/streamingSearch");
      u.searchParams.set("q", q);
      u.searchParams.set("page", "1");
      u.searchParams.set("count", "1");
      u.searchParams.set("safeSearch", "Off");
      u.searchParams.set("onShoppingPage", "false");
      u.searchParams.set("domain", "youchat");
      return u.toString();
    },
  ];

  for (const makeUrl of candidates) {
    try {
      const r = await fetch(makeUrl(prompt), {
        method: "GET",
        headers: { ...defaultHeaders(), accept: "text/event-stream", ...(cookie ? { cookie } : {}) },
      });
      if (!r.ok || !r.body) continue;
      await parseYouSSE(r.body, onToken);
      return true;
    } catch (_) {}
  }
  return false;
}

async function parseYouSSE(readable, onToken) {
  const reader = readable.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let idx;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const chunk = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      const line = chunk.trim();
      if (!line) continue;
      const m = line.match(/^data:\s*(.*)$/i);
      if (!m) continue;
      const payload = m[1];
      if (payload === "[DONE]") break;
      try {
        const obj = JSON.parse(payload);
        const token = obj?.youChatToken || obj?.token || obj?.text || obj?.message || obj?.delta || "";
        if (token) await onToken(String(token));
      } catch (_) {
        // Sometimes streamingSearch sends plain tokens
        if (payload) await onToken(String(payload));
      }
    }
  }
}

function makeSSEStream() {
  const ts = new TransformStream();
  const writer = ts.writable.getWriter();
  return {
    stream: ts.readable,
    controller: {
      enqueue(chunk) {
        writer.write(chunk);
      },
      close() {
        try { writer.close(); } catch (_) {}
      },
    },
  };
}

function encodeSSE({ data }) {
  return new TextEncoder().encode(`data: ${data}\n\n`);
}

async function getInitialCookie() {
  try {
    const r = await fetch("https://you.com/", { headers: defaultHeaders() });
    const setCookie = r.headers.get("set-cookie");
    if (setCookie) return extractCookie(setCookie);
  } catch (_) {}
  return "";
}

function mergeCookies(base, setCookieHeader) {
  const add = extractCookie(setCookieHeader);
  if (!base) return add;
  // naive merge
  const baseParts = base.split("; ").filter(Boolean);
  const addParts = add.split("; ").filter(Boolean);
  const jar = new Map();
  for (const p of baseParts) {
    const [k, v] = p.split("=");
    jar.set(k, v);
  }
  for (const p of addParts) {
    const [k, v] = p.split("=");
    jar.set(k, v);
  }
  return Array.from(jar.entries())
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

function extractCookie(setCookieHeader) {
  // Extract only cookie pairs (k=v) from Set-Cookie header(s)
  // This is a naive implementation; sufficient for best-effort fetch.
  const parts = setCookieHeader.split(",");
  const pairs = [];
  for (const part of parts) {
    const segs = part.split("; ");
    const kv = segs[0];
    if (kv && kv.includes("=")) pairs.push(kv.trim());
  }
  return pairs.join("; ");
}

function defaultHeaders() {
  return {
    "user-agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
    accept: "application/json, text/plain, */*",
  };
}

async function safeJson(resp) {
  try {
    return await resp.json();
  } catch (_) {
    return null;
  }
}

async function safeParseJson(request) {
  try {
    return await request.json();
  } catch (_) {
    return null;
  }
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
}

function withCors(response, request) {
  const headers = new Headers(response.headers);
  const origin = request.headers.get("origin") || "*";
  headers.set("access-control-allow-origin", origin === "null" ? "*" : origin);
  headers.set("access-control-allow-credentials", "true");
  headers.set(
    "access-control-allow-headers",
    "authorization, content-type, x-api-key, x-requested-with"
  );
  headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
  return new Response(response.body, { status: response.status, headers });
}

function makeId() {
  const rnd = Math.random().toString(36).slice(2, 10);
  return `chatcmpl_${Date.now()}_${rnd}`;
}
