/*
  Cloudflare Worker for exposing an OpenAI-compatible /v1/models endpoint backed by you.com account context.

  Features:
  - Manual API key protection via Authorization: Bearer <MANUAL_API_KEY> or X-API-Key header
  - GET /v1/models returns models available to the account (best-effort)
  - Optional attempt to fetch models from you.com using username/password (experimental)
  - Fallback to a configurable static model list when dynamic fetch is unavailable

  Required Env Vars (set in Cloudflare Worker > Settings > Variables):
  - MANUAL_API_KEY        Manually defined API key the client must present

  Optional Env Vars:
  - YOU_USERNAME          you.com 登录邮箱/用户名
  - YOU_PASSWORD          you.com 登录密码
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
            endpoints: ["GET /health", "GET /v1/models"],
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

      // Not implemented routes
      if (url.pathname === "/v1/chat/completions") {
        return withCors(
          json(
            {
              error: "not_implemented",
              message:
                "This worker currently only implements GET /v1/models for use in Cherry Studio model discovery.",
            },
            501
          ),
          request
        );
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
  if (!username || !password) return null;

  // Best-effort: some endpoints may be public or require auth; we attempt several
  const publicCandidates = [
    "https://you.com/api/models",
    "https://you.com/api/llm/models",
    "https://you.com/api/llm/providers",
  ];

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
