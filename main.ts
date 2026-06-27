/**
 * 6盘（清真云/2dland）远程离线下载中继服务 — OpenAPI 版
 * 
 * 使用 6盘新一代 OpenAPI（HL6-HMAC-SHA256 签名认证）
 * 旧的 Cookie/密码登录已废弃，改用 Client ID + Client Secret + Refresh Token
 *
 * 部署：Deno Deploy (console.deno.com)
 * 环境变量：
 *   SIXPAN_CLIENT_ID      - 客户端 ID（从 6盘授权管理页获取）
 *   SIXPAN_CLIENT_SECRET  - 客户端密钥（从 6盘授权管理页获取）
 *   SIXPAN_REFRESH_TOKEN  - 刷新令牌（首次可留空，通过 /auth 接口获取）
 *   AUTH_TOKEN            - 快捷指令鉴权 token
 *   SIXPAN_SAVE_TO        - 默认保存路径，默认 "/"
 */

const OPENAPI_HOST = "openapi.2dland.cn";
const SIGN_PREFIX = "HL6";
const SIGN_ALGO   = "HL6-HMAC-SHA256";
const REQUEST_SUFFIX = "hl6_request";

// ── HMAC-SHA256 签名（逆向自 halalcloud/golang-sdk-lite）───────

function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  // Deno Deploy 支持 Web Crypto API
  // 但 HMAC 需要同步计算，这里用纯 JS 实现
  // 其实 Deno 有 crypto.subtle，但需要 async；为简化用 Node 兼容方式
  // Deno Deploy 支持使用 crypto.subtle
  throw new Error("Use async hmacSha256Async instead");
}

async function hmacSha256Async(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, data);
  return new Uint8Array(sig);
}

function sha256Hex(data: string | Uint8Array): Promise<string> {
  const encoded = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return crypto.subtle.digest("SHA-256", encoded).then(buf => {
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  });
}

async function signRequest(
  clientId: string, clientSecret: string, accessToken: string,
  method: string, apiPath: string, params: Record<string, string>,
  requestBody: string, extraHeaders: Record<string, string>,
): Promise<{ url: string; headers: Record<string, string> }> {
  const utcTime = new Date();
  const dateString = utcTime.toISOString().split("T")[0]; // YYYY-MM-DD
  const rfc3339 = utcTime.toISOString();
  const nonce = Date.now().toString(36) + Math.random().toString(36).substring(2, 8);

  // 构建 headers
  const headers: Record<string, string> = {
    "host": OPENAPI_HOST,
    "x-hl-nonce": nonce,
    "x-hl-timestamp": rfc3339,
    "other-header": "other-value",
  };

  // 合入额外 headers
  for (const [k, v] of Object.entries(extraHeaders)) {
    if (k.toLowerCase() !== "authorization") {
      headers[k.toLowerCase()] = v;
    }
  }

  // 确定 signedHeaders
  const headersToSign = new Set<string>(["host", "x-hl-nonce", "x-hl-timestamp", "other-header"]);
  for (const [k] of Object.entries(extraHeaders)) {
    const lk = k.toLowerCase();
    if (lk === "content-type" || lk.startsWith("x-hl-")) {
      headersToSign.add(lk);
    }
  }

  // Canonical headers
  const sortedHeaderNames = [...headersToSign].sort();
  const canonicalHeaders = sortedHeaderNames
    .filter(h => headers[h] !== undefined)
    .map(h => `${h}:${headers[h]}\n`)
    .join("");
  const signedHeadersStr = sortedHeaderNames.join(";");

  // Sorted query string
  const sortedParams = Object.entries(params)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${rfc3986Encode(k)}=${v ? rfc3986Encode(v) : ""}`)
    .join("&");

  // SHA256 of body
  const bodyHash = await sha256Hex(requestBody);

  // Canonical request
  const canonicalRequest = [
    method,
    apiPath,
    sortedParams,
    canonicalHeaders,
    signedHeadersStr,
    bodyHash,
  ].join("\n");

  // Credential scope
  const credentialScope = `${dateString}/${accessToken}/${REQUEST_SUFFIX}`;

  // String to sign
  const hashedCanonical = await sha256Hex(canonicalRequest);
  const stringToSign = [
    SIGN_ALGO,
    rfc3339,
    credentialScope,
    hashedCanonical,
  ].join("\n");

  // Derive signing key
  const secretKeyBytes = new TextEncoder().encode(SIGN_PREFIX + clientSecret);
  const dateKey = await hmacSha256Async(secretKeyBytes, new TextEncoder().encode(dateString));
  const accessTokenKey = await hmacSha256Async(dateKey, new TextEncoder().encode(accessToken));
  const signingKey = await hmacSha256Async(accessTokenKey, new TextEncoder().encode(REQUEST_SUFFIX));

  // Calculate signature
  const signatureBytes = await hmacSha256Async(signingKey, new TextEncoder().encode(stringToSign));
  const signature = [...signatureBytes].map(b => b.toString(16).padStart(2, "0")).join("");

  // Authorization header
  const authorization = `${SIGN_ALGO} Credential=${clientId}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

  headers["authorization"] = authorization;

  // Build URL
  const url = `https://${OPENAPI_HOST}${apiPath}${sortedParams ? "?" + sortedParams : ""}`;

  return { url, headers };
}

function rfc3986Encode(s: string): string {
  return encodeURIComponent(s).replace(/\+/g, "%20");
}

// ── Token 管理 ──────────────────────────────────────────────────

interface TokenInfo {
  accessToken: string;
  refreshToken: string;
  expiresAt: number; // Unix ms
}

let tokenCache: TokenInfo | null = null;

async function refreshTokenFlow(
  clientId: string, clientSecret: string, refreshToken: string,
): Promise<TokenInfo> {
  const body = JSON.stringify({
    refresh_token: refreshToken,
    grant_type: "refresh_token",
    client_id: clientId,
  });

  const { url, headers } = await signRequest(
    clientId, clientSecret, "", // accessToken 为空（刷新 token 时不需要）
    "POST", "/v6/oauth/refresh_token", {},
    body,
    { "content-type": "application/json; charset=utf-8" },
  );

  const resp = await fetch(url, {
    method: "POST",
    headers,
    body,
  });

  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`刷新 token 失败 (HTTP ${resp.status}): ${text.substring(0, 300)}`);
  }

  let json: any;
  try { json = JSON.parse(text); }
  catch { throw new Error(`刷新 token 返回非 JSON: ${text.substring(0, 300)}`); }

  if (!json.access_token) {
    throw new Error(`刷新 token 返回无效: ${text.substring(0, 300)}`);
  }

  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token || refreshToken,
    expiresAt: Date.now() + (json.expires_in || 3600) * 1000,
  };
}

async function getAccessToken(): Promise<string> {
  const clientId     = (Deno.env.get("SIXPAN_CLIENT_ID") || "").trim();
  const clientSecret = (Deno.env.get("SIXPAN_CLIENT_SECRET") || "").trim();
  const initialRT    = (Deno.env.get("SIXPAN_REFRESH_TOKEN") || "").trim();

  if (!clientId || !clientSecret) {
    throw new Error(
      "请配置环境变量：\n" +
      "  SIXPAN_CLIENT_ID — 从 6盘 授权管理页获取\n" +
      "  SIXPAN_CLIENT_SECRET — 从 6盘 授权管理页获取\n" +
      "  SIXPAN_REFRESH_TOKEN — 首次可留空，访问 /auth 获取\n" +
      "\n获取步骤：\n" +
      "  1. 登录 https://drive.2dland.cn\n" +
      "  2. 用户中心 → 授权管理 → 新建授权\n" +
      "  3. 记录 Client ID 和 Client Secret"
    );
  }

  // 检查缓存
  if (tokenCache && tokenCache.expiresAt > Date.now()) {
    return tokenCache.accessToken;
  }

  // 需要刷新
  const rt = tokenCache?.refreshToken || initialRT;
  if (!rt) {
    throw new Error(
      "缺少 Refresh Token，请先访问 /auth 接口获取授权\n" +
      "或者手动在 6盘网站获取 Refresh Token 后设置环境变量 SIXPAN_REFRESH_TOKEN"
    );
  }

  const result = await refreshTokenFlow(clientId, clientSecret, rt);
  tokenCache = result;
  
  console.log(`Token 刷新成功，有效期至 ${new Date(result.expiresAt).toISOString()}`);
  return result.accessToken;
}

// ── 6盘 OpenAPI 调用 ───────────────────────────────────────────

async function callAPI(
  method: string, apiPath: string, 
  params: Record<string, string>, body: any,
): Promise<any> {
  const clientId     = (Deno.env.get("SIXPAN_CLIENT_ID") || "").trim();
  const clientSecret = (Deno.env.get("SIXPAN_CLIENT_SECRET") || "").trim();
  const accessToken  = await getAccessToken();

  const bodyStr = body ? JSON.stringify(body) : "";
  const extraHeaders: Record<string, string> = {};
  if (body) {
    extraHeaders["content-type"] = "application/json; charset=utf-8";
  }

  const { url, headers } = await signRequest(
    clientId, clientSecret, accessToken,
    method, apiPath, params, bodyStr, extraHeaders,
  );

  const resp = await fetch(url, { method, headers, body: bodyStr || undefined });
  const text = await resp.text();

  // 401 → 尝试刷新 token 后重试一次
  if (resp.status === 401) {
    tokenCache = null;
    const accessToken2 = await getAccessToken();
    const { url: url2, headers: headers2 } = await signRequest(
      clientId, clientSecret, accessToken2,
      method, apiPath, params, bodyStr, extraHeaders,
    );
    const resp2 = await fetch(url2, { method, headers: headers2, body: bodyStr || undefined });
    const text2 = await resp2.text();
    if (!resp2.ok) throw new Error(`API 调用失败 (HTTP ${resp2.status}): ${text2.substring(0, 300)}`);
    try { return JSON.parse(text2); }
    catch { throw new Error(`API 返回非 JSON: ${text2.substring(0, 300)}`); }
  }

  if (!resp.ok) throw new Error(`API 调用失败 (HTTP ${resp.status}): ${text.substring(0, 300)}`);

  try { return JSON.parse(text); }
  catch { throw new Error(`API 返回非 JSON: ${text.substring(0, 300)}`); }
}

// ── 离线下载 ────────────────────────────────────────────────────

async function parseUrl(url: string): Promise<any> {
  return await callAPI("POST", "/v6/user/offline/parse", {}, { url });
}

async function addOfflineTask(
  infoHash: string, saveTo: string, fileName: string,
  fileCount: number, fileSize: number, fileList: string,
): Promise<any> {
  return await callAPI("POST", "/v6/user/offline/add", {}, {
    info_hash: infoHash,
    save_to: saveTo,
    file_name: fileName,
    file_count: fileCount,
    file_size: fileSize,
    file_list: fileList,
  });
}

async function listOfflineTasks(): Promise<any> {
  return await callAPI("POST", "/v6/user/offline/list", {}, {});
}

// ── OAuth2 授权流程（获取初始 Refresh Token）───────────────────
// 用户访问 /auth 页面 → 重定向到 6盘授权页 → 授权后回调 → 获取 refresh_token

const OAUTH_AUTH_URL = `https://drive.2dland.cn/oauth/authorize`;

async function handleAuth(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const clientId = (Deno.env.get("SIXPAN_CLIENT_ID") || "").trim();
  
  if (!clientId) {
    return new Response("请先设置环境变量 SIXPAN_CLIENT_ID", { status: 400 });
  }

  // 如果是回调（带有 code 参数）
  const code = url.searchParams.get("code");
  if (code) {
    const clientSecret = (Deno.env.get("SIXPAN_CLIENT_SECRET") || "").trim();
    // 用 code 换取 refresh_token
    const body = JSON.stringify({
      grant_type: "authorization_code",
      code: code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: `${url.origin}/auth`,
    });

    const { url: tokenUrl, headers: tokenHeaders } = await signRequest(
      clientId, clientSecret, "",
      "POST", "/v6/oauth/token", {},
      body,
      { "content-type": "application/json; charset=utf-8" },
    );

    const resp = await fetch(tokenUrl, { method: "POST", headers: tokenHeaders, body });
    const text = await resp.text();
    
    if (!resp.ok) {
      return jsonResponse({ success: false, error: `授权失败: ${text.substring(0, 300)}` }, 400);
    }

    let json: any;
    try { json = JSON.parse(text); }
    catch { return jsonResponse({ success: false, error: `授权返回非 JSON: ${text.substring(0, 200)}` }, 400); }

    if (json.refresh_token) {
      // 缓存 token
      tokenCache = {
        accessToken: json.access_token || "",
        refreshToken: json.refresh_token,
        expiresAt: Date.now() + (json.expires_in || 3600) * 1000,
      };

      return new Response(
        `<html><body style="font-family:sans-serif;text-align:center;padding:40px">
        <h1>✅ 授权成功！</h1>
        <p>Refresh Token 已自动获取并缓存。</p>
        <p>请将以下值设置为 Deno Deploy 环境变量 <b>SIXPAN_REFRESH_TOKEN</b>：</p>
        <textarea style="width:80%;height:60px;font-size:14px">${json.refresh_token}</textarea>
        <p style="color:#999;font-size:13px">设置后服务将自动刷新 token，无需再次授权</p>
        </body></html>`,
        { headers: { "Content-Type": "text/html; charset=utf-8" } }
      );
    }

    return jsonResponse({ success: false, error: "授权响应中缺少 refresh_token", raw: text.substring(0, 300) }, 400);
  }

  // 重定向到 6盘授权页
  const redirectUri = `${url.origin}/auth`;
  const authUrl = `${OAUTH_AUTH_URL}?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=all`;
  return Response.redirect(authUrl, 302);
}

// ── HTTP 处理 ──────────────────────────────────────────────────

function jsonResponse(data: any, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function authCheck(request: Request): boolean {
  const authToken = Deno.env.get("AUTH_TOKEN");
  if (!authToken) return true;
  const url = new URL(request.url);
  const token = url.searchParams.get("token") || request.headers.get("X-Auth-Token") || "";
  return token === authToken;
}

async function handleAdd(request: Request): Promise<Response> {
  if (!authCheck(request)) {
    return jsonResponse({ success: false, error: "鉴权失败，请在 URL 中附加 ?token=xxx" }, 401);
  }

  let body: any;
  try { body = await request.json(); }
  catch { return jsonResponse({ success: false, error: "无效的 JSON，需要 {\"magnet\": \"...\"}" }, 400); }

  const magnet = body.magnet || body.url || "";
  if (!magnet) return jsonResponse({ success: false, error: "缺少 magnet 字段" }, 400);

  const saveTo = body.saveTo || new URL(request.url).searchParams.get("saveTo") || Deno.env.get("SIXPAN_SAVE_TO") || "/";

  try {
    // ① 解析磁力链
    const parseResult = await parseUrl(magnet) as any;

    if (!parseResult.data && !parseResult.info_hash) {
      return jsonResponse({
        success: false,
        error: parseResult.message || "解析磁力链失败",
        raw: JSON.stringify(parseResult).substring(0, 300),
      }, 400);
    }

    // 适配可能的响应格式
    const data = parseResult.data || parseResult;
    const infoHash   = data.info_hash || data.infoHash || "";
    const name       = data.name || data.file_name || "未知";
    const files      = data.files || [];
    const fileCount  = files.length || data.file_count || 1;
    const fileSize   = files.reduce ? files.reduce((s: number, f: any) => s + (f.size || 0), 0) : (data.file_size || 0);
    const fileList   = files.map ? files.map((f: any) => f.name || f.file_name).join(",") : (data.file_list || "");

    if (!infoHash) {
      return jsonResponse({ success: false, error: "解析结果缺少 infoHash", raw: JSON.stringify(parseResult).substring(0, 300) }, 400);
    }

    // ② 提交离线任务
    const addResult = await addOfflineTask(infoHash, saveTo, name, fileCount, fileSize, fileList) as any;

    if (addResult.error || addResult.message && !addResult.task_id) {
      return jsonResponse({
        success: false,
        error: addResult.message || addResult.error || "提交离线任务失败",
        raw: JSON.stringify(addResult).substring(0, 300),
      }, 400);
    }

    return jsonResponse({
      success: true,
      taskId: addResult.task_id || addResult.taskId || addResult.data?.task_id,
      name, infoHash, fileCount, fileSize, saveTo,
      message: "离线下载任务已提交 ✅",
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("401") || msg.includes("token")) tokenCache = null;
    return jsonResponse({ success: false, error: msg }, 500);
  }
}

async function handleStatus(request: Request): Promise<Response> {
  if (!authCheck(request)) return jsonResponse({ success: false, error: "鉴权失败" }, 401);
  try {
    const at = await getAccessToken();
    return jsonResponse({
      success: true,
      accessTokenValid: true,
      accessTokenPreview: at.substring(0, 10) + "...",
      tokenExpiresAt: tokenCache ? new Date(tokenCache.expiresAt).toISOString() : null,
      hasClientId: !!Deno.env.get("SIXPAN_CLIENT_ID"),
      hasClientSecret: !!Deno.env.get("SIXPAN_CLIENT_SECRET"),
      hasRefreshToken: !!Deno.env.get("SIXPAN_REFRESH_TOKEN"),
      mode: "openapi-hl6",
    });
  } catch (err) {
    return jsonResponse({ success: false, error: err instanceof Error ? err.message : String(err) }, 500);
  }
}

async function handleDebug(request: Request): Promise<Response> {
  if (!authCheck(request)) return jsonResponse({ success: false, error: "鉴权失败" }, 401);

  const steps: Record<string, any> = {};

  steps["env"] = {
    hasClientId: !!Deno.env.get("SIXPAN_CLIENT_ID"),
    clientIdPrefix: (Deno.env.get("SIXPAN_CLIENT_ID") || "").substring(0, 5) + "***",
    hasClientSecret: !!Deno.env.get("SIXPAN_CLIENT_SECRET"),
    hasRefreshToken: !!Deno.env.get("SIXPAN_REFRESH_TOKEN"),
    refreshTokenPrefix: (Deno.env.get("SIXPAN_REFRESH_TOKEN") || "").substring(0, 5) + "***",
    openapiHost: OPENAPI_HOST,
    signAlgorithm: SIGN_ALGO,
  };

  try {
    // Step 1: 获取 access token
    const at = await getAccessToken();
    steps["accessToken"] = { success: true, preview: at.substring(0, 10) + "...", expiresAt: tokenCache?.expiresAt };

    // Step 2: 测试 signed API 调用（获取用户信息）
    try {
      const userResult = await callAPI("POST", "/v6/user/get", {}, {});
      steps["userApi"] = { success: true, data: userResult };
    } catch (e) {
      steps["userApi"] = { error: e instanceof Error ? e.message : String(e) };
    }

    // Step 3: 测试 parse API
    try {
      const parseResult = await callAPI("POST", "/v6/user/offline/parse", {}, { url: "magnet:?xt=urn:btih:08ada5a7a6183aae1e09d831df674e6df36b7d4a" });
      steps["parseApi"] = { success: true, data: parseResult };
    } catch (e) {
      steps["parseApi"] = { error: e instanceof Error ? e.message : String(e) };
    }
  } catch (e) {
    steps["error"] = e instanceof Error ? e.message : String(e);
  }

  return jsonResponse({ debug: true, timestamp: new Date().toISOString(), ...steps });
}

// ── 路由 ───────────────────────────────────────────────────────

async function handler(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/add"    && request.method === "POST") return await handleAdd(request);
  if (path === "/status" && request.method === "GET")  return await handleStatus(request);
  if (path === "/debug"  && request.method === "GET")  return await handleDebug(request);
  if (path === "/auth"   && request.method === "GET")  return await handleAuth(request);
  if (path === "/tasks"  && request.method === "GET")  {
    if (!authCheck(request)) return jsonResponse({ success: false, error: "鉴权失败" }, 401);
    try { return jsonResponse(await listOfflineTasks()); }
    catch (err) { return jsonResponse({ success: false, error: err instanceof Error ? err.message : String(err) }, 500); }
  }
  if (path === "/" && request.method === "GET") return new Response(HTML_HOME, { headers: { "Content-Type": "text/html; charset=utf-8" } });

  return new Response("Not Found", { status: 404 });
}

Deno.serve(handler);

// ── 首页 HTML ───────────────────────────────────────────────────
const HTML_HOME = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>6盘离线下载中继</title>
  <style>
    * { box-sizing: border-box; margin:0; padding:0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
           background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
           min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .card { background: white; border-radius: 16px; padding: 32px; max-width: 560px; width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.15); }
    h1 { font-size: 24px; color: #333; margin-bottom: 8px; }
    .subtitle { color: #666; font-size: 14px; margin-bottom: 24px; }
    label { display: block; margin-top: 16px; font-weight: 600; font-size: 14px; color: #444; }
    input, textarea { width: 100%; padding: 10px 12px; margin-top: 6px; border-radius: 8px; 
                     border: 1px solid #ddd; font-size: 14px; font-family: inherit; }
    textarea { min-height: 80px; resize: vertical; }
    button { width: 100%; padding: 12px; margin-top: 20px; border-radius: 8px; 
             border: none; font-size: 16px; font-weight: 600; cursor: pointer;
             background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
    button:hover { opacity: 0.9; }
    .result { margin-top: 16px; padding: 14px; border-radius: 8px; font-size: 13px; line-height: 1.6; white-space: pre-wrap; }
    .success { background: #e8f5e9; color: #2e7d32; border: 1px solid #a5d6a7; }
    .error { background: #ffebee; color: #c62828; border: 1px solid #ef9a9a; }
    .status { margin-top: 16px; padding: 12px; border-radius: 8px; font-size: 13px; background: #f5f5f5; color: #333; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
    .badge.ok { background: #e8f5e9; color: #2e7d32; }
    .badge.err { background: #ffebee; color: #c62828; }
    .link { color: #667eea; text-decoration: none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>📥 6盘离线下载</h1>
    <p class="subtitle">使用 OpenAPI 签名认证，远程提交磁力链</p>
    
    <label>磁力链</label>
    <textarea id="magnet" placeholder="magnet:?xt=urn:btih:..."></textarea>
    
    <label>保存路径 <span style="font-weight:400;color:#999">（默认 /）</span></label>
    <input id="saveTo" type="text" placeholder="/" value="/" />
    
    <label>鉴权 Token</label>
    <input id="token" type="text" placeholder="与环境变量 AUTH_TOKEN 一致" />
    
    <button onclick="submit()">🚀 提交离线下载</button>
    <div id="result"></div>
    <div class="status" id="statusBox"><b>服务状态：</b><span id="statusText">检测中...</span></div>
    <div style="margin-top:12px;font-size:13px;color:#666">
      首次使用？<a href="/auth" class="link">点击授权获取 Refresh Token</a>
    </div>
  </div>

  <script>
    const params = new URLSearchParams(location.search);
    if (params.get('token')) document.getElementById('token').value = params.get('token');

    async function checkStatus() {
      const token = document.getElementById('token').value.trim();
      const statusText = document.getElementById('statusText');
      try {
        const resp = await fetch('/status' + (token ? '?token=' + encodeURIComponent(token) : ''));
        const data = await resp.json();
        if (data.success) {
          statusText.innerHTML = '<span class="badge ok">✅ 正常</span> OpenAPI 模式 | Token有效期至: ' + new Date(data.tokenExpiresAt).toLocaleString('zh-CN');
        } else {
          statusText.innerHTML = '<span class="badge err">❌ ' + data.error + '</span>';
        }
      } catch(e) {
        statusText.innerHTML = '<span class="badge err">❌ 无法连接</span>';
      }
    }
    checkStatus();
    setInterval(checkStatus, 30000);

    async function submit() {
      const magnet = document.getElementById('magnet').value.trim();
      const saveTo = document.getElementById('saveTo').value.trim();
      const token  = document.getElementById('token').value.trim();
      const result = document.getElementById('result');
      if (!magnet) { result.className='result error'; result.textContent='请输入磁力链'; return; }
      result.className = 'result';
      result.textContent = '⏳ 提交中...';
      try {
        const resp = await fetch('/add?token=' + encodeURIComponent(token), {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ magnet, saveTo }),
        });
        const data = await resp.json();
        if (data.success) {
          result.className = 'result success';
          result.textContent = '✅ 提交成功！\\n文件名: ' + data.name + '\\n保存位置: ' + data.saveTo;
        } else {
          result.className = 'result error';
          result.textContent = '❌ ' + data.error;
        }
      } catch(e) {
        result.className = 'result error';
        result.textContent = '❌ 网络错误: ' + e.message;
      }
    }
  </script>
</body>
</html>`;
