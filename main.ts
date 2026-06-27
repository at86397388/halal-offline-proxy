// ── 6盘（清真云）远程离线下载中继服务 v6 ───────────────────────────────
// 基于 halalcloud/golang-sdk-lite 逆向的 OpenAPI 完整实现
// 认证：HL6-HMAC-SHA256 签名 + Device Code 授权 + 自动 Token 刷新
// 协议：JSON REST（非 gRPC-Web）
// ─────────────────────────────────────────────────────────────────────

// ── 常量 ────────────────────────────────────────────────────────────
const SIGN_PREFIX = "HL6";
const REQUEST_SUFFIX = "hl6_request";
const SIGN_ALGORITHM = "HL6-HMAC-SHA256";
const API_HOST = "openapi.2dland.cn";
const API_BASE = `https://${API_HOST}`;

// ── 环境变量 ────────────────────────────────────────────────────────
const CLIENT_ID = Deno.env.get("SIXPAN_CLIENT_ID") || "";
const CLIENT_SECRET = Deno.env.get("SIXPAN_CLIENT_SECRET") || "";
const AUTH_TOKEN = Deno.env.get("AUTH_TOKEN") || "";
const SAVE_PATH = Deno.env.get("SIXPAN_SAVE_TO") || "/All/";
const MANUAL_COOKIE = Deno.env.get("SIXPAN_COOKIE") || "";

// ── Token 存储（内存，Deno Deploy 冷启动后需要重新授权）─────────────
let accessToken = "";
let refreshToken = "";
let tokenExpiresAt = 0;
let cookieCache = "";

// ── HMAC-SHA256 工具 ────────────────────────────────────────────────
async function asyncHmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, data);
  return new Uint8Array(sig);
}

async function sha256Hex(input: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256HexBytes(input: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", input);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexEncode(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── HL6-HMAC-SHA256 签名（支持空 AccessToken，用于 OAuth2 端点）───────
async function signRequest(
  method: string, apiPath: string, body: Uint8Array | null,
  accessToken: string, clientId: string, clientSecret: string,
  extraParams?: Record<string, string>,
): Promise<{ url: string; headers: Record<string, string> }> {
  // accessToken 可为空（OAuth2 公开端点），此时 credential scope 中 AccessToken 部分为空

  const utcTime = new Date();
  const dateString = utcTime.toISOString().split("T")[0];
  const nonce = BigInt(utcTime.getTime() * 1_000_000).toString(36);
  const timestamp = utcTime.toISOString();

  const headers: Record<string, string> = {
    "host": API_HOST,
    "x-hl-nonce": nonce,
    "x-hl-timestamp": timestamp,
    "other-header": "other-value",
  };

  const headersToSign: string[] = ["host", "x-hl-nonce", "x-hl-timestamp", "other-header"];

  if (body) {
    headers["content-type"] = "application/json; charset=utf-8";
    headersToSign.push("content-type");
  }

  const uniqueHeadersToSign = [...new Set(headersToSign)].sort();

  const canonicalHeaders = uniqueHeadersToSign
    .filter(h => headers[h])
    .map(h => `${h}:${headers[h]}`)
    .join("\n") + "\n";

  const signedHeaders = uniqueHeadersToSign.join(";");

  let sortedQueryString = "";
  if (extraParams && Object.keys(extraParams).length > 0) {
    const encodedParams: Record<string, string> = {};
    const keys: string[] = [];
    for (const [k, v] of Object.entries(extraParams)) {
      const ek = rfc3986Encode(k);
      encodedParams[ek] = v ? rfc3986Encode(v) : "";
      keys.push(ek);
    }
    keys.sort();
    sortedQueryString = keys.map(k => `${k}=${encodedParams[k]}`).join("&");
  }

  const bodyHash = body ? await sha256HexBytes(body) : await sha256Hex("");
  const canonicalRequest = [
    method,
    apiPath,
    sortedQueryString,
    canonicalHeaders,
    signedHeaders,
    bodyHash,
  ].join("\n");

  const credentialScope = `${dateString}/${accessToken}/${REQUEST_SUFFIX}`;

  const hashedCanonical = await sha256Hex(canonicalRequest);
  const stringToSign = [
    SIGN_ALGORITHM,
    timestamp,
    credentialScope,
    hashedCanonical,
  ].join("\n");

  const secretKeyBytes = new TextEncoder().encode(SIGN_PREFIX + clientSecret);
  const dateKey = await asyncHmacSha256(secretKeyBytes, new TextEncoder().encode(dateString));
  const accessTokenKey = await asyncHmacSha256(dateKey, new TextEncoder().encode(accessToken));
  const signingKey = await asyncHmacSha256(accessTokenKey, new TextEncoder().encode(REQUEST_SUFFIX));

  const signatureBytes = await asyncHmacSha256(signingKey, new TextEncoder().encode(stringToSign));
  const signature = hexEncode(signatureBytes);

  const authorization = `${SIGN_ALGORITHM} Credential=${clientId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  headers["authorization"] = authorization;

  const url = `https://${API_HOST}${apiPath}${sortedQueryString ? "?" + sortedQueryString : ""}`;
  return { url, headers };
}

function rfc3986Encode(s: string): string {
  return encodeURIComponent(s).replace(/%20/g, "+").replace(/!/g, "%21")
    .replace(/'/g, "%27").replace(/\(/g, "%28").replace(/\)/g, "%29");
}

// ── API 调用（带签名，用于已认证的端点）───────────────────────────────
async function signedApiCall<T>(
  method: string, apiPath: string,
  body?: Record<string, unknown>,
  params?: Record<string, string>,
): Promise<T> {
  const bodyBytes = body ? new TextEncoder().encode(JSON.stringify(body)) : null;

  const { url, headers } = await signRequest(
    method, apiPath, bodyBytes, accessToken, CLIENT_ID, CLIENT_SECRET, params
  );

  const fetchOptions: RequestInit = {
    method,
    headers: Object.entries(headers).map(([k, v]) => [k, v]),
  };
  if (bodyBytes) fetchOptions.body = bodyBytes;

  const resp = await fetch(url, fetchOptions);
  const respText = await resp.text();

  if (respText.trimStart().startsWith("<")) {
    throw new Error(`6盘 API 返回 HTML（可能处于封存/维护状态）。HTTP ${resp.status}`);
  }

  if (resp.status === 401) {
    const refreshed = await refreshAccessToken();
    if (refreshed) return signedApiCall<T>(method, apiPath, body, params);
    throw new Error("Token 过期且刷新失败，请重新授权。访问 /auth");
  }

  if (resp.status < 200 || resp.status >= 300) {
    let errMsg = `HTTP ${resp.status}`;
    try { const errJson = JSON.parse(respText); errMsg += `: ${errJson.message || errJson.error || respText.substring(0, 200)}`; }
    catch { errMsg += `: ${respText.substring(0, 200)}`; }
    throw new Error(errMsg);
  }

  return JSON.parse(respText) as T;
}

// ── OAuth2 签名 API 调用（Client ID/Secret 签名，AccessToken 为空）─────
// 用于 device_code、get_device_code_state 等端点
async function oauthApiCall<T>(
  method: string, apiPath: string,
  body?: Record<string, unknown>,
  params?: Record<string, string>,
): Promise<T> {
  const bodyBytes = body ? new TextEncoder().encode(JSON.stringify(body)) : null;

  const { url, headers } = await signRequest(
    method, apiPath, bodyBytes, "", CLIENT_ID, CLIENT_SECRET, params
  );

  const fetchOptions: RequestInit = {
    method,
    headers: Object.entries(headers).map(([k, v]) => [k, v]),
  };
  if (bodyBytes) fetchOptions.body = bodyBytes;

  const resp = await fetch(url, fetchOptions);
  const respText = await resp.text();

  if (respText.trimStart().startsWith("<")) {
    throw new Error(`OAuth2 端点返回 HTML（可能处于封存/维护状态）。HTTP ${resp.status}。预览: ${respText.substring(0, 200)}`);
  }

  if (resp.status < 200 || resp.status >= 300) {
    let errMsg = `HTTP ${resp.status}`;
    try { const errJson = JSON.parse(respText); errMsg += `: ${errJson.message || errJson.error || respText.substring(0, 200)}`; }
    catch { errMsg += `: ${respText.substring(0, 200)}`; }
    throw new Error(errMsg);
  }

  return JSON.parse(respText) as T;
}

// ── 无签名 API 调用（仅用于 token 交换等内部端点）───────────────────────
async function unsignedApiCall<T>(
  method: string, apiPath: string,
  body?: Record<string, unknown>,
): Promise<T> {
  const url = `${API_BASE}${apiPath}`;
  const fetchOptions: RequestInit = {
    method,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  };
  if (body) fetchOptions.body = JSON.stringify(body);

  const resp = await fetch(url, fetchOptions);
  const respText = await resp.text();

  if (respText.trimStart().startsWith("<")) {
    throw new Error(`OAuth2 端点返回 HTML（可能处于封存/维护状态）。HTTP ${resp.status}。预览: ${respText.substring(0, 200)}`);
  }

  if (resp.status < 200 || resp.status >= 300) {
    let errMsg = `HTTP ${resp.status}`;
    try { const errJson = JSON.parse(respText); errMsg += `: ${errJson.message || errJson.error || respText.substring(0, 200)}`; }
    catch { errMsg += `: ${respText.substring(0, 200)}`; }
    throw new Error(errMsg);
  }

  return JSON.parse(respText) as T;
}

// ── Cookie 模式 API 调用（用于旧版 v3 API）─────────────────────────────
const V3_API = "https://api.2dland.cn/v3";
const V3_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

async function cookieApiCall<T>(
  method: string, apiPath: string,
  body?: Record<string, unknown>,
  cookie?: string,
): Promise<T> {
  const url = `${V3_API}${apiPath}`;
  const fetchOptions: RequestInit = {
    method,
    headers: {
      "Content-Type": "application/json",
      "User-Agent": V3_UA,
      "Cookie": cookie || cookieCache || MANUAL_COOKIE,
    },
  };
  if (body) fetchOptions.body = JSON.stringify(body);

  const resp = await fetch(url, fetchOptions);
  const respText = await resp.text();

  if (respText.trimStart().startsWith("<")) {
    throw new Error(`Cookie API 返回 HTML。HTTP ${resp.status}。6盘可能处于维护状态。`);
  }

  if (resp.status < 200 || resp.status >= 300) {
    let errMsg = `HTTP ${resp.status}`;
    try { const errJson = JSON.parse(respText); errMsg += `: ${errJson.message || errJson.error || respText.substring(0, 200)}`; }
    catch { errMsg += `: ${respText.substring(0, 200)}`; }
    throw new Error(errMsg);
  }

  return JSON.parse(respText) as T;
}

// ── Token 管理 ──────────────────────────────────────────────────────

async function refreshAccessToken(): Promise<boolean> {
  if (!refreshToken) return false;
  try {
    const resp = await oauthApiCall<{ access_token: string; refresh_token: string; expires_in: number }>(
      "POST", "/v6/oauth/refresh_token",
      { refresh_token: refreshToken, grant_type: "refresh_token", client_id: CLIENT_ID },
    );
    accessToken = resp.access_token;
    refreshToken = resp.refresh_token;
    tokenExpiresAt = Date.now() + resp.expires_in * 1000;
    console.log(`Token 刷新成功，有效期 ${resp.expires_in} 秒`);
    return true;
  } catch (err) {
    console.error("Token 刷新失败:", err);
    return false;
  }
}

async function ensureToken(): Promise<void> {
  if (accessToken && tokenExpiresAt > Date.now()) {
    // Token 还有效，提前 5 分钟刷新
    if (tokenExpiresAt - Date.now() < 5 * 60 * 1000) {
      await refreshAccessToken();
    }
    return;
  }
  if (refreshToken) {
    const ok = await refreshAccessToken();
    if (ok) return;
  }
  throw new Error("需要重新授权。请访问 /auth 获取新的授权码");
}

// ── Device Code 授权流程（需要 Client ID/Secret 签名，AccessToken 为空）────

async function requestDeviceCode(): Promise<{
  user_code: string; device_code: string; verification_uri: string;
  expires_in: number; interval: number;
}> {
  return await oauthApiCall("POST", "/v6/oauth/device_code", {
    client_id: CLIENT_ID,
    response_type: "device_code",
    scope: "read write offline",
    device: "sixpan-relay-deno",
  });
}

async function checkDeviceCodeState(deviceCode: string): Promise<{
  login: boolean; access_token?: string; refresh_token?: string;
  expires_in?: number; status?: string; error?: string;
  [key: string]: unknown;
}> {
  return await oauthApiCall("POST", "/v6/oauth/get_device_code_state", {
    device_code: deviceCode,
    client_id: CLIENT_ID,
  });
}

// 当授权状态为 AUTHORIZATION_SUCCESS 时，交换 device_code 获取 Token
async function exchangeDeviceCode(deviceCode: string): Promise<{
  access_token: string; refresh_token: string; expires_in: number;
}> {
  // 尝试多个可能的 Token 交换端点
  const endpoints = [
    "/v6/oauth/device_token",
    "/v6/oauth/token",
    "/v6/oauth/get_device_token",
  ];

  const body = {
    device_code: deviceCode,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: "device_code",
  };

  for (const endpoint of endpoints) {
    try {
      const result = await oauthApiCall<{
        access_token: string; refresh_token: string; expires_in: number;
        [key: string]: unknown;
      }>("POST", endpoint, body);
      if (result.access_token) {
        console.log(`Token 交换成功，使用端点: ${endpoint}`);
        return result;
      }
    } catch (err) {
      console.log(`端点 ${endpoint} 失败: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  throw new Error("所有 Token 交换端点都失败了。请把 /auth?action=check 的完整 JSON 输出发给我，我来调整端点。");
}

// ── 离线下载 API ────────────────────────────────────────────────────

interface ParseResult {
  meta?: {
    identity: string; type: number; status: number; name: string; size: number;
    url: string; code: number; message: string;
  };
  task_files?: Array<{
    identity: string; path: string; name: string; size: number;
    status: number; directory: boolean; index: number;
  }>;
}

interface AddResult {
  identity: string; type: number; status: number; name: string;
  url: string; save_path: string; code: number; message: string;
}

// OpenAPI 模式：解析磁力链
async function openapiParseMagnet(magnetUrl: string): Promise<ParseResult> {
  return await signedApiCall<ParseResult>("POST", "/v6/offline_task/parse", { url: magnetUrl });
}

// OpenAPI 模式：添加离线下载任务
async function openapiAddOfflineTask(
  magnetUrl: string, savePath: string, parseResult?: ParseResult,
): Promise<AddResult> {
  const taskBody: Record<string, unknown> = {
    url: magnetUrl,
    save_path: savePath,
  };
  if (parseResult?.meta) {
    taskBody.name = parseResult.meta.name || "";
    taskBody.size = parseResult.meta.size || 0;
    taskBody.identity = parseResult.meta.identity || "";
    taskBody.type = parseResult.meta.type || 0;
  }
  return await signedApiCall<AddResult>("POST", "/v6/offline_task/add", taskBody);
}

// OpenAPI 模式：列出离线下载任务
async function openapiListOfflineTasks(): Promise<unknown> {
  return await signedApiCall("POST", "/v6/offline_task/list", {
    list_info: { limit: 20, version: 0 },
  });
}

// Cookie 模式：解析磁力链
async function cookieParseMagnet(magnetUrl: string): Promise<any> {
  return await cookieApiCall("POST", "/offline/parse", { url: magnetUrl, ts: Math.floor(Date.now() / 1000) });
}

// Cookie 模式：添加离线下载任务
async function cookieAddOfflineTask(infoHash: string, saveTo: string, fileName: string, fileCount: number, fileSize: number, fileList: string): Promise<any> {
  return await cookieApiCall("POST", "/offline/add", {
    infoHash, saveTo, fileName, fileCount, fileSize, fileList, ts: Math.floor(Date.now() / 1000),
  });
}

// ── 通用下载入口（自动选择模式）────────────────────────────────────────
async function submitDownload(magnetUrl: string, savePath: string): Promise<Response> {
  // 优先 OpenAPI 模式
  if (CLIENT_ID && CLIENT_SECRET && accessToken) {
    try {
      await ensureToken();
      let parseResult: ParseResult | undefined;
      try { parseResult = await openapiParseMagnet(magnetUrl); }
      catch (e) { console.log("OpenAPI Parse 失败（不影响 Add）:", e); }
      const addResult = await openapiAddOfflineTask(magnetUrl, savePath, parseResult);
      return jsonResponse({
        success: true, mode: "openapi", message: "离线任务已提交 ✅", task: addResult,
      });
    } catch (err) {
      // OpenAPI 失败，尝试 Cookie 模式
      console.log("OpenAPI 失败，尝试 Cookie:", err);
      if (MANUAL_COOKIE || cookieCache) {
        try {
          const parseResult = await cookieParseMagnet(magnetUrl);
          const infoHash = parseResult?.infoHash || parseResult?.meta?.identity || "";
          const fileName = parseResult?.fileName || parseResult?.meta?.name || "";
          const fileCount = parseResult?.fileCount || 0;
          const fileSize = parseResult?.fileSize || parseResult?.meta?.size || 0;
          const fileList = parseResult?.fileList || "";
          const addResult = await cookieAddOfflineTask(infoHash, savePath, fileName, fileCount, fileSize, fileList);
          return jsonResponse({
            success: true, mode: "cookie", message: "离线任务已提交 ✅（Cookie 模式）", task: addResult,
          });
        } catch (cookieErr) {
          return jsonResponse({
            success: false, error: `OpenAPI: ${err instanceof Error ? err.message : String(err)} | Cookie: ${cookieErr instanceof Error ? cookieErr.message : String(cookieErr)}`,
          }, 500);
        }
      }
      return jsonResponse({ success: false, error: err instanceof Error ? err.message : String(err) }, 500);
    }
  }

  // Cookie 模式
  if (MANUAL_COOKIE || cookieCache) {
    try {
      const parseResult = await cookieParseMagnet(magnetUrl);
      const infoHash = parseResult?.infoHash || parseResult?.meta?.identity || "";
      const fileName = parseResult?.fileName || parseResult?.meta?.name || "";
      const fileCount = parseResult?.fileCount || 0;
      const fileSize = parseResult?.fileSize || parseResult?.meta?.size || 0;
      const fileList = parseResult?.fileList || "";
      const addResult = await cookieAddOfflineTask(infoHash, savePath, fileName, fileCount, fileSize, fileList);
      return jsonResponse({ success: true, mode: "cookie", message: "离线任务已提交 ✅", task: addResult });
    } catch (err) {
      return jsonResponse({ success: false, error: err instanceof Error ? err.message : String(err) }, 500);
    }
  }

  // 没有任何认证方式
  return jsonResponse({
    success: false, error: "没有可用的认证方式",
    hint: "请设置 SIXPAN_COOKIE（Cookie 模式）或完成 /auth 授权（OpenAPI 模式）",
  }, 401);
}

// ── HTTP 路由 ───────────────────────────────────────────────────────

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function authCheck(request: Request): boolean {
  const url = new URL(request.url);
  const token = url.searchParams.get("token") ||
    request.headers.get("Authorization")?.replace("Bearer ", "") || "";
  return token === AUTH_TOKEN;
}

// ── 路由处理 ─────────────────────────────────────────────────────────

async function handleAdd(request: Request): Promise<Response> {
  if (request.method !== "POST") return jsonResponse({ error: "仅支持 POST，请用快捷指令调用" }, 405);
  if (!authCheck(request)) return jsonResponse({ error: "鉴权失败" }, 401);

  try {
    const body = await request.json() as { magnet?: string; url?: string; saveTo?: string };
    const magnetUrl = body.magnet || body.url || "";
    const savePath = body.saveTo || SAVE_PATH;

    if (!magnetUrl) return jsonResponse({ error: "缺少 magnet/url 参数" }, 400);
    if (!magnetUrl.startsWith("magnet:") && !magnetUrl.startsWith("http") && !magnetUrl.startsWith("ed2k")) {
      return jsonResponse({ error: "仅支持 magnet/http/ed2k 链接" }, 400);
    }

    return await submitDownload(magnetUrl, savePath);
  } catch (err) {
    return jsonResponse({
      success: false, error: err instanceof Error ? err.message : String(err),
    }, 500);
  }
}

async function handleAuth(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const action = url.searchParams.get("action");

  // Step 1: 申请设备授权码（JSON 返回）
  if (action === "start") {
    try {
      const deviceCodeResp = await requestDeviceCode();
      return jsonResponse({
        step: 1,
        message: "请在浏览器/手机打开以下链接，输入验证码授权",
        verification_uri: deviceCodeResp.verification_uri,
        user_code: deviceCodeResp.user_code,
        device_code: deviceCodeResp.device_code,
        expires_in: deviceCodeResp.expires_in,
        hint: `授权后，访问 /auth?action=poll&device_code=${deviceCodeResp.device_code} 自动等待授权完成`,
      });
    } catch (err) {
      return jsonResponse({
        error: "获取设备授权码失败",
        detail: err instanceof Error ? err.message : String(err),
        env_check: {
          has_client_id: !!CLIENT_ID,
          has_client_secret: !!CLIENT_SECRET,
          client_id_prefix: CLIENT_ID ? CLIENT_ID.substring(0, 8) + "***" : "未设置",
        },
      }, 500);
    }
  }

  // Step 2: 自动轮询等待授权完成（HTML 页面）
  if (action === "poll") {
    const deviceCode = url.searchParams.get("device_code") || "";
    if (!deviceCode) return jsonResponse({ error: "缺少 device_code 参数" }, 400);

    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>6盘授权 — 等待中</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; line-height: 1.8; text-align: center; }
  h1 { color: #333; }
  .spinner { display: inline-block; width: 40px; height: 40px; border: 4px solid #ddd; border-top-color: #007bff;
    border-radius: 50%; animation: spin 1s linear infinite; margin: 20px 0; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .status { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
  .success { background: #d4edda; color: #155724; padding: 20px; border-radius: 8px; }
  .fail { background: #f8d7da; color: #721c24; padding: 20px; border-radius: 8px; }
  .hidden { display: none; }
</style></head><body>
<h1>等待授权中...</h1>
<div class="spinner"></div>
<div id="waiting" class="status">
  正在等待你在 6盘 完成授权...<br>
  每 5 秒自动检查一次
</div>
<div id="success" class="success hidden">
  <h2>授权成功 ✅</h2>
  <p>Token 已保存，现在可以正常使用离线下载了</p>
  <a href="/status?token=${AUTH_TOKEN}">查看状态 →</a><br>
  <a href="/">返回首页 →</a>
</div>
<div id="fail" class="fail hidden">
  <h2>授权失败 ❌</h2>
  <p id="failMsg"></p>
  <a href="/auth">重新授权 →</a>
</div>

<script>
const deviceCode = "${deviceCode}";
let attempts = 0;
const maxAttempts = 60; // 最多等待 5 分钟

async function poll() {
  attempts++;
  if (attempts > maxAttempts) {
    document.getElementById('waiting').classList.add('hidden');
    document.getElementById('fail').classList.remove('hidden');
    document.getElementById('failMsg').textContent = '等待超时（5分钟），请重新申请授权码';
    document.querySelector('.spinner').style.display = 'none';
    return;
  }

  try {
    const resp = await fetch('/auth?action=check&device_code=' + deviceCode);
    const data = await resp.json();

    if (data.success && data.login) {
      document.getElementById('waiting').classList.add('hidden');
      document.getElementById('success').classList.remove('hidden');
      document.querySelector('.spinner').style.display = 'none';
      return;
    }

    // Token 交换失败但授权已成功 — 显示详细错误
    if (data.status === 'AUTHORIZATION_SUCCESS' && !data.success) {
      document.getElementById('waiting').classList.add('hidden');
      document.getElementById('fail').classList.remove('hidden');
      document.getElementById('failMsg').textContent = '授权已成功，但 Token 交换失败：' + (data.exchange_error || '未知错误');
      document.querySelector('.spinner').style.display = 'none';
      return;
    }

    if (data.error && data.status !== 'pending') {
      document.getElementById('waiting').classList.add('hidden');
      document.getElementById('fail').classList.remove('hidden');
      document.getElementById('failMsg').textContent = data.error + (data.detail ? ' — ' + data.detail : '');
      document.querySelector('.spinner').style.display = 'none';
      return;
    }
  } catch (err) {
    // 网络错误，继续轮询
    console.error('Poll error:', err);
  }

  setTimeout(poll, 5000);
}

poll();
</script>
</body></html>`;

    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  // Step 3: 检查授权状态（JSON，给轮询页面调用）
  if (action === "check") {
    const deviceCode = url.searchParams.get("device_code") || "";
    if (!deviceCode) return jsonResponse({ error: "缺少 device_code 参数" }, 400);

    try {
      const state = await checkDeviceCodeState(deviceCode);

      // 方式 1：状态检查直接返回了 Token
      if (state.login && state.access_token && state.refresh_token) {
        accessToken = state.access_token;
        refreshToken = state.refresh_token;
        tokenExpiresAt = Date.now() + (state.expires_in || 3600) * 1000;
        return jsonResponse({ success: true, login: true, message: "授权成功 ✅ Token 已保存" });
      }

      // 方式 2：状态为 AUTHORIZATION_SUCCESS，但 Token 需要单独交换
      if (state.status === "AUTHORIZATION_SUCCESS" || state.login === true) {
        try {
          const tokenResult = await exchangeDeviceCode(deviceCode);
          accessToken = tokenResult.access_token;
          refreshToken = tokenResult.refresh_token;
          tokenExpiresAt = Date.now() + (tokenResult.expires_in || 3600) * 1000;
          return jsonResponse({ success: true, login: true, message: "授权成功 ✅ Token 已保存", exchange_method: "device_code_token" });
        } catch (exchangeErr) {
          return jsonResponse({
            success: false,
            status: state.status,
            login: state.login,
            message: "授权已成功，但 Token 交换失败",
            exchange_error: exchangeErr instanceof Error ? exchangeErr.message : String(exchangeErr),
            raw_state: state, // 保留原始响应，方便调试
          }, 500);
        }
      }

      // 方式 3：直接有 error
      if (state.error) {
        return jsonResponse({ success: false, login: false, error: state.error });
      }

      // 还未授权
      return jsonResponse({
        success: false, login: false, status: state.status || "pending",
        message: "尚未授权，请先在浏览器完成授权",
        raw_state: state,
      });
    } catch (err) {
      return jsonResponse({
        error: "检查授权状态失败",
        detail: err instanceof Error ? err.message : String(err),
      }, 500);
    }
  }

  // 默认：显示授权指导页面（HTML）
  const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>6盘授权</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; line-height: 1.8; }
  h1 { color: #333; } h2 { color: #555; }
  .step { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0; }
  .btn { display: inline-block; padding: 10px 20px; background: #007bff; color: white; border-radius: 6px;
    text-decoration: none; margin: 10px 0; cursor: pointer; border: none; font-size: 16px; }
  .btn:hover { background: #0056b3; }
  .btn-green { background: #28a745; } .btn-green:hover { background: #218838; }
  .warn { background: #fff3cd; padding: 12px; border-radius: 6px; color: #856404; }
  .info { background: #d1ecf1; padding: 12px; border-radius: 6px; color: #0c5460; }
  code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 14px; }
  .result { background: #e9ecef; padding: 15px; border-radius: 8px; white-space: pre-wrap; word-break: break-all;
    font-family: monospace; margin: 10px 0; display: none; }
  #loading { display: none; color: #007bff; margin: 10px 0; }
</style></head><body>
<h1>6盘（清真云）离线下载 — 授权</h1>

<div class="warn">⚠️ 6盘已于 2026-06-20 进入「封存状态」，API 可能不稳定。现有用户仍可使用。</div>

<div class="info">💡 两种认证方式：
<br><strong>① OpenAPI 模式</strong>（需要 Client ID + Client Secret → Device Code 授权 → 自动刷新 Token）
<br><strong>② Cookie 模式</strong>（最简单！浏览器复制 Cookie → 填环境变量 SIXPAN_COOKIE）
<br>推荐先试 Cookie 模式，如果不行再试 OpenAPI。
</div>

<h2>OpenAPI 模式授权</h2>
<div class="step">
  <p><strong>前提</strong>：已在 Deno Deploy 设置 <code>SIXPAN_CLIENT_ID</code> 和 <code>SIXPAN_CLIENT_SECRET</code></p>
  <p>获取方法：登录 <a href="https://drive.2dland.cn" target="_blank">drive.2dland.cn</a> → 用户中心 → 授权管理 → 新建授权</p>
  <button class="btn" onclick="startAuth()">申请授权码 →</button>
  <div id="loading">⏳ 正在申请授权码...</div>
  <div id="startResult" class="result"></div>
</div>

<div id="pollSection" style="display:none">
  <h2>自动等待授权完成</h2>
  <div class="step">
    <p id="pollStatus">正在等待你在 6盘 完成授权...</p>
    <button class="btn btn-green" onclick="openPollPage()">打开自动等待页面 →</button>
  </div>
</div>

<h2>Cookie 模式（更简单）</h2>
<div class="step">
  <p>1. 登录 <a href="https://drive.2dland.cn" target="_blank">drive.2dland.cn</a></p>
  <p>2. F12 → Network → 刷新页面 → 找任意 API 请求 → 复制请求头中的 <code>Authorization: Bearer xxx</code></p>
  <p>3. 但 6盘 使用 gRPC-Web + Bearer JWT，Cookie 模式可能已不可用</p>
  <p>如果你之前有有效的 Cookie，可以设置 <code>SIXPAN_COOKIE</code> 环境变量</p>
</div>

<h2>快速测试</h2>
<div class="step">
  <a class="btn" href="/debug?token=${AUTH_TOKEN}">🔍 查看服务状态 →</a>
  <a class="btn" href="/status?token=${AUTH_TOKEN}">📊 查看 Token 状态 →</a>
</div>

<script>
async function startAuth() {
  const btn = document.querySelector('.btn');
  btn.disabled = true;
  btn.textContent = '⏳ 申请中...';
  document.getElementById('loading').style.display = 'block';
  document.getElementById('startResult').style.display = 'none';

  try {
    const resp = await fetch('/auth?action=start');
    const data = await resp.json();

    document.getElementById('loading').style.display = 'none';
    document.getElementById('startResult').style.display = 'block';
    document.getElementById('startResult').textContent = JSON.stringify(data, null, 2);

    if (data.device_code) {
      document.getElementById('pollSection').style.display = 'block';
      document.getElementById('pollStatus').textContent =
        '请在浏览器打开 ' + data.verification_uri + ' 输入验证码 ' + data.user_code;
    }
  } catch (err) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('startResult').style.display = 'block';
    document.getElementById('startResult').textContent = '错误: ' + err.message;
  }

  btn.disabled = false;
  btn.textContent = '申请授权码 →';
}

function openPollPage() {
  const resultText = document.getElementById('startResult').textContent;
  try {
    const data = JSON.parse(resultText);
    if (data.device_code) {
      window.open('/auth?action=poll&device_code=' + data.device_code, '_blank');
    }
  } catch {}
}
</script>
</body></html>`;

  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handleStatus(request: Request): Promise<Response> {
  if (!authCheck(request)) return jsonResponse({ error: "鉴权失败" }, 401);
  return jsonResponse({
    success: true,
    mode: accessToken ? "openapi" : (MANUAL_COOKIE || cookieCache ? "cookie" : "none"),
    openapi: {
      hasAccessToken: !!accessToken,
      hasRefreshToken: !!refreshToken,
      tokenExpires: tokenExpiresAt ? new Date(tokenExpiresAt).toISOString() : null,
      clientId: CLIENT_ID ? CLIENT_ID.substring(0, 8) + "***" : "未设置",
    },
    cookie: {
      hasManualCookie: !!MANUAL_COOKIE,
      hasCachedCookie: !!cookieCache,
    },
    savePath: SAVE_PATH,
  });
}

async function handleDebug(request: Request): Promise<Response> {
  if (!authCheck(request)) return jsonResponse({ error: "鉴权失败" }, 401);

  const result: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    env: {
      hasClientId: !!CLIENT_ID,
      clientIdPrefix: CLIENT_ID ? CLIENT_ID.substring(0, 8) + "***" : "",
      hasClientSecret: !!CLIENT_SECRET,
      hasAuthToken: !!AUTH_TOKEN,
      hasManualCookie: !!MANUAL_COOKIE,
      savePath: SAVE_PATH,
    },
    token: {
      hasAccessToken: !!accessToken,
      hasRefreshToken: !!refreshToken,
      tokenExpires: tokenExpiresAt ? new Date(tokenExpiresAt).toISOString() : null,
    },
  };

  // 测试 OpenAPI 域名可达性（使用 OAuth2 签名但 AccessToken 为空）
  try {
    const bodyBytes = new TextEncoder().encode(JSON.stringify({ client_id: CLIENT_ID, response_type: "device_code" }));
    const { url: testUrl, headers: testHeaders } = await signRequest(
      "POST", "/v6/oauth/device_code", bodyBytes, "", CLIENT_ID, CLIENT_SECRET
    );
    const testResp = await fetch(testUrl, {
      method: "POST",
      headers: Object.entries(testHeaders).map(([k, v]) => [k, v]),
      body: bodyBytes,
    });
    const testText = await testResp.text();
    result.openapiReachable = true;
    result.openapiHttpStatus = testResp.status;
    result.openapiReturnsHtml = testText.trimStart().startsWith("<");
    result.openapiResponsePreview = testText.substring(0, 300);
  } catch (err) {
    result.openapiReachable = false;
    result.openapiError = err instanceof Error ? err.message : String(err);
  }

  // 测试 v3 Cookie API 可达性
  try {
    const v3Resp = await fetch(`${V3_API}/user/info`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": V3_UA,
        "Cookie": MANUAL_COOKIE || "test=test",
      },
      body: JSON.stringify({ ts: Math.floor(Date.now() / 1000) }),
    });
    const v3Text = await v3Resp.text();
    result.v3ApiReachable = true;
    result.v3ApiHttpStatus = v3Resp.status;
    result.v3ApiReturnsHtml = v3Text.trimStart().startsWith("<");
    result.v3ApiResponsePreview = v3Text.substring(0, 300);
  } catch (err) {
    result.v3ApiReachable = false;
    result.v3ApiError = err instanceof Error ? err.message : String(err);
  }

  // 如果有 token，测试实际 API 调用
  if (accessToken) {
    try {
      await ensureToken();
      const tasks = await openapiListOfflineTasks();
      result.openapiApiWorking = true;
      result.offlineTasks = tasks;
    } catch (err) {
      result.openapiApiWorking = false;
      result.openapiApiError = err instanceof Error ? err.message : String(err);
    }
  }

  return jsonResponse(result);
}

async function handleTasks(request: Request): Promise<Response> {
  if (!authCheck(request)) return jsonResponse({ error: "鉴权失败" }, 401);
  try {
    if (accessToken && CLIENT_ID && CLIENT_SECRET) {
      await ensureToken();
      const tasks = await openapiListOfflineTasks();
      return jsonResponse({ success: true, mode: "openapi", tasks });
    }
    return jsonResponse({ success: false, error: "没有可用的认证方式" }, 401);
  } catch (err) {
    return jsonResponse({ success: false, error: err instanceof Error ? err.message : String(err) }, 500);
  }
}

// ── 首页 ────────────────────────────────────────────────────────────
const HTML_HOME = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>6盘离线下载中继</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; line-height: 1.8; }
  h1 { color: #333; }
  .box { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0; }
  .btn { display: inline-block; padding: 10px 20px; background: #007bff; color: white; border-radius: 6px;
    text-decoration: none; margin: 5px; }
  form input, form textarea { width: 100%; padding: 8px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; }
  form button { padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 6px; cursor: pointer; }
  .warn { background: #fff3cd; padding: 12px; border-radius: 6px; color: #856404; }
</style></head><body>
<h1>6盘（清真云）离线下载中继 v6</h1>
<p>iPhone 快捷指令 → Deno Deploy → 6盘 OpenAPI</p>

<div class="warn">⚠️ 6盘已于 2026-06-20 进入「封存状态」，API 可能不稳定。</div>

<div class="box">
  <a class="btn" href="/auth">🔑 授权/登录</a>
  <a class="btn" href="/status?token=${AUTH_TOKEN}">📊 状态</a>
  <a class="btn" href="/tasks?token=${AUTH_TOKEN}">📋 任务列表</a>
  <a class="btn" href="/debug?token=${AUTH_TOKEN}">🔍 调试</a>
</div>

<form id="dlForm" onsubmit="submitMagnet(event)">
  <h3>手动提交磁力链</h3>
  <input type="text" id="magnet" placeholder="magnet:?xt=urn:btih:... 或 http/ed2k 链接" required>
  <input type="text" id="saveTo" placeholder="保存路径（默认 /All/）" value="/All/">
  <input type="text" id="token" placeholder="AUTH_TOKEN" required>
  <button type="submit">提交离线下载</button>
</form>
<div id="result" class="box" style="display:none"></div>

<script>
async function submitMagnet(e) {
  e.preventDefault();
  const magnet = document.getElementById('magnet').value;
  const saveTo = document.getElementById('saveTo').value;
  const token = document.getElementById('token').value;
  const resDiv = document.getElementById('result');
  resDiv.style.display = 'block';
  resDiv.textContent = '提交中...';
  try {
    const resp = await fetch('/add?token=' + token, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ magnet, saveTo })
    });
    const data = await resp.json();
    resDiv.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    resDiv.textContent = '错误: ' + err.message;
  }
}
</script>
</body></html>`;

// ── 主路由 ──────────────────────────────────────────────────────────
Deno.serve(async (request: Request): Promise<Response> => {
  const url = new URL(request.url);
  const path = url.pathname;

  try {
    if (path === "/add") return await handleAdd(request);
    if (path === "/auth") return await handleAuth(request);
    if (path === "/status") return await handleStatus(request);
    if (path === "/debug") return await handleDebug(request);
    if (path === "/tasks") return await handleTasks(request);
    if (path === "/") return new Response(HTML_HOME, { headers: { "Content-Type": "text/html; charset=utf-8" } });

    return jsonResponse({ error: "未知路径", available: ["/", "/add", "/auth", "/status", "/debug", "/tasks"] }, 404);
  } catch (err) {
    return jsonResponse({ error: err instanceof Error ? err.message : String(err) }, 500);
  }
});
