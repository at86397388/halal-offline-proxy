// ── 6盘（清真云）远程离线下载中继服务 v5 ───────────────────────────────
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

// ── Token 存储（内存，Deno Deploy 冷启动后需要重新授权）─────────────
let accessToken = "";
let refreshToken = "";
let tokenExpiresAt = 0;

// ── HMAC-SHA256 工具 ────────────────────────────────────────────────
function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  const cryptoKey = Deno.env.get("DENO_DEPLOY") ? null : null; // placeholder
  // Deno Deploy 支持 Web Crypto API
  // 但由于需要多次 HMAC 迭代，我们用纯 JS 实现
  // 使用 SubtleCrypto 是异步的，不方便迭代，改用 Deno 的 std 库
  // 但 Deno Deploy 不支持 import，所以手动实现 HMAC-SHA256

  // 简化方案：使用 Web Crypto API（异步）
  // 但迭代签名需要同步，所以用 Deno.crypto.subtle
  // 实际上 Deno Deploy 支持 crypto.subtle，但它是异步的
  // 让我重新设计：先准备所有数据，再一次性调用

  // 最可靠的方案：用 Deno 的 crypto.subtle（异步）
  return new Uint8Array(); // placeholder - 实际实现在 asyncHmacSha256 中
}

// 异步 HMAC-SHA256（使用 Web Crypto API，Deno Deploy 支持）
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

// ── HL6-HMAC-SHA256 签名 ───────────────────────────────────────────
async function signRequest(
  method: string, apiPath: string, body: Uint8Array | null,
  accessToken: string, clientId: string, clientSecret: string,
  extraParams?: Record<string, string>,
): Promise<{ url: string; headers: Record<string, string> }> {

  const utcTime = new Date();
  const dateString = utcTime.toISOString().split("T")[0]; // YYYY-MM-DD
  const nonce = BigInt(utcTime.getTime() * 1_000_000).toString(36); // base36 of unix micro
  const timestamp = utcTime.toISOString(); // RFC3339

  // 构建 headers
  const headers: Record<string, string> = {
    "host": API_HOST,
    "x-hl-nonce": nonce,
    "x-hl-timestamp": timestamp,
    "other-header": "other-value",
  };

  // 确定 HeadersToSign
  const headersToSign: string[] = ["host", "x-hl-nonce", "x-hl-timestamp", "other-header"];

  // 如果有 body，添加 content-type
  if (body) {
    headers["content-type"] = "application/json; charset=utf-8";
    headersToSign.push("content-type");
  }

  // 确保唯一
  const uniqueHeadersToSign = [...new Set(headersToSign)].sort();

  // 构建 Canonical Headers
  const canonicalHeaders = uniqueHeadersToSign
    .filter(h => headers[h])
    .map(h => `${h}:${headers[h]}`)
    .join("\n") + "\n";

  const signedHeaders = uniqueHeadersToSign.join(";");

  // 构建 Sorted Query String
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

  // 构建 Canonical Request
  const bodyHash = body ? await sha256HexBytes(body) : await sha256Hex("");
  const canonicalRequest = [
    method,
    apiPath,
    sortedQueryString,
    canonicalHeaders,
    signedHeaders,
    bodyHash,
  ].join("\n");

  // Credential Scope
  const credentialScope = `${dateString}/${accessToken}/${REQUEST_SUFFIX}`;

  // String To Sign
  const hashedCanonical = await sha256Hex(canonicalRequest);
  const stringToSign = [
    SIGN_ALGORITHM,
    timestamp,
    credentialScope,
    hashedCanonical,
  ].join("\n");

  // Derive Signing Key
  const secretKeyBytes = new TextEncoder().encode(SIGN_PREFIX + clientSecret);
  const dateKey = await asyncHmacSha256(secretKeyBytes, new TextEncoder().encode(dateString));
  const accessTokenKey = await asyncHmacSha256(dateKey, new TextEncoder().encode(accessToken));
  const signingKey = await asyncHmacSha256(accessTokenKey, new TextEncoder().encode(REQUEST_SUFFIX));

  // Calculate Signature
  const signatureBytes = await asyncHmacSha256(signingKey, new TextEncoder().encode(stringToSign));
  const signature = hexEncode(signatureBytes);

  // Authorization Header
  const authorization = `${SIGN_ALGORITHM} Credential=${clientId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  headers["authorization"] = authorization;

  // Build URL
  const url = `https://${API_HOST}${apiPath}${sortedQueryString ? "?" + sortedQueryString : ""}`;

  return { url, headers };
}

function rfc3986Encode(s: string): string {
  return encodeURIComponent(s).replace(/%20/g, "+").replace(/!/g, "%21")
    .replace(/'/g, "%27").replace(/\(/g, "%28").replace(/\)/g, "%29");
}

// ── API 调用 ────────────────────────────────────────────────────────
async function apiCall<T>(
  method: string, apiPath: string,
  body?: Record<string, unknown>,
  accessTokenOverride?: string,
  params?: Record<string, string>,
): Promise<T> {
  const currentAccessToken = accessTokenOverride || accessToken;
  const bodyBytes = body ? new TextEncoder().encode(JSON.stringify(body)) : null;

  const { url, headers } = await signRequest(
    method, apiPath, bodyBytes, currentAccessToken, CLIENT_ID, CLIENT_SECRET, params
  );

  const fetchOptions: RequestInit = {
    method,
    headers: Object.entries(headers).map(([k, v]) => [k, v]),
  };
  if (bodyBytes) {
    fetchOptions.body = bodyBytes;
  }

  const resp = await fetch(url, fetchOptions);
  const respText = await resp.text();

  // 检查是否返回 HTML（6盘封存状态）
  if (respText.trimStart().startsWith("<")) {
    throw new Error(`6盘 API 返回 HTML（可能处于封存/维护状态）。HTTP ${resp.status}`);
  }

  if (resp.status === 401 && !accessTokenOverride) {
    // Token 过期，尝试刷新
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      // 重试一次
      return apiCall<T>(method, apiPath, body, accessToken, params);
    }
    throw new Error("Token 过期且刷新失败，请重新授权");
  }

  if (resp.status < 200 || resp.status >= 300) {
    let errMsg = `HTTP ${resp.status}`;
    try {
      const errJson = JSON.parse(respText);
      errMsg += `: ${errJson.message || errJson.error || respText.substring(0, 200)}`;
    } catch {
      errMsg += `: ${respText.substring(0, 200)}`;
    }
    throw new Error(errMsg);
  }

  return JSON.parse(respText) as T;
}

// ── Token 管理 ──────────────────────────────────────────────────────

// 刷新 Access Token
async function refreshAccessToken(): Promise<boolean> {
  if (!refreshToken) return false;
  try {
    const resp = await apiCall<{ access_token: string; refresh_token: string; expires_in: number }>(
      "POST", "/v6/oauth/refresh_token",
      {
        refresh_token: refreshToken,
        grant_type: "refresh_token",
        client_id: CLIENT_ID,
      },
      accessToken, // 刷新 token 请求用当前 accessToken 签名
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

// 确保 Token 有效
async function ensureToken(): Promise<void> {
  if (!accessToken || !refreshToken || tokenExpiresAt < Date.now()) {
    // 尝试刷新
    if (refreshToken) {
      const ok = await refreshAccessToken();
      if (ok) return;
    }
    throw new Error("需要重新授权。请访问 /auth 获取新的授权码");
  }
  // Token 还有效，提前 5 分钟刷新
  if (tokenExpiresAt - Date.now() < 5 * 60 * 1000) {
    await refreshAccessToken();
  }
}

// ── Device Code 授权流程 ────────────────────────────────────────────

// Step 1: 申请设备授权码
async function requestDeviceCode(): Promise<{
  user_code: string; device_code: string; verification_uri: string;
  expires_in: number; interval: number;
}> {
  return await apiCall("POST", "/v6/oauth/device_code", {
    client_id: CLIENT_ID,
    response_type: "device_code",
    scope: "read write offline",
    device: "sixpan-relay-deno",
  }, "", // 初始授权没有 accessToken
  );
}

// Step 2: 检查授权状态
async function checkDeviceCodeState(deviceCode: string): Promise<{
  login: boolean; access_token?: string; refresh_token?: string;
  expires_in?: number; status?: string;
}> {
  return await apiCall("POST", "/v6/oauth/get_device_code_state", {
    device_code: deviceCode,
  }, accessToken || "");
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

// 解析磁力链
async function parseMagnet(magnetUrl: string): Promise<ParseResult> {
  return await apiCall<ParseResult>("POST", "/v6/offline_task/parse", {
    url: magnetUrl,
  });
}

// 添加离线下载任务
async function addOfflineTask(
  magnetUrl: string, savePath: string, parseResult?: ParseResult,
): Promise<AddResult> {
  const taskBody: Record<string, unknown> = {
    url: magnetUrl,
    save_path: savePath,
  };

  // 如果有解析结果，填充更多信息
  if (parseResult?.meta) {
    taskBody.name = parseResult.meta.name || "";
    taskBody.size = parseResult.meta.size || 0;
    taskBody.identity = parseResult.meta.identity || "";
    taskBody.type = parseResult.meta.type || 0;
  }

  return await apiCall<AddResult>("POST", "/v6/offline_task/add", taskBody);
}

// 列出离线下载任务
async function listOfflineTasks(): Promise<unknown> {
  return await apiCall("POST", "/v6/offline_task/list", {
    list_info: { limit: 20, version: 0 },
  });
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

    await ensureToken();

    // Step 1: 解析
    let parseResult: ParseResult | undefined;
    try {
      parseResult = await parseMagnet(magnetUrl);
    } catch (err) {
      console.log("Parse 失败（不影响 Add）:", err);
    }

    // Step 2: 添加任务
    const addResult = await addOfflineTask(magnetUrl, savePath, parseResult);

    return jsonResponse({
      success: true,
      message: `离线任务已提交 ✅`,
      task: addResult,
    });
  } catch (err) {
    return jsonResponse({
      success: false,
      error: err instanceof Error ? err.message : String(err),
      hint: err instanceof Error && err.message.includes("重新授权")
        ? "请访问 /auth 重新获取授权"
        : undefined,
    }, 500);
  }
}

async function handleAuth(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const action = url.searchParams.get("action");

  if (action === "start") {
    // Step 1: 申请设备授权码
    try {
      const deviceCodeResp = await requestDeviceCode();
      return jsonResponse({
        step1: "请在浏览器/手机打开以下链接，输入验证码授权",
        verification_uri: deviceCodeResp.verification_uri,
        user_code: deviceCodeResp.user_code,
        device_code: deviceCodeResp.device_code,
        expires_in: deviceCodeResp.expires_in,
        hint: `授权后，访问 /auth?action=check&device_code=${deviceCodeResp.device_code} 检查状态`,
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

  if (action === "check") {
    const deviceCode = url.searchParams.get("device_code") || "";
    if (!deviceCode) return jsonResponse({ error: "缺少 device_code 参数" }, 400);

    try {
      const state = await checkDeviceCodeState(deviceCode);
      if (state.login && state.access_token && state.refresh_token) {
        // 授权成功！保存 token
        accessToken = state.access_token;
        refreshToken = state.refresh_token;
        tokenExpiresAt = Date.now() + (state.expires_in || 3600) * 1000;

        return jsonResponse({
          success: true,
          message: "授权成功 ✅ Token 已保存，现在可以正常使用离线下载了",
          expires_in: state.expires_in,
          hint: "iPhone 快捷指令调用 /add 即可",
        });
      }

      return jsonResponse({
        success: false,
        status: state.status || "pending",
        message: "尚未授权，请先在浏览器完成授权",
        login: state.login,
        hint: "授权后再次访问此链接检查",
      });
    } catch (err) {
      return jsonResponse({
        error: "检查授权状态失败",
        detail: err instanceof Error ? err.message : String(err),
      }, 500);
    }
  }

  // 默认：显示授权指导页面
  const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>6盘授权</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; line-height: 1.8; }
  h1 { color: #333; } h2 { color: #555; }
  .step { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0; }
  .btn { display: inline-block; padding: 10px 20px; background: #007bff; color: white; border-radius: 6px;
    text-decoration: none; margin: 10px 0; }
  .warn { background: #fff3cd; padding: 12px; border-radius: 6px; color: #856404; }
  code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; }
</style></head><body>
<h1>6盘（清真云）离线下载 — 授权</h1>

<div class="warn">⚠️ 6盘已于 2026-06-20 进入「封存状态」，API 可能不稳定。现有用户仍可使用。</div>

<h2>步骤 1：获取设备授权码</h2>
<div class="step">
  点击下方按钮申请授权码（需要先设置环境变量 <code>SIXPAN_CLIENT_ID</code> 和 <code>SIXPAN_CLIENT_SECRET</code>）
  <br><a class="btn" href="/auth?action=start">申请授权码 →</a>
</div>

<h2>步骤 2：在浏览器授权</h2>
<div class="step">
  Step 1 会返回一个 <code>verification_uri</code> 和 <code>user_code</code>
  <br>在浏览器打开 verification_uri，输入 user_code 完成授权
</div>

<h2>步骤 3：检查授权状态</h2>
<div class="step">
  授权完成后，访问：<br>
  <code>/auth?action=check&device_code=你的device_code</code>
  <br>成功后 Token 自动保存，即可正常使用
</div>

<h2>如何获取 Client ID 和 Client Secret？</h2>
<div class="step">
  1. 登录 <a href="https://drive.2dland.cn" target="_blank">drive.2dland.cn</a>
  <br>2. 用户中心 → 授权管理 → 输入密码验证身份
  <br>3. 新建授权（名称随意）→ 获得 Client ID + Client Secret
  <br>4. 在 Deno Deploy 设置环境变量
</div>

<h2>快速测试</h2>
<div class="step">
  <a class="btn" href="/debug?token=${AUTH_TOKEN}">查看服务状态 →</a>
</div>

</body></html>`;

  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handleStatus(request: Request): Promise<Response> {
  if (!authCheck(request)) return jsonResponse({ error: "鉴权失败" }, 401);
  return jsonResponse({
    success: true,
    hasToken: !!accessToken,
    tokenExpires: tokenExpiresAt ? new Date(tokenExpiresAt).toISOString() : null,
    hasRefreshToken: !!refreshToken,
    clientId: CLIENT_ID ? CLIENT_ID.substring(0, 8) + "***" : "未设置",
    savePath: SAVE_PATH,
    mode: "openapi-device-code",
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
      savePath: SAVE_PATH,
    },
    token: {
      hasAccessToken: !!accessToken,
      hasRefreshToken: !!refreshToken,
      tokenExpires: tokenExpiresAt ? new Date(tokenExpiresAt).toISOString() : null,
    },
  };

  // 测试 OpenAPI 域名可达性
  try {
    const testResp = await fetch(`https://${API_HOST}/v6/oauth/refresh_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test: true }),
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

  // 如果有 token，测试 API 调用
  if (accessToken) {
    try {
      await ensureToken();
      const tasks = await listOfflineTasks();
      result.apiWorking = true;
      result.offlineTasks = tasks;
    } catch (err) {
      result.apiWorking = false;
      result.apiError = err instanceof Error ? err.message : String(err);
    }
  } else {
    result.apiWorking = false;
    result.apiHint = "无 Token，请先访问 /auth 授权";
  }

  return jsonResponse(result);
}

async function handleTasks(request: Request): Promise<Response> {
  if (!authCheck(request)) return jsonResponse({ error: "鉴权失败" }, 401);
  try {
    await ensureToken();
    const tasks = await listOfflineTasks();
    return jsonResponse({ success: true, tasks });
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
</style></head><body>
<h1>6盘（清真云）离线下载中继</h1>
<p>iPhone 快捷指令 → Deno Deploy → 6盘 OpenAPI</p>

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
