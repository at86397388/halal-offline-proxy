// ── 6盘（清真云）远程离线下载中继服务 v8 ───────────────────────────────
// 基于 halalcloud/golang-sdk-lite 逆向的 OpenAPI 完整实现
// 认证：HL6-HMAC-SHA256 签名 + Device Code 授权 + 自动 Token 刷新
// 协议：JSON REST
// ★ 请求：camelCase（protobuf JSON 规范）
// ★ 响应：兼容 camelCase 和 snake_case（因为不确定服务器用哪种格式）
// ─────────────────────────────────────────────────────────────────────

// ── 常量 ────────────────────────────────────────────────────────────
const SIGN_PREFIX = "HL6";
const REQUEST_SUFFIX = "hl6_request";
const SIGN_ALGORITHM = "HL6-HMAC-SHA256";
const API_HOST = "openapi.2dland.cn";
const API_BASE = `https://${API_HOST}`;

// ★ 6盘设备授权页面（fallback，如果服务器不返回 verificationUri）
const FALLBACK_VERIFICATION_URL = "https://static.2dland.cn/user/landing/";

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

// ── 响应字段兼容工具 ────────────────────────────────────────────────
// ★ 服务器可能返回 camelCase 或 snake_case，同时尝试两种
function getField(obj: Record<string, unknown>, camelName: string): unknown {
  const snakeName = camelName.replace(/[A-Z]/g, c => "_" + c.toLowerCase());
  return obj[camelName] ?? obj[snakeName] ?? undefined;
}

function getFieldStr(obj: Record<string, unknown>, camelName: string): string {
  return String(getField(obj, camelName) ?? "");
}

function getFieldNum(obj: Record<string, unknown>, camelName: string): number {
  const v = getField(obj, camelName);
  return typeof v === "number" ? v : (typeof v === "string" ? parseInt(String(v)) || 0 : 0);
}

function getFieldBool(obj: Record<string, unknown>, camelName: string): boolean {
  const v = getField(obj, camelName);
  return typeof v === "boolean" ? v : (v === "true" || v === 1);
}

// ── HL6-HMAC-SHA256 签名（支持空 AccessToken，用于 OAuth2 端点）───────
async function signRequest(
  method: string, apiPath: string, body: Uint8Array | null,
  accessToken: string, clientId: string, clientSecret: string,
  extraParams?: Record<string, string>,
): Promise<{ url: string; headers: Record<string, string> }> {
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
// ★ 返回解析后的 JSON 对象（兼容 camelCase/snake_case）
async function signedApiCall(
  method: string, apiPath: string,
  body?: Record<string, unknown>,
  params?: Record<string, string>,
): Promise<Record<string, unknown>> {
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
    if (refreshed) return signedApiCall(method, apiPath, body, params);
    throw new Error("Token 过期且刷新失败，请重新授权。访问 /auth");
  }

  if (resp.status < 200 || resp.status >= 300) {
    let errMsg = `HTTP ${resp.status}`;
    try { const errJson = JSON.parse(respText); errMsg += `: ${errJson.message || errJson.error || respText.substring(0, 200)}`; }
    catch { errMsg += `: ${respText.substring(0, 200)}`; }
    throw new Error(errMsg);
  }

  return JSON.parse(respText) as Record<string, unknown>;
}

// ── OAuth2 签名 API 调用（Client ID/Secret 签名，AccessToken 为空）─────
// ★ 返回 { parsed, raw } — parsed 是兼容 camelCase/snake_case 的对象，raw 是原始响应文本
async function oauthApiCall(
  method: string, apiPath: string,
  body?: Record<string, unknown>,
  params?: Record<string, string>,
): Promise<{ parsed: Record<string, unknown>; raw: string }> {
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

  const parsed = JSON.parse(respText) as Record<string, unknown>;
  return { parsed, raw: respText };
}

// ── Cookie 模式 API 调用（用于旧版 v3 API）─────────────────────────────
const V3_API = "https://api.2dland.cn/v3";
const V3_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

async function cookieApiCall(
  method: string, apiPath: string,
  body?: Record<string, unknown>,
  cookie?: string,
): Promise<Record<string, unknown>> {
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

  return JSON.parse(respText) as Record<string, unknown>;
}

// ── Token 管理 ──────────────────────────────────────────────────────

// ★ 刷新 Token — 兼容 camelCase/snake_case 响应字段
async function refreshAccessToken(): Promise<boolean> {
  if (!refreshToken) return false;
  try {
    const { parsed } = await oauthApiCall(
      "POST", "/v6/oauth/refresh_token",
      { refreshToken, grantType: "refresh_token", clientId: CLIENT_ID },
    );
    accessToken = getFieldStr(parsed, "accessToken");
    refreshToken = getFieldStr(parsed, "refreshToken");
    tokenExpiresAt = Date.now() + (getFieldNum(parsed, "expiresIn") || 3600) * 1000;
    console.log(`Token 刷新成功，有效期 ${getFieldNum(parsed, "expiresIn")} 秒`);
    return !!accessToken;
  } catch (err) {
    console.error("Token 刷新失败:", err);
    return false;
  }
}

async function ensureToken(): Promise<void> {
  if (accessToken && tokenExpiresAt > Date.now()) {
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

// ── Device Code 授权流程 ──────────────────────────────────────────────
// ★ 请求：camelCase（protobuf JSON 规范）
// ★ 响应：兼容 camelCase 和 snake_case
// ★ clientId 通过签名 Authorization 头传递，但也在请求体中（SDK 也这么做）

async function requestDeviceCode(): Promise<{
  userCode: string; deviceCode: string; verificationUri: string;
  expiresIn: number; interval: number; rawResponse: string;
}> {
  const { parsed, raw } = await oauthApiCall("POST", "/v6/oauth/device_code", {
    clientId: CLIENT_ID,
    device: "sixpan-relay-deno",
  });

  // ★ 兼容两种格式：verificationUri (camelCase) 和 verification_uri (snake_case)
  let verificationUri = getFieldStr(parsed, "verificationUri");
  if (!verificationUri) {
    // 服务器可能不返回此字段，使用 fallback
    verificationUri = FALLBACK_VERIFICATION_URL;
  }

  return {
    userCode: getFieldStr(parsed, "userCode"),
    deviceCode: getFieldStr(parsed, "deviceCode"),
    verificationUri,
    expiresIn: getFieldNum(parsed, "expiresIn") || 300,
    interval: getFieldNum(parsed, "interval") || 5,
    rawResponse: raw,
  };
}

// ★ 兼容两种格式的状态检查
async function checkDeviceCodeState(deviceCode: string): Promise<{
  login: boolean; accessToken: string; refreshToken: string;
  expiresIn: number; status: string; error: string;
  rawResponse: string; rawParsed: Record<string, unknown>;
}> {
  const { parsed, raw } = await oauthApiCall("POST", "/v6/oauth/get_device_code_state", {
    deviceCode,
  });

  return {
    login: getFieldBool(parsed, "login"),
    accessToken: getFieldStr(parsed, "accessToken"),
    refreshToken: getFieldStr(parsed, "refreshToken"),
    expiresIn: getFieldNum(parsed, "expiresIn"),
    status: getFieldStr(parsed, "status"),
    error: getFieldStr(parsed, "error"),
    rawResponse: raw,
    rawParsed: parsed,
  };
}

// ── 离线下载 API ────────────────────────────────────────────────────

async function openapiParseMagnet(magnetUrl: string): Promise<Record<string, unknown>> {
  return await signedApiCall("POST", "/v6/offline_task/parse", { url: magnetUrl });
}

async function openapiAddOfflineTask(
  magnetUrl: string, savePath: string, parseResult?: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const taskBody: Record<string, unknown> = {
    url: magnetUrl,
    savePath,
  };
  // ★ 兼容两种格式的 parse 结果
  const meta = parseResult?.meta as Record<string, unknown> | undefined;
  if (meta) {
    taskBody.name = getFieldStr(meta, "name") || "";
    taskBody.size = getFieldNum(meta, "size") || 0;
    taskBody.identity = getFieldStr(meta, "identity") || "";
    taskBody.type = getFieldNum(meta, "type") || 0;
  }
  return await signedApiCall("POST", "/v6/offline_task/add", taskBody);
}

async function openapiListOfflineTasks(): Promise<Record<string, unknown>> {
  return await signedApiCall("POST", "/v6/offline_task/list", {
    listInfo: { limit: 20, version: 0 },
  });
}

async function cookieParseMagnet(magnetUrl: string): Promise<Record<string, unknown>> {
  return await cookieApiCall("POST", "/offline/parse", { url: magnetUrl, ts: Math.floor(Date.now() / 1000) });
}

async function cookieAddOfflineTask(
  infoHash: string, saveTo: string, fileName: string,
  fileCount: number, fileSize: number, fileList: string,
): Promise<Record<string, unknown>> {
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
      let parseResult: Record<string, unknown> | undefined;
      try { parseResult = await openapiParseMagnet(magnetUrl); }
      catch (e) { console.log("OpenAPI Parse 失败（不影响 Add）:", e); }
      const addResult = await openapiAddOfflineTask(magnetUrl, savePath, parseResult);
      return jsonResponse({
        success: true, mode: "openapi", message: "离线任务已提交 ✅", task: addResult,
      });
    } catch (err) {
      console.log("OpenAPI 失败，尝试 Cookie:", err);
      if (MANUAL_COOKIE || cookieCache) {
        try {
          const parseResult = await cookieParseMagnet(magnetUrl);
          const pr = parseResult as Record<string, unknown>;
          const meta = (pr.meta ?? pr) as Record<string, unknown>;
          const infoHash = getFieldStr(meta, "identity") || getFieldStr(pr, "infoHash");
          const fileName = getFieldStr(meta, "name") || getFieldStr(pr, "fileName");
          const fileCount = getFieldNum(pr, "fileCount") || 0;
          const fileSize = getFieldNum(meta, "size") || getFieldNum(pr, "fileSize") || 0;
          const fileList = getFieldStr(pr, "fileList");
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
      const pr = parseResult as Record<string, unknown>;
      const meta = (pr.meta ?? pr) as Record<string, unknown>;
      const infoHash = getFieldStr(meta, "identity") || getFieldStr(pr, "infoHash");
      const fileName = getFieldStr(meta, "name") || getFieldStr(pr, "fileName");
      const fileCount = getFieldNum(pr, "fileCount") || 0;
      const fileSize = getFieldNum(meta, "size") || getFieldNum(pr, "fileSize") || 0;
      const fileList = getFieldStr(pr, "fileList");
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

  // Step 1: 申请设备授权码
  if (action === "start") {
    try {
      const deviceCodeResp = await requestDeviceCode();
      return jsonResponse({
        step: 1,
        message: "请在浏览器/手机打开以下链接，输入验证码授权",
        verificationUri: deviceCodeResp.verificationUri,
        userCode: deviceCodeResp.userCode,
        deviceCode: deviceCodeResp.deviceCode,
        expiresIn: deviceCodeResp.expiresIn,
        interval: deviceCodeResp.interval,
        hint: `授权后，访问 /auth?action=poll&device_code=${deviceCodeResp.deviceCode} 自动等待授权完成`,
        // ★ 包含原始响应，方便调试字段名格式
        rawResponse: deviceCodeResp.rawResponse,
        isFallbackUrl: deviceCodeResp.verificationUri === FALLBACK_VERIFICATION_URL,
      });
    } catch (err) {
      return jsonResponse({
        error: "获取设备授权码失败",
        detail: err instanceof Error ? err.message : String(err),
        envCheck: {
          hasClientId: !!CLIENT_ID,
          hasClientSecret: !!CLIENT_SECRET,
          clientIdPrefix: CLIENT_ID ? CLIENT_ID.substring(0, 8) + "***" : "未设置",
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
  .debug { background: #e9ecef; padding: 10px; border-radius: 6px; font-size: 12px; max-height: 200px; overflow: auto; }
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
  <div id="failDebug" class="debug"></div>
  <a href="/auth">重新授权 →</a>
</div>

<script>
const deviceCode = "${deviceCode}";
let attempts = 0;
const maxAttempts = 60;

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

    if (data.error && data.status !== 'pending') {
      document.getElementById('waiting').classList.add('hidden');
      document.getElementById('fail').classList.remove('hidden');
      document.getElementById('failMsg').textContent = data.error + (data.detail ? ' — ' + data.detail : '');
      if (data.rawResponse) {
        document.getElementById('failDebug').textContent = '原始响应: ' + data.rawResponse;
      }
      document.querySelector('.spinner').style.display = 'none';
      return;
    }
  } catch (err) {
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

      // 方式 1：login=true 且有 Token
      if (state.login && state.accessToken && state.refreshToken) {
        accessToken = state.accessToken;
        refreshToken = state.refreshToken;
        tokenExpiresAt = Date.now() + (state.expiresIn || 3600) * 1000;
        return jsonResponse({ success: true, login: true, message: "授权成功 ✅ Token 已保存" });
      }

      // 方式 2：status=AUTHORIZATION_SUCCESS，可能有 Token
      if (state.status === "AUTHORIZATION_SUCCESS") {
        if (state.accessToken) {
          accessToken = state.accessToken;
          refreshToken = state.refreshToken || "";
          tokenExpiresAt = Date.now() + (state.expiresIn || 3600) * 1000;
          return jsonResponse({ success: true, login: true, message: "授权成功 ✅ Token 已保存" });
        }
        // Token 为空
        return jsonResponse({
          success: false,
          status: state.status,
          login: state.login,
          message: "授权已成功，但响应中没有 Token（可能是服务器问题）",
          rawResponse: state.rawResponse,
          rawParsed: state.rawParsed,
        }, 500);
      }

      // 方式 3：有 error
      if (state.error) {
        return jsonResponse({
          success: false, login: false, error: state.error,
          rawResponse: state.rawResponse,
        });
      }

      // 还未授权
      return jsonResponse({
        success: false, login: false, status: state.status || "pending",
        message: "尚未授权，请先在浏览器完成授权",
        rawResponse: state.rawResponse,
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
  .fallback-note { background: #fff3cd; padding: 8px; border-radius: 4px; margin: 8px 0; }
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
  <div id="fallbackNote" class="fallback-note" style="display:none">
    ⚠️ 服务器没有返回授权网址，使用默认地址。请在 <a href="${FALLBACK_VERIFICATION_URL}" target="_blank">${FALLBACK_VERIFICATION_URL}</a> 页面输入验证码。
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

    if (data.deviceCode) {
      document.getElementById('pollSection').style.display = 'block';

      if (data.isFallbackUrl) {
        document.getElementById('fallbackNote').style.display = 'block';
        document.getElementById('pollStatus').textContent =
          '请在浏览器打开 ' + data.verificationUri + ' 输入验证码 ' + data.userCode + '（注意：此网址为默认地址，非服务器返回）';
      } else {
        document.getElementById('pollStatus').textContent =
          '请在浏览器打开 ' + data.verificationUri + ' 输入验证码 ' + data.userCode;
      }
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
    if (data.deviceCode) {
      window.open('/auth?action=poll&device_code=' + data.deviceCode, '_blank');
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
    version: "v8 — 双格式响应兼容 + 原始响应调试",
  };

  // ★ 测试 device_code 端点 — 显示完整原始响应
  try {
    const { parsed, raw } = await oauthApiCall("POST", "/v6/oauth/device_code", {
      clientId: CLIENT_ID,
      device: "debug-test",
    });
    result.deviceCodeTest = {
      success: true,
      rawResponse: raw,
      parsedFields: {
        userCode: getFieldStr(parsed, "userCode"),
        deviceCode: getFieldStr(parsed, "deviceCode"),
        verificationUri: getFieldStr(parsed, "verificationUri"),
        expiresIn: getFieldNum(parsed, "expiresIn"),
        interval: getFieldNum(parsed, "interval"),
      },
    };
  } catch (err) {
    result.deviceCodeTest = {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
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
<h1>6盘（清真云）离线下载中继 v8</h1>
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
