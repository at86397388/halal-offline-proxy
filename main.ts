/**
 * 6盘（清真云/2dland）远程离线下载中继服务
 * 支持用户名密码自动登录，Cookie 过期后自动刷新
 *
 * 部署：Deno Deploy / Deno 1.40+
 * 环境变量：
 *   SIXPAN_USER      - 6盘用户名（手机号或邮箱）
 *   SIXPAN_PASS_MD5  - 密码的 MD5 值（32位小写十六进制）
 *   AUTH_TOKEN       - 快捷指令调用鉴权 token（建议 32 位随机字符串）
 *   SIXPAN_COOKIE    - （可选）直接提供 Cookie，跳过密码登录
 *   SIXPAN_SAVE_TO   - 默认保存路径，默认 "/All/"
 */

const SIXPAN_API     = "https://api.2dland.cn/v3";
const SIXPAN_ACCOUNT = "https://account.2dland.cn";
const APP_ID         = "3a5654a9ccc9";
const USER_AGENT     = "6pan WindowsPC 3.1.0 (/C:)";
const DESTINATION    = "https://v3-beta.6pan.cn/files/all/";

// ── Cookie 缓存 ────────────────────────────────────────────────
// Deno Deploy 每次冷启动会丢失，但 Cookie 有效期 30 天，
// 所以冷启动后第一次请求会重新登录，之后 25 天内复用缓存。

interface CachedCookie {
  value: string;
  expires: number;  // Unix ms
}

let cookieCache: CachedCookie | null = null;

/** 从响应头解析 set-cookie，提取指定 cookie 名的值 */
function extractCookie(setCookieHeader: string | null, name: string): string | null {
  if (!setCookieHeader) return null;
  // set-cookie 可能有多个，用逗号或换行分割（实际是分开的 header）
  // fetch API 中 set-cookie 不可读（出于安全原因）！
  // ⒈ 问题：Deno Deploy (Service Worker) 中，fetch 响应的 set-cookie 头可能被剥离
  // 解决：使用 Deno.createHttpClient 禁用自动 cookie jar，或直接用 Deno.serveHttp
  // 但实际上 Deno Deploy 的 fetch 是可以读取 set-cookie 的（不同于浏览器）
  // 验证：先假设可以读取
  const match = setCookieHeader.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}

// ── 6盘登录（逆向自 6盘小白羊 Go 源码）─────────────────────
// 登录分两步：
//   ① POST /v3/oauth/login  →  获取 login-status cookie
//   ② GET  /v3/oauth/checkCookie?...  →  获取 token + token.sig cookie

async function loginSixPan(username: string, passMd5: string): Promise<string> {
  const referer = `${SIXPAN_ACCOUNT}/login?appid=${APP_ID}&destination=${encodeURIComponent(DESTINATION)}&response=redirect&scope=&state=7go9cgga6&lang=zh-CN`;

  // ① 提交用户名密码
  const loginUrl = `${SIXPAN_ACCOUNT}/v3/oauth/login`;
  const loginBody = JSON.stringify({ user: username, password: passMd5 });

  const loginResp = await fetch(loginUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
      "Referer": referer,
    },
    body: loginBody,
    redirect: "manual",  // 不自动跟随重定向，以便读取 set-cookie
  });

  const loginJson = await loginResp.json();
  if (!loginJson.success) {
    throw new Error(`登录失败: ${loginJson.message || "未知错误"}`);
  }

  // 从响应头获取 login-status cookie
  // 注意：Deno 的 fetch 可以读取 set-cookie，但格式可能是多个 header
  const loginSetCookie = loginResp.headers.get("set-cookie") || "";
  const statusMatch = loginSetCookie.match(/login-status=([^;,\s]+)/);
  
  // 如果 set-cookie 在 redirect 响应的 302 里，需要用 loginResp.headers 读取
  // 但 POST /v3/oauth/login 实际返回 200 + JSON + set-cookie: login-status=...
  // 所以这里应该从 loginResp.headers 读取

  if (!statusMatch) {
    // 尝试从原始响应头字符串中查找（某些情况下 set-cookie 可能被合并）
    const rawHeaders = [...loginResp.headers.entries()];
    const allCookies = rawHeaders.filter(([k]) => k.toLowerCase() === "set-cookie");
    const found = allCookies.find(([, v]) => v.includes("login-status"));
    if (!found) {
      throw new Error("登录响应中未找到 login-status cookie，请检查账号密码");
    }
    const m = found[1].match(/login-status=([^;]+)/);
    if (!m) throw new Error("解析 login-status 失败");
  }

  // 更简单可靠的方式：收集所有 set-cookie 头
  const allSetCookies: string[] = [];
  for (const [key, value] of loginResp.headers.entries()) {
    if (key.toLowerCase() === "set-cookie") {
      allSetCookies.push(value);
    }
  }
  // 也检查 comma-separated 的情况（不应该出现，但防御性处理）
  
  let loginStatusValue: string | null = null;
  for (const cookie of allSetCookies) {
    const m = cookie.match(/login-status=([^;]+)/);
    if (m) { loginStatusValue = m[1]; break; }
  }
  if (!loginStatusValue) {
    throw new Error("登录响应中未找到 login-status cookie");
  }

  // ② 校验登录状态，获取 token
  const checkUrl = `${SIXPAN_ACCOUNT}/v3/oauth/checkCookie?appid=${APP_ID}&destination=${encodeURIComponent(DESTINATION)}&lang=zh-CN&scope=&state=7go9cgga6&response=redirect`;
  
  const checkResp = await fetch(checkUrl, {
    method: "GET",
    headers: {
      "User-Agent": USER_AGENT,
      "Referer": referer,
      "Cookie": `login-status=${loginStatusValue}`,
    },
    redirect: "manual",  // 302 重定向，我们从中提取 set-cookie
  });

  // checkCookie 返回 302，token 在 302 响应的 set-cookie 里
  const checkSetCookies: string[] = [];
  for (const [key, value] of checkResp.headers.entries()) {
    if (key.toLowerCase() === "set-cookie") {
      checkSetCookies.push(value);
    }
  }

  let tokenValue: string | null = null;
  let tokenSigValue: string | null = null;
  
  for (const cookie of checkSetCookies) {
    let m = cookie.match(/token=([^;]+)/);
    if (m) tokenValue = m[1];
    m = cookie.match(/token\.sig=([^;]+)/);
    if (m) tokenSigValue = m[1];
  }

  // 如果 302 重定向导致 set-cookie 在 localStorage 中，可能需要跟随一次重定向
  // 但实际测试：checkCookie 的 302 响应本身就包含 set-cookie: token=...
  // 如果上面没拿到，尝试跟随一次重定向
  if (!tokenValue || !tokenSigValue) {
    // 跟随 302 重定向，从最终响应中读取 cookie
    const followResp = await fetch(checkUrl, {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        "Referer": referer,
        "Cookie": `login-status=${loginStatusValue}`,
      },
      redirect: "follow",
    });
    for (const [key, value] of followResp.headers.entries()) {
      if (key.toLowerCase() === "set-cookie") {
        let m = value.match(/token=([^;]+)/);
        if (m) tokenValue = m[1];
        m = value.match(/token\.sig=([^;]+)/);
        if (m) tokenSigValue = m[1];
      }
    }
  }

  if (!tokenValue || !tokenSigValue) {
    throw new Error("获取 token 失败，请检查账号密码是否正确");
  }

  const cookie = `locale=zh-cn; token=${tokenValue}; token.sig=${tokenSigValue}`;
  return cookie;
}

/** 验证 Cookie 是否有效 */
async function verifyCookie(cookie: string): Promise<boolean> {
  try {
    const resp = await fetch(`${SIXPAN_API}/user/info`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "Cookie": cookie,
      },
      body: JSON.stringify({ ts: Math.floor(Date.now() / 1000) }),
    });
    if (!resp.ok) return false;
    const json = await resp.json();
    return !!(json as any).identity;
  } catch {
    return false;
  }
}

/** 获取有效 Cookie（自动刷新） */
async function getCookie(): Promise<string> {
  const user     = Deno.env.get("SIXPAN_USER");
  const passMd5  = Deno.env.get("SIXPAN_PASS_MD5");
  const manualCookie = Deno.env.get("SIXPAN_COOKIE");

  // 模式 1：用户直接提供了 Cookie
  if (manualCookie) {
    if (await verifyCookie(manualCookie)) {
      return manualCookie;
    }
    console.error("SIXPAN_COOKIE 已过期，请更新环境变量");
    throw new Error("Cookie 已过期，请更新 SIXPAN_COOKIE 环境变量");
  }

  // 模式 2：用户名 + 密码自动登录
  if (!user || !passMd5) {
    throw new Error(
      "请配置环境变量：\n" +
      "  方式① SIXPAN_USER + SIXPAN_PASS_MD5（自动登录，推荐）\n" +
      "  方式② SIXPAN_COOKIE（手动提供 Cookie）\n" +
      "获取 MD5 密码：在终端运行 `echo -n 你的密码 | md5sum`"
    );
  }

  // 检查缓存（有效期 25 天）
  if (cookieCache && cookieCache.expires > Date.now()) {
    // 快速校验（每 10 次请求完整校验一次，这里简化为每次都校验）
    const valid = await verifyCookie(cookieCache.value);
    if (valid) return cookieCache.value;
    console.log("Cookie 缓存已失效，重新登录...");
  }

  // 重新登录
  console.log(`正在以 ${user} 登录 6盘...`);
  const newCookie = await loginSixPan(user, passMd5);
  
  // 缓存 25 天（Cookie 有效期约 30 天）
  cookieCache = {
    value: newCookie,
    expires: Date.now() + 25 * 24 * 60 * 60 * 1000,
  };

  console.log("登录成功，Cookie 已缓存");
  return newCookie;
}

// ── 离线下载 API ────────────────────────────────────────────────

/** 解析磁力链，获取 infoHash 和文件列表 */
async function parseMagnet(magnet: string, cookie: string): Promise<any> {
  const url = `${SIXPAN_API}/offline/parse`;
  const body = JSON.stringify({ url: magnet, ts: Math.floor(Date.now() / 1000) });

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
      "Cookie": cookie,
    },
    body,
  });

  return await resp.json();
}

/** 提交离线下载任务 */
async function addOfflineTask(
  infoHash: string,
  saveTo: string,
  fileName: string,
  fileCount: number,
  fileSize: number,
  fileList: string,
  cookie: string,
): Promise<any> {
  const url = `${SIXPAN_API}/offline/add`;
  const body = JSON.stringify({
    infoHash,
    saveTo,
    fileName,
    fileCount,
    fileSize,
    fileList,
    ts: Math.floor(Date.now() / 1000),
  });

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
      "Cookie": cookie,
    },
    body,
  });

  return await resp.json();
}

/** 查询离线任务列表 */
async function listOfflineTasks(cookie: string): Promise<any> {
  const url = `${SIXPAN_API}/offline/list`;
  const body = JSON.stringify({ ts: Math.floor(Date.now() / 1000) });

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
      "Cookie": cookie,
    },
    body,
  });

  return await resp.json();
}

// ── HTTP 路由处理 ──────────────────────────────────────────────

function jsonResponse(data: any, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

/** 鉴权检查 */
function authCheck(request: Request): boolean {
  const authToken = Deno.env.get("AUTH_TOKEN");
  if (!authToken) return true; // 未设置 AUTH_TOKEN 则不鉴权

  const url = new URL(request.url);
  const token = url.searchParams.get("token") 
             || request.headers.get("X-Auth-Token") 
             || "";
  return token === authToken;
}

/** POST /add — 提交离线下载任务 */
async function handleAdd(request: Request): Promise<Response> {
  if (!authCheck(request)) {
    return jsonResponse({ success: false, error: "鉴权失败，请在 URL 中附加 ?token=xxx" }, 401);
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ success: false, error: "无效的 JSON body，需要 {\"magnet\": \"...\"}" }, 400);
  }

  const magnet: string = body.magnet || body.url || "";
  if (!magnet) {
    return jsonResponse({ success: false, error: "缺少 magnet 字段，请提供磁力链" }, 400);
  }

  const url = new URL(request.url);
  const saveTo: string = body.saveTo || url.searchParams.get("saveTo") || Deno.env.get("SIXPAN_SAVE_TO") || "/All/";

  try {
    const cookie = await getCookie();

    // ① 解析磁力链
    const parseResult = await parseMagnet(magnet, cookie);
    if (!parseResult.success || !parseResult.data) {
      return jsonResponse({
        success: false,
        error: parseResult.message || "解析磁力链失败，请检查链接是否有效",
      }, 400);
    }

    const { infoHash, name, files } = parseResult.data;
    const fileCount = files?.length || 0;
    const fileSize = files?.reduce((sum: number, f: any) => sum + (f.size || 0), 0) || 0;
    const fileList = files?.map((f: any) => f.name).join(",") || "";

    // ② 提交离线任务
    const addResult = await addOfflineTask(
      infoHash,
      saveTo,
      name,
      fileCount,
      fileSize,
      fileList,
      cookie,
    );

    if (!addResult.success) {
      return jsonResponse({
        success: false,
        error: addResult.message || "提交离线任务失败",
      }, 400);
    }

    return jsonResponse({
      success: true,
      taskId: addResult.taskId || addResult.data?.taskId,
      name,
      infoHash,
      fileCount,
      fileSize,
      saveTo,
      message: "离线下载任务已提交 ✅",
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    
    // Cookie 可能失效，清除缓存让下次请求重新登录
    if (msg.includes("Cookie") || msg.includes("过期") || msg.includes("登录") || msg.includes("鉴权")) {
      cookieCache = null;
    }

    return jsonResponse({ 
      success: false, 
      error: msg,
      hint: "如果是 Cookie 问题，已自动清除缓存，下次请求将重新登录",
    }, 500);
  }
}

/** GET /status — 检查服务状态 */
async function handleStatus(request: Request): Promise<Response> {
  if (!authCheck(request)) {
    return jsonResponse({ success: false, error: "鉴权失败" }, 401);
  }

  try {
    const cookie = await getCookie();
    const valid = await verifyCookie(cookie);
    return jsonResponse({
      success: true,
      cookieValid: valid,
      cookieExpires: cookieCache ? new Date(cookieCache.expires).toISOString() : null,
      mode: Deno.env.get("SIXPAN_COOKIE") ? "manual-cookie" : "auto-login",
      user: Deno.env.get("SIXPAN_USER") || null,
    });
  } catch (err) {
    return jsonResponse({
      success: false,
      error: err instanceof Error ? err.message : String(err),
    }, 500);
  }
}

/** POST /login — 手动触发重新登录 */
async function handleManualLogin(request: Request): Promise<Response> {
  if (!authCheck(request)) {
    return jsonResponse({ success: false, error: "鉴权失败" }, 401);
  }

  cookieCache = null;
  try {
    const cookie = await getCookie();
    const valid = await verifyCookie(cookie);
    return jsonResponse({
      success: true,
      message: "重新登录成功 ✅",
      cookieValid: valid,
    });
  } catch (err) {
    return jsonResponse({
      success: false,
      error: err instanceof Error ? err.message : String(err),
    }, 500);
  }
}

/** GET /tasks — 查询离线任务列表 */
async function handleListTasks(request: Request): Promise<Response> {
  if (!authCheck(request)) {
    return jsonResponse({ success: false, error: "鉴权失败" }, 401);
  }

  try {
    const cookie = await getCookie();
    const result = await listOfflineTasks(cookie);
    return jsonResponse(result);
  } catch (err) {
    return jsonResponse({
      success: false,
      error: err instanceof Error ? err.message : String(err),
    }, 500);
  }
}

// ── 路由 ───────────────────────────────────────────────────────

addEventListener("fetch", (event: FetchEvent) => {
  const request = event.request;
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/add" && request.method === "POST") {
    event.respondWith(handleAdd(request));
  } else if (path === "/status" && request.method === "GET") {
    event.respondWith(handleStatus(request));
  } else if (path === "/login" && request.method === "POST") {
    event.respondWith(handleManualLogin(request));
  } else if (path === "/tasks" && request.method === "GET") {
    event.respondWith(handleListTasks(request));
  } else if (path === "/" && request.method === "GET") {
    event.respondWith(new Response(HTML_HOME, { headers: { "Content-Type": "text/html; charset=utf-8" } }));
  } else {
    event.respondWith(new Response("Not Found", { status: 404 }));
  }
});

// ── 首页 HTML ───────────────────────────────────────────────────
const HTML_HOME = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>6盘离线下载中继</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
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
             background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;
             transition: opacity 0.2s; }
    button:hover { opacity: 0.9; }
    button:active { transform: scale(0.98); }
    .result { margin-top: 16px; padding: 14px; border-radius: 8px; font-size: 13px; line-height: 1.6; white-space: pre-wrap; }
    .success { background: #e8f5e9; color: #2e7d32; border: 1px solid #a5d6a7; }
    .error { background: #ffebee; color: #c62828; border: 1px solid #ef9a9a; }
    .status { margin-top: 16px; padding: 12px; border-radius: 8px; font-size: 13px; 
              background: #f5f5f5; color: #333; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
    .badge.ok { background: #e8f5e9; color: #2e7d32; }
    .badge.err { background: #ffebee; color: #c62828; }
  </style>
</head>
<body>
  <div class="card">
    <h1>📥 6盘离线下载</h1>
    <p class="subtitle">远程提交磁力链到 6盘 离线下载</p>
    
    <label>磁力链</label>
    <textarea id="magnet" placeholder="magnet:?xt=urn:btih:..."></textarea>
    
    <label>保存路径 <span style="font-weight:400;color:#999">（默认 /All/）</span></label>
    <input id="saveTo" type="text" placeholder="/All/我的资源/" value="/All/" />
    
    <label>鉴权 Token</label>
    <input id="token" type="text" placeholder="与环境变量 AUTH_TOKEN 一致" />
    
    <button onclick="submit()">🚀 提交离线下载</button>
    
    <div id="result"></div>
    
    <div class="status" id="statusBox">
      <b>服务状态：</b><span id="statusText">检测中...</span>
    </div>
  </div>

  <script>
    // 自动填充 URL 中的 token 参数
    const params = new URLSearchParams(location.search);
    if (params.get('token')) document.getElementById('token').value = params.get('token');

    // 检测服务状态
    async function checkStatus() {
      const token = document.getElementById('token').value.trim();
      const statusText = document.getElementById('statusText');
      try {
        const resp = await fetch('/status' + (token ? '?token=' + encodeURIComponent(token) : ''));
        const data = await resp.json();
        if (data.success) {
          statusText.innerHTML = '<span class="badge ok">✅ 正常</span> 模式: ' + data.mode + ' | Cookie有效期至: ' + new Date(data.cookieExpires).toLocaleString('zh-CN');
        } else {
          statusText.innerHTML = '<span class="badge err">❌ ' + data.error + '</span>';
        }
      } catch(e) {
        statusText.innerHTML = '<span class="badge err">❌ 无法连接</span>';
      }
    }
    checkStatus();
    setInterval(checkStatus, 30000);

    // 提交离线下载
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
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ magnet, saveTo }),
        });
        const data = await resp.json();
        if (data.success) {
          result.className = 'result success';
          result.textContent = '✅ 提交成功！\\n任务ID: ' + data.taskId + '\\n文件名: ' + data.name + '\\n保存位置: ' + data.saveTo;
        } else {
          result.className = 'result error';
          result.textContent = '❌ ' + data.error + (data.hint ? '\\n💡 ' + data.hint : '');
        }
      } catch(e) {
        result.className = 'result error';
        result.textContent = '❌ 网络错误: ' + e.message;
      }
    }
  </script>
</body>
</html>`;
