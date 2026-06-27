/**
 * 6盘（清真云/2dland）远程离线下载中继服务
 * 支持用户名密码自动登录，Cookie 过期后自动刷新
 *
 * 部署：Deno Deploy (console.deno.com) — Deno 1.40+
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
interface CachedCookie {
  value: string;
  expires: number;
}

let cookieCache: CachedCookie | null = null;

// ── 6盘登录（逆向自 6盘小白羊 Go 源码）─────────────────────

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
  });

  const loginJson = await loginResp.json() as any;
  if (!loginJson.success) {
    throw new Error(`登录失败: ${loginJson.message || "未知错误"}`);
  }

  // 收集所有 set-cookie 头
  const allSetCookies: string[] = [];
  for (const [key, value] of loginResp.headers.entries()) {
    if (key.toLowerCase() === "set-cookie") {
      allSetCookies.push(value);
    }
  }

  let loginStatusValue: string | null = null;
  for (const cookie of allSetCookies) {
    const m = cookie.match(/login-status=([^;]+)/);
    if (m) { loginStatusValue = m[1]; break; }
  }

  if (!loginStatusValue) {
    throw new Error("登录响应中未找到 login-status cookie，请检查账号密码");
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
  });

  // 收集 checkCookie 响应的 set-cookie
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

  // 如果没拿到，跟随重定向再试
  if (!tokenValue || !tokenSigValue) {
    const followResp = await fetch(checkUrl, {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        "Referer": referer,
        "Cookie": `login-status=${loginStatusValue}`,
      },
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

  return `locale=zh-cn; token=${tokenValue}; token.sig=${tokenSigValue}`;
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
    const json = await resp.json() as any;
    return !!json.identity;
  } catch {
    return false;
  }
}

/** 获取有效 Cookie（自动刷新） */
async function getCookie(): Promise<string> {
  const user       = Deno.env.get("SIXPAN_USER");
  const passMd5    = Deno.env.get("SIXPAN_PASS_MD5");
  const manualCookie = Deno.env.get("SIXPAN_COOKIE");

  // 模式 1：直接提供 Cookie
  if (manualCookie) {
    if (await verifyCookie(manualCookie)) return manualCookie;
    throw new Error("SIXPAN_COOKIE 已过期，请更新");
  }

  // 模式 2：自动登录
  if (!user || !passMd5) {
    throw new Error(
      "请配置环境变量：\n" +
      "  方式① SIXPAN_USER + SIXPAN_PASS_MD5（自动登录，推荐）\n" +
      "  方式② SIXPAN_COOKIE（手动提供 Cookie）\n" +
      "密码 MD5 计算：echo -n 密码 | md5sum"
    );
  }

  // 检查缓存
  if (cookieCache && cookieCache.expires > Date.now()) {
    const valid = await verifyCookie(cookieCache.value);
    if (valid) return cookieCache.value;
    console.log("Cookie 缓存已失效，重新登录...");
  }

  console.log(`正在以 ${user} 登录 6盘...`);
  const newCookie = await loginSixPan(user, passMd5);

  cookieCache = {
    value: newCookie,
    expires: Date.now() + 25 * 24 * 60 * 60 * 1000,
  };

  console.log("登录成功，Cookie 已缓存");
  return newCookie;
}

// ── 离线下载 API ────────────────────────────────────────────────

async function parseMagnet(magnet: string, cookie: string): Promise<any> {
  const resp = await fetch(`${SIXPAN_API}/offline/parse`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
      "Cookie": cookie,
    },
    body: JSON.stringify({ url: magnet, ts: Math.floor(Date.now() / 1000) }),
  });
  return await resp.json();
}

async function addOfflineTask(
  infoHash: string, saveTo: string, fileName: string,
  fileCount: number, fileSize: number, fileList: string,
  cookie: string,
): Promise<any> {
  const resp = await fetch(`${SIXPAN_API}/offline/add`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
      "Cookie": cookie,
    },
    body: JSON.stringify({ infoHash, saveTo, fileName, fileCount, fileSize, fileList, ts: Math.floor(Date.now() / 1000) }),
  });
  return await resp.json();
}

async function listOfflineTasks(cookie: string): Promise<any> {
  const resp = await fetch(`${SIXPAN_API}/offline/list`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
      "Cookie": cookie,
    },
    body: JSON.stringify({ ts: Math.floor(Date.now() / 1000) }),
  });
  return await resp.json();
}

// ── HTTP 处理 ──────────────────────────────────────────────────

function jsonResponse(data: any, status = 200): Response {
  return new Response(JSON.stringify(data), {
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
  catch { return jsonResponse({ success: false, error: "无效的 JSON" }, 400); }

  const magnet = body.magnet || body.url || "";
  if (!magnet) return jsonResponse({ success: false, error: "缺少 magnet 字段" }, 400);

  const saveTo = body.saveTo || new URL(request.url).searchParams.get("saveTo") || Deno.env.get("SIXPAN_SAVE_TO") || "/All/";

  try {
    const cookie = await getCookie();
    const parseResult = await parseMagnet(magnet, cookie) as any;

    if (!parseResult.success || !parseResult.data) {
      return jsonResponse({ success: false, error: parseResult.message || "解析磁力链失败" }, 400);
    }

    const { infoHash, name, files } = parseResult.data;
    const fileCount = files?.length || 0;
    const fileSize = files?.reduce((s: number, f: any) => s + (f.size || 0), 0) || 0;
    const fileList = files?.map((f: any) => f.name).join(",") || "";

    const addResult = await addOfflineTask(infoHash, saveTo, name, fileCount, fileSize, fileList, cookie) as any;

    if (!addResult.success) {
      return jsonResponse({ success: false, error: addResult.message || "提交离线任务失败" }, 400);
    }

    return jsonResponse({
      success: true,
      taskId: addResult.taskId || addResult.data?.taskId,
      name, infoHash, fileCount, fileSize, saveTo,
      message: "离线下载任务已提交 ✅",
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("Cookie") || msg.includes("过期") || msg.includes("登录")) cookieCache = null;
    return jsonResponse({ success: false, error: msg }, 500);
  }
}

async function handleStatus(request: Request): Promise<Response> {
  if (!authCheck(request)) return jsonResponse({ success: false, error: "鉴权失败" }, 401);
  try {
    const cookie = await getCookie();
    const valid = await verifyCookie(cookie);
    return jsonResponse({
      success: true, cookieValid: valid,
      cookieExpires: cookieCache ? new Date(cookieCache.expires).toISOString() : null,
      mode: Deno.env.get("SIXPAN_COOKIE") ? "manual-cookie" : "auto-login",
      user: Deno.env.get("SIXPAN_USER") || null,
    });
  } catch (err) {
    return jsonResponse({ success: false, error: err instanceof Error ? err.message : String(err) }, 500);
  }
}

async function handleManualLogin(request: Request): Promise<Response> {
  if (!authCheck(request)) return jsonResponse({ success: false, error: "鉴权失败" }, 401);
  cookieCache = null;
  try {
    const cookie = await getCookie();
    const valid = await verifyCookie(cookie);
    return jsonResponse({ success: true, message: "重新登录成功 ✅", cookieValid: valid });
  } catch (err) {
    return jsonResponse({ success: false, error: err instanceof Error ? err.message : String(err) }, 500);
  }
}

async function handleListTasks(request: Request): Promise<Response> {
  if (!authCheck(request)) return jsonResponse({ success: false, error: "鉴权失败" }, 401);
  try {
    const cookie = await getCookie();
    const result = await listOfflineTasks(cookie);
    return jsonResponse(result);
  } catch (err) {
    return jsonResponse({ success: false, error: err instanceof Error ? err.message : String(err) }, 500);
  }
}

// ── 路由（Deno.serve 模式，兼容 console.deno.com）────────────

async function handler(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/add" && request.method === "POST") return await handleAdd(request);
  if (path === "/status" && request.method === "GET") return await handleStatus(request);
  if (path === "/login" && request.method === "POST") return await handleManualLogin(request);
  if (path === "/tasks" && request.method === "GET") return await handleListTasks(request);
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
    <div class="status" id="statusBox"><b>服务状态：</b><span id="statusText">检测中...</span></div>
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
          result.textContent = '✅ 提交成功！\\n任务ID: ' + data.taskId + '\\n文件名: ' + data.name + '\\n保存位置: ' + data.saveTo;
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
