/**
 * 6盘（清真云）050.003 离线下载中转服务
 * 适配 iOS 快捷指令 + Deno Deploy
 * 支持快捷指令传 `url`（单数文本）或 `urls`（数组）两种格式
 */

export default {
  async fetch(req: Request): Promise<Response> {
    // 只允许 POST 请求
    if (req.method !== "POST") {
      return new Response("仅支持 POST 请求", { status: 405 });
    }

    // ==================== 环境变量校验（必填）====================
    const CLIENT_ID = Deno.env.get("CLIENT_ID");
    const CLIENT_SECRET = Deno.env.get("CLIENT_SECRET");
    if (!CLIENT_ID || !CLIENT_SECRET) {
      return new Response(
        JSON.stringify({
          error: "请在 Deno Deploy 控制台配置环境变量：CLIENT_ID、CLIENT_SECRET",
        }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      );
    }

    // ==================== 6盘 050.003 接口配置 ====================
    // 用网页版同域接口，避免跨域/404问题（如果还404，参考下方备选地址）
    const BASE = "https://grpcuserapi.2dland.cn";
    const API_PATH = "/v6.services.pub.PubOfflineTask/Add"; 
    // 备选接口地址（如果上面404，依次尝试）：
    // const API_PATH = "/v6.services.pub.PubOfflineTask/Add";
    // const BASE = "https://openapi.2dland.cn"; const API_PATH = "/v6.services.pub.PubOfflineTask/Add";
    // const BASE = "https://grpcuserapi.2dland.cn"; const API_PATH = "/v6.services.pub.PubOfflineTask/Add";

    // ==================== 解析快捷指令请求 ====================
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ error: "快捷指令请求体 JSON 格式错误" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // 兼容两种传参方式：url（单数）或 urls（数组），统一转成 url 单数
    let url: string;
    if (typeof body.url === "string") {
      url = body.url; // 快捷指令传 { "url": "剪贴板内容" }
    } else if (Array.isArray(body.urls) && typeof body.urls[0] === "string") {
      url = body.urls[0]; // 快捷指令传 { "urls": ["剪贴板内容"] }
    } else {
      return new Response(
        JSON.stringify({
          error: "快捷指令请求体必须包含 url（文本）或 urls（数组），例如：{ \"url\": \"链接\" }",
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    const save_to = (body.save_to as string) || "/"; // 默认存6盘根目录
    const forwardBody = JSON.stringify({ url, save_to }); // 转发给6盘的请求体（必须是 url 单数）

    // ==================== HMAC-SHA256 签名（清真云050系列要求） ====================
    const ts = Math.floor(Date.now() / 1000).toString(); // 秒级时间戳
    const nonce = crypto.randomUUID().replace(/-/g, "").slice(0, 16); // 随机串
    // 签名拼接规则：timestamp + nonce + CLIENT_ID + 请求体JSON（如果签名报错401，调整这行的拼接顺序）
    const canonical = [ts, nonce, CLIENT_ID, forwardBody].join("\n");

    // 生成签名
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(CLIENT_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical));
    const sig = Array.from(new Uint8Array(sigBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // ==================== 调用6盘050.003接口 ====================
    const resp = await fetch(`${BASE}${API_PATH}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-ID": CLIENT_ID,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Sign": sig,
      },
      body: forwardBody,
    });

    const upstreamText = await resp.text();

    // ==================== 调试输出（方便排查问题，稳定后可把 DEBUG 改成 false） ====================
    const DEBUG = true; 
    if (DEBUG) {
      return new Response(
        JSON.stringify({
          // Deno接收到的快捷指令请求
          deno_received: body,
          // Deno转发给6盘的内容
          deno_forwarded: JSON.parse(forwardBody),
          // 6盘返回的HTTP状态码
          upstream_status: resp.status,
          // 6盘返回的响应体
          upstream_body: (() => {
            try {
              return JSON.parse(upstreamText);
            } catch {
              return upstreamText; // 非JSON响应直接返回原始内容
            }
          })(),
          // 调试提示
          tip: "如果 upstream_status 是404，尝试更换代码里的 API_PATH 备选地址；如果是401，调整 canonical 拼接顺序",
        }, null, 2),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }

    // 非调试模式：直接返回6盘的响应
    return new Response(upstreamText, {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  },
};
