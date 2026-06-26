/**
 * 6盘（清真云）远程离线下载中转服务
 * 适配真实网页版接口：grpcuserapi.2dland.cn/v6.services.pub.PubOfflineTask/Add
 * 兼容 iOS 快捷指令（支持 url/urls 两种传参格式）
 */

export default {
  async fetch(req: Request): Promise<Response> {
    // 仅允许 POST 请求
    if (req.method !== "POST") {
      return new Response("仅支持 POST 请求，请用快捷指令调用", { status: 405 });
    }

    // ==================== 环境变量配置（必填）====================
    // 从 Deno Deploy 控制台 → Settings → Environment Variables 添加
    const BEARER = Deno.env.get("BEARER");
    if (!BEARER) {
      return new Response(
        JSON.stringify({
          error: "请在 Deno Deploy 控制台配置环境变量 BEARER",
          tip: "BEARER 获取方式：浏览器登录 drive.2dland.cn → F12 → Network → 找到 PubOfflineTask/Add 请求 → 复制 Request Headers 里的 Authorization: Bearer 后面的完整字符串",
        }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      );
    }

    // ==================== 6盘真实离线接口配置 ====================
    // 完全匹配你 F12 抓到的真实接口地址
    const BASE = "https://grpcuserapi.2dland.cn";
    const API_PATH = "/v6.services.pub.PubOfflineTask/Add";

    // ==================== 解析快捷指令请求 ====================
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ error: "快捷指令请求体 JSON 格式错误，请检查配置" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // 兼容两种传参方式：url（单数文本，推荐）或 urls（数组）
    let url: string;
    if (typeof body.url === "string") {
      url = body.url; // 快捷指令传 { "url": "剪贴板内容" }
    } else if (Array.isArray(body.urls) && typeof body.urls[0] === "string") {
      url = body.urls[0]; // 快捷指令传 { "urls": ["剪贴板内容"] }
    } else {
      return new Response(
        JSON.stringify({
          error: "快捷指令请求体必须包含 url（文本）或 urls（数组）",
          example_url: { url: "https://speed.hetzner.de/1MB.bin", save_to: "/" },
          example_urls: { urls: ["https://speed.hetzner.de/1MB.bin"], save_to: "/" },
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // 离线文件保存路径（6盘内的路径，默认根目录）
    const save_to = (body.save_to as string) || "/";
    // 转发给6盘的请求体（gRPC-JSON 网关兼容 { url, save_to } 格式）
    const forwardBody = JSON.stringify({ url, save_to });

    // ==================== 调用6盘真实离线接口 ====================
    const resp = await fetch(`${BASE}${API_PATH}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // 网页版接口专用鉴权头（无需 HMAC，直接用 Bearer）
        "Authorization": `Bearer ${BEARER}`,
        // 可选：模拟网页版请求头，提高兼容性
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
      },
      body: forwardBody,
    });

    const upstreamText = await resp.text();

    // ==================== 调试输出（稳定后可把 DEBUG 改为 false） ====================
    const DEBUG = true;
    if (DEBUG) {
      return new Response(
        JSON.stringify({
          // Deno 接收到的快捷指令请求（用于验证快捷指令配置是否正确）
          deno_received: body,
          // Deno 转发给6盘的内容
          deno_forwarded: JSON.parse(forwardBody),
          // 6盘返回的HTTP状态码（200=成功，401=Bearer过期，403=无权限）
          upstream_status: resp.status,
          // 6盘返回的响应体（核心调试信息）
          upstream_body: (() => {
            try {
              return JSON.parse(upstreamText);
            } catch {
              return upstreamText; // 非JSON响应直接返回原始内容
            }
          })(),
          // 使用提示
          tip: "200=成功；401=Bearer过期，请重新从网页版获取；403=账号无离线权限；404/405=接口路径错误",
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
