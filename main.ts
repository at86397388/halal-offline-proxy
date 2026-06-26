/**
 * 6盘（清真云）远程离线下载中转 — A路线（最终通版）
 * 接口：grpcuserapi.2dland.cn/v6.services.pub.PubOfflineTask/Add
 * 鉴权：Bearer 硬编码（过期后需从网页版F12重抠）
 * 兼容快捷指令：{ "url": "剪贴板" } 或 { "urls": ["剪贴板"] }
 */

export default {
  async fetch(req: Request): Promise<Response> {
    if (req.method !== "POST") {
      return new Response("仅支持 POST，请用快捷指令调用", { status: 405 });
    }

    // ==================== 1. 核心配置（仅需修改这里）====================
    // ⚠️ 从浏览器F12抓取：drive.2dland.cn → Network → PubOfflineTask/Add → Request Headers → Authorization 后的 eyJ 开头字符串
    // ⚠️ 不要带 "Bearer " 前缀，代码已自动拼接
    // ⚠️ Bearer 有效期几小时~几天，过期后需重新抓取替换
    const BEARER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRvbiI6IiIsImV4cCI6MTc4MjQ5MDY2OCwiZXhwX3RzIjoxNzgyNDkwNjY4MTk4LCJpYXQiOjE3ODI0ODM0NjgsImljb24iOiIiLCJpc3MiOiJ1c2VyLWNlbnRlcjp1c2VyLWNlbnRlci01ODlmYzhkODVkLWxiZmdmIiwianRpIjoiNjhhODBlZTEtOGY2Ni00NDNkLTkyMWUtOWM0ZWYxNzlmMTEyIiwibmFtZSI6ImF0d29ya2VtYWlsIiwibmJmIjoxNzgyNDgyODY4LCJzaWQiOiI0ZGYzZGFlOS05M2VhLTQ0NTItOTZhOC1hY2IxZDg4NDI0MDUiLCJzdWIiOiIzY2I2NDFhOGQ0OGM0OTk2YjYwMTAyODM0MWVjNGZlZSIsInRpbWVtaWxsaSI6IjE3ODI0ODM0NjgxOTgiLCJ0aW1lc3RhbXAiOiIxNzgyNDgzNDY4IiwidmVyIjoyfQ.zf1AojQr3bw3QnO0BZzGavue-vpbDLxzxPS-CpN2vko";

    // 6盘网页版真实离线接口（与你F12抓取的完全一致）
    const BASE = "https://grpcuserapi.2dland.cn";
    const API_PATH = "/v6.services.pub.PubOfflineTask/Add";

    // ==================== 2. 解析快捷指令请求 ====================
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ error: "快捷指令JSON格式错误，请检查请求体配置" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // 兼容两种快捷指令传参方式
    let url: string;
    if (typeof body.url === "string") {
      url = body.url; // 推荐：{ "url": "剪贴板内容" }
    } else if (Array.isArray(body.urls) && typeof body.urls[0] === "string") {
      url = body.urls[0]; // 兼容：{ "urls": ["剪贴板内容"] }
    } else {
      return new Response(
        JSON.stringify({ error: "请求必须包含 url（文本）或 urls（数组）" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // 离线文件保存路径："/" 为6盘根目录，指定文件夹需填文件夹的file_id（非名称）
    const save_to = (body.save_to as string) || "/";
    const forwardBody = JSON.stringify({ url, save_to });

    // ==================== 3. 调用6盘离线接口 ====================
    const resp = await fetch(`${BASE}${API_PATH}`, {
      method: "POST",
      headers: {
        // ✅ gRPC-JSON网关专用Content-Type（解决415错误的核心）
        "Content-Type": "application/grpc+json; charset=utf-8",
        // 鉴权头（自动拼接Bearer前缀）
        "Authorization": `Bearer ${BEARER}`,
        // 模拟网页版请求特征，避免被拦截
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
      },
      body: forwardBody,
    });

    const upstreamText = await resp.text();

    // ==================== 4. 调试返回（通了后可把DEBUG改为false）====================
    const DEBUG = true;
    if (DEBUG) {
      return new Response(
        JSON.stringify({
          // Deno接收的快捷指令请求（验证快捷指令配置是否正确）
          deno_received: body,
          // Deno转发给6盘的内容
          deno_forwarded: JSON.parse(forwardBody),
          // 6盘返回的HTTP状态码（200=成功，401=Bearer过期，415=Content-Type错误）
          upstream_status: resp.status,
          // 6盘返回的响应内容（核心调试信息）
          upstream_body: (() => {
            try { return JSON.parse(upstreamText); }
            catch { return upstreamText; }
          })(),
          // 快速排查指南
          tip: "200=成功，去6盘离线列表查看；401=Bearer过期，重新从F12抓取；415=Content-Type错误，尝试去掉charset"
        }, null, 2),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }

    // 非调试模式：直接返回6盘响应
    return new Response(upstreamText, {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  },
};
