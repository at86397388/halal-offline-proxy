/**
 * 6盘（清真云）远程离线下载中转 — A路线
 * 接口：grpcuserapi.2dland.cn/v6.services.pub.PubOfflineTask/Add
 * 鉴权：Bearer 硬编码（BEARER 过期后需从 F12 重抠）
 *
 * 快捷指令兼容：{ "url": "剪贴板" } 或 { "urls": ["剪贴板"] }
 */

export default {
  async fetch(req: Request): Promise<Response> {
    if (req.method !== "POST") {
      return new Response("仅支持 POST，快捷指令里用", { status: 405 });
    }

    // ==================== 1. Bearer（你从 F12 抠的那串 eyJ...）====================
    // ⚠️ 不要带 "Bearer " 前缀，代码里自己拼
    // ⚠️ 这版是硬编码测试版，通了之后建议移到 Deno 环境变量，或加 refresh 逻辑
    const BEARER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRvbiI6IiIsImV4cCI6MTc4MjQ5MDY2OCwiZXhwX3RzIjoxNzgyNDkwNjY4MTk4LCJpYXQiOjE3ODI0ODM0NjgsImljb24iOiIiLCJpc3MiOiJ1c2VyLWNlbnRlcjp1c2VyLWNlbnRlci01ODlmYzhkODVkLWxiZmdmIiwianRpIjoiNjhhODBlZTEtOGY2Ni00NDNkLTkyMWUtOWM0ZWYxNzlmMTEyIiwibmFtZSI6ImF0d29ya2VtYWlsIiwibmJmIjoxNzgyNDgyODY4LCJzaWQiOiI0ZGYzZGFlOS05M2VhLTQ0NTItOTZhOC1hY2IxZDg4NDI0MDUiLCJzdWIiOiIzY2I2NDFhOGQ0OGM0OTk2YjYwMTAyODM0MWVjNGZlZSIsInRpbWVtaWxsaSI6IjE3ODI0ODM0NjgxOTgiLCJ0aW1lc3RhbXAiOiIxNzgyNDgzNDY4IiwidmVyIjoyfQ.zf1AojQr3bw3QnO0BZzGavue-vpbDLxzxPS-CpN2vko";

    // ==================== 2. 6盘真实离线接口（你F12抓到的）====================
    const BASE = "https://grpcuserapi.2dland.cn";
    const API_PATH = "/v6.services.pub.PubOfflineTask/Add";

    // ==================== 3. 解析快捷指令请求 ====================
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ error: "快捷指令 JSON 格式错，检查请求体" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // 兼容 url（单数）和 urls（数组）
    let url: string;
    if (typeof body.url === "string") {
      url = body.url;
    } else if (Array.isArray(body.urls) && typeof body.urls[0] === "string") {
      url = body.urls[0];
    } else {
      return new Response(
        JSON.stringify({ error: "必须有 url（文本）或 urls（数组）" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    const save_to = (body.save_to as string) || "/";
    const forwardBody = JSON.stringify({ url, save_to });

    // ==================== 4. 调 6盘离线接口 ====================
    const resp = await fetch(`${BASE}${API_PATH}`, {
      method: "POST",
      headers: {
        // gRPC-JSON 网关，对齐网页版 F12 里看到的 Content-Type
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": `Bearer ${BEARER}`,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Accept": "application/json",
      },
      body: forwardBody,
    });

    const text = await resp.text();

    // ==================== 5. 调试返回（通了之后把 DEBUG 改 false）====================
    const DEBUG = true;
    if (DEBUG) {
      return new Response(
        JSON.stringify({
          deno_received: body,
          deno_forwarded: JSON.parse(forwardBody),
          upstream_status: resp.status,
          upstream_body: (() => { try { return JSON.parse(text); } catch { return text; } })(),
          tip: "200=通了去6盘看离线列表；415=换Content-Type为application/grpc+json；401=Bearer过期",
        }, null, 2),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }

    return new Response(text, {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  },
};
