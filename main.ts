// main.ts — 适配 050.003 接口的 urls 复数要求
export default {
  async fetch(req: Request): Promise<Response> {
    if (req.method !== "POST") {
      return new Response("only POST", { status: 405 });
    }

    const CLIENT_ID = Deno.env.get("CLIENT_ID")!;
    const CLIENT_SECRET = Deno.env.get("CLIENT_SECRET")!;
    // 050 接口基址，如果后续报错可以换成 drive.2dland.cn/api
    const BASE = "https://openapi.2dland.cn";

    let body: { urls?: string[]; save_to?: string };
    try {
      body = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: "bad json" }), { status: 400 });
    }

    // 【修改点1】解构用 urls（复数），对应 050.003 接口要求
    const { urls, save_to = "/" } = body;
    // 【修改点2】校验逻辑改成检查 urls 是数组且不为空
    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return new Response(JSON.stringify({ error: "missing urls" }), { status: 400 });
    }

    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
    // 【修改点3】转发给 050.003 的请求体也用 urls 字段
    const bodyStr = JSON.stringify({ urls, save_to });

    // Web Crypto HMAC-SHA256 签名（不用改）
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(CLIENT_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sigBuf = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode([ts, nonce, CLIENT_ID, bodyStr].join("\n")),
    );
    const sig = Array.from(new Uint8Array(sigBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // 调用 050.003 离线下载接口
    const resp = await fetch(`${BASE}/050/003`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-ID": CLIENT_ID,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Sign": sig,
      },
      body: bodyStr,
    });

    const text = await resp.text();
    return new Response(text, {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  },
};
