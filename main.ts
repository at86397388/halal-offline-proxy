// main.ts — 基线版：能部署 + 兼容 url/urls + 调试信息走响应体
export default {
  async fetch(req: Request): Promise<Response> {
    if (req.method !== "POST") {
      return new Response("only POST", { status: 405 });
    }

    const CLIENT_ID = Deno.env.get("CLIENT_ID");
    const CLIENT_SECRET = Deno.env.get("CLIENT_SECRET");
    const BASE = "https://openapi.2dland.cn";

    if (!CLIENT_ID || !CLIENT_SECRET) {
      return new Response(
        JSON.stringify({ error: "env not set" }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      );
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ error: "bad json" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // 兼容 url（单数）/ urls（复数）
    let urls: string[];
    if (Array.isArray(body.urls)) {
      urls = body.urls as string[];
    } else if (typeof body.url === "string") {
      urls = [body.url as string];
    } else {
      return new Response(
        JSON.stringify({ error: "missing urls" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    if (urls.length === 0) {
      return new Response(
        JSON.stringify({ error: "empty urls" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    const save_to = (body.save_to as string) || "/";
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
    const bodyStr = JSON.stringify({ urls, save_to });

    // HMAC
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

    // 调 050.003
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

    // ===== 调试开关：true 时把信息吐回快捷指令，false 时走原样 =====
    const DEBUG = true;
    if (DEBUG) {
      return new Response(
        JSON.stringify({
          deno_received: body,
          deno_urls_normalized: urls,
          upstream_status: resp.status,
          upstream_body: (() => { try { return JSON.parse(text); } catch { return text; } })(),
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
