// main.ts — Deno Deploy entry
export default {
  async fetch(req: Request): Promise<Response> {
    if (req.method !== "POST") {
      return new Response("only POST", { status: 405 });
    }

    const CLIENT_ID = Deno.env.get("CLIENT_ID")!;
    const CLIENT_SECRET = Deno.env.get("CLIENT_SECRET")!;
    // 050 基址以清真云文档为准，不确定就先用 openapi.2dland.cn 或 drive.2dland.cn，抓一下确认
    const BASE = "https://openapi.2dland.cn";

    let body: { url?: string; save_to?: string };
    try {
      body = await req.json();
    } catch {
      return new Response("bad json", { status: 400 });
    }
    const { url, save_to = "/" } = body;
    if (!url) return new Response("missing url", { status: 400 });

    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
    const bodyStr = JSON.stringify({ url, save_to });

    // Web Crypto HMAC-SHA256
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
