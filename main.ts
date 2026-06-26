// main.ts — 正确版：050.003 要的是 url（单数）
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
        JSON.stringify({ error: "env not set: check Deno Deploy Settings" }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      );
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ error: "bad json, check shortcut JSON body" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // 归一化：快捷指令可能传 url（字符串）或 urls（数组），统一取第一个
    let url: string;
    if (typeof body.url === "string") {
      url = body.url;
    } else if (Array.isArray(body.urls) && body.urls.length > 0) {
      url = body.urls[0] as string;
    } else {
      return new Response(
        JSON.stringify({ error: "missing url: must provide url or urls" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    const save_to = (body.save_to as string) || "/";
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomUUID().replace(/-/g, "").slice(0, 16);

    // 050.003 要的是 { url: "...", save_to: "..." }，字段名 url 单数
    const bodyStr = JSON.stringify({ url, save_to });

    // HMAC-SHA256
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

    console.log("requesting 050.003 with body:", bodyStr);

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
    console.log("050.003 response:", text);

    // 调试模式：把中间过程吐回快捷指令
    const DEBUG = true;
    if (DEBUG) {
      return new Response(
        JSON.stringify({
          deno_received: body,
          deno_forwarded: JSON.parse(bodyStr),
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
