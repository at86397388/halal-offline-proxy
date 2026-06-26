// 在 return new Response(text, ...) 之前，临时加一行调试返回：
// 把 Deno 收到的 + 050.003 返回的都拼一起返给快捷指令

const debug = {
  deno_received: body,
  deno_canonical: [ts, nonce, CLIENT_ID, bodyStr].join("\n"),
  upstream_status: resp.status,
  upstream_body: JSON.parse(text || "{}"),
};
return new Response(JSON.stringify(debug, null, 2), {
  status: 200,
  headers: { "Content-Type": "application/json" },
});
