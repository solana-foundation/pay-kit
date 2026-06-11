import type { Endpoint, Primitive } from '../types'
import manifest from './snippets.gen.json'

export const LANGUAGES = [
  'curl',
  'pay',
  'typescript',
  'rust',
  'go',
  'python',
  'ruby',
  'php',
  'lua',
  'kotlin',
  'swift',
] as const

export type Language = (typeof LANGUAGES)[number]
export type Side = 'client' | 'server'

/** Per-language snippet bundle. Each side is optional. */
export type SnippetSet = Record<Language, Partial<Record<Side, string>>>

export function buildUrl(endpoint: Endpoint, paramValues: Record<string, string>): string {
  let url = endpoint.path
  const query: string[] = []
  for (const p of endpoint.params ?? []) {
    const v = paramValues[p.name] ?? p.default
    if (v.length === 0) continue
    if (url.includes(`:${p.name}`)) url = url.replace(`:${p.name}`, encodeURIComponent(v))
    else query.push(`${encodeURIComponent(p.name)}=${encodeURIComponent(v)}`)
  }
  if (query.length) url += `?${query.join('&')}`
  return url
}

/**
 * Generated manifest shape — emitted by playground/scripts/gen-snippets.mjs
 * from each language's `<lang>/docs/snippets/` directory. Languages absent
 * from the manifest fall through to the inline templates below.
 */
type Manifest = Partial<Record<Language, Partial<Record<Primitive, Partial<Record<Side, string>>>>>>

const GEN: Manifest = manifest as Manifest

export function buildSnippets(
  endpoint: Endpoint,
  paramValues: Record<string, string>,
  baseUrl: string,
): SnippetSet {
  const ctx: Ctx = {
    endpoint,
    path: buildUrl(endpoint, paramValues),
    baseUrl,
    fullUrl: baseUrl + buildUrl(endpoint, paramValues),
    method: endpoint.method,
    methodFlag: endpoint.method !== 'GET' ? `-X ${endpoint.method} ` : '',
    primitive: endpoint.primitive,
  }

  return {
    curl: { client: `curl -i ${ctx.methodFlag}${ctx.fullUrl}` },
    pay: { client: `pay --sandbox curl ${ctx.methodFlag}\\\n  ${ctx.fullUrl}` },
    typescript: resolve('typescript', ctx, fallback.typescript),
    rust: resolve('rust', ctx, fallback.rust),
    go: resolve('go', ctx, fallback.go),
    python: resolve('python', ctx, fallback.python),
    ruby: resolve('ruby', ctx, fallback.ruby),
    php: resolve('php', ctx, fallback.php),
    lua: resolve('lua', ctx, fallback.lua),
    kotlin: resolve('kotlin', ctx, fallback.kotlin),
    swift: resolve('swift', ctx, fallback.swift),
  }
}

interface Ctx {
  endpoint: Endpoint
  path: string
  baseUrl: string
  fullUrl: string
  method: string
  methodFlag: string
  primitive: Primitive
}

/** Pull from the generated manifest first; fall back to the inline template
 * for any language/(primitive, side) combo that hasn't been migrated yet.
 *
 * Placeholders (see docs/snippets-convention.md):
 * - `${URL}`  — the full endpoint URL (client snippets fetch it)
 * - `${PATH}` — the route path only (server snippets register it) */
function resolve(
  lang: Language,
  ctx: Ctx,
  fb: (ctx: Ctx) => Partial<Record<Side, string>>,
): Partial<Record<Side, string>> {
  const fromGen = GEN[lang]?.[ctx.primitive] ?? {}
  const fromFb = fb(ctx)
  const out: Partial<Record<Side, string>> = {}
  for (const side of ['client', 'server'] as const) {
    const body = fromGen[side] ?? fromFb[side]
    if (body !== undefined) {
      out[side] = body.replaceAll('${URL}', ctx.fullUrl).replaceAll('${PATH}', ctx.endpoint.path)
    }
  }
  return out
}

// ─────────────────────────────────────────────────────────────────────
// Inline fallbacks — used when the generated manifest doesn't yet have a
// snippet for the (language, primitive, side) triple. As each language's
// `<lang>/docs/snippets/` directory is populated and the manifest
// regenerated, the corresponding fallback becomes dead code and can be
// deleted.
// ─────────────────────────────────────────────────────────────────────

const fallback = {
  typescript: (_: Ctx) => ({}), // migrated — manifest serves all four primitives
  rust: (c: Ctx) => ({
    client:
      c.primitive === 'x402'
        ? `use pay_kit::client::{x402, ClientBuilder};

let client = ClientBuilder::new().with_x402_signer(signer).build();
let res = client.get("${c.fullUrl}").send().await?;
let data: serde_json::Value = res.json().await?;
println!("{data}");`
        : `use pay_kit::client::{mpp, ClientBuilder};

let client = ClientBuilder::new()
    .with_mpp_signer(signer)
    .rpc_url("http://localhost:8899")
    .build();

let res = client.get("${c.fullUrl}").send().await?;
let data: serde_json::Value = res.json().await?;
println!("{data}");`,
    server: `use axum::{Router, routing::${c.method.toLowerCase()}};
use pay_core::server::{${c.primitive === 'session' ? 'session' : c.primitive === 'subscription' ? 'subscription' : 'charge'}, ServerBuilder};

let gate = ServerBuilder::new()
    .recipient(recipient)
    .network("mainnet")
    .signer(fee_payer)
    .build_${c.primitive === 'session' ? 'session' : c.primitive === 'subscription' ? 'subscription' : 'charge'}();

let app = Router::new()
    .route("${c.endpoint.path}", ${c.method.toLowerCase()}(handler).layer(gate));`,
  }),
  go: (c: Ctx) => ({
    server: `import (
    "net/http"
    "github.com/solana-foundation/pay-kit/go/server"
)

gate := server.New${c.primitive === 'session' ? 'Session' : c.primitive === 'subscription' ? 'Subscription' : 'Charge'}(server.Options{
    Recipient: recipient, Network: "mainnet", Signer: feePayer,
})

http.Handle("${c.endpoint.path}", gate.Wrap(handler))`,
  }),
  python: (c: Ctx) => ({
    client: `from pay_kit.client import PayKitClient

client = PayKitClient(signer=signer, rpc_url="http://localhost:8899")
res = client.get("${c.fullUrl}")
print(res.json())`,
    server: `from flask import Flask
from pay_kit.server import ${c.primitive === 'session' ? 'Session' : c.primitive === 'subscription' ? 'Subscription' : 'Charge'}Gate

app = Flask(__name__)
gate = ${c.primitive === 'session' ? 'Session' : c.primitive === 'subscription' ? 'Subscription' : 'Charge'}Gate(
    recipient=RECIPIENT, network="mainnet", signer=fee_payer,
)

@app.route("${c.endpoint.path}", methods=["${c.method}"])
@gate.guard
def handler():
    return {"ok": True}`,
  }),
  ruby: (c: Ctx) => ({
    server: `require "sinatra"
require "solana_pay_kit/server"

gate = SolanaPayKit::Server.${c.primitive === 'session' ? 'session' : c.primitive === 'subscription' ? 'subscription' : 'charge'}(
  recipient: RECIPIENT, network: "mainnet", signer: fee_payer,
)

${c.method.toLowerCase()} "${c.endpoint.path}" do
  gate.guard(request) { json ok: true }
end`,
  }),
  php: (c: Ctx) => {
    const kind = c.primitive === 'session' ? 'Session' : c.primitive === 'subscription' ? 'Subscription' : 'Charge'
    return {
      server: `<?php
// Laravel route — pay-kit ships a PSR-15 middleware that wraps any framework.
use SolanaFoundation\\PayKit\\Middleware\\${kind}Gate;

Route::${c.method.toLowerCase()}('${c.endpoint.path}', fn () => response()->json(['ok' => true]))
    ->middleware(${kind}Gate::class
        ->recipient(env('PAY_RECIPIENT'))
        ->network('mainnet')
        ->signer(env('PAY_FEE_PAYER')));`,
    }
  },
  lua: (c: Ctx) => {
    const kind = c.primitive === 'session' ? 'session' : c.primitive === 'subscription' ? 'subscription' : 'charge'
    return {
      server: `-- nginx.conf — pay-kit ships an OpenResty access-phase middleware.
location ${c.endpoint.path} {
    access_by_lua_block {
        local gate = require("pay_kit.${kind}")
        gate.guard({
            recipient = "$PAY_RECIPIENT",
            network   = "mainnet",
            signer    = "$PAY_FEE_PAYER",
        })
    }
    content_by_lua_block { ngx.say('{"ok":true}') }
}`,
    }
  },
  kotlin: (c: Ctx) => ({
    client: `import com.solanafoundation.paykit.PayKitClient

val client = PayKitClient(signer = signer, rpcUrl = "http://localhost:8899")
val res = client.get("${c.fullUrl}").execute()
println(res.body?.string())`,
  }),
  swift: (c: Ctx) => ({
    client: `import PayKit

let client = PayKit.Client(signer: signer, rpcURL: URL(string: "http://localhost:8899")!)
let (data, _) = try await client.get(URL(string: "${c.fullUrl}")!)
print(String(data: data, encoding: .utf8) ?? "")`,
  }),
}
