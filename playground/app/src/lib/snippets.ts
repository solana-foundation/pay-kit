import type { Endpoint } from '../types'

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

export interface SnippetSet {
  curl: string
  pay: string
  typescript: string
  rust: string
  go: string
  python: string
  ruby: string
  php: string
  lua: string
  kotlin: string
  swift: string
}

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

export function buildSnippets(
  endpoint: Endpoint,
  paramValues: Record<string, string>,
  baseUrl: string,
): SnippetSet {
  const path = buildUrl(endpoint, paramValues)
  const fullUrl = baseUrl + path
  const method = endpoint.method
  const methodFlag = method !== 'GET' ? `-X ${method} ` : ''
  const isCharge = endpoint.primitive === 'charge'
  const isSub = endpoint.primitive === 'subscription'
  const isX402 = endpoint.primitive === 'x402'
  const isSession = endpoint.primitive === 'session'

  return {
    curl: `curl -i ${methodFlag}${fullUrl}`,
    pay: `pay --sandbox curl ${methodFlag}\\\n  ${fullUrl}`,
    typescript: tsSnippet(endpoint, fullUrl, { isCharge, isSub, isX402, isSession }),
    rust: rustSnippet(endpoint, fullUrl, { isX402 }),
    go: goSnippet(endpoint, fullUrl, { isX402 }),
    python: pythonSnippet(endpoint, fullUrl),
    ruby: rubySnippet(endpoint, fullUrl),
    php: phpSnippet(endpoint, fullUrl),
    lua: luaSnippet(endpoint, fullUrl),
    kotlin: kotlinSnippet(endpoint, fullUrl),
    swift: swiftSnippet(endpoint, fullUrl),
  }
}

interface Flags {
  isCharge?: boolean
  isSub?: boolean
  isX402?: boolean
  isSession?: boolean
}

function tsSnippet(_ep: Endpoint, url: string, f: Flags): string {
  if (f.isSub) {
    return `import { Mppx, solana } from '@solana/mpp/client'
import { createKeyPairSignerFromBytes, getBase58Encoder } from '@solana/kit'

const signer = await createKeyPairSignerFromBytes(getBase58Encoder().encode(SECRET))

const method = solana.subscription({
  signer,
  rpcUrl: 'http://localhost:8899',
})

const mppx = Mppx.create({ methods: [method] })

// First call activates the subscription on-chain.
// Subsequent calls re-use the active subscription — no further payment.
const res = await mppx.fetch('${url}')
const data = await res.json()
console.log(data)`
  }

  if (f.isX402) {
    return `import { wrapFetchWithPayment } from 'x402-fetch'
import { createSigner } from 'x402/types'

const signer = createSigner('solana-devnet', SECRET_KEY)
const fetch = wrapFetchWithPayment(globalThis.fetch, signer)

const res = await fetch('${url}')
const data = await res.json()
console.log(data)`
  }

  if (f.isSession) {
    return `import { createPaymentChannelSessionOpener, SessionConsumer } from '@solana/mpp/client'

const opener = createPaymentChannelSessionOpener({ signer, rpcUrl })
const session = await opener.open({ url: '${url}' })

const consumer = new SessionConsumer({ session })
for await (const chunk of consumer.stream()) {
  console.log(chunk.data, '— paid', chunk.cumulative)
}`
  }

  return `import { Mppx, solana } from '@solana/mpp/client'
import { createKeyPairSignerFromBytes, getBase58Encoder } from '@solana/kit'

const signer = await createKeyPairSignerFromBytes(getBase58Encoder().encode(SECRET))

const method = solana.charge({
  signer,
  rpcUrl: 'http://localhost:8899',
})

const mppx = Mppx.create({ methods: [method] })

const res = await mppx.fetch('${url}')
const data = await res.json()
console.log(data)`
}

function rustSnippet(_ep: Endpoint, url: string, f: Flags): string {
  if (f.isX402) {
    return `use pay_kit::client::{x402, ClientBuilder};

let client = ClientBuilder::new()
    .with_x402_signer(signer)
    .build();

let res = client.get("${url}").send().await?;
let data: serde_json::Value = res.json().await?;
println!("{data}");`
  }
  return `use pay_kit::client::{mpp, ClientBuilder};

let client = ClientBuilder::new()
    .with_mpp_signer(signer)
    .rpc_url("http://localhost:8899")
    .build();

let res = client.get("${url}").send().await?;
let data: serde_json::Value = res.json().await?;
println!("{data}");`
}

function goSnippet(_ep: Endpoint, url: string, f: Flags): string {
  if (f.isX402) {
    return `import (
    "github.com/solana-foundation/pay-kit/go"
    _ "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

client := paykit.NewClient(paykit.WithX402Signer(signer))
res, _ := client.Get("${url}")
body, _ := io.ReadAll(res.Body)
fmt.Println(string(body))`
  }
  return `import (
    "github.com/solana-foundation/pay-kit/go"
    _ "github.com/solana-foundation/pay-kit/go/protocols/mpp"
)

client := paykit.NewClient(paykit.WithMPPSigner(signer))
res, _ := client.Get("${url}")
body, _ := io.ReadAll(res.Body)
fmt.Println(string(body))`
}

function pythonSnippet(_ep: Endpoint, url: string): string {
  return `from pay_kit.client import PayKitClient

client = PayKitClient(signer=signer, rpc_url="http://localhost:8899")
res = client.get("${url}")
print(res.json())`
}

function rubySnippet(_ep: Endpoint, url: string): string {
  return `# Server-side example — Ruby ships the server gem; clients should use the \`pay\` CLI.
require "solana_pay_kit"
puts SolanaPayKit::Client.get("${url}").body`
}

function phpSnippet(_ep: Endpoint, url: string): string {
  return `<?php
// Server-side example — PHP ships the server library; clients should use \`pay\`.
$response = file_get_contents('${url}');
echo $response;`
}

function luaSnippet(_ep: Endpoint, url: string): string {
  return `-- Server-side example — Lua ships the server library; clients should use \`pay\`.
local http = require "resty.http"
local res, err = http.new():request_uri("${url}")
ngx.say(res.body)`
}

function kotlinSnippet(_ep: Endpoint, url: string): string {
  return `import com.solanafoundation.paykit.PayKitClient

val client = PayKitClient(signer = signer, rpcUrl = "http://localhost:8899")
val res = client.get("${url}").execute()
println(res.body?.string())`
}

function swiftSnippet(_ep: Endpoint, url: string): string {
  return `import PayKit

let client = PayKit.Client(signer: signer, rpcURL: URL(string: "http://localhost:8899")!)
let (data, _) = try await client.get(URL(string: "${url}")!)
print(String(data: data, encoding: .utf8) ?? "")`
}
