/**
 * Metadata + quickstart snippet for each language pay-kit ships in.
 *
 * Languages present in the shared snippets manifest (snippets.gen.json,
 * extracted from each language's `<lang>/docs/snippets/` directory by
 * playground/scripts/gen-snippets.mjs) derive their card — quickstart
 * snippet and client/server availability — from the manifest. Languages
 * that haven't migrated their snippets yet fall back to the curated
 * entries below. See docs/snippets-convention.md.
 */

import manifest from './snippets.gen.json'

const REPO = 'https://github.com/solana-foundation/pay-kit/blob/main'

export interface LangDoc {
  id: string
  name: string
  framework: string
  install: string
  /** ✅ if a server example exists for the language, — otherwise. */
  server: '✅' | '—'
  /** ✅ if a client example exists for the language, — otherwise. */
  client: '✅' | '—'
  /** Quickstart snippet — from the manifest when the language has migrated,
   * curated fallback otherwise. `${URL}` / `${PATH}` are substituted at
   * module load with example values. */
  snippet: string
  /** GitHub URL for the language's README. */
  href: string
}

interface LangMeta {
  id: string
  name: string
  framework: string
  install: string
  href: string
}

/** Pure metadata — no code snippets. */
const LANG_META: LangMeta[] = [
  {
    id: 'typescript',
    name: 'TypeScript',
    framework: 'Express',
    install: 'npm install @solana/pay-kit',
    href: `${REPO}/typescript/README.md`,
  },
  {
    id: 'rust',
    name: 'Rust',
    framework: 'Axum',
    install: 'cargo add solana-pay-kit',
    href: `${REPO}/rust/README.md`,
  },
  {
    id: 'go',
    name: 'Go',
    framework: 'net/http',
    install: 'go get github.com/solana-foundation/pay-kit/go',
    href: `${REPO}/go/README.md`,
  },
  {
    id: 'python',
    name: 'Python',
    framework: 'Flask / FastAPI',
    install: 'pip install solana-pay-kit[flask]',
    href: `${REPO}/python/README.md`,
  },
  {
    id: 'ruby',
    name: 'Ruby',
    framework: 'Sinatra / Rails',
    install: 'gem install solana_pay_kit',
    href: `${REPO}/ruby/README.md`,
  },
  {
    id: 'php',
    name: 'PHP',
    framework: 'Laravel / Symfony',
    install: 'composer require solana-foundation/pay-kit',
    href: `${REPO}/php/README.md`,
  },
  {
    id: 'lua',
    name: 'Lua',
    framework: 'OpenResty / Kong / APISIX',
    install: 'luarocks install pay-kit',
    href: `${REPO}/lua/README.md`,
  },
  {
    id: 'kotlin',
    name: 'Kotlin',
    framework: 'JVM + Android (client)',
    install: 'implementation("com.solanafoundation:pay-kit:...")',
    href: `${REPO}/kotlin/README.md`,
  },
  {
    id: 'swift',
    name: 'Swift',
    framework: 'iOS + macOS (client)',
    install: '.package(path: "../pay-kit/swift")',
    href: `${REPO}/swift/README.md`,
  },
]

interface CuratedDoc {
  client: boolean
  server: boolean
  snippet: string
}

/** Curated fallbacks for languages whose snippets haven't been migrated to
 * `<lang>/docs/snippets/` yet. Sourced from the per-language READMEs. */
const CURATED: Record<string, CuratedDoc> = {
  typescript: {
    server: true,
    client: true,
    snippet: `import express from 'express'
import { createPayKit, usd } from '@solana/pay-kit'

const pay = await createPayKit({
  network: 'localnet',
  pricing: { paid: { amount: usd('0.10'), description: 'Premium report' } },
})

const app = express()

// pay.express(gate) settles the 402 (MPP or x402) before the handler runs.
app.get('/paid', pay.express('paid'), (_req, res) => {
  res.json({ ok: true })
})
app.listen(4567)`,
  },
  rust: {
    server: true,
    client: true,
    snippet: `use axum::Router;
use solana_pay_kit::{paid_get, PayKit, PayKitConfig, Payment};

async fn report(payment: Payment) -> String {
    format!("premium content (paid {} via {})", payment.amount, payment.protocol)
}

#[tokio::main]
async fn main() {
    let pay = PayKit::new(PayKitConfig {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        network: "localnet".to_string(),
        rpc_url: Some("https://402.surfnet.dev:8899".to_string()),
        ..Default::default()
    })
    .expect("valid config");

    // paid_get(handler, price, &pay) gates the route over MPP or x402.
    let app = Router::new().route("/paid", paid_get(report, "0.10", &pay));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4567").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}`,
  },
  go: {
    server: true,
    client: true,
    snippet: `package main

import (
    "fmt"
    "net/http"
    _ "github.com/solana-foundation/pay-kit/go/paycore/signer"
    "github.com/solana-foundation/pay-kit/go/paykit"
    _ "github.com/solana-foundation/pay-kit/go/paykit/adapters/mpp"
    _ "github.com/solana-foundation/pay-kit/go/paykit/adapters/x402"
)

func main() {
    client, _ := paykit.New(paykit.Config{
        Network: paykit.SolanaLocalnet,
        Accept:  []paykit.Protocol{paykit.X402, paykit.MPP},
        MPP:     paykit.MPPConfig{ChallengeBindingSecret: []byte("local-dev-secret")},
    })
    gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

    mux := http.NewServeMux()
    mux.Handle("/report", client.Require(gate)(http.HandlerFunc(
        func(w http.ResponseWriter, r *http.Request) {
            fmt.Fprintln(w, "premium content")
        })))
    http.ListenAndServe(":4567", mux)
}`,
  },
  python: {
    server: true,
    client: true,
    snippet: `# app.py
from flask import Flask, jsonify
import solana_pay_kit
from solana_pay_kit import usd
from solana_pay_kit.flask import require_payment

solana_pay_kit.configure(network="solana_localnet")
app = Flask(__name__)

@app.get("/report")
@require_payment(usd("0.10"))
def report():
    return jsonify(content="premium content")

app.run(host="127.0.0.1", port=8000)`,
  },
  ruby: {
    server: true,
    client: false,
    snippet: `# config.ru
require "sinatra/base"
require "solana_pay_kit"

class App < Sinatra::Base
  get("/report") do
    require_payment! usd("0.10")
    "premium content"
  end
end

run App`,
  },
  php: {
    server: true,
    client: false,
    snippet: `<?php
// routes/api.php
use PayKit\\Gate;
use PayKit\\Price;
use Illuminate\\Support\\Facades\\Route;

Route::get('/report', fn () => ['premium' => 'report'])
    ->middleware(['paykit:inline'])
    ->defaults('paykit.gate', new Gate(amount: Price::usd('0.10')));`,
  },
  lua: {
    server: true,
    client: false,
    snippet: `-- nginx.conf
http {
  lua_shared_dict pay_kit_replay 10m;
  init_by_lua_block {
    local pay_kit = require('pay_kit')
    assert(pay_kit.configure({ network = 'solana_localnet' }))
    pay_kit.gate('report', { amount = pay_kit.usd('0.10') })
  }
  server {
    listen 4570;
    location = /report {
      access_by_lua_block { require('pay_kit').require_payment('report') }
      return 200 '{"ok":true}';
    }
  }
}`,
  },
  kotlin: {
    server: false,
    client: true,
    snippet: `import com.solana.paykit.client.PayKitClient
import com.solana.paykit.protocols.mpp.client.JsonRpcClient
import com.solana.paykit.paycore.MemorySigner

val signer = MemorySigner.fromSecretKey(walletSecretKeyBytes)
val client = PayKitClient.Builder()
    .signer(signer)
    .charge(blockhashProvider = JsonRpcClient("https://402.surfnet.dev"))
    .build()

val result = client.get("https://402.surfnet.dev/paid")
println(result.status)        // 200
println(result.paymentSent)   // true
println(result.settlement)    // on-chain signature`,
  },
  swift: {
    server: false,
    client: true,
    snippet: `import SolanaPayKit

let signer = try MemorySigner(secretKey: secretKeyData)
let rpc = RpcClient(endpoint: URL(string: "https://402.surfnet.dev")!)
let client = PayKit.HttpClient.mpp(signer: signer, rpc: rpc)

let response = try await client
    .request(URL(string: "https://api.example.com/paid")!)
    .response()
print(response.status)              // 200 after the payment retry
print(response.settlementSignature) // base58 on-chain signature`,
  },
}

type Side = 'client' | 'server'
type ManifestEntry = Partial<Record<Side, string>>
type Manifest = Partial<Record<string, Partial<Record<string, ManifestEntry>>>>

const GEN: Manifest = manifest as Manifest

/** Pick the most representative quickstart snippet for a language from the
 * generated manifest. For server languages we show the server side of
 * `charge`; for client-only languages, the client side; falling back across
 * primitives if `charge` isn't present. Returns null when the language has
 * no manifest entry at all. */
function pickGenerated(langId: string): CuratedDoc | null {
  const lang = GEN[langId]
  if (!lang) return null
  const hasClient = (Object.values(lang) as ManifestEntry[]).some((p) => !!p?.client)
  const hasServer = (Object.values(lang) as ManifestEntry[]).some((p) => !!p?.server)

  const sidePref: Side = hasServer ? 'server' : 'client'
  const primPref = ['charge', 'subscription', 'session', 'x402'] as const
  for (const primitive of primPref) {
    const body = lang[primitive]?.[sidePref]
    if (body) return { snippet: body, client: hasClient, server: hasServer }
  }
  for (const primitive of primPref) {
    const body = lang[primitive]?.client ?? lang[primitive]?.server
    if (body) return { snippet: body, client: hasClient, server: hasServer }
  }
  return null
}

export const LANG_DOCS: LangDoc[] = LANG_META.map((m) => {
  // Generated snippet data wins when the language is in the manifest;
  // curated data is the fallback.
  const doc = pickGenerated(m.id) ?? CURATED[m.id] ?? { client: false, server: false, snippet: '' }
  return {
    ...m,
    client: doc.client ? '✅' : '—',
    server: doc.server ? '✅' : '—',
    snippet: doc.snippet
      .replaceAll('${URL}', 'https://api.example.com/paid')
      .replaceAll('${PATH}', '/paid'),
  }
})
