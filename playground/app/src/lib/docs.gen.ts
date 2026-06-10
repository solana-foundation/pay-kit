/**
 * Hand-curated quickstarts for each language pay-kit ships in.
 *
 * Source of truth lives in the per-language READMEs at the repo root
 * ({lang}/README.md). To regenerate this file, run `pnpm docs:gen` from
 * the playground root (see scripts/gen-docs.ts).
 */

export interface LangDoc {
  id: string
  name: string
  framework: string
  install: string
  client: '✅' | '—'
  server: '✅' | '—'
  /** Minimal 10-15 line snippet showing the most-used flow. */
  snippet: string
  /** GitHub URL for the language's README. */
  href: string
}

const REPO = 'https://github.com/solana-foundation/pay-kit/blob/main'

export const LANG_DOCS: LangDoc[] = [
  {
    id: 'typescript',
    name: 'TypeScript',
    framework: 'Express',
    install: 'npm install @solana/mpp',
    server: '✅',
    client: '✅',
    href: `${REPO}/typescript/README.md`,
    snippet: `import express from 'express'
import { Mppx, solana } from '@solana/mpp/server'

const mppx = Mppx.create({
  methods: [solana.charge({
    recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
    currency: 'USDC',
    network: 'localnet',
  })],
})

const app = express()
app.get('/paid', async (req, res) => {
  const result = await mppx.charge({ amount: '1000', currency: 'USDC' })(
    new Request(\`http://localhost\${req.url}\`, { headers: req.headers as any }),
  )
  if (result.status === 402) {
    const c = result.challenge as Response
    res.writeHead(c.status, Object.fromEntries(c.headers))
    res.end(await c.text()); return
  }
  res.json({ ok: true })
})
app.listen(4567)`,
  },
  {
    id: 'rust',
    name: 'Rust',
    framework: 'Axum',
    install: 'cargo add solana-pay-kit',
    server: '✅',
    client: '✅',
    href: `${REPO}/rust/README.md`,
    snippet: `use axum::{routing::get, Router};
use solana_pay_kit::server::{ChargeBuilder, MppxLayer};

let layer = MppxLayer::new()
    .charge(ChargeBuilder::new()
        .recipient("CXhrFZ...".parse()?)
        .currency("USDC")
        .network("localnet"));

let app = Router::new()
    .route("/paid", get(|| async { "premium content" }))
    .layer(layer);

axum::Server::bind(&"0.0.0.0:4567".parse()?)
    .serve(app.into_make_service())
    .await?;`,
  },
  {
    id: 'go',
    name: 'Go',
    framework: 'net/http',
    install: 'go get github.com/solana-foundation/pay-kit/go',
    server: '✅',
    client: '✅',
    href: `${REPO}/go/README.md`,
    snippet: `package main

import (
    "fmt"
    "net/http"
    "github.com/solana-foundation/pay-kit/go/paykit"
    _ "github.com/solana-foundation/pay-kit/go/protocols/mpp"
    _ "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

func main() {
    client, _ := paykit.New(paykit.Config{
        Network: paykit.SolanaLocalnet,
        Accept:  []paykit.Protocol{paykit.X402, paykit.MPP},
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
  {
    id: 'python',
    name: 'Python',
    framework: 'Flask / FastAPI',
    install: 'pip install solana-pay-kit[flask]',
    server: '✅',
    client: '✅',
    href: `${REPO}/python/README.md`,
    snippet: `# app.py
from flask import Flask, jsonify
import pay_kit
from pay_kit import usd
from pay_kit.flask import require_payment

pay_kit.configure(network="solana_localnet")
app = Flask(__name__)

@app.get("/report")
@require_payment(usd("0.10"))
def report():
    return jsonify(content="premium content")

app.run(host="127.0.0.1", port=8000)`,
  },
  {
    id: 'ruby',
    name: 'Ruby',
    framework: 'Sinatra / Rails',
    install: 'gem install solana_pay_kit',
    server: '✅',
    client: '—',
    href: `${REPO}/ruby/README.md`,
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
  {
    id: 'php',
    name: 'PHP',
    framework: 'Laravel / Symfony',
    install: 'composer require solana-foundation/pay-kit',
    server: '✅',
    client: '—',
    href: `${REPO}/php/README.md`,
    snippet: `<?php
// routes/api.php
use PayKit\\Gate;
use PayKit\\Price;
use Illuminate\\Support\\Facades\\Route;

Route::get('/report', fn () => ['premium' => 'report'])
    ->middleware(['paykit:inline'])
    ->defaults('paykit.gate', new Gate(amount: Price::usd('0.10')));`,
  },
  {
    id: 'lua',
    name: 'Lua',
    framework: 'OpenResty / Kong / APISIX',
    install: 'luarocks install pay-kit',
    server: '✅',
    client: '—',
    href: `${REPO}/lua/README.md`,
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
  {
    id: 'kotlin',
    name: 'Kotlin',
    framework: 'JVM + Android (client)',
    install: 'implementation("com.solanafoundation:pay-kit:...")',
    server: '—',
    client: '✅',
    href: `${REPO}/kotlin/README.md`,
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
  {
    id: 'swift',
    name: 'Swift',
    framework: 'iOS + macOS (client)',
    install: '.package(path: "../pay-kit/swift")',
    server: '—',
    client: '✅',
    href: `${REPO}/swift/README.md`,
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
]
