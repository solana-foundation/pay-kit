import { useState, useEffect, createContext, useContext, type ReactNode, createElement } from 'react'
import type { ConfigResponse, Endpoint, Method, Primitive } from '../types'

const ConfigContext = createContext<ConfigResponse | null>(null)

/** A payment offer in an operation's `x-payment-info` extension. */
interface OpenApiOffer {
  amount?: string | null
  currency?: string
  description?: string
  feePayer?: string
  intent?: string
  method?: string
  network?: string
  payTo?: string
  planId?: string
  scheme?: string
  unitPrice?: string
}

interface OpenApiOperation {
  summary?: string
  'x-payment-info'?: { offers?: OpenApiOffer[] }
}

interface OpenApiDoc {
  paths?: Record<string, Record<string, OpenApiOperation>>
}

/**
 * Adapt the server's `/openapi.json` discovery document into the UI's config
 * shape. Each priced operation (one carrying `x-payment-info`) becomes an
 * endpoint; the offer's `intent` decides which primitive page it lands on —
 * `subscription` / `session` are first-class intents, and otherwise an
 * MPP-settleable charge → `charge`, else `x402`. The wallet/network metadata
 * is read from the offers themselves (mppx's per-endpoint convention), not a
 * bespoke document-level block.
 */
function toConfig(doc: OpenApiDoc): ConfigResponse {
  const endpoints: Endpoint[] = []
  let recipient = ''
  let network = ''
  let feePayer: string | undefined
  let planId: string | undefined

  for (const [openApiPath, item] of Object.entries(doc.paths ?? {})) {
    for (const [rawMethod, operation] of Object.entries(item)) {
      const offers = operation['x-payment-info']?.offers ?? []
      if (offers.length === 0) continue

      for (const offer of offers) {
        if (!recipient && offer.payTo) recipient = offer.payTo
        if (!network && offer.network) network = offer.network
        if (!feePayer && offer.feePayer) feePayer = offer.feePayer
        if (!planId && offer.planId) planId = offer.planId
      }

      const method = rawMethod.toUpperCase() as Method
      const path = openApiPath.replace(/\{([^}]+)\}/g, ':$1')
      const intent = offers.find((o) => o.intent)?.intent
      const primitive: Primitive =
        intent === 'subscription'
          ? 'subscription'
          : intent === 'session'
            ? 'session'
            : offers.some((o) => o.method === 'mpp')
              ? 'charge'
              : 'x402'
      const unitPrice = offers.find((o) => o.unitPrice)?.unitPrice
      const protocols = [...new Set(offers.map((o) => o.method))].filter(
        (m): m is 'mpp' | 'x402' => m === 'mpp' || m === 'x402',
      )
      const params = [...openApiPath.matchAll(/\{([^}]+)\}/g)].map((m) => ({
        name: m[1] ?? '',
        default: m[1] === 'symbol' ? 'SPCX' : '',
      }))

      // The endpoint name stays clean (the server's summary); the protocol +
      // scheme each offer settles through (e.g. "mpp/charge, x402/exact") is
      // derived from the offers and shown as the description.
      const schemes = [...new Set(offers.map((o) => [o.method, o.scheme].filter(Boolean).join('/')))]
        .filter(Boolean)
        .join(', ')

      endpoints.push({
        id: `${method}-${path}`.replace(/[^a-zA-Z0-9]+/g, '-').replace(/(^-|-$)/g, ''),
        primitive,
        method,
        path,
        title: operation.summary ?? path,
        description: schemes,
        cost: offers[0]?.description ?? '',
        ...(protocols.length ? { protocols } : {}),
        ...(unitPrice ? { unitPrice } : {}),
        ...(params.length ? { params } : {}),
      })
    }
  }

  // The server's RPC endpoint is intentionally not advertised in discovery.
  return { recipient, network, rpcUrl: '', feePayer, ...(planId ? { planId } : {}), endpoints }
}

export function ConfigProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<ConfigResponse | null>(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const res = await fetch('/openapi.json')
        if (!res.ok) throw new Error(`openapi ${res.status}`)
        const doc = (await res.json()) as OpenApiDoc
        if (!cancelled) setConfig(toConfig(doc))
      } catch {
        // surfpool may be cold; retry after a moment
        setTimeout(load, 1500)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  return createElement(ConfigContext.Provider, { value: config }, children)
}

export function useConfig() {
  return useContext(ConfigContext)
}

export function explorerAddrUrl(address: string, network: string): string {
  if (network === 'mainnet-beta' || network === 'mainnet') {
    return `https://explorer.solana.com/address/${address}`
  }
  if (network === 'devnet' || network === 'testnet') {
    return `https://explorer.solana.com/address/${address}?cluster=${network}`
  }
  return `https://explorer.solana.com/address/${address}?cluster=custom`
}
