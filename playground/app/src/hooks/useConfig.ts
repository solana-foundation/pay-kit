import { useState, useEffect, createContext, useContext, type ReactNode, createElement } from 'react'
import type { ConfigResponse } from '../types'

const ConfigContext = createContext<ConfigResponse | null>(null)

export function ConfigProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<ConfigResponse | null>(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const res = await fetch('/api/v1/config')
        if (!res.ok) throw new Error(`config ${res.status}`)
        const data = (await res.json()) as ConfigResponse
        if (!cancelled) setConfig(data)
      } catch (err) {
        // surfpool may be cold; retry once after a moment
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
