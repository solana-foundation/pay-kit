import { useConfig } from '../hooks/useConfig'
import { EndpointWorkbench } from '../components/EndpointWorkbench'

export function X402({ onBalanceChange }: { onBalanceChange?: () => void }) {
  const config = useConfig()
  const endpoints = (config?.endpoints ?? []).filter((e) => e.primitive === 'x402')
  return <EndpointWorkbench endpoints={endpoints} primitive="x402" onBalanceChange={onBalanceChange} />
}
