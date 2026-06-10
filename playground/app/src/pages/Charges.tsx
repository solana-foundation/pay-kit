import { useConfig } from '../hooks/useConfig'
import { EndpointWorkbench } from '../components/EndpointWorkbench'

export function Charges({ onBalanceChange }: { onBalanceChange?: () => void }) {
  const config = useConfig()
  const endpoints = (config?.endpoints ?? []).filter((e) => e.primitive === 'charge')
  return <EndpointWorkbench endpoints={endpoints} primitive="charge" onBalanceChange={onBalanceChange} />
}
