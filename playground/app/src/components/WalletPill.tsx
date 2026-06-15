import type { Balances } from '../lib/wallet'

interface Props {
  address: string
  balances: Balances | null
  onClick: () => void
}

function shorten(addr: string): string {
  if (addr.length <= 12) return addr
  return `${addr.slice(0, 4)}…${addr.slice(-4)}`
}

export function WalletPill({ address, balances, onClick }: Props) {
  return (
    <button className="wallet-pill" onClick={onClick} title="Wallet details">
      <span className="addr">{shorten(address)}</span>
      <span className="usdc">{balances ? balances.usdc.toFixed(2) : '—'} USDC</span>
      <span className="fund-btn">Fund</span>
    </button>
  )
}
