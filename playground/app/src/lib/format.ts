export function shortenAddr(addr: string, head = 4, tail = 4): string {
  if (addr.length <= head + tail + 1) return addr
  return `${addr.slice(0, head)}…${addr.slice(-tail)}`
}

export function fmtUnits(amount: string | number | bigint, decimals: number, symbol = 'USDC'): string {
  const n = typeof amount === 'bigint' ? amount : BigInt(amount)
  const divisor = 10n ** BigInt(decimals)
  const whole = n / divisor
  const frac = n % divisor
  const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '')
  const value = fracStr ? `${whole}.${fracStr}` : whole.toString()
  return `${value} ${symbol}`
}

export function fmtTime(d: Date | string): string {
  const dt = typeof d === 'string' ? new Date(d) : d
  const hh = String(dt.getHours()).padStart(2, '0')
  const mm = String(dt.getMinutes()).padStart(2, '0')
  const ss = String(dt.getSeconds()).padStart(2, '0')
  const ms = String(dt.getMilliseconds()).padStart(3, '0')
  return `${hh}:${mm}:${ss}.${ms}`
}

export function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(2)}s`
}
