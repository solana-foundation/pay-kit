import { useState, useEffect } from 'react'
import {
  getBalances,
  clearWallet,
  loadSecretKey,
  getSigner,
  requestAirdrop,
  type Balances,
} from '../lib/wallet'
import { resetMppxClients } from '../lib/flow'

interface Props {
  onClose: () => void
  onReset: () => void
  onBalanceRefresh: () => void
}

export function WalletModal({ onClose, onReset, onBalanceRefresh }: Props) {
  const [address, setAddress] = useState('')
  const [balances, setBalances] = useState<Balances | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    getSigner().then((s) => setAddress(s.address))
    getBalances()
      .then(setBalances)
      .catch(() => {})
  }, [])

  const handleReset = () => {
    clearWallet()
    resetMppxClients()
    onReset()
  }

  const handleFund = async () => {
    setBusy(true)
    try {
      await requestAirdrop()
      const next = await getBalances()
      setBalances(next)
      onBalanceRefresh()
    } finally {
      setBusy(false)
    }
  }

  const copy = (text: string) => navigator.clipboard.writeText(text)
  const copyKey = () => {
    const key = loadSecretKey()
    if (key) copy(key)
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>Wallet</h3>

        <div className="modal-field">
          <div className="modal-row">
            <label>Address</label>
            <button className="btn-ghost" onClick={() => copy(address)}>
              copy
            </button>
          </div>
          <div className="value addr">{address}</div>
        </div>

        <div className="modal-field">
          <label>Balances</label>
          <div style={{ display: 'flex', gap: 20, marginTop: 4 }}>
            <div>
              <div style={{ color: 'var(--green)', fontSize: 18, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                {balances ? balances.usdc.toFixed(2) : '—'}
              </div>
              <div style={{ color: 'var(--fg-muted)', fontSize: 10 }}>USDC</div>
            </div>
            <div>
              <div style={{ color: 'var(--fg)', fontSize: 18, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                {balances ? balances.sol.toFixed(4) : '—'}
              </div>
              <div style={{ color: 'var(--fg-muted)', fontSize: 10 }}>SOL</div>
            </div>
          </div>
        </div>

        <div className="modal-field">
          <div className="modal-row">
            <label>Secret key</label>
            <button className="btn-ghost" onClick={copyKey}>
              copy
            </button>
          </div>
          <div style={{ color: 'var(--fg-muted)', fontSize: 11 }}>Base58 64-byte keypair. Keep it secret.</div>
        </div>

        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose}>
            Close
          </button>
          <button className="btn-primary" onClick={handleFund} disabled={busy}>
            {busy ? 'Funding…' : 'Airdrop 100 SOL + 100 USDC'}
          </button>
          <button className="btn-danger" onClick={handleReset}>
            Reset
          </button>
        </div>
      </div>
    </div>
  )
}
