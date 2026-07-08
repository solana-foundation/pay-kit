import { useState, useCallback, type DragEvent } from 'react'
import { generateWallet, saveSecretKey, getSigner, requestAirdrop, importKeypairJson } from '../lib/wallet'

interface Props {
  onReady: () => void
}

type Screen = 'start' | 'funded' | 'importing'

export function WalletSetup({ onReady }: Props) {
  const [screen, setScreen] = useState<Screen>('start')
  const [address, setAddress] = useState('')
  const [importKey, setImportKey] = useState('')
  const [error, setError] = useState('')
  const [funding, setFunding] = useState(false)
  const [funded, setFunded] = useState(false)
  const [dragging, setDragging] = useState(false)

  // Create a fresh in-browser keypair and fund it with USDC. No SOL — the
  // server is the fee payer for every request, so client wallets never pay fees.
  const handleFundNew = async () => {
    setError('')
    setFunding(true)
    try {
      if (!address) setAddress((await generateWallet()).address)
      setScreen('funded')
      await requestAirdrop()
      setFunded(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setFunding(false)
    }
  }

  const handleImport = async () => {
    try {
      setError('')
      saveSecretKey(importKey.trim())
      await getSigner()
      onReady()
    } catch (err) {
      setError('Invalid private key: ' + (err instanceof Error ? err.message : String(err)))
    }
  }

  const handleFile = useCallback(
    async (file: File) => {
      try {
        setError('')
        await importKeypairJson(await file.text())
        onReady()
      } catch (err) {
        setError('Failed to load keypair: ' + (err instanceof Error ? err.message : String(err)))
      }
    },
    [onReady],
  )

  const onDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault()
      setDragging(false)
      const file = e.dataTransfer.files[0]
      if (file) handleFile(file)
    },
    [handleFile],
  )
  const onDragOver = (e: DragEvent) => {
    e.preventDefault()
    setDragging(true)
  }
  const onDragLeave = () => setDragging(false)
  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
  }

  if (screen === 'funded') {
    return (
      <div className="setup-page">
        <div className="setup-card">
          <h2>{funded ? 'Account funded' : 'Funding account…'}</h2>
          <p className="sub">
            A new keypair was generated and stored in this browser's localStorage
            {funded ? ', funded with 100 USDC.' : '.'} It pays no network fees — the server fee-pays every request.
          </p>
          <div className="modal-field" style={{ marginTop: 20 }}>
            <label>Address</label>
            <div className="value addr">{address}</div>
          </div>
          <div className="setup-actions">
            {!funded && (
              <button className="btn-primary" onClick={handleFundNew} disabled={funding}>
                {funding ? 'Funding…' : 'Retry funding'}
              </button>
            )}
            <button className={funded ? 'btn-primary' : 'btn-secondary'} onClick={onReady}>
              Enter playground
            </button>
          </div>
          {error && <div style={{ marginTop: 10, color: 'var(--red)', fontSize: 12 }}>{error}</div>}
        </div>
      </div>
    )
  }

  if (screen === 'importing') {
    return (
      <div className="setup-page" onDrop={onDrop} onDragOver={onDragOver} onDragLeave={onDragLeave}>
        <div className="setup-card">
          <h2>Load a private key</h2>
          <p className="sub">Paste a base58-encoded 64-byte secret key, or drop a Solana CLI keypair JSON.</p>
          <textarea
            value={importKey}
            onChange={(e) => setImportKey(e.target.value)}
            placeholder="Paste secret key…"
            rows={3}
            style={{
              width: '100%',
              background: 'var(--bg)',
              border: '1px solid var(--border)',
              color: 'var(--fg)',
              padding: 10,
              borderRadius: 'var(--radius)',
              fontFamily: 'var(--font-mono)',
              fontSize: 12,
              resize: 'vertical',
              outline: 'none',
              marginTop: 12,
            }}
          />
          <div
            className={`drop-zone${dragging ? ' dragging' : ''}`}
            onDrop={onDrop}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
          >
            <div className="icon">{dragging ? '↓' : '📄'}</div>
            <div className="hint">{dragging ? 'Drop keypair here' : 'or drop a keypair JSON'}</div>
            <label className="browse">
              browse
              <input type="file" accept=".json" onChange={handleFileInput} style={{ display: 'none' }} />
            </label>
          </div>
          {error && <div style={{ marginTop: 8, color: 'var(--red)', fontSize: 12 }}>{error}</div>}
          <div className="setup-actions">
            <button
              className="btn-secondary"
              onClick={() => {
                setScreen('start')
                setError('')
              }}
            >
              Back
            </button>
            <button className="btn-primary" onClick={handleImport} disabled={!importKey.trim()}>
              Load key
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="setup-page">
      <div className="setup-card">
        <h2>Welcome to PayKit Playground</h2>
        <p className="sub">
          A sandbox for the four payment primitives the kit ships: <strong>charges</strong>,{' '}
          <strong>subscriptions</strong>, <strong>sessions</strong>, and <strong>x402</strong>. Runs against the local
          Solana Payment Sandbox — no real funds needed.
        </p>
        <div className="setup-actions" style={{ marginTop: 24 }}>
          <button className="btn-primary" onClick={handleFundNew} disabled={funding}>
            Fund a new account
          </button>
          <button className="btn-secondary" onClick={() => setScreen('importing')}>
            Load a private key
          </button>
        </div>
        {error && <div style={{ marginTop: 10, color: 'var(--red)', fontSize: 12 }}>{error}</div>}
      </div>
    </div>
  )
}
