import { useState, useCallback, type DragEvent } from 'react'
import {
  generateWallet,
  saveSecretKey,
  getSigner,
  requestAirdrop,
  importKeypairJson,
} from '../lib/wallet'

interface Props {
  onReady: () => void
}

type Screen = 'start' | 'generated' | 'importing'

export function WalletSetup({ onReady }: Props) {
  const [screen, setScreen] = useState<Screen>('start')
  const [address, setAddress] = useState('')
  const [importKey, setImportKey] = useState('')
  const [error, setError] = useState('')
  const [airdropping, setAirdropping] = useState(false)
  const [airdropped, setAirdropped] = useState(false)
  const [dragging, setDragging] = useState(false)

  const handleGenerate = async () => {
    try {
      const signer = await generateWallet()
      setAddress(signer.address)
      setScreen('generated')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const handleImport = async () => {
    try {
      setError('')
      saveSecretKey(importKey.trim())
      const signer = await getSigner()
      setAddress(signer.address)
      onReady()
    } catch (err) {
      setError('Invalid secret key: ' + (err instanceof Error ? err.message : String(err)))
    }
  }

  const handleAirdrop = async () => {
    setAirdropping(true)
    try {
      await requestAirdrop()
      setAirdropped(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setAirdropping(false)
    }
  }

  const handleFile = useCallback(async (file: File) => {
    try {
      setError('')
      const text = await file.text()
      const signer = await importKeypairJson(text)
      setAddress(signer.address)
      setScreen('generated')
    } catch (err) {
      setError('Failed to import keypair: ' + (err instanceof Error ? err.message : String(err)))
    }
  }, [])

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

  if (screen === 'generated') {
    return (
      <div className="setup-page">
        <div className="setup-card">
          <h2>Wallet ready</h2>
          <p className="sub">
            A new keypair was generated and stored in this browser's localStorage. Fund it once to start hitting paid
            endpoints.
          </p>
          <div className="modal-field" style={{ marginTop: 20 }}>
            <label>Address</label>
            <div className="value addr">{address}</div>
          </div>
          <div className="setup-actions">
            <button
              className={airdropped ? 'btn-secondary' : 'btn-primary'}
              onClick={handleAirdrop}
              disabled={airdropping || airdropped}
            >
              {airdropping ? 'Requesting…' : airdropped ? 'Funded ✓' : 'Airdrop 100 SOL + 100 USDC'}
            </button>
            <button className="btn-secondary" onClick={onReady}>
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
      <div className="setup-page">
        <div className="setup-card">
          <h2>Import wallet</h2>
          <p className="sub">Paste a base58-encoded 64-byte keypair.</p>
          <textarea
            className="param-row"
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
          {error && <div style={{ marginTop: 8, color: 'var(--red)', fontSize: 12 }}>{error}</div>}
          <div className="setup-actions">
            <button className="btn-secondary" onClick={() => setScreen('start')}>
              Back
            </button>
            <button className="btn-primary" onClick={handleImport} disabled={!importKey.trim()}>
              Import
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="setup-page" onDrop={onDrop} onDragOver={onDragOver} onDragLeave={onDragLeave}>
      <div className="setup-card">
        <h2>Welcome to PayKit Playground</h2>
        <p className="sub">
          A sandbox for testing the four payment primitives the kit ships: <strong>charges</strong>,{' '}
          <strong>subscriptions</strong>, <strong>sessions</strong>, and <strong>x402</strong>. Runs against the local
          Solana Payment Sandbox — no real funds needed.
        </p>
        <p className="sub" style={{ marginTop: 12, marginBottom: 0 }}>
          To get started, generate a fresh in-browser keypair, or drop a Solana CLI keypair JSON.
        </p>

        <div className={`drop-zone${dragging ? ' dragging' : ''}`} onDrop={onDrop} onDragOver={onDragOver} onDragLeave={onDragLeave}>
          <div className="icon">{dragging ? '↓' : '📄'}</div>
          <div className="hint">{dragging ? 'Drop keypair here' : 'Drop a Solana keypair JSON file'}</div>
          <label className="browse">
            or browse
            <input type="file" accept=".json" onChange={handleFileInput} style={{ display: 'none' }} />
          </label>
        </div>

        <div className="setup-actions">
          <button className="btn-primary" onClick={handleGenerate}>
            Generate new wallet
          </button>
          <button className="btn-secondary" onClick={() => setScreen('importing')}>
            Paste secret key
          </button>
        </div>
        {error && <div style={{ marginTop: 10, color: 'var(--red)', fontSize: 12 }}>{error}</div>}
      </div>
    </div>
  )
}
