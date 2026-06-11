import { useState, useEffect, useCallback } from 'react'
import { Routes, Route, useNavigate, Navigate, useLocation } from 'react-router-dom'
import { useTheme } from './hooks/useTheme'
import { useKeyboard } from './hooks/useKeyboard'
import { ConfigProvider, useConfig } from './hooks/useConfig'
import { Header } from './components/Header'
import { TopNav } from './components/TopNav'
import { WalletSetup } from './components/WalletSetup'
import { WalletModal } from './components/WalletModal'
import { EndpointPicker } from './components/EndpointPicker'
import { loadSecretKey, getSigner, getBalances, type Balances } from './lib/wallet'
import { Charges } from './pages/Charges'
import { Subscriptions } from './pages/Subscriptions'
import { Sessions } from './pages/Sessions'
import { X402 } from './pages/X402'
import { Docs } from './pages/Docs'
import { ApiReference } from './pages/ApiReference'
import type { Endpoint } from './types'

function pageRouteFor(ep: Endpoint): string {
  switch (ep.primitive) {
    case 'charge':
      return '/charges'
    case 'subscription':
      return '/subscriptions'
    case 'session':
      return '/sessions'
    case 'x402':
      return '/x402'
  }
}

function Shell() {
  const { theme, toggle: toggleTheme } = useTheme()
  const navigate = useNavigate()
  const location = useLocation()
  const config = useConfig()

  const [walletReady, setWalletReady] = useState(!!loadSecretKey())
  const [address, setAddress] = useState<string | null>(null)
  const [balances, setBalances] = useState<Balances | null>(null)
  const [showWallet, setShowWallet] = useState(false)
  const [showPicker, setShowPicker] = useState(false)
  const [selectedEndpointId, setSelectedEndpointId] = useState<string | null>(null)

  const refreshBalances = useCallback(async () => {
    if (!walletReady) return
    try {
      setBalances(await getBalances())
    } catch {
      /* surfpool may be down */
    }
  }, [walletReady])

  useEffect(() => {
    if (!walletReady) {
      setAddress(null)
      return
    }
    getSigner()
      .then((s) => setAddress(s.address))
      .catch(() => setAddress(null))
    refreshBalances()
  }, [walletReady, refreshBalances])

  const onEndpointClick = (ep: Endpoint) => {
    setSelectedEndpointId(ep.id)
    const target = pageRouteFor(ep)
    if (location.pathname !== target) navigate(`${target}?ep=${encodeURIComponent(ep.id)}`)
    else navigate(`${target}?ep=${encodeURIComponent(ep.id)}`, { replace: true })
  }

  useKeyboard([
    { key: 'k', meta: true, handler: () => setShowPicker((v) => !v) },
    { key: '.', meta: true, handler: toggleTheme },
    { key: 'Escape', handler: () => setShowPicker(false), preventDefault: false },
  ])

  if (!walletReady) {
    return <WalletSetup onReady={() => setWalletReady(true)} />
  }

  return (
    <div className="app">
      <Header
        theme={theme}
        onToggleTheme={toggleTheme}
        walletReady={walletReady}
        address={address}
        balances={balances}
        onOpenWallet={() => setShowWallet(true)}
      />
      <TopNav selectedEndpointId={selectedEndpointId} onEndpointClick={onEndpointClick} />
      <div className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/charges" replace />} />
          <Route path="/charges" element={<Charges onBalanceChange={refreshBalances} />} />
          <Route path="/subscriptions" element={<Subscriptions onBalanceChange={refreshBalances} />} />
          <Route path="/sessions" element={<Sessions onBalanceChange={refreshBalances} />} />
          <Route path="/x402" element={<X402 onBalanceChange={refreshBalances} />} />
          <Route path="/docs" element={<Docs />} />
          <Route path="/docs/ref/:lang" element={<ApiReference />} />
        </Routes>
      </div>
      {showWallet && (
        <WalletModal
          onClose={() => setShowWallet(false)}
          onReset={() => {
            setShowWallet(false)
            setWalletReady(false)
          }}
          onBalanceRefresh={refreshBalances}
        />
      )}
      {showPicker && config && (
        <EndpointPicker
          endpoints={config.endpoints}
          onClose={() => setShowPicker(false)}
          onSelect={(ep) => {
            setShowPicker(false)
            onEndpointClick(ep)
          }}
        />
      )}
    </div>
  )
}

export function App() {
  return (
    <ConfigProvider>
      <Shell />
    </ConfigProvider>
  )
}
