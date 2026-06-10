import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReceiptState, VoucherState } from '../../lib/gemini/types'

interface Props {
  isRunning: boolean
  receipt?: ReceiptState
  voucher: VoucherState | null
}

const ACTIVE_LAG_MS = 650
const IDLE_CATCH_UP_MS = 140
const RECEIPT_CATCH_UP_MS = 90
const MIN_USD_PER_SECOND = 0.000035
const DISPLAY_EPSILON = 0.00000005

export function AnimatedCost({ isRunning, receipt, voucher }: Props) {
  const receiptTransactionId = receipt?.transactionId
  const targetAmount = useMemo(() => parseUsdcAmount(voucher?.cumulativeUsdc), [voucher?.cumulativeUsdc])
  const [displayAmount, setDisplayAmount] = useState(targetAmount)
  const [isBlinking, setIsBlinking] = useState(false)
  const displayRef = useRef(displayAmount)
  const isRunningRef = useRef(isRunning)
  const receiptRef = useRef(receiptTransactionId)
  const targetRef = useRef(targetAmount)

  useEffect(() => {
    targetRef.current = targetAmount
  }, [targetAmount])

  useEffect(() => {
    isRunningRef.current = isRunning
  }, [isRunning])

  useEffect(() => {
    receiptRef.current = receiptTransactionId
  }, [receiptTransactionId])

  useEffect(() => {
    let frame = 0
    let previous = performance.now()
    function tick(now: number) {
      const elapsedMs = Math.max(0, now - previous)
      previous = now
      const current = displayRef.current
      const target = targetRef.current
      const gap = target - current

      if (gap < 0) {
        displayRef.current = target
        setDisplayAmount(target)
      } else if (gap > DISPLAY_EPSILON) {
        const lagMs = receiptRef.current
          ? RECEIPT_CATCH_UP_MS
          : isRunningRef.current
            ? ACTIVE_LAG_MS
            : IDLE_CATCH_UP_MS
        const easedStep = (gap * elapsedMs) / lagMs
        const minimumStep = MIN_USD_PER_SECOND * (elapsedMs / 1_000)
        let next = Math.min(target, current + Math.max(easedStep, minimumStep))
        if (!isRunningRef.current && target - next < DISPLAY_EPSILON * 10) next = target
        displayRef.current = next
        setDisplayAmount(next)
      }
      frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [])

  useEffect(() => {
    if (!receiptTransactionId) {
      setIsBlinking(false)
      return
    }
    const blinkTimer = window.setTimeout(() => setIsBlinking(true), 280)
    const stopBlinkTimer = window.setTimeout(() => setIsBlinking(false), 900)
    return () => {
      clearTimeout(blinkTimer)
      clearTimeout(stopBlinkTimer)
    }
  }, [receiptTransactionId])

  return (
    <div className="gemini-counter gemini-counter-cost">
      <div className="gemini-counter-label">Cost</div>
      <div className={`gemini-counter-value${isBlinking ? ' blinking' : ''}`}>{formatUsdDisplay(displayAmount)}</div>
    </div>
  )
}

function parseUsdcAmount(value: string | undefined): number {
  if (!value) return 0
  const numeric = Number.parseFloat(value.replace(/\s*USDC$/u, ''))
  return Number.isFinite(numeric) ? numeric : 0
}

function formatUsdDisplay(value: number): string {
  return `$${Math.max(0, value).toFixed(6)}`
}

interface MetricProps {
  isRunning: boolean
  label: string
  value: number
}

export function AnimatedTokenCounter({ isRunning, label, value }: MetricProps) {
  const displayed = useAnimatedInteger(value, isRunning)
  const [isUpdating, setIsUpdating] = useState(false)

  useEffect(() => {
    if (value === 0) {
      setIsUpdating(false)
      return
    }
    setIsUpdating(true)
    const timer = window.setTimeout(() => setIsUpdating(false), 180)
    return () => clearTimeout(timer)
  }, [value])

  return (
    <div className="gemini-counter">
      <div className="gemini-counter-label">{label}</div>
      <div className={`gemini-counter-value${isUpdating ? ' updating' : ''}`}>{formatInteger(displayed)}</div>
    </div>
  )
}

function useAnimatedInteger(target: number, isRunning: boolean): number {
  const [displayed, setDisplayed] = useState(target)
  const displayedRef = useRef(target)
  const targetRef = useRef(target)
  const isRunningRef = useRef(isRunning)

  useEffect(() => {
    targetRef.current = target
  }, [target])

  useEffect(() => {
    isRunningRef.current = isRunning
  }, [isRunning])

  useEffect(() => {
    let frame = 0
    let previous = performance.now()
    function tick(now: number) {
      const elapsedMs = Math.max(0, now - previous)
      previous = now
      const current = displayedRef.current
      const targetValue = targetRef.current
      const gap = targetValue - current
      if (gap < 0) {
        displayedRef.current = targetValue
        setDisplayed(targetValue)
      } else if (gap >= 1) {
        const lagMs = isRunningRef.current ? 520 : 120
        const easedStep = (gap * elapsedMs) / lagMs
        const minimumStep = 90 * (elapsedMs / 1_000)
        const next = Math.min(targetValue, current + Math.max(easedStep, minimumStep))
        displayedRef.current = next
        setDisplayed(Math.round(next))
      } else if (current !== targetValue) {
        displayedRef.current = targetValue
        setDisplayed(targetValue)
      }
      frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [])

  return displayed
}

function formatInteger(value: number): string {
  return Math.max(0, Math.round(value)).toLocaleString('en-US')
}
