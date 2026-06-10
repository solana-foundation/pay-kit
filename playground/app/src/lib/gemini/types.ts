export interface PaymentEvent {
  readonly detail: string
  readonly label: string
  readonly state: 'error' | 'success' | 'working'
}

export interface VoucherState {
  readonly baselineCumulativeAmount?: string
  readonly cumulativeAmount: string
  readonly cumulativeUsdc: string
  readonly currency: string
  readonly decimals?: number
  readonly deliveryId?: string
  readonly deltaAmount?: string
  readonly minVoucherDeltaAmount?: string
  readonly sessionId: string
  readonly source: 'committed' | 'local-meter'
}

export interface ReceiptState {
  readonly explorerUrl: string
  readonly transactionId: string
}

export interface GeminiUsage {
  readonly candidatesTokenCount?: number
  readonly promptTokenCount?: number
  readonly thoughtsTokenCount?: number
  readonly totalTokenCount?: number
}

export interface GeminiDemoResponse {
  readonly error?: string
  readonly model?: string
  readonly modelVersion?: string
  readonly paymentEvents?: PaymentEvent[]
  readonly proxyBaseUrl?: string
  readonly receipt?: ReceiptState
  readonly text?: string
  readonly usage?: GeminiUsage
  readonly voucher?: VoucherState
}

export type GeminiDemoStreamEvent =
  | { readonly model: string; readonly proxyBaseUrl: string; readonly type: 'meta' }
  | { readonly event: PaymentEvent; readonly type: 'payment' }
  | { readonly text: string; readonly type: 'delta' }
  | { readonly modelVersion?: string; readonly type: 'usage'; readonly usage?: GeminiUsage }
  | { readonly error: string; readonly type: 'error' }
  | { readonly receipt: ReceiptState; readonly type: 'receipt' }
  | {
      readonly model: string
      readonly modelVersion?: string
      readonly type: 'done'
      readonly usage?: GeminiUsage
    }
  | { readonly type: 'voucher'; readonly voucher: VoucherState }

export type RunState = 'error' | 'idle' | 'running' | 'success'
