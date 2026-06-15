export type Primitive = 'charge' | 'subscription' | 'session' | 'x402'

export type Method = 'GET' | 'POST'

export interface ParamSpec {
  name: string
  default: string
  description?: string
}

export interface Endpoint {
  id: string
  primitive: Primitive
  method: Method
  path: string
  title: string
  description: string
  cost: string
  /** Machine-readable per-delivery price in base units (sessions only). */
  unitPrice?: string
  params?: ParamSpec[]
  /** Optional override of which primitive-page the endpoint lives on. Defaults to the primitive's page. */
  page?: 'charges' | 'subscriptions' | 'sessions' | 'x402'
}

export interface ConfigResponse {
  recipient: string
  network: string
  rpcUrl: string
  feePayer?: string
  planId?: string
  endpoints: Endpoint[]
}

export type LogKind = 'req' | 'x402' | 'ok' | 'error' | 'info' | 'dim'

export interface LogLine {
  id: number
  ts: string
  message: string
  kind: LogKind
  detail?: string
  /** Optional external URL — rendered as a trailing link in the entry. */
  link?: { href: string; label: string }
}

export type FlowStepStatus = 'pending' | 'in-progress' | 'completed' | 'failed'

export interface FlowStep {
  key: string
  label: string
  status: FlowStepStatus
  ts?: string
}

export type MobileTab = 'api' | 'flow' | 'response' | 'code'

export type ResponsePayload =
  | { kind: 'json'; data: unknown; status: number; headers: Record<string, string>; latencyMs: number }
  | { kind: 'text'; text: string; status: number; headers: Record<string, string>; latencyMs: number }
  | { kind: 'error'; message: string }

export type FlowProgress =
  | { type: 'request'; url: string; method: string }
  | { type: 'challenge'; amount: string; currency: string; recipient: string; feePayerKey?: string; decimals?: number }
  | { type: 'signing' }
  | { type: 'paying' }
  | { type: 'confirming'; signature: string }
  | { type: 'paid'; signature: string }
  | { type: 'activated'; signature: string }
  | { type: 'voucher'; cumulative: string; delta: string }
  // Partial body of a streamed (SSE) response — `text` is everything
  // received so far, so the UI can render the stream as it arrives.
  | { type: 'chunk'; text: string; status: number; headers: Record<string, string>; latencyMs: number }
  | { type: 'success'; data: unknown; status: number; headers: Record<string, string>; latencyMs: number }
  | { type: 'error'; message: string }
