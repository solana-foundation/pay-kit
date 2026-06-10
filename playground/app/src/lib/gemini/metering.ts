import type { GeminiUsage } from './types'

export interface UnitPrice {
  readonly microUsdPerUnit: number
  readonly tokensPerUnit: number
}

export interface GeminiMeteringSpec {
  readonly input: UnitPrice
  readonly output: UnitPrice
}

export interface TokenPriceBreakdown {
  readonly amount: string
  readonly microUsdPerUnit: number
  readonly tokens: number
  readonly tokensPerUnit: number
  readonly units: number
}

export interface GeminiMeteringBreakdown {
  readonly baselineCumulativeAmount: string
  readonly cumulativeAmount: string
  readonly currentCumulativeAmount: string
  readonly deltaAmount: string
  readonly input: TokenPriceBreakdown
  readonly minVoucherDeltaAmount: string
  readonly output: TokenPriceBreakdown
  readonly rawAmount: string
  readonly roundedAmount: string
}

export function getGeminiMeteringSpec(model: string): GeminiMeteringSpec {
  return geminiMeter(model)
}

export function createGeminiMeteringBreakdown({
  baselineCumulativeAmount,
  currentCumulativeAmount,
  minVoucherDeltaAmount,
  model,
  targetCumulativeAmount,
  usage,
}: {
  baselineCumulativeAmount: string
  currentCumulativeAmount: string
  minVoucherDeltaAmount: string
  model: string
  targetCumulativeAmount?: string
  usage: GeminiUsage | undefined
}): GeminiMeteringBreakdown | null {
  if (!usage) return null
  const meter = geminiMeter(model)
  const inputTokens = usage.promptTokenCount ?? 0
  const meteredOutputTokens = Math.max(0, (usage.totalTokenCount ?? 0) - inputTokens)
  const outputTokens = Math.max(usage.candidatesTokenCount ?? 0, meteredOutputTokens)
  const input = tokenPriceBreakdown(inputTokens, meter.input)
  const output = tokenPriceBreakdown(outputTokens, meter.output)
  const rawAmount = BigInt(input.amount) + BigInt(output.amount)
  const minDelta = parsePositiveBigInt(minVoucherDeltaAmount) ?? BigInt(1)
  const roundedAmount = rawAmount === BigInt(0) ? BigInt(0) : roundUp(rawAmount, minDelta)
  const baseline = parseBigIntOrZero(baselineCumulativeAmount)
  const current = parseBigIntOrZero(currentCumulativeAmount)
  const target =
    targetCumulativeAmount === undefined ? baseline + roundedAmount : parseBigIntOrZero(targetCumulativeAmount)
  const displayBaseline =
    targetCumulativeAmount === undefined ? baseline : maxBigInt(BigInt(0), target - roundedAmount)
  const cumulativeAmount = targetCumulativeAmount === undefined ? baseline + roundedAmount : target
  const deltaAmount = cumulativeAmount > current ? cumulativeAmount - current : BigInt(0)
  return {
    baselineCumulativeAmount: displayBaseline.toString(),
    cumulativeAmount: cumulativeAmount.toString(),
    currentCumulativeAmount: current.toString(),
    deltaAmount: deltaAmount.toString(),
    input,
    minVoucherDeltaAmount: minDelta.toString(),
    output,
    rawAmount: rawAmount.toString(),
    roundedAmount: roundedAmount.toString(),
  }
}

function tokenPriceBreakdown(tokens: number, price: UnitPrice): TokenPriceBreakdown {
  const units = Math.ceil(tokens / price.tokensPerUnit)
  return {
    amount: (BigInt(units) * BigInt(price.microUsdPerUnit)).toString(),
    microUsdPerUnit: price.microUsdPerUnit,
    tokens,
    tokensPerUnit: price.tokensPerUnit,
    units,
  }
}

function geminiMeter(model: string): GeminiMeteringSpec {
  if (model.includes('gemini-2.5-flash-lite') || model.includes('gemini-2.0-flash')) {
    return {
      input: { microUsdPerUnit: 1, tokensPerUnit: 10 },
      output: { microUsdPerUnit: 2, tokensPerUnit: 5 },
    }
  }
  if (model.includes('gemini-2.5-pro')) {
    return {
      input: { microUsdPerUnit: 5, tokensPerUnit: 4 },
      output: { microUsdPerUnit: 10, tokensPerUnit: 1 },
    }
  }
  return {
    input: { microUsdPerUnit: 3, tokensPerUnit: 10 },
    output: { microUsdPerUnit: 5, tokensPerUnit: 2 },
  }
}

function parseBigIntOrZero(value: string): bigint {
  try {
    return BigInt(value)
  } catch {
    return BigInt(0)
  }
}

function parsePositiveBigInt(value: string): bigint | undefined {
  try {
    const parsed = BigInt(value)
    return parsed > BigInt(0) ? parsed : undefined
  } catch {
    return undefined
  }
}

function roundUp(value: bigint, step: bigint): bigint {
  const remainder = value % step
  return remainder === BigInt(0) ? value : value + step - remainder
}

function maxBigInt(left: bigint, right: bigint): bigint {
  return left > right ? left : right
}
