import { InvalidExternalBudgetError } from './errors.js'

export type ExternalScanBudgets = Readonly<{
  maxRequests: number
  maxRedirects: number
  maxAssets: number
  maxResponseBytes: number
  maxHtmlBytes: number
  maxAssetBytes: number
  maxDecompressedBytes: number
  maxHeaderBytes: number
  connectTimeoutMs: number
  responseTimeoutMs: number
  overallDeadlineMs: number
  maxConcurrency: number
}>

export type ExternalScanBudgetOverrides = Readonly<
  Partial<{
    maxRequests: number
    maxRedirects: number
    maxAssets: number
    maxResponseBytes: number
    maxHtmlBytes: number
    maxAssetBytes: number
    maxDecompressedBytes: number
    maxHeaderBytes: number
    connectTimeoutMs: number
    responseTimeoutMs: number
    overallDeadlineMs: number
    maxConcurrency: number
  }>
>

/** Accepted E1 plan defaults. */
export const EXTERNAL_BUDGET_DEFAULTS: ExternalScanBudgets = Object.freeze({
  maxRequests: 12,
  maxRedirects: 5,
  maxAssets: 8,
  maxResponseBytes: 1 * 1024 * 1024,
  maxHtmlBytes: 512 * 1024,
  maxAssetBytes: 512 * 1024,
  maxDecompressedBytes: 2 * 1024 * 1024,
  maxHeaderBytes: 64 * 1024,
  connectTimeoutMs: 5_000,
  responseTimeoutMs: 10_000,
  overallDeadlineMs: 30_000,
  maxConcurrency: 2,
})

/** Accepted E1 hard safety maxima. Configured values must not exceed these. */
export const EXTERNAL_BUDGET_HARD_SAFETY_MAX: ExternalScanBudgets = Object.freeze({
  maxRequests: 32,
  maxRedirects: 10,
  maxAssets: 16,
  maxResponseBytes: 4 * 1024 * 1024,
  maxHtmlBytes: 2 * 1024 * 1024,
  maxAssetBytes: 2 * 1024 * 1024,
  maxDecompressedBytes: 8 * 1024 * 1024,
  maxHeaderBytes: 128 * 1024,
  connectTimeoutMs: 15_000,
  responseTimeoutMs: 30_000,
  overallDeadlineMs: 120_000,
  maxConcurrency: 4,
})

const BUDGET_KEYS = Object.freeze([
  'maxRequests',
  'maxRedirects',
  'maxAssets',
  'maxResponseBytes',
  'maxHtmlBytes',
  'maxAssetBytes',
  'maxDecompressedBytes',
  'maxHeaderBytes',
  'connectTimeoutMs',
  'responseTimeoutMs',
  'overallDeadlineMs',
  'maxConcurrency',
] as const)

type BudgetKey = (typeof BUDGET_KEYS)[number]

/**
 * Fields that may be zero (e.g. disable redirects/assets). Positive-only fields
 * reject zero.
 */
const ZERO_ALLOWED = new Set<BudgetKey>(['maxRedirects', 'maxAssets'])

export function createExternalScanBudgets(
  overrides: unknown = {},
): ExternalScanBudgets {
  if (typeof overrides !== 'object' || overrides === null || Array.isArray(overrides)) {
    throw new InvalidExternalBudgetError()
  }

  const record = overrides as ExternalScanBudgetOverrides
  const result: Record<BudgetKey, number> = { ...EXTERNAL_BUDGET_DEFAULTS }

  for (const key of BUDGET_KEYS) {
    if (!(key in record)) continue
    result[key] = readBudgetInteger(record[key], key)
  }

  return Object.freeze(result)
}

function readBudgetInteger(value: unknown, key: BudgetKey): number {
  if (
    typeof value !== 'number' ||
    !Number.isFinite(value) ||
    !Number.isInteger(value)
  ) {
    throw new InvalidExternalBudgetError()
  }
  if (value < 0) throw new InvalidExternalBudgetError()
  if (value === 0 && !ZERO_ALLOWED.has(key)) {
    throw new InvalidExternalBudgetError()
  }
  if (value > EXTERNAL_BUDGET_HARD_SAFETY_MAX[key]) {
    throw new InvalidExternalBudgetError()
  }
  return value
}
