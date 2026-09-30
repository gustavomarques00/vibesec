import {
  createExternalScanBudgets,
  type ExternalScanBudgetOverrides,
  type ExternalScanBudgets,
} from '../domain/budgets.js'
import {
  InvalidExternalBudgetError,
  InvalidExternalTargetError,
  UnsupportedExternalPortError,
  UnsupportedExternalSchemeError,
} from '../domain/errors.js'
import { normalizeExternalTarget } from '../domain/target.js'
import { ExternalTransportError } from '../infra/errors.js'
import type { OutboundHttpCapability } from '../infra/types.js'
import { scanExternalDocument } from '../orchestration/index.js'
import {
  createExternalScanResult,
  deriveExternalLimitations,
  renderExternalReport,
  type ExternalReportFormat,
  type ExternalScanResult,
} from '../reporters/index.js'
import { evaluateExternalRules } from '../rules/index.js'

export type { ExternalReportFormat, ExternalScanResult }

export type ExternalScanOptions = Readonly<{
  format: ExternalReportFormat
  /** Required injectable transport — production CLI supplies secure capability. */
  transport: OutboundHttpCapability
  budgets?: ExternalScanBudgetOverrides
  /**
   * Deterministic evaluation clock (ms since epoch).
   * Production may omit and use an injected clock; tests must supply fixed time.
   */
  evaluationTimeMs?: number
  /** Optional clock used when evaluationTimeMs is omitted. */
  clock?: () => number
  signal?: AbortSignal
}>

export type ExternalScanApplicationResult = Readonly<{
  output: string
  findingCount: number
  result: ExternalScanResult
}>

/**
 * Controlled External failure for CLI mapping (exit 2).
 * Message is intentional and must not include secrets or stack details.
 */
export class ExternalScanError extends Error {
  constructor(message = 'The External scan could not be completed.') {
    super(message)
    this.name = 'ExternalScanError'
  }
}

/**
 * Application composition: target → transport → graph → rules → result.
 * Network capability must be supplied by the caller (CLI production path).
 */
export async function runExternalScan(
  target: string,
  options: ExternalScanOptions,
): Promise<ExternalScanApplicationResult> {
  if (typeof target !== 'string' || target.trim().length === 0) {
    throw new ExternalScanError('The External target is invalid.')
  }

  let budgets: ExternalScanBudgets
  try {
    budgets = createExternalScanBudgets(options.budgets ?? {})
  } catch (error) {
    throw mapExternalFailure(error)
  }

  const evaluationTimeMs = resolveEvaluationTimeMs(options)

  let normalizedDisplayTarget: string
  try {
    normalizedDisplayTarget = normalizeExternalTarget(target).requestUrl
  } catch (error) {
    throw mapExternalFailure(error)
  }

  let documentScan
  try {
    documentScan = await scanExternalDocument({
      target,
      budgets,
      transport: options.transport,
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
    })
  } catch (error) {
    throw mapExternalFailure(error)
  }

  const findings = evaluateExternalRules(documentScan.graph, { evaluationTimeMs })
  const limitations = deriveExternalLimitations(documentScan.graph)
  const effectiveUrl = documentScan.graph.finalUrl ?? normalizedDisplayTarget

  const result = createExternalScanResult({
    target: normalizedDisplayTarget,
    effectiveUrl,
    findings,
    limitations,
    evaluationTimeMs,
    requestsConsumed: documentScan.requestsConsumed,
  })

  const output = renderExternalReport(result, options.format)
  return Object.freeze({
    output,
    findingCount: findings.length,
    result,
  })
}

function resolveEvaluationTimeMs(options: ExternalScanOptions): number {
  if (
    typeof options.evaluationTimeMs === 'number' &&
    Number.isFinite(options.evaluationTimeMs)
  ) {
    return Math.trunc(options.evaluationTimeMs)
  }
  if (options.clock !== undefined) {
    const value = options.clock()
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new ExternalScanError('The External evaluation clock is invalid.')
    }
    return Math.trunc(value)
  }
  // Composition-boundary default only — rules/reporters must not call Date.now().
  return Date.now()
}

function mapExternalFailure(error: unknown): ExternalScanError {
  if (error instanceof ExternalScanError) return error
  if (error instanceof InvalidExternalTargetError) {
    return new ExternalScanError('The External target is invalid.')
  }
  if (error instanceof UnsupportedExternalSchemeError) {
    return new ExternalScanError('The External target scheme is not supported.')
  }
  if (error instanceof UnsupportedExternalPortError) {
    return new ExternalScanError('The External target port is not supported.')
  }
  if (error instanceof InvalidExternalBudgetError) {
    return new ExternalScanError('The External scan budget configuration is invalid.')
  }
  if (error instanceof ExternalTransportError) {
    return new ExternalScanError(safeTransportMessage(error.code))
  }
  return new ExternalScanError('The External scan could not be completed.')
}

function safeTransportMessage(code: string): string {
  switch (code) {
    case 'DnsFailure':
      return 'External scan failed: DNS resolution failed.'
    case 'BlockedDestination':
      return 'External scan failed: destination is not allowed.'
    case 'ConnectTimeout':
      return 'External scan failed: connection timed out.'
    case 'ConnectionFailed':
      return 'External scan failed: connection failed.'
    case 'RemoteAddressMismatch':
      return 'External scan failed: remote address verification failed.'
    case 'TlsFailure':
      return 'External scan failed: TLS verification failed.'
    case 'RedirectBlocked':
      return 'External scan failed: redirect was blocked by policy.'
    case 'RedirectLoop':
      return 'External scan failed: redirect loop detected.'
    case 'RedirectBudgetExceeded':
      return 'External scan failed: redirect budget exceeded.'
    case 'RequestBudgetExceeded':
      return 'External scan failed: request budget exceeded.'
    case 'ResponseTimeout':
      return 'External scan failed: response timed out.'
    case 'ResponseTooLarge':
      return 'External scan failed: response exceeded size limits.'
    case 'HeaderTooLarge':
      return 'External scan failed: response headers exceeded size limits.'
    case 'OverallDeadlineExceeded':
      return 'External scan failed: overall deadline exceeded.'
    case 'InvalidMethod':
      return 'External scan failed: invalid request method.'
    default:
      return 'The External scan could not be completed.'
  }
}
