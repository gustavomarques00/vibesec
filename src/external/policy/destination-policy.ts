import { compareExternalStrings } from '../domain/ordering.js'
import type { NormalizedExternalTarget } from '../domain/target.js'
import {
  evaluateStaticHostnamePolicy,
  type StaticHostnamePolicyResult,
} from './blocked-hostnames.js'
import {
  classifyIpAddress,
  classifyParsedIpAddress,
  type IpClassification,
} from './ip-classification.js'
import { parseIpAddress } from './ip-address.js'

export type DestinationEvaluationKind =
  'BLOCKED_STATICALLY' | 'IP_ALLOWED' | 'IP_DENIED' | 'RESOLUTION_REQUIRED' | 'INVALID'

export type DestinationPolicyResult = Readonly<{
  kind: DestinationEvaluationKind
  hostname: string
  ip?: IpClassification
  hostnamePolicy?: StaticHostnamePolicyResult
}>

export type ResolvedAddressSetDecision =
  'ALLOW' | 'DENY_NON_PUBLIC' | 'DENY_EMPTY' | 'DENY_INVALID'

export type ResolvedAddressVerdict = Readonly<{
  input: string
  canonical?: string
  classification: IpClassification
}>

export type ResolvedAddressSetPolicyResult = Readonly<{
  decision: ResolvedAddressSetDecision
  hostname: string
  approved: readonly ResolvedAddressVerdict[]
  denied: readonly ResolvedAddressVerdict[]
  invalid: readonly ResolvedAddressVerdict[]
}>

/**
 * Pure destination evaluation for a normalized External target.
 * Does not perform DNS. Literal IPs are classified immediately.
 */
export function evaluateNormalizedDestination(
  target: NormalizedExternalTarget,
): DestinationPolicyResult {
  const hostname = target.hostname
  const asIp = parseIpAddress(hostname)
  if (asIp !== undefined) {
    const classification = classifyParsedIpAddress(asIp)
    if (classification.decision === 'ALLOW_PUBLIC') {
      return Object.freeze({
        kind: 'IP_ALLOWED',
        hostname,
        ip: classification,
      })
    }
    if (classification.decision === 'INVALID') {
      return Object.freeze({
        kind: 'INVALID',
        hostname,
        ip: classification,
      })
    }
    return Object.freeze({
      kind: 'IP_DENIED',
      hostname,
      ip: classification,
    })
  }

  const hostnamePolicy = evaluateStaticHostnamePolicy(hostname)
  if (hostnamePolicy.decision === 'BLOCKED_STATICALLY') {
    return Object.freeze({
      kind: 'BLOCKED_STATICALLY',
      hostname,
      hostnamePolicy,
    })
  }

  return Object.freeze({
    kind: 'RESOLUTION_REQUIRED',
    hostname,
    hostnamePolicy,
  })
}

/**
 * Pure policy for a future DNS answer set.
 * Fail closed: any non-public or invalid member denies the entire set.
 * Ordering of inputs does not affect the decision.
 */
export function evaluateResolvedAddressSet(
  hostname: string,
  resolvedAddresses: readonly string[],
): ResolvedAddressSetPolicyResult {
  const hostPolicy = evaluateStaticHostnamePolicy(hostname)
  if (hostPolicy.decision === 'BLOCKED_STATICALLY') {
    return Object.freeze({
      decision: 'DENY_NON_PUBLIC',
      hostname: hostPolicy.hostname,
      approved: Object.freeze([]),
      denied: Object.freeze([]),
      invalid: Object.freeze([]),
    })
  }

  if (resolvedAddresses.length === 0) {
    return Object.freeze({
      decision: 'DENY_EMPTY',
      hostname: hostPolicy.hostname,
      approved: Object.freeze([]),
      denied: Object.freeze([]),
      invalid: Object.freeze([]),
    })
  }

  const unique = dedupeResolvedInputs(resolvedAddresses)
  const approved: ResolvedAddressVerdict[] = []
  const denied: ResolvedAddressVerdict[] = []
  const invalid: ResolvedAddressVerdict[] = []

  for (const input of unique) {
    const classification = classifyIpAddress(input)
    const verdict: ResolvedAddressVerdict = Object.freeze({
      input,
      classification,
      ...(classification.canonical !== undefined
        ? { canonical: classification.canonical }
        : {}),
    })
    if (classification.decision === 'ALLOW_PUBLIC') approved.push(verdict)
    else if (classification.decision === 'INVALID') invalid.push(verdict)
    else denied.push(verdict)
  }

  const sortedApproved = Object.freeze(sortVerdicts(approved))
  const sortedDenied = Object.freeze(sortVerdicts(denied))
  const sortedInvalid = Object.freeze(sortVerdicts(invalid))

  let decision: ResolvedAddressSetDecision = 'ALLOW'
  if (sortedInvalid.length > 0 || sortedDenied.length > 0) {
    decision = 'DENY_NON_PUBLIC'
  } else if (sortedApproved.length === 0) {
    decision = 'DENY_EMPTY'
  }

  return Object.freeze({
    decision,
    hostname: hostPolicy.hostname,
    approved: sortedApproved,
    denied: sortedDenied,
    invalid: sortedInvalid,
  })
}

function dedupeResolvedInputs(inputs: readonly string[]): readonly string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const input of inputs) {
    const parsed = parseIpAddress(input)
    const key = parsed?.canonical ?? `invalid:${input.normalize('NFC')}`
    if (seen.has(key)) continue
    seen.add(key)
    result.push(input)
  }
  return Object.freeze(result)
}

function sortVerdicts(
  verdicts: readonly ResolvedAddressVerdict[],
): ResolvedAddressVerdict[] {
  return [...verdicts].sort((left, right) => {
    const leftKey = left.canonical ?? left.input
    const rightKey = right.canonical ?? right.input
    return compareExternalStrings(leftKey, rightKey)
  })
}
