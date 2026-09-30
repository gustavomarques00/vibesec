import type { SecretCandidateFact, StackFact } from '../core/models/fact.js'
import type { ScanKernelContext } from '../core/scan/scan-kernel-context.js'
import {
  buildLineStarts,
  classifyFileContext,
  isPlaceholderText,
  locationForRange,
  rangesOverlap,
} from './text-utils.js'

export type { RuntimeExposure } from '../utils/runtime-exposure.js'
export { classifyRuntimeExposure } from '../utils/runtime-exposure.js'

const MAX_CANDIDATE_BYTES = 8_192
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gu
const SB_SECRET = /\bsb_secret_[A-Za-z0-9]{16,}\b/gu
const SB_PUBLISHABLE = /\bsb_publishable_[A-Za-z0-9]{16,}\b/gu
const SERVICE_ASSIGNMENT =
  /\b((?:SUPABASE_)?SERVICE_ROLE(?:_KEY)?|SUPABASE_SERVICE_KEY)\s*[=:]\s*['"]?([^\s'"`]{12,})['"]?/giu

export function extractSupabaseKeyFacts(
  scan: ScanKernelContext,
  relativePath: string,
  content: string,
  occupiedRanges: readonly Readonly<{ start: number; end: number }>[] = [],
): Readonly<{
  secrets: readonly SecretCandidateFact[]
  inventory: readonly StackFact[]
}> {
  const secrets: SecretCandidateFact[] = []
  const inventory: StackFact[] = []
  const lineStarts = buildLineStarts(content)
  const context = classifyFileContext(relativePath)
  const claimed: Readonly<{ start: number; end: number }>[] = [...occupiedRanges]

  const claim = (start: number, end: number): boolean => {
    if (claimed.some((range) => rangesOverlap(range.start, range.end, start, end))) {
      return false
    }
    claimed.push(Object.freeze({ start, end }))
    return true
  }

  for (const match of content.matchAll(SERVICE_ASSIGNMENT)) {
    const name = match[1]
    const value = match[2]
    if (name === undefined || value === undefined) continue
    if (value.length > MAX_CANDIDATE_BYTES || isPlaceholderText(value)) continue
    const valueOffset = match[0].lastIndexOf(value)
    if (valueOffset < 0) continue
    const start = match.index + valueOffset
    const end = start + value.length
    if (!claim(start, end)) continue
    if (isAnonLiteral(value)) {
      inventory.push(inventoryFact(relativePath, lineStarts, start, end, context, name))
      continue
    }
    secrets.push(
      secretFact(scan, relativePath, lineStarts, start, end, context, name, value),
    )
  }

  for (const match of content.matchAll(SB_SECRET)) {
    const value = match[0]
    if (value.length > MAX_CANDIDATE_BYTES || isPlaceholderText(value)) continue
    const start = match.index
    const end = start + value.length
    if (!claim(start, end)) continue
    secrets.push(
      secretFact(
        scan,
        relativePath,
        lineStarts,
        start,
        end,
        context,
        'sb_secret',
        value,
      ),
    )
  }

  for (const match of content.matchAll(SB_PUBLISHABLE)) {
    const value = match[0]
    if (value.length > MAX_CANDIDATE_BYTES || isPlaceholderText(value)) continue
    const start = match.index
    const end = start + value.length
    if (!claim(start, end)) continue
    inventory.push(
      inventoryFact(relativePath, lineStarts, start, end, context, 'sb_publishable'),
    )
  }

  for (const match of content.matchAll(JWT_PATTERN)) {
    const value = match[0]
    if (value.length > MAX_CANDIDATE_BYTES || isPlaceholderText(value)) continue
    const role = readJwtRole(value)
    if (role === undefined) continue
    const start = match.index
    const end = start + value.length
    if (!claim(start, end)) continue
    if (role === 'service_role') {
      secrets.push(
        secretFact(
          scan,
          relativePath,
          lineStarts,
          start,
          end,
          context,
          'service_role_jwt',
          value,
        ),
      )
    } else {
      inventory.push(
        inventoryFact(relativePath, lineStarts, start, end, context, 'anon_jwt'),
      )
    }
  }

  return Object.freeze({
    secrets: Object.freeze(secrets),
    inventory: Object.freeze(inventory),
  })
}

function secretFact(
  scan: ScanKernelContext,
  relativePath: string,
  lineStarts: readonly number[],
  start: number,
  end: number,
  context: SecretCandidateFact['source']['context'],
  bindingName: string,
  rawValue: string,
): SecretCandidateFact {
  const protectedValue = scan.protectSecret(rawValue, { visiblePrefix: 0 })
  return Object.freeze({
    kind: 'secret.candidate',
    location: locationForRange(relativePath, lineStarts, start, end),
    source: Object.freeze({
      extractor: 'supabase-key',
      context,
      syntax: 'text',
    }),
    confidence: 'high',
    secretType: 'supabase_key',
    bindingName: bindingName.normalize('NFC'),
    protectedValue,
    isPlaceholder: false,
  })
}

function inventoryFact(
  relativePath: string,
  lineStarts: readonly number[],
  start: number,
  end: number,
  context: StackFact['source']['context'],
  label: string,
): StackFact {
  return Object.freeze({
    kind: 'stack.evidence',
    location: locationForRange(relativePath, lineStarts, start, end),
    source: Object.freeze({
      extractor: 'supabase-key',
      context,
      syntax: 'text',
    }),
    confidence: 'medium',
    stack: `supabase-anon:${label}`,
    evidenceType: 'config',
  })
}

function isAnonLiteral(value: string): boolean {
  if (value.startsWith('sb_publishable_')) return true
  return readJwtRole(value) === 'anon'
}

function readJwtRole(token: string): 'service_role' | 'anon' | undefined {
  const parts = token.split('.')
  if (parts.length !== 3) return undefined
  const payload = parts[1]
  if (payload === undefined || payload.length < 4) return undefined
  try {
    const json = Buffer.from(
      payload.replaceAll('-', '+').replaceAll('_', '/'),
      'base64',
    ).toString('utf8')
    const parsed: unknown = JSON.parse(json)
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return undefined
    }
    const role = (parsed as Record<string, unknown>)['role']
    if (role === 'service_role' || role === 'anon') return role
    return undefined
  } catch {
    return undefined
  }
}
