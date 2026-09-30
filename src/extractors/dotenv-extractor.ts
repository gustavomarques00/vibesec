import type {
  EnvironmentBindingFact,
  SecretCandidateFact,
} from '../core/models/fact.js'
import type { ScanKernelContext } from '../core/scan/scan-kernel-context.js'
import {
  buildLineStarts,
  classifyFileContext,
  isDotenvPath,
  isPlaceholderText,
  locationForRange,
  shannonEntropy,
} from './text-utils.js'

const DOTENV_LINE =
  /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*(?:#.*)?$/u
const CLIENT_PREFIXES = ['VITE_', 'NEXT_PUBLIC_', 'PUBLIC_', 'REACT_APP_'] as const
const SENSITIVE_NAME =
  /(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIAL|DATABASE_URL|PRIVATE)/iu

export { isDotenvPath } from './text-utils.js'

export function exposureForEnvName(name: string): EnvironmentBindingFact['exposure'] {
  const normalized = name.normalize('NFC')
  return CLIENT_PREFIXES.some((prefix) => normalized.startsWith(prefix))
    ? 'client'
    : 'private'
}

export function extractDotenvFacts(
  scan: ScanKernelContext,
  relativePath: string,
  content: string,
): Readonly<{
  bindings: readonly EnvironmentBindingFact[]
  secrets: readonly SecretCandidateFact[]
}> {
  if (!isDotenvPath(relativePath)) {
    return Object.freeze({
      bindings: Object.freeze([]),
      secrets: Object.freeze([]),
    })
  }

  const bindings: EnvironmentBindingFact[] = []
  const secrets: SecretCandidateFact[] = []
  const lineStarts = buildLineStarts(content)
  const context = classifyFileContext(relativePath)
  const lines = content.split(/\r?\n/u)

  let offset = 0
  for (const line of lines) {
    const match = DOTENV_LINE.exec(line)
    if (match !== null) {
      const name = match[1]
      const rawValue = unquote(match[2] ?? '')
      if (name !== undefined && name.length > 0) {
        const nameStart = offset + line.indexOf(name)
        const exposure = exposureForEnvName(name)
        bindings.push(
          Object.freeze({
            kind: 'environment.binding',
            location: locationForRange(
              relativePath,
              lineStarts,
              nameStart,
              nameStart + name.length,
            ),
            source: Object.freeze({
              extractor: 'dotenv',
              context,
              syntax: 'dotenv',
            }),
            confidence: 'high',
            name: name.normalize('NFC'),
            exposure,
            valueKind: rawValue.length === 0 ? 'unknown' : 'literal',
          }),
        )

        if (
          rawValue.length >= 8 &&
          !isPlaceholderText(rawValue) &&
          (SENSITIVE_NAME.test(name) ||
            exposure === 'client' ||
            shannonEntropy(rawValue) >= 3.3)
        ) {
          const valueIndex = line.lastIndexOf(rawValue)
          if (valueIndex >= 0) {
            const start = offset + valueIndex
            const end = start + rawValue.length
            const protectedValue = scan.protectSecret(rawValue, {
              visiblePrefix: 0,
            })
            secrets.push(
              Object.freeze({
                kind: 'secret.candidate',
                location: locationForRange(relativePath, lineStarts, start, end),
                source: Object.freeze({
                  extractor: 'dotenv',
                  context,
                  syntax: 'dotenv',
                }),
                confidence: 'high',
                secretType: classifyEnvSecretType(name, rawValue),
                bindingName: name.normalize('NFC'),
                protectedValue,
                isPlaceholder: false,
              }),
            )
          }
        }
      }
    }
    offset += line.length
    if (offset < content.length) {
      // Account for the exact newline sequence removed by split.
      if (content.startsWith('\r\n', offset)) offset += 2
      else if (content.startsWith('\n', offset) || content.startsWith('\r', offset)) {
        offset += 1
      }
    }
  }

  return Object.freeze({
    bindings: Object.freeze(bindings),
    secrets: Object.freeze(secrets),
  })
}

export function extractClientPrefixBindingFacts(
  relativePath: string,
  content: string,
): readonly EnvironmentBindingFact[] {
  if (isDotenvPath(relativePath)) {
    return Object.freeze([])
  }
  const pattern = /\b((?:VITE_|NEXT_PUBLIC_|PUBLIC_|REACT_APP_)[A-Za-z0-9_]+)\b/gu
  const facts: EnvironmentBindingFact[] = []
  const lineStarts = buildLineStarts(content)
  const context = classifyFileContext(relativePath)
  const seen = new Set<string>()

  for (const match of content.matchAll(pattern)) {
    const name = match[1]
    if (name === undefined) continue
    const start = match.index
    const end = start + name.length
    const key = `${name}@${String(start)}`
    if (seen.has(key)) continue
    seen.add(key)
    facts.push(
      Object.freeze({
        kind: 'environment.binding',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'client-env-prefix',
          context,
          syntax: 'text',
        }),
        confidence: 'medium',
        name: name.normalize('NFC'),
        exposure: 'client',
        valueKind: 'reference',
      }),
    )
  }
  return Object.freeze(facts)
}

function unquote(value: string): string {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1)
  }
  return value
}

function classifyEnvSecretType(
  name: string,
  value: string,
): SecretCandidateFact['secretType'] {
  const upper = name.toUpperCase()
  if (upper.includes('DATABASE') || /:\/\/[^/@]+:[^/@]+@/u.test(value)) {
    return 'database_url'
  }
  if (upper.includes('JWT')) return 'jwt'
  if (upper.includes('WEBHOOK')) return 'webhook_secret'
  if (upper.includes('PASSWORD') || upper.includes('PASSWD')) return 'password'
  if (upper.includes('TOKEN') || upper.includes('BEARER')) return 'bearer_token'
  if (upper.includes('KEY')) return 'api_key'
  return 'unknown'
}
