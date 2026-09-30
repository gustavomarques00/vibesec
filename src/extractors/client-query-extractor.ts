import type { ClientQueryFact } from '../core/models/fact.js'
import { buildLineStarts, classifyFileContext, locationForRange } from './text-utils.js'
import { isJsLikePath, stripLineAndBlockComments } from './source-sanitize.js'

export const DEFAULT_MAX_CLIENT_QUERIES = 1_000

const FROM_CHAIN =
  /\.from\s*\(\s*(['"`])([^'"`]+)\1\s*\)([\s\S]{0,400}?)(?=\.from\s*\(|;|$)/giu

const OPERATION = /\.(select|insert|update|delete|rpc)\s*\(/iu

const OWNERSHIP = /\.eq\s*\(\s*(['"`])(user_id|owner_id|uid|profile_id|author_id)\1/iu

export function extractClientQueryFacts(
  relativePath: string,
  content: string,
  options: Readonly<{ maxQueries?: number }> = {},
): readonly ClientQueryFact[] {
  if (!isJsLikePath(relativePath)) return Object.freeze([])
  const maxQueries = options.maxQueries ?? DEFAULT_MAX_CLIENT_QUERIES
  if (!Number.isSafeInteger(maxQueries) || maxQueries < 1) {
    throw new Error('Client query candidate limit exceeded.')
  }

  const code = stripLineAndBlockComments(content)
  const lineStarts = buildLineStarts(content)
  const context = classifyFileContext(relativePath)
  const facts: ClientQueryFact[] = []

  for (const match of code.matchAll(FROM_CHAIN)) {
    const resource = match[2]
    const chain = match[3] ?? ''
    if (resource === undefined) continue
    const operationMatch = OPERATION.exec(chain)
    if (operationMatch === null) continue
    const operation = normalizeOperation(operationMatch[1])
    if (operation === undefined) continue
    const start = match.index
    const end = start + Math.min(match[0].length, 240)
    if (facts.length >= maxQueries) {
      throw new Error('Client query candidate limit exceeded.')
    }
    facts.push(
      Object.freeze({
        kind: 'client.query',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'client-query',
          context,
          syntax: relativePath.toLowerCase().includes('.ts')
            ? 'typescript'
            : 'javascript',
        }),
        confidence: 'medium',
        provider: 'supabase',
        resource: resource.normalize('NFC'),
        operation,
        hasOwnershipFilter: OWNERSHIP.test(chain),
      }),
    )
  }

  return Object.freeze(facts)
}

function normalizeOperation(
  value: string | undefined,
): ClientQueryFact['operation'] | undefined {
  switch ((value ?? '').toLowerCase()) {
    case 'select':
      return 'select'
    case 'insert':
      return 'insert'
    case 'update':
      return 'update'
    case 'delete':
      return 'delete'
    case 'rpc':
      return 'rpc'
    default:
      return undefined
  }
}
