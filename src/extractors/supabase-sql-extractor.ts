import type {
  StackFact,
  SupabasePolicyFact,
  SupabaseRlsFact,
  SupabaseTableFact,
} from '../core/models/fact.js'
import { buildLineStarts, locationForRange } from './text-utils.js'

export const DEFAULT_MAX_SQL_STATEMENTS = 2_000
export const DEFAULT_MAX_SUPABASE_FACTS = 5_000

const CREATE_TABLE =
  /\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:"[^"]+"|[\w]+)\s*\.\s*(?:"[^"]+"|[\w]+)|(?:"[^"]+"|[\w]+))/giu

const ALTER_RLS =
  /\bALTER\s+TABLE\s+((?:"[^"]+"|[\w]+)\s*\.\s*(?:"[^"]+"|[\w]+)|(?:"[^"]+"|[\w]+))\s+(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY\b/giu

const CREATE_POLICY =
  /\bCREATE\s+POLICY\s+((?:"[^"]+"|[\w]+))\s+ON\s+((?:"[^"]+"|[\w]+)\s*\.\s*(?:"[^"]+"|[\w]+)|(?:"[^"]+"|[\w]+))(?:\s+AS\s+(?:PERMISSIVE|RESTRICTIVE))?(?:\s+FOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE))?(?:\s+TO\s+((?:"[^"]+"|[\w]+)(?:\s*,\s*(?:"[^"]+"|[\w]+))*))?(?:\s+USING\s*\(([^)]*)\))?(?:\s+WITH\s+CHECK\s*\(([^)]*)\))?/giu

export function isSqlMigrationPath(relativePath: string): boolean {
  const normalized = relativePath.normalize('NFC').toLowerCase().replaceAll('\\', '/')
  if (!normalized.endsWith('.sql')) return false
  return normalized.includes('/migrations/') || normalized.includes('/supabase/')
}

export function extractSupabaseSqlFacts(
  relativePath: string,
  content: string,
  options: Readonly<{
    maxStatements?: number
    maxFacts?: number
  }> = {},
): readonly (SupabaseTableFact | SupabaseRlsFact | SupabasePolicyFact | StackFact)[] {
  if (!isSqlMigrationPath(relativePath)) return Object.freeze([])

  const maxStatements = options.maxStatements ?? DEFAULT_MAX_SQL_STATEMENTS
  const maxFacts = options.maxFacts ?? DEFAULT_MAX_SUPABASE_FACTS
  if (
    !Number.isSafeInteger(maxStatements) ||
    maxStatements < 1 ||
    !Number.isSafeInteger(maxFacts) ||
    maxFacts < 1
  ) {
    throw new Error('Supabase SQL inventory limits exceeded.')
  }

  const facts: (
    SupabaseTableFact | SupabaseRlsFact | SupabasePolicyFact | StackFact
  )[] = []
  const lineStarts = buildLineStarts(content)
  let statements = 0

  const push = (
    fact: SupabaseTableFact | SupabaseRlsFact | SupabasePolicyFact | StackFact,
  ): void => {
    if (facts.length >= maxFacts)
      throw new Error('Supabase SQL inventory limits exceeded.')
    facts.push(fact)
  }

  for (const match of content.matchAll(CREATE_TABLE)) {
    statements += 1
    if (statements > maxStatements) {
      throw new Error('Supabase SQL inventory limits exceeded.')
    }
    const rawName = match[1]
    if (rawName === undefined) continue
    const { schema, table } = splitRelation(rawName)
    const start = match.index
    const end = start + match[0].length
    push(
      Object.freeze({
        kind: 'supabase.table',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'supabase-sql',
          context: 'migration',
          syntax: 'sql',
        }),
        confidence: 'high',
        schema,
        table,
        operation: 'create',
      }),
    )
  }

  for (const match of content.matchAll(ALTER_RLS)) {
    statements += 1
    if (statements > maxStatements) {
      throw new Error('Supabase SQL inventory limits exceeded.')
    }
    const rawName = match[1]
    const mode = match[2]?.toUpperCase()
    if (rawName === undefined || mode === undefined) continue
    const { schema, table } = splitRelation(rawName)
    const start = match.index
    const end = start + match[0].length
    push(
      Object.freeze({
        kind: 'supabase.rls',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'supabase-sql',
          context: 'migration',
          syntax: 'sql',
        }),
        confidence: 'high',
        schema,
        table,
        enabled: mode === 'ENABLE',
      }),
    )
  }

  for (const match of content.matchAll(CREATE_POLICY)) {
    statements += 1
    if (statements > maxStatements) {
      throw new Error('Supabase SQL inventory limits exceeded.')
    }
    const policyName = stripQuotes(match[1] ?? '')
    const rawTable = match[2]
    if (policyName.length === 0 || rawTable === undefined) continue
    const { schema, table } = splitRelation(rawTable)
    const command = normalizeCommand(match[3])
    const roles = parseRoles(match[4] ?? 'public')
    const usingClause = (match[5] ?? '').trim()
    const checkClause = (match[6] ?? '').trim()
    const hasUsingClause = usingClause.length > 0
    const hasCheckClause = checkClause.length > 0
    const referencesAuthUid =
      /\bauth\.uid\s*\(/iu.test(usingClause) || /\bauth\.uid\s*\(/iu.test(checkClause)
    const isBroad =
      isTruthySqlExpression(usingClause) || isTruthySqlExpression(checkClause)
    const start = match.index
    const end = start + Math.min(match[0].length, 400)
    push(
      Object.freeze({
        kind: 'supabase.policy',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'supabase-sql',
          context: 'migration',
          syntax: 'sql',
        }),
        confidence: 'medium',
        schema,
        table,
        policyName: policyName.normalize('NFC'),
        command,
        roles: Object.freeze(roles),
        hasUsingClause,
        hasCheckClause,
        referencesAuthUid,
        isBroad,
      }),
    )
  }

  if (facts.some((fact) => fact.kind === 'supabase.table')) {
    push(
      Object.freeze({
        kind: 'stack.evidence',
        location: Object.freeze({ file: relativePath, startLine: 1 }),
        source: Object.freeze({
          extractor: 'supabase-sql',
          context: 'migration',
          syntax: 'sql',
        }),
        confidence: 'medium',
        stack: 'supabase',
        evidenceType: 'config',
      }),
    )
  }

  return Object.freeze(facts)
}

function splitRelation(raw: string): Readonly<{ schema: string; table: string }> {
  const cleaned = raw.replaceAll(/\s+/gu, '')
  const parts = cleaned.split('.')
  if (parts.length >= 2) {
    return Object.freeze({
      schema: stripQuotes(parts[0] ?? 'public').toLowerCase() || 'public',
      table: stripQuotes(parts[1] ?? '').toLowerCase(),
    })
  }
  return Object.freeze({
    schema: 'public',
    table: stripQuotes(cleaned).toLowerCase(),
  })
}

function stripQuotes(value: string): string {
  const trimmed = value.trim()
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

function normalizeCommand(value: string | undefined): SupabasePolicyFact['command'] {
  switch ((value ?? 'all').toLowerCase()) {
    case 'select':
      return 'select'
    case 'insert':
      return 'insert'
    case 'update':
      return 'update'
    case 'delete':
      return 'delete'
    default:
      return 'all'
  }
}

function parseRoles(raw: string): string[] {
  return raw
    .split(',')
    .map((part) => stripQuotes(part).toLowerCase())
    .filter((part) => part.length > 0)
}

function isTruthySqlExpression(expression: string): boolean {
  const normalized = expression.replaceAll(/\s+/gu, ' ').trim().toLowerCase()
  return normalized === 'true' || normalized === '(true)'
}
