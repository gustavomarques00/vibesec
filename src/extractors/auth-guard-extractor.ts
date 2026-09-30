import type { AuthGuardFact } from '../core/models/fact.js'
import { classifyRuntimeExposure } from '../utils/runtime-exposure.js'
import { buildLineStarts, classifyFileContext, locationForRange } from './text-utils.js'
import {
  classifyArgumentKind,
  isJsLikePath,
  stripLineAndBlockComments,
} from './source-sanitize.js'

export const DEFAULT_MAX_AUTH_GUARDS = 500

const CLIENT_ROLE_CHECK =
  /\b(?:if\s*\([^)]*\b(?:isAdmin|is_admin|hasRole|userRole|role)\b[^)]*\)|[\w.]*(?:isAdmin|hasRole)\s*\()/giu

const STORAGE_ROLE_READ =
  /\b(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(\s*(['"`])((?:role|isAdmin|is_admin|userRole|admin)[^'"`]*)\1\s*\)/giu

const SUPABASE_SESSION_STORAGE =
  /\b(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem)\s*\(\s*(['"`])(?:sb-[^'"`]+-auth-token|supabase\.auth\.token)\1/giu

const CLIENT_ROUTE_GUARD =
  /\b(?:Navigate|redirect|Redirect)\s*(?:to=|\()\s*(['"`])\/(?:login|signin|auth)/giu

export function extractAuthGuardFacts(
  relativePath: string,
  content: string,
  options: Readonly<{ maxGuards?: number }> = {},
): readonly AuthGuardFact[] {
  if (!isJsLikePath(relativePath)) return Object.freeze([])
  const maxGuards = options.maxGuards ?? DEFAULT_MAX_AUTH_GUARDS
  if (!Number.isSafeInteger(maxGuards) || maxGuards < 1) {
    throw new Error('Auth guard candidate limit exceeded.')
  }

  const code = stripLineAndBlockComments(content)
  const lineStarts = buildLineStarts(content)
  const context = classifyFileContext(relativePath)
  const exposure = classifyRuntimeExposure(relativePath)
  const facts: AuthGuardFact[] = []

  const push = (fact: AuthGuardFact): void => {
    if (facts.length >= maxGuards) {
      throw new Error('Auth guard candidate limit exceeded.')
    }
    facts.push(fact)
  }

  for (const match of code.matchAll(STORAGE_ROLE_READ)) {
    const key = match[2] ?? 'role'
    const start = match.index
    const end = start + match[0].length
    push(
      Object.freeze({
        kind: 'auth.guard',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'auth-guard',
          context,
          syntax: syntaxFor(relativePath),
        }),
        confidence: 'high',
        guardType: 'role',
        enforcement: 'client',
        subject: `storage:${key.normalize('NFC')}`,
      }),
    )
  }

  // Standard Supabase session storage is inventoried only when it is the sole
  // match class; it must not emit auth.guard role facts.
  for (const match of code.matchAll(SUPABASE_SESSION_STORAGE)) {
    void match
  }

  for (const match of code.matchAll(CLIENT_ROLE_CHECK)) {
    if (isInsideStringLiteral(code, match.index)) continue
    const start = match.index
    const end = start + match[0].length
    push(
      Object.freeze({
        kind: 'auth.guard',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'auth-guard',
          context,
          syntax: syntaxFor(relativePath),
        }),
        confidence: 'medium',
        guardType: 'role',
        enforcement: exposure === 'server' ? 'server' : 'client',
        subject: 'role-check',
      }),
    )
  }

  for (const match of code.matchAll(CLIENT_ROUTE_GUARD)) {
    if (isInsideStringLiteral(code, match.index)) continue
    const start = match.index
    const end = start + match[0].length
    push(
      Object.freeze({
        kind: 'auth.guard',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'auth-guard',
          context,
          syntax: syntaxFor(relativePath),
        }),
        confidence: 'medium',
        guardType: 'authentication',
        enforcement: exposure === 'server' ? 'server' : 'client',
        subject: 'route-redirect',
      }),
    )
  }

  // Server-ish middleware/auth helpers.
  const serverAuth =
    /\b(?:requireAuth|requireUser|assertAuthenticated|getServerSession|createServerClient)\s*\(/giu
  for (const match of code.matchAll(serverAuth)) {
    if (isInsideStringLiteral(code, match.index)) continue
    if (
      exposure !== 'server' &&
      !/(^|\/)(?:server|api|middleware)\./u.test(relativePath)
    ) {
      // Still record as server if filename suggests middleware.
      if (!/(^|\/)middleware\.[jt]sx?$/u.test(relativePath.replaceAll('\\', '/'))) {
        continue
      }
    }
    const start = match.index
    const end = start + match[0].length
    push(
      Object.freeze({
        kind: 'auth.guard',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'auth-guard',
          context,
          syntax: syntaxFor(relativePath),
        }),
        confidence: 'medium',
        guardType: 'authentication',
        enforcement: 'server',
        subject: 'server-auth',
      }),
    )
  }

  return Object.freeze(facts)
}

function syntaxFor(relativePath: string): AuthGuardFact['source']['syntax'] {
  const lower = relativePath.toLowerCase()
  if (lower.endsWith('.ts') || lower.endsWith('.tsx')) return 'typescript'
  if (lower.endsWith('.js') || lower.endsWith('.jsx')) return 'javascript'
  return 'text'
}

function isInsideStringLiteral(code: string, index: number): boolean {
  // After comment stripping, string quotes remain. Cheap quote parity check.
  const before = code.slice(Math.max(0, index - 80), index)
  const singles = (before.match(/'/gu) ?? []).length
  const doubles = (before.match(/"/gu) ?? []).length
  const ticks = (before.match(/`/gu) ?? []).length
  return singles % 2 === 1 || doubles % 2 === 1 || ticks % 2 === 1
}

export { classifyArgumentKind }
