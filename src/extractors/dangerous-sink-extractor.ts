import type { DangerousSinkFact } from '../core/models/fact.js'
import { classifyRuntimeExposure } from '../utils/runtime-exposure.js'
import { buildLineStarts, classifyFileContext, locationForRange } from './text-utils.js'
import {
  classifyArgumentKind,
  isJsLikePath,
  stripLineAndBlockComments,
} from './source-sanitize.js'

export const DEFAULT_MAX_DANGEROUS_SINKS = 500

type SinkPattern = Readonly<{
  sink: DangerousSinkFact['sink']
  pattern: RegExp
  argumentGroup: number
  requireServer?: boolean
}>

const SINKS: readonly SinkPattern[] = [
  {
    sink: 'eval',
    pattern: /\beval\s*\(\s*([^)]*)\)/giu,
    argumentGroup: 1,
  },
  {
    sink: 'new_function',
    pattern: /\bnew\s+Function\s*\(\s*([^)]*)\)/giu,
    argumentGroup: 1,
  },
  {
    sink: 'dangerously_set_inner_html',
    pattern:
      /\bdangerouslySetInnerHTML\s*=\s*\{\s*(?:\{\s*__html\s*:\s*([^}]+)\s*\}|([A-Za-z_$][\w$]*))\s*\}/giu,
    argumentGroup: 1,
  },
  {
    sink: 'inner_html',
    pattern: /\.innerHTML\s*=\s*([^;\n]+)/giu,
    argumentGroup: 1,
  },
  {
    sink: 'document_write',
    pattern: /\bdocument\.write(?:ln)?\s*\(\s*([^)]*)\)/giu,
    argumentGroup: 1,
  },
  {
    sink: 'shell_exec',
    pattern:
      /\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*([^,)]+)/giu,
    argumentGroup: 1,
    requireServer: true,
  },
  {
    sink: 'raw_sql',
    pattern:
      /\b(?:\.query|\.raw|sql)\s*(?:`|\(\s*(['"`]))([\s\S]*?)(?:`|(?:\1)\s*\))/giu,
    argumentGroup: 2,
    requireServer: true,
  },
]

const SANITIZER = /\b(?:DOMPurify\.sanitize|sanitizeHtml|xss\(|escapeHtml)\b/u

export function extractDangerousSinkFacts(
  relativePath: string,
  content: string,
  options: Readonly<{ maxSinks?: number }> = {},
): readonly DangerousSinkFact[] {
  if (!isJsLikePath(relativePath)) return Object.freeze([])
  const maxSinks = options.maxSinks ?? DEFAULT_MAX_DANGEROUS_SINKS
  if (!Number.isSafeInteger(maxSinks) || maxSinks < 1) {
    throw new Error('Dangerous sink candidate limit exceeded.')
  }

  const code = stripLineAndBlockComments(content)
  const lineStarts = buildLineStarts(content)
  const context = classifyFileContext(relativePath)
  const exposure = classifyRuntimeExposure(relativePath)
  const facts: DangerousSinkFact[] = []

  for (const sink of SINKS) {
    if (sink.requireServer && exposure === 'client') continue
    for (const match of code.matchAll(sink.pattern)) {
      if (isInsideStringLiteral(code, match.index)) continue
      let argument =
        match[sink.argumentGroup] ?? match[sink.argumentGroup + 1] ?? match[1] ?? ''
      if (sink.sink === 'dangerously_set_inner_html' && argument.trim().length === 0) {
        argument = match[2] ?? ''
      }
      const input = classifyArgumentKind(argument)
      const nearby = code.slice(
        Math.max(0, match.index - 40),
        match.index + match[0].length + 80,
      )
      const sanitizer = SANITIZER.test(nearby) ? 'recognized' : undefined
      if (facts.length >= maxSinks) {
        throw new Error('Dangerous sink candidate limit exceeded.')
      }
      facts.push(
        Object.freeze({
          kind: 'dangerous.sink',
          location: locationForRange(
            relativePath,
            lineStarts,
            match.index,
            match.index + Math.min(match[0].length, 200),
          ),
          source: Object.freeze({
            extractor: 'dangerous-sink',
            context,
            syntax: relativePath.toLowerCase().includes('.ts')
              ? 'typescript'
              : 'javascript',
          }),
          confidence: input === 'dynamic' ? 'medium' : 'low',
          sink: sink.sink,
          input,
          ...(sanitizer === undefined ? {} : { sanitizer }),
        }),
      )
    }
  }

  return Object.freeze(facts)
}

function isInsideStringLiteral(code: string, index: number): boolean {
  const before = code.slice(Math.max(0, index - 80), index)
  const singles = (before.match(/'/gu) ?? []).length
  const doubles = (before.match(/"/gu) ?? []).length
  const ticks = (before.match(/`/gu) ?? []).length
  return singles % 2 === 1 || doubles % 2 === 1 || ticks % 2 === 1
}
