/**
 * Bounded comment stripping for heuristic extractors.
 * Does not execute code. Strings keep their contents so API names inside
 * string literals remain visible to detectors that must ignore them via
 * other heuristics, or callers may scan only comment-stripped text for
 * call-site patterns that should not match comments.
 */
export function stripLineAndBlockComments(source: string): string {
  let output = ''
  let index = 0
  let state: 'code' | 'line' | 'block' | 'sq' | 'dq' | 'tmpl' = 'code'

  while (index < source.length) {
    const current = source[index] ?? ''
    const next = source[index + 1] ?? ''

    switch (state) {
      case 'code':
        if (current === '/' && next === '/') {
          state = 'line'
          output += '  '
          index += 2
          continue
        }
        if (current === '/' && next === '*') {
          state = 'block'
          output += '  '
          index += 2
          continue
        }
        if (current === "'") {
          state = 'sq'
          output += current
          index += 1
          continue
        }
        if (current === '"') {
          state = 'dq'
          output += current
          index += 1
          continue
        }
        if (current === '`') {
          state = 'tmpl'
          output += current
          index += 1
          continue
        }
        output += current
        index += 1
        continue
      case 'line':
        if (current === '\n') {
          state = 'code'
          output += current
        } else {
          output += ' '
        }
        index += 1
        continue
      case 'block':
        if (current === '*' && next === '/') {
          state = 'code'
          output += '  '
          index += 2
          continue
        }
        output += current === '\n' ? '\n' : ' '
        index += 1
        continue
      case 'sq':
        output += current
        if (current === '\\' && index + 1 < source.length) {
          output += source[index + 1] ?? ''
          index += 2
          continue
        }
        if (current === "'") state = 'code'
        index += 1
        continue
      case 'dq':
        output += current
        if (current === '\\' && index + 1 < source.length) {
          output += source[index + 1] ?? ''
          index += 2
          continue
        }
        if (current === '"') state = 'code'
        index += 1
        continue
      case 'tmpl':
        output += current
        if (current === '\\' && index + 1 < source.length) {
          output += source[index + 1] ?? ''
          index += 2
          continue
        }
        if (current === '`') state = 'code'
        index += 1
        continue
    }
  }
  return output
}

export function isJsLikePath(relativePath: string): boolean {
  const normalized = relativePath.normalize('NFC').toLowerCase()
  return /\.(?:[cm]?[jt]sx?)$/u.test(normalized)
}

export function classifyArgumentKind(
  argument: string,
): 'constant' | 'dynamic' | 'unknown' {
  const trimmed = argument.trim()
  if (trimmed.length === 0) return 'unknown'
  if (/^(['"`]).*\1$/su.test(trimmed) && !trimmed.includes('${')) {
    return 'constant'
  }
  if (/^`[^`$]*`$/su.test(trimmed)) return 'constant'
  if (/^[0-9]+(?:\.[0-9]+)?$/u.test(trimmed)) return 'constant'
  if (/^(?:true|false|null|undefined)$/u.test(trimmed)) return 'constant'
  if (/^[A-Za-z_$][\w$]*$/u.test(trimmed)) return 'dynamic'
  if (trimmed.includes('${')) return 'dynamic'
  if (trimmed.includes('+') || trimmed.includes('(')) {
    return 'dynamic'
  }
  return 'unknown'
}
