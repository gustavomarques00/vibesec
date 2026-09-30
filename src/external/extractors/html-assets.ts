/**
 * Bounded, linear HTML scanner for explicit asset references.
 * No DOM, no JS execution, no catastrophic regex backtracking.
 */

export type HtmlAssetKind = 'script' | 'stylesheet'

export type HtmlAssetReferenceCandidate = Readonly<{
  kind: HtmlAssetKind
  rawReference: string
}>

export type HtmlAssetExtractionResult = Readonly<{
  parsed: boolean
  truncated: boolean
  skipReason?: 'not-html' | 'oversized'
  baseHref?: string
  candidates: readonly HtmlAssetReferenceCandidate[]
}>

const MAX_ATTR_CHARS = 2_048
const MAX_TAG_CHARS = 8_192

const HTML_CONTENT_TYPES = new Set(['text/html', 'application/xhtml+xml'])

export function isHtmlContentType(contentType: string | undefined): boolean {
  if (contentType === undefined) return false
  const media = contentType.split(';', 1)[0]?.trim().toLowerCase() ?? ''
  return HTML_CONTENT_TYPES.has(media)
}

/**
 * Extract explicit script/stylesheet references from bounded HTML bytes.
 * Document order is preserved. Does not resolve URLs or fetch.
 */
export function extractAssetReferences(
  htmlBytes: Uint8Array,
  options: Readonly<{ maxHtmlBytes: number; contentType?: string }> = {
    maxHtmlBytes: 512 * 1024,
  },
): HtmlAssetExtractionResult {
  if (!isHtmlContentType(options.contentType)) {
    return Object.freeze({
      parsed: false,
      truncated: false,
      skipReason: 'not-html',
      candidates: Object.freeze([]),
    })
  }

  if (htmlBytes.byteLength > options.maxHtmlBytes) {
    return Object.freeze({
      parsed: false,
      truncated: true,
      skipReason: 'oversized',
      candidates: Object.freeze([]),
    })
  }

  const html = new TextDecoder('utf-8', { fatal: false }).decode(htmlBytes)
  const candidates: HtmlAssetReferenceCandidate[] = []
  let baseHref: string | undefined
  let index = 0

  while (index < html.length) {
    if (html.startsWith('<!--', index)) {
      const end = html.indexOf('-->', index + 4)
      index = end === -1 ? html.length : end + 3
      continue
    }

    if (charAt(html, index) !== '<') {
      index += 1
      continue
    }

    const tagParse = readTag(html, index)
    if (tagParse === undefined) {
      index += 1
      continue
    }
    index = tagParse.nextIndex

    const name = tagParse.name
    if (name === 'script') {
      if (tagParse.selfClosing) continue
      const src = tagParse.attrs.get('src')
      if (src !== undefined && src.length > 0) {
        candidates.push(Object.freeze({ kind: 'script', rawReference: src }))
      }
      index = skipUntilClosingTag(html, index, 'script')
      continue
    }

    if (name === 'base') {
      const href = tagParse.attrs.get('href')
      if (baseHref === undefined && href !== undefined && href.length > 0) {
        baseHref = href
      }
      continue
    }

    if (name === 'link') {
      const href = tagParse.attrs.get('href')
      if (href === undefined || href.length === 0) continue
      const rel = (tagParse.attrs.get('rel') ?? '').toLowerCase()
      const as = (tagParse.attrs.get('as') ?? '').toLowerCase()
      if (rel.split(/\s+/u).includes('stylesheet')) {
        candidates.push(Object.freeze({ kind: 'stylesheet', rawReference: href }))
        continue
      }
      if (rel.split(/\s+/u).includes('preload') && as === 'style') {
        candidates.push(Object.freeze({ kind: 'stylesheet', rawReference: href }))
      }
    }
  }

  return Object.freeze({
    parsed: true,
    truncated: false,
    ...(baseHref !== undefined ? { baseHref } : {}),
    candidates: Object.freeze(candidates),
  })
}

type ParsedTag = Readonly<{
  name: string
  attrs: ReadonlyMap<string, string>
  selfClosing: boolean
  nextIndex: number
}>

function readTag(html: string, start: number): ParsedTag | undefined {
  if (charAt(html, start) !== '<') return undefined
  let index = start + 1
  if (index >= html.length) return undefined
  const first = charAt(html, index)
  if (first === '/' || first === '!' || first === '?') return undefined

  const nameStart = index
  while (index < html.length && isNameChar(charAt(html, index))) index += 1
  if (index === nameStart) return undefined
  const name = html.slice(nameStart, index).toLowerCase()

  const attrs = new Map<string, string>()
  let selfClosing = false

  while (index < html.length) {
    while (index < html.length && isSpace(charAt(html, index))) index += 1
    if (index >= html.length) break

    if (charAt(html, index) === '>') {
      index += 1
      break
    }
    if (charAt(html, index) === '/' && charAt(html, index + 1) === '>') {
      selfClosing = true
      index += 2
      break
    }

    const attr = readAttribute(html, index)
    if (attr === undefined) {
      index += 1
      if (index - start > MAX_TAG_CHARS) return undefined
      continue
    }
    index = attr.nextIndex
    if (!attrs.has(attr.name)) attrs.set(attr.name, attr.value)
    if (index - start > MAX_TAG_CHARS) {
      return Object.freeze({
        name,
        attrs,
        selfClosing,
        nextIndex: Math.min(html.length, index),
      })
    }
  }

  return Object.freeze({ name, attrs, selfClosing, nextIndex: index })
}

function readAttribute(
  html: string,
  start: number,
): { name: string; value: string; nextIndex: number } | undefined {
  let index = start
  const nameStart = index
  while (index < html.length && isAttrNameChar(charAt(html, index))) index += 1
  if (index === nameStart) return undefined
  const name = html.slice(nameStart, index).toLowerCase()

  while (index < html.length && isSpace(charAt(html, index))) index += 1
  if (charAt(html, index) !== '=') {
    return { name, value: '', nextIndex: index }
  }
  index += 1
  while (index < html.length && isSpace(charAt(html, index))) index += 1

  const quote = charAt(html, index)
  if (quote === '"' || quote === "'") {
    index += 1
    const valueStart = index
    while (index < html.length && charAt(html, index) !== quote) {
      index += 1
      if (index - valueStart > MAX_ATTR_CHARS) {
        const truncated = html.slice(valueStart, valueStart + MAX_ATTR_CHARS)
        while (
          index < html.length &&
          charAt(html, index) !== quote &&
          charAt(html, index) !== '>'
        ) {
          index += 1
        }
        if (charAt(html, index) === quote) index += 1
        return { name, value: truncated, nextIndex: index }
      }
    }
    const value = html.slice(valueStart, index)
    if (charAt(html, index) === quote) index += 1
    return { name, value, nextIndex: index }
  }

  const valueStart = index
  while (
    index < html.length &&
    !isSpace(charAt(html, index)) &&
    charAt(html, index) !== '>' &&
    charAt(html, index) !== '/'
  ) {
    index += 1
    if (index - valueStart > MAX_ATTR_CHARS) {
      return {
        name,
        value: html.slice(valueStart, valueStart + MAX_ATTR_CHARS),
        nextIndex: index,
      }
    }
  }
  return { name, value: html.slice(valueStart, index), nextIndex: index }
}

function skipUntilClosingTag(html: string, start: number, tagName: string): number {
  const needle = `</${tagName}`
  let index = start
  while (index < html.length) {
    const found = indexOfIgnoreCase(html, needle, index)
    if (found === -1) return html.length
    const after = found + needle.length
    if (after < html.length && isNameChar(charAt(html, after))) {
      index = after
      continue
    }
    const close = html.indexOf('>', after)
    return close === -1 ? html.length : close + 1
  }
  return html.length
}

function indexOfIgnoreCase(
  haystack: string,
  needle: string,
  fromIndex: number,
): number {
  const limit = haystack.length - needle.length
  for (let index = fromIndex; index <= limit; index += 1) {
    let matched = true
    for (let offset = 0; offset < needle.length; offset += 1) {
      if (charAt(haystack, index + offset).toLowerCase() !== charAt(needle, offset)) {
        matched = false
        break
      }
    }
    if (matched) return index
  }
  return -1
}

function charAt(text: string, index: number): string {
  return text.charAt(index)
}

function isSpace(character: string): boolean {
  return (
    character === ' ' || character === '\n' || character === '\r' || character === '\t'
  )
}

function isNameChar(character: string): boolean {
  return /[A-Za-z0-9:-]/u.test(character)
}

function isAttrNameChar(character: string): boolean {
  return /[A-Za-z0-9:_-]/u.test(character)
}
