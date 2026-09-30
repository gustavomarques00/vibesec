/**
 * Bounded sourceMappingURL detection. Does not fetch maps.
 * Never retains inline data: payloads.
 */

export type SourceMapObservation = Readonly<{
  referenced: boolean
  inlineSourceMap: boolean
  /** Bounded http(s) or relative reference only. */
  reference?: string
}>

const MAX_SOURCE_MAP_REF_CHARS = 2_048
const MARKER = 'sourceMappingURL='

/**
 * Detect sourceMappingURL in textual JS/CSS bytes.
 * Scans linearly; ignores giant data: payloads beyond a presence flag.
 */
export function extractSourceMapObservation(
  body: Uint8Array,
  contentType: string | undefined,
): SourceMapObservation {
  if (!isTextualAssetContentType(contentType)) {
    return Object.freeze({ referenced: false, inlineSourceMap: false })
  }

  const text = new TextDecoder('utf-8', { fatal: false }).decode(body)
  const markerIndex = text.lastIndexOf(MARKER)
  if (markerIndex === -1) {
    return Object.freeze({ referenced: false, inlineSourceMap: false })
  }

  let valueStart = markerIndex + MARKER.length
  while (valueStart < text.length && /\s/u.test(text.charAt(valueStart))) {
    valueStart += 1
  }

  let valueEnd = valueStart
  while (valueEnd < text.length) {
    const character = text.charAt(valueEnd)
    if (character === '\n' || character === '\r') break
    if (character === '*' && text.charAt(valueEnd + 1) === '/') break
    valueEnd += 1
    if (valueEnd - valueStart > MAX_SOURCE_MAP_REF_CHARS) break
  }

  const raw = text.slice(valueStart, valueEnd).trim()
  if (raw.length === 0) {
    return Object.freeze({ referenced: false, inlineSourceMap: false })
  }

  if (/^data:/iu.test(raw)) {
    return Object.freeze({ referenced: true, inlineSourceMap: true })
  }

  if (/^(?:javascript|blob|file|ftp|ws|wss):/iu.test(raw)) {
    return Object.freeze({ referenced: true, inlineSourceMap: false })
  }

  const bounded =
    raw.length <= MAX_SOURCE_MAP_REF_CHARS
      ? raw
      : raw.slice(0, MAX_SOURCE_MAP_REF_CHARS)

  return Object.freeze({
    referenced: true,
    inlineSourceMap: false,
    reference: bounded.normalize('NFC'),
  })
}

function isTextualAssetContentType(contentType: string | undefined): boolean {
  if (contentType === undefined) return true
  const media = contentType.split(';', 1)[0]?.trim().toLowerCase() ?? ''
  return (
    media.includes('javascript') ||
    media.includes('ecmascript') ||
    media === 'text/css' ||
    media === 'text/plain' ||
    media === 'application/json' ||
    media.startsWith('text/')
  )
}
