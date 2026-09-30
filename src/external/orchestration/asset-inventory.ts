import type { ExternalScanBudgets } from '../domain/budgets.js'
import type {
  ExternalAssetObservation,
  ExternalAssetSkipReason,
  ExternalObservationGraph,
} from '../domain/observations.js'
import {
  isSameExternalOrigin,
  normalizeExternalTarget,
  toExternalOrigin,
  type ExternalOrigin,
  type NormalizedExternalTarget,
} from '../domain/target.js'
import {
  buildExternalObservationGraph,
  extractAssetReferences,
  extractSourceMapObservation,
} from '../extractors/index.js'
import {
  ExternalTransportError,
  RedirectBlockedError,
  RequestBudgetExceededError,
} from '../infra/errors.js'
import type { ExternalRawObservation, OutboundHttpCapability } from '../infra/types.js'

export type AssetInventoryResult = Readonly<{
  assets: readonly ExternalAssetObservation[]
  requestsConsumed: number
}>

export type ExternalDocumentScanResult = Readonly<{
  transport: ExternalRawObservation
  graph: ExternalObservationGraph
  requestsConsumed: number
}>

/**
 * Scan a document URL via secure transport, extract observations, and
 * inventory bounded same-origin assets. Sequential asset fetching.
 */
export async function scanExternalDocument(args: {
  target: string
  budgets: ExternalScanBudgets
  transport: OutboundHttpCapability
  signal?: AbortSignal
}): Promise<ExternalDocumentScanResult> {
  const document = await args.transport.request(
    { target: args.target, method: 'GET' },
    {
      budgets: args.budgets,
      ...(args.signal !== undefined ? { signal: args.signal } : {}),
    },
  )

  let requestsConsumed = document.requestsConsumed
  const finalHop = document.hops[document.hops.length - 1]
  const documentOrigin = toExternalOrigin(normalizeExternalTarget(document.finalUrl))

  const graphBase = buildExternalObservationGraph({
    initialRequestUrl: document.initialRequestUrl,
    finalUrl: document.finalUrl,
    method: document.method,
    redirects: document.redirects,
    hops: document.hops.map((hop) => ({
      requestUrl: hop.requestUrl,
      method: hop.method,
      statusCode: hop.statusCode,
      headers: hop.headers,
      bodyByteLength: hop.body.byteLength,
      ...(hop.tls !== undefined ? { tls: hop.tls } : {}),
    })),
  })

  let assets: readonly ExternalAssetObservation[] = Object.freeze([])
  if (finalHop !== undefined) {
    const contentType = findHeader(finalHop.headers, 'content-type')
    const inventory = await inventorySameOriginAssets({
      documentUrl: document.finalUrl,
      documentOrigin,
      contentType,
      htmlBody: finalHop.body,
      budgets: args.budgets,
      requestsAlreadyUsed: requestsConsumed,
      transport: args.transport,
      ...(args.signal !== undefined ? { signal: args.signal } : {}),
    })
    assets = inventory.assets
    requestsConsumed += inventory.requestsConsumed
  }

  // Bodies discarded after extraction — graph holds facts only.
  const graph = Object.freeze({
    ...graphBase,
    assets,
  })

  return Object.freeze({
    transport: document,
    graph,
    requestsConsumed,
  })
}

/**
 * Pure eligibility + secure fetch of same-origin SCRIPT/STYLESHEET assets.
 * Uses document order after dedupe; takes first maxAssets.
 */
export async function inventorySameOriginAssets(args: {
  documentUrl: string
  documentOrigin: ExternalOrigin
  contentType: string | undefined
  htmlBody: Uint8Array
  budgets: ExternalScanBudgets
  requestsAlreadyUsed: number
  transport: OutboundHttpCapability
  signal?: AbortSignal
}): Promise<AssetInventoryResult> {
  const extraction = extractAssetReferences(args.htmlBody, {
    maxHtmlBytes: args.budgets.maxHtmlBytes,
    ...(args.contentType !== undefined ? { contentType: args.contentType } : {}),
  })

  if (!extraction.parsed) {
    return Object.freeze({
      assets: Object.freeze([]),
      requestsConsumed: 0,
    })
  }

  const baseUrl = resolveBaseUrl(args.documentUrl, extraction.baseHref)
  const selected: {
    kind: 'script' | 'stylesheet'
    target: NormalizedExternalTarget
    sourceUrl: string
  }[] = []
  const seen = new Set<string>()
  const skipped: ExternalAssetObservation[] = []

  for (const candidate of extraction.candidates) {
    const classified = classifyCandidate(
      candidate.rawReference,
      candidate.kind,
      baseUrl,
      args.documentOrigin,
      args.documentUrl,
    )
    if (classified.kind === 'skip') {
      skipped.push(classified.observation)
      continue
    }
    if (seen.has(classified.target.requestUrl)) {
      skipped.push(
        Object.freeze({
          sourceUrl: args.documentUrl,
          requestUrl: classified.target.requestUrl,
          kind: candidate.kind,
          sameOrigin: true,
          fetched: false,
          skipReason: 'duplicate',
        }),
      )
      continue
    }
    seen.add(classified.target.requestUrl)
    selected.push({
      kind: candidate.kind,
      target: classified.target,
      sourceUrl: args.documentUrl,
    })
  }

  const toFetch = selected.slice(0, args.budgets.maxAssets)
  const overflow = selected.slice(args.budgets.maxAssets)

  for (const extra of overflow) {
    skipped.push(
      Object.freeze({
        sourceUrl: extra.sourceUrl,
        requestUrl: extra.target.requestUrl,
        kind: extra.kind,
        sameOrigin: true,
        fetched: false,
        skipReason: 'max-assets',
      }),
    )
  }

  const fetched: ExternalAssetObservation[] = []
  let requestsConsumed = 0
  let remaining = Math.max(0, args.budgets.maxRequests - args.requestsAlreadyUsed)

  for (const item of toFetch) {
    if (remaining <= 0) {
      fetched.push(
        Object.freeze({
          sourceUrl: item.sourceUrl,
          requestUrl: item.target.requestUrl,
          kind: item.kind,
          sameOrigin: true,
          fetched: false,
          skipReason: 'budget',
        }),
      )
      continue
    }

    const assetBudgets = Object.freeze({
      ...args.budgets,
      maxResponseBytes: Math.min(
        args.budgets.maxAssetBytes,
        args.budgets.maxResponseBytes,
      ),
    })

    try {
      const result = await args.transport.request(
        { target: item.target, method: 'GET' },
        {
          budgets: assetBudgets,
          maxRequestsOverride: remaining,
          sameOriginRedirects: args.documentOrigin,
          ...(args.signal !== undefined ? { signal: args.signal } : {}),
        },
      )
      requestsConsumed += result.requestsConsumed
      remaining = Math.max(0, remaining - result.requestsConsumed)

      const finalHop = result.hops[result.hops.length - 1]
      const contentType = finalHop
        ? findHeader(finalHop.headers, 'content-type')
        : undefined
      const body = finalHop?.body ?? new Uint8Array()
      const map = extractSourceMapObservation(body, contentType)

      fetched.push(
        Object.freeze({
          sourceUrl: item.sourceUrl,
          requestUrl: result.finalUrl,
          kind: item.kind,
          sameOrigin: true,
          fetched: true,
          ...(finalHop !== undefined ? { statusCode: finalHop.statusCode } : {}),
          ...(contentType !== undefined ? { contentType } : {}),
          byteLength: body.byteLength,
          redirected: result.redirects.length > 0,
          sourceMapReferenced: map.referenced,
          ...(map.inlineSourceMap ? { inlineSourceMap: true } : {}),
          ...(map.reference !== undefined ? { sourceMapReference: map.reference } : {}),
        }),
      )
    } catch (error) {
      let skipReason: ExternalAssetSkipReason = 'fetch-failed'
      if (remaining <= 0 || error instanceof RequestBudgetExceededError) {
        skipReason = 'budget'
      } else if (error instanceof RedirectBlockedError) {
        skipReason = 'redirect-left-origin'
      }
      fetched.push(
        Object.freeze({
          sourceUrl: item.sourceUrl,
          requestUrl: item.target.requestUrl,
          kind: item.kind,
          sameOrigin: true,
          fetched: false,
          skipReason,
        }),
      )
      const consumed = resolveFailedRequestConsumption(error, remaining)
      if (consumed > 0) {
        requestsConsumed += consumed
        remaining = Math.max(0, remaining - consumed)
      }
    }
  }

  // Deterministic assets: fetched (document order) then skipped (document order).
  return Object.freeze({
    assets: Object.freeze([...fetched, ...skipped]),
    requestsConsumed,
  })
}

function classifyCandidate(
  rawReference: string,
  kind: 'script' | 'stylesheet',
  baseUrl: string,
  documentOrigin: ExternalOrigin,
  documentUrl: string,
):
  | { kind: 'ok'; target: NormalizedExternalTarget }
  | { kind: 'skip'; observation: ExternalAssetObservation } {
  const trimmed = rawReference.trim()
  if (/^(?:data|blob|javascript|file|ftp|ws|wss):/iu.test(trimmed)) {
    return {
      kind: 'skip',
      observation: Object.freeze({
        sourceUrl: documentUrl,
        requestUrl: trimmed.slice(0, 128),
        kind,
        sameOrigin: false,
        fetched: false,
        skipReason: 'unsupported-scheme',
      }),
    }
  }

  let absolute: URL
  try {
    absolute = new URL(trimmed, baseUrl)
  } catch {
    return {
      kind: 'skip',
      observation: Object.freeze({
        sourceUrl: documentUrl,
        requestUrl: trimmed.slice(0, 128),
        kind,
        sameOrigin: false,
        fetched: false,
        skipReason: 'normalize-failed',
      }),
    }
  }

  if (absolute.username !== '' || absolute.password !== '') {
    return {
      kind: 'skip',
      observation: Object.freeze({
        sourceUrl: documentUrl,
        requestUrl: absolute.origin + absolute.pathname,
        kind,
        sameOrigin: false,
        fetched: false,
        skipReason: 'credentials',
      }),
    }
  }

  let target: NormalizedExternalTarget
  try {
    target = normalizeExternalTarget(absolute.toString())
  } catch {
    const port = absolute.port
    const skipReason: ExternalAssetSkipReason =
      absolute.protocol !== 'http:' && absolute.protocol !== 'https:'
        ? 'unsupported-scheme'
        : port !== '' && port !== '80' && port !== '443'
          ? 'unsupported-port'
          : 'normalize-failed'
    return {
      kind: 'skip',
      observation: Object.freeze({
        sourceUrl: documentUrl,
        requestUrl: `${absolute.protocol}//${absolute.host}${absolute.pathname}`,
        kind,
        sameOrigin: false,
        fetched: false,
        skipReason,
      }),
    }
  }

  const assetOrigin = toExternalOrigin(target)
  if (!isSameExternalOrigin(documentOrigin, assetOrigin)) {
    return {
      kind: 'skip',
      observation: Object.freeze({
        sourceUrl: documentUrl,
        requestUrl: target.requestUrl,
        kind,
        sameOrigin: false,
        fetched: false,
        skipReason: 'off-origin',
      }),
    }
  }

  return { kind: 'ok', target }
}

function resolveBaseUrl(documentUrl: string, baseHref: string | undefined): string {
  if (baseHref === undefined || baseHref.trim().length === 0) return documentUrl
  try {
    const resolved = new URL(baseHref, documentUrl)
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
      return documentUrl
    }
    return resolved.toString()
  } catch {
    return documentUrl
  }
}

function findHeader(
  headers: readonly { name: string; value: string }[],
  name: string,
): string | undefined {
  const lower = name.toLowerCase()
  for (const header of headers) {
    if (header.name.toLowerCase() === lower) return header.value
  }
  return undefined
}

/**
 * Account outbound attempts for a failed asset fetch.
 * Prefer transport-reported consumption; otherwise charge one attempt (fail closed).
 */
function resolveFailedRequestConsumption(error: unknown, remaining: number): number {
  if (remaining <= 0) return 0
  if (
    error instanceof ExternalTransportError &&
    typeof error.requestsConsumed === 'number' &&
    Number.isFinite(error.requestsConsumed)
  ) {
    return Math.max(0, Math.min(remaining, Math.trunc(error.requestsConsumed)))
  }
  return 1
}
