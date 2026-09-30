import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

import { createExternalScanBudgets } from '../src/external/domain/index.js'
import {
  isSameExternalOrigin,
  normalizeExternalTarget,
  toExternalOrigin,
} from '../src/external/domain/target.js'
import {
  extractAssetReferences,
  extractSourceMapObservation,
  isHtmlContentType,
} from '../src/external/extractors/index.js'
import {
  inventorySameOriginAssets,
  scanExternalDocument,
} from '../src/external/orchestration/index.js'
import type {
  ExternalRawObservation,
  ExternalRequestContext,
  ExternalRequestPlan,
  OutboundHttpCapability,
} from '../src/external/infra/types.js'
import { RedirectBlockedError } from '../src/external/infra/errors.js'

const HTML_CANARY = 'HTML_BODY_SECRET_CANARY'
const JS_CANARY = 'JS_BODY_SECRET_CANARY'
const CSS_CANARY = 'CSS_BODY_SECRET_CANARY'
const PUBLIC = '203.0.114.1'

function budgets(overrides: Parameters<typeof createExternalScanBudgets>[0] = {}) {
  return createExternalScanBudgets(overrides)
}

function encode(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function fakeObservation(args: {
  url: string
  statusCode?: number
  headers?: { name: string; value: string }[]
  body?: Uint8Array
  redirects?: ExternalRawObservation['redirects']
  requestsConsumed?: number
}): ExternalRawObservation {
  const body = args.body ?? new Uint8Array()
  return Object.freeze({
    initialRequestUrl: args.url,
    finalUrl: args.url,
    method: 'GET',
    hops: Object.freeze([
      Object.freeze({
        requestUrl: args.url,
        method: 'GET' as const,
        statusCode: args.statusCode ?? 200,
        headers: Object.freeze(args.headers ?? []),
        body,
        pinnedAddress: PUBLIC,
        remoteAddress: PUBLIC,
      }),
    ]),
    redirects: Object.freeze(args.redirects ?? []),
    requestsConsumed: args.requestsConsumed ?? 1,
  })
}

function createFakeTransport(script: {
  responses: Map<string, ExternalRawObservation | (() => ExternalRawObservation)>
  onRequest?: (plan: ExternalRequestPlan, context: ExternalRequestContext) => void
}): { transport: OutboundHttpCapability; calls: string[] } {
  const calls: string[] = []
  const transport: OutboundHttpCapability = Object.freeze({
    request(plan, context) {
      const target =
        typeof plan.target === 'string'
          ? normalizeExternalTarget(plan.target)
          : plan.target
      calls.push(target.requestUrl)
      script.onRequest?.(plan, context)

      if (
        context.maxRequestsOverride !== undefined &&
        context.maxRequestsOverride <= 0
      ) {
        return Promise.reject(new Error('RequestBudgetExceeded'))
      }

      const entry = script.responses.get(target.requestUrl)
      if (entry === undefined) {
        return Promise.reject(new Error('missing fixture'))
      }
      const observation = typeof entry === 'function' ? entry() : entry

      if (context.sameOriginRedirects !== undefined) {
        for (const redirect of observation.redirects) {
          const next = normalizeExternalTarget(redirect.toUrl)
          if (
            !isSameExternalOrigin(context.sameOriginRedirects, toExternalOrigin(next))
          ) {
            return Promise.reject(new RedirectBlockedError())
          }
        }
      }

      return Promise.resolve(observation)
    },
  })
  return { transport, calls }
}

describe('External E1.5 HTML extraction', () => {
  it('extracts script and stylesheet references in document order', () => {
    const html = `
      <html><head>
      <base href="https://example.com/app/">
      <link rel="stylesheet" href="/a.css">
      <link REL="Stylesheet" HREF="b.css">
      <link rel="preload" as="style" href="/preload.css">
      <script src="/app.js"></script>
      <script SRC='local.js'></script>
      <script>var x = "<script src='/fake.js'></script>"</script>
      <!-- <script src="/commented.js"></script> -->
      </head></html>
    `
    const result = extractAssetReferences(encode(html), {
      maxHtmlBytes: 64_000,
      contentType: 'text/html',
    })
    expect(result.parsed).toBe(true)
    expect(result.baseHref).toBe('https://example.com/app/')
    expect(result.candidates.map((c) => c.rawReference)).toEqual([
      '/a.css',
      'b.css',
      '/preload.css',
      '/app.js',
      'local.js',
    ])
    expect(result.candidates.some((c) => c.rawReference.includes('fake'))).toBe(false)
    expect(result.candidates.some((c) => c.rawReference.includes('commented'))).toBe(
      false,
    )
  })

  it('skips non-HTML and oversized bodies', () => {
    expect(
      extractAssetReferences(encode('<script src="/x.js"></script>'), {
        maxHtmlBytes: 100,
        contentType: 'application/json',
      }).skipReason,
    ).toBe('not-html')
    expect(
      extractAssetReferences(encode('x'.repeat(200)), {
        maxHtmlBytes: 50,
        contentType: 'text/html',
      }).skipReason,
    ).toBe('oversized')
    expect(isHtmlContentType('text/html; charset=utf-8')).toBe(true)
  })
})

describe('External E1.5 same-origin inventory', () => {
  it('fetches only same-origin assets and rejects off-origin before network', async () => {
    const html = `
      <script src="/app.js"></script>
      <script src="https://cdn.example.com/x.js"></script>
      <script src="http://example.com/insecure.js"></script>
      <script src="https://sub.example.com/y.js"></script>
      <script src="data:text/javascript,alert(1)"></script>
      <link rel="stylesheet" href="/app.css">
    `
    const docUrl = 'https://example.com/'
    const { transport, calls } = createFakeTransport({
      responses: new Map([
        [
          'https://example.com/app.js',
          fakeObservation({
            url: 'https://example.com/app.js',
            headers: [{ name: 'Content-Type', value: 'application/javascript' }],
            body: encode(
              `console.log('${JS_CANARY}')\n//# sourceMappingURL=app.js.map\n`,
            ),
          }),
        ],
        [
          'https://example.com/app.css',
          fakeObservation({
            url: 'https://example.com/app.css',
            headers: [{ name: 'Content-Type', value: 'text/css' }],
            body: encode(
              `/* ${CSS_CANARY} */\n/*# sourceMappingURL=data:application/json;base64,AAAA */\n`,
            ),
          }),
        ],
      ]),
    })

    const result = await inventorySameOriginAssets({
      documentUrl: docUrl,
      documentOrigin: toExternalOrigin(normalizeExternalTarget(docUrl)),
      contentType: 'text/html',
      htmlBody: encode(html),
      budgets: budgets({ maxAssets: 8, maxRequests: 12 }),
      requestsAlreadyUsed: 1,
      transport,
    })

    expect(calls).toEqual(['https://example.com/app.js', 'https://example.com/app.css'])
    const fetched = result.assets.filter((a) => a.fetched)
    expect(fetched).toHaveLength(2)
    expect(fetched[0]?.sourceMapReferenced).toBe(true)
    expect(fetched[0]?.sourceMapReference).toBe('app.js.map')
    expect(fetched[1]?.inlineSourceMap).toBe(true)
    expect(fetched[1]?.sourceMapReference).toBeUndefined()

    const skipped = result.assets.filter((a) => !a.fetched)
    expect(skipped.some((a) => a.skipReason === 'off-origin')).toBe(true)
    expect(skipped.some((a) => a.skipReason === 'unsupported-scheme')).toBe(true)
    expect(JSON.stringify(result.assets)).not.toContain(JS_CANARY)
    expect(JSON.stringify(result.assets)).not.toContain(CSS_CANARY)
    expect(JSON.stringify(result.assets)).not.toMatch(
      /severity|finding|ruleId|vulnerability/i,
    )
  })

  it('deduplicates equivalent URLs and respects maxAssets / global budget', async () => {
    const html = `
      <script src="/app.js"></script>
      <script src="https://example.com/app.js"></script>
      <script src="https://EXAMPLE.com:443/app.js#frag"></script>
      <script src="/one.js"></script>
      <script src="/two.js"></script>
      <script src="/three.js"></script>
    `
    const calls: string[] = []
    const { transport } = createFakeTransport({
      responses: new Map([
        [
          'https://example.com/app.js',
          fakeObservation({ url: 'https://example.com/app.js' }),
        ],
        [
          'https://example.com/one.js',
          fakeObservation({ url: 'https://example.com/one.js' }),
        ],
        [
          'https://example.com/two.js',
          fakeObservation({ url: 'https://example.com/two.js' }),
        ],
        [
          'https://example.com/three.js',
          fakeObservation({ url: 'https://example.com/three.js' }),
        ],
      ]),
      onRequest: (plan) => {
        const target =
          typeof plan.target === 'string'
            ? normalizeExternalTarget(plan.target)
            : plan.target
        calls.push(target.requestUrl)
      },
    })

    const result = await inventorySameOriginAssets({
      documentUrl: 'https://example.com/',
      documentOrigin: toExternalOrigin(normalizeExternalTarget('https://example.com/')),
      contentType: 'text/html',
      htmlBody: encode(html),
      budgets: budgets({ maxAssets: 2, maxRequests: 12 }),
      requestsAlreadyUsed: 0,
      transport,
    })
    expect(calls).toEqual(['https://example.com/app.js', 'https://example.com/one.js'])
    expect(result.assets.some((a) => a.skipReason === 'max-assets')).toBe(true)
    expect(result.assets.some((a) => a.skipReason === 'duplicate')).toBe(true)

    const budgeted = await inventorySameOriginAssets({
      documentUrl: 'https://example.com/',
      documentOrigin: toExternalOrigin(normalizeExternalTarget('https://example.com/')),
      contentType: 'text/html',
      htmlBody: encode(`
        <script src="/a.js"></script>
        <script src="/b.js"></script>
        <script src="/c.js"></script>
      `),
      budgets: budgets({ maxRequests: 3, maxAssets: 8 }),
      requestsAlreadyUsed: 1,
      transport: createFakeTransport({
        responses: new Map([
          [
            'https://example.com/a.js',
            fakeObservation({ url: 'https://example.com/a.js' }),
          ],
          [
            'https://example.com/b.js',
            fakeObservation({ url: 'https://example.com/b.js' }),
          ],
          [
            'https://example.com/c.js',
            fakeObservation({ url: 'https://example.com/c.js' }),
          ],
        ]),
      }).transport,
    })
    const fetchedCount = budgeted.assets.filter((a) => a.fetched).length
    expect(fetchedCount).toBe(2)
    expect(budgeted.assets.some((a) => a.skipReason === 'budget')).toBe(true)
  })

  it('blocks same-origin asset redirect that leaves origin before fetch completes', async () => {
    const { transport, calls } = createFakeTransport({
      responses: new Map([
        [
          'https://example.com/app.js',
          fakeObservation({
            url: 'https://example.com/app.js',
            redirects: [
              {
                index: 0,
                fromUrl: 'https://example.com/app.js',
                toUrl: 'https://cdn.example.com/app.js',
                statusCode: 302,
              },
            ],
          }),
        ],
      ]),
    })

    const result = await inventorySameOriginAssets({
      documentUrl: 'https://example.com/',
      documentOrigin: toExternalOrigin(normalizeExternalTarget('https://example.com/')),
      contentType: 'text/html',
      htmlBody: encode('<script src="/app.js"></script>'),
      budgets: budgets(),
      requestsAlreadyUsed: 0,
      transport,
    })
    expect(calls).toEqual(['https://example.com/app.js'])
    expect(result.assets[0]?.fetched).toBe(false)
    expect(result.assets[0]?.skipReason).toBe('redirect-left-origin')
  })
})

describe('External E1.5 document scan composition', () => {
  it('shares request budget across document and assets and discards bodies', async () => {
    const html = `<html><body>${HTML_CANARY}<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script></body></html>`
    const { transport } = createFakeTransport({
      responses: new Map([
        [
          'https://example.com/',
          fakeObservation({
            url: 'https://example.com/',
            headers: [{ name: 'Content-Type', value: 'text/html' }],
            body: encode(html),
            requestsConsumed: 1,
          }),
        ],
        [
          'https://example.com/a.js',
          fakeObservation({ url: 'https://example.com/a.js' }),
        ],
        [
          'https://example.com/b.js',
          fakeObservation({ url: 'https://example.com/b.js' }),
        ],
        [
          'https://example.com/c.js',
          fakeObservation({ url: 'https://example.com/c.js' }),
        ],
      ]),
    })

    const result = await scanExternalDocument({
      target: 'https://example.com/',
      budgets: budgets({ maxRequests: 3, maxAssets: 8 }),
      transport,
    })

    expect(result.graph.assets.filter((a) => a.fetched)).toHaveLength(2)
    expect(result.graph.assets.some((a) => a.skipReason === 'budget')).toBe(true)
    expect(JSON.stringify(result.graph)).not.toContain(HTML_CANARY)
    expect(result.graph).not.toHaveProperty('body')
    expect(result.requestsConsumed).toBeGreaterThanOrEqual(3)
  })
})

describe('External E1.5 source map facts', () => {
  it('detects references without fetching maps', () => {
    const js = extractSourceMapObservation(
      encode('x=1\n//# sourceMappingURL=/maps/app.map\n'),
      'application/javascript',
    )
    expect(js).toEqual({
      referenced: true,
      inlineSourceMap: false,
      reference: '/maps/app.map',
    })
    const inline = extractSourceMapObservation(
      encode('/*# sourceMappingURL=data:application/json;base64,QQQQ */'),
      'text/css',
    )
    expect(inline.inlineSourceMap).toBe(true)
    expect(inline.reference).toBeUndefined()
  })
})

describe('External E1.5 architecture boundary', () => {
  it('keeps HTML extractors network-free and orchestration free of node http/dns', () => {
    for (const root of ['src/external/extractors', 'src/external/orchestration']) {
      const files = readdirSync(path.resolve(root), {
        recursive: true,
        encoding: 'utf8',
      }).filter((file) => file.endsWith('.ts'))
      const forbidden = new Set([
        'node:dns',
        'node:net',
        'node:http',
        'node:https',
        'node:tls',
      ])
      for (const file of files) {
        const source = readFileSync(path.join(root, file), 'utf8')
        const sourceFile = ts.createSourceFile(
          file,
          source,
          ts.ScriptTarget.Latest,
          true,
          ts.ScriptKind.TS,
        )
        const visit = (node: ts.Node): void => {
          if (
            ts.isImportDeclaration(node) &&
            ts.isStringLiteral(node.moduleSpecifier)
          ) {
            expect(forbidden.has(node.moduleSpecifier.text)).toBe(false)
          }
          ts.forEachChild(node, visit)
        }
        visit(sourceFile)
        expect(source).not.toMatch(/\bfetch\s*\(/u)
        expect(source).not.toMatch(
          /Playwright|Puppeteer|child_process|allowPrivate|skipSsrf/u,
        )
        expect(source).not.toMatch(
          /\bseverity\b|\bfinding\b|\bruleId\b|\bvulnerability\b/i,
        )
      }
    }
  })

  it('does not export orchestration from public package entry', () => {
    const source = readFileSync(path.resolve('src/index.ts'), 'utf8')
    expect(source).not.toContain('external/orchestration')
    expect(source).not.toContain('scanExternalDocument')
  })
})
