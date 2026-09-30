import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

import { runExternalScan } from '../src/external/application/run-external-scan.js'
import {
  createExternalScanBudgets,
  normalizeExternalTarget,
} from '../src/external/domain/index.js'
import {
  createOutboundHttpCapability,
  RemoteAddressMismatchError,
  type DnsResolver,
  type PinnedConnectRequest,
  type PinnedConnectResponse,
  type PinnedHttpConnector,
} from '../src/external/infra/index.js'
import { canonicalRemoteAddress } from '../src/external/infra/pin-selection.js'
import { inventorySameOriginAssets } from '../src/external/orchestration/index.js'
import {
  classifyIpAddress,
  evaluateNormalizedDestination,
  evaluateResolvedAddressSet,
} from '../src/external/policy/index.js'
import {
  createExternalScanResult,
  renderExternalMarkdownReport,
  renderExternalReport,
  renderExternalTerminalReport,
} from '../src/external/reporters/index.js'
import {
  EXTERNAL_RULE_IDS,
  evaluateExternalRules,
} from '../src/external/rules/index.js'
import { toExternalOrigin } from '../src/external/domain/target.js'
import type {
  ExternalHttpResponseObservation,
  ExternalObservationGraph,
  ExternalSecurityHeaderObservation,
} from '../src/external/domain/observations.js'
import { runCli } from '../src/cli/run.js'
import * as publicApi from '../src/index.js'

const FIXED_TIME = Date.parse('2024-06-15T12:00:00.000Z')
const PUBLIC_V4 = '203.0.114.10'
const CANARIES = Object.freeze([
  'SUPER_SECRET_COOKIE_CANARY_123',
  'SESSION_TOKEN_DO_NOT_LEAK',
  'JWT_SHAPED_TEST_VALUE',
  'AUTHORIZATION_SECRET_CANARY',
  'HTML_BODY_SECRET_CANARY',
  'JS_BODY_SECRET_CANARY',
  'CSS_BODY_SECRET_CANARY',
] as const)

function assertNoCanaries(text: string): void {
  for (const canary of CANARIES) {
    expect(text).not.toContain(canary)
  }
}

function encode(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function budgets(overrides: Parameters<typeof createExternalScanBudgets>[0] = {}) {
  return createExternalScanBudgets(overrides)
}

function createFakeDns(map: Readonly<Record<string, readonly string[]>>): DnsResolver {
  return Object.freeze({
    lookupAll(hostname: string) {
      const addresses = map[hostname]
      if (addresses === undefined) {
        return Promise.reject(new Error(`DNS boom ${CANARIES[0]}`))
      }
      return Promise.resolve(
        Object.freeze({ addresses: Object.freeze([...addresses]) }),
      )
    },
  })
}

function createFakeConnector(script: {
  byUrl: ReadonlyMap<
    string,
    {
      statusCode: number
      headers?: readonly { name: string; value: string }[]
      body?: Uint8Array
      remoteAddress?: string
    }[]
  >
}): { connector: PinnedHttpConnector; calls: PinnedConnectRequest[] } {
  const calls: PinnedConnectRequest[] = []
  const indices = new Map<string, number>()
  const connector: PinnedHttpConnector = Object.freeze({
    connect(request: PinnedConnectRequest): Promise<PinnedConnectResponse> {
      calls.push(request)
      const key = `${request.scheme}://${request.hostname}${request.pathname}${request.search}`
      const hops = script.byUrl.get(key)
      if (hops === undefined) {
        return Promise.reject(new Error(`connect miss ${CANARIES[1]}`))
      }
      const index = indices.get(key) ?? 0
      indices.set(key, index + 1)
      const hop = hops[Math.min(index, hops.length - 1)]
      if (hop === undefined) {
        return Promise.reject(new Error('empty hop'))
      }
      const remoteAddress = hop.remoteAddress ?? request.pinnedAddress
      const remoteCanonical = canonicalRemoteAddress(remoteAddress)
      const approved = new Set(
        request.approvedAddresses
          .map((address) => canonicalRemoteAddress(address))
          .filter((address): address is string => address !== undefined),
      )
      if (remoteCanonical === undefined || !approved.has(remoteCanonical)) {
        return Promise.reject(new RemoteAddressMismatchError())
      }
      return Promise.resolve(
        Object.freeze({
          statusCode: hop.statusCode,
          headers: Object.freeze(hop.headers ?? []),
          body: hop.body ?? new Uint8Array(),
          pinnedAddress: request.pinnedAddress,
          remoteAddress,
          ...(request.scheme === 'https'
            ? { tls: Object.freeze({ authorized: true as const, protocol: 'TLSv1.3' }) }
            : {}),
        }),
      )
    },
  })
  return { connector, calls }
}

function emptyGraph(
  overrides: Partial<ExternalObservationGraph> = {},
): ExternalObservationGraph {
  return Object.freeze({
    initialRequestUrl: overrides.initialRequestUrl ?? 'https://example.com/',
    ...(overrides.finalUrl !== undefined ? { finalUrl: overrides.finalUrl } : {}),
    redirects: Object.freeze(overrides.redirects ?? []),
    blockedRedirects: Object.freeze(overrides.blockedRedirects ?? []),
    responses: Object.freeze(overrides.responses ?? []),
    assets: Object.freeze(overrides.assets ?? []),
  })
}

function httpsDoc(
  overrides: Partial<ExternalHttpResponseObservation> & {
    headerStatus?: Partial<
      Record<
        | 'strict-transport-security'
        | 'content-security-policy'
        | 'x-content-type-options'
        | 'referrer-policy',
        'OBSERVED' | 'MISSING' | 'UNKNOWN'
      >
    >
  } = {},
): ExternalHttpResponseObservation {
  const status = overrides.headerStatus ?? {}
  const securityHeaders: ExternalSecurityHeaderObservation[] = [
    Object.freeze({
      name: 'strict-transport-security',
      status:
        status['strict-transport-security'] === 'MISSING' ? 'MISSING' : 'OBSERVED',
      values:
        status['strict-transport-security'] === 'MISSING'
          ? Object.freeze([])
          : Object.freeze(['max-age=1']),
    }),
    Object.freeze({
      name: 'content-security-policy',
      status: status['content-security-policy'] === 'MISSING' ? 'MISSING' : 'OBSERVED',
      values:
        status['content-security-policy'] === 'MISSING'
          ? Object.freeze([])
          : Object.freeze(["default-src 'self'"]),
    }),
    Object.freeze({
      name: 'x-content-type-options',
      status: status['x-content-type-options'] === 'MISSING' ? 'MISSING' : 'OBSERVED',
      values:
        status['x-content-type-options'] === 'MISSING'
          ? Object.freeze([])
          : Object.freeze(['nosniff']),
    }),
    Object.freeze({
      name: 'referrer-policy',
      status: status['referrer-policy'] === 'MISSING' ? 'MISSING' : 'OBSERVED',
      values:
        status['referrer-policy'] === 'MISSING'
          ? Object.freeze([])
          : Object.freeze(['no-referrer']),
    }),
  ]

  // UNKNOWN is represented by omitting a successful document response entirely
  // or by using NOT_APPLICABLE/unknown TLS facts — never by inventing MISSING.
  void status

  return Object.freeze({
    url: overrides.url ?? 'https://example.com/',
    method: overrides.method ?? 'GET',
    statusCode: overrides.statusCode ?? 200,
    scheme: overrides.scheme ?? 'https',
    headers: Object.freeze(overrides.headers ?? []),
    securityHeaders: Object.freeze(overrides.securityHeaders ?? securityHeaders),
    hsts:
      overrides.hsts ??
      Object.freeze(
        status['strict-transport-security'] === 'MISSING'
          ? { status: 'MISSING' as const }
          : { status: 'OBSERVED' as const, maxAgeSeconds: 1 },
      ),
    bodyByteLength: overrides.bodyByteLength ?? 0,
    cookies: Object.freeze(overrides.cookies ?? []),
    tlsUsed: overrides.tlsUsed ?? true,
    ...(overrides.tls !== undefined
      ? { tls: overrides.tls }
      : { tls: Object.freeze({ authorized: true as const }) }),
  })
}

describe('External E1.8 adversarial target normalization', () => {
  it('fail-closes ambiguous IPv4 encodings and credentialed/hostile targets', () => {
    for (const target of [
      'http://127.1/',
      'http://127.0.1/',
      'http://0x7f000001/',
      'http://2130706433/',
      'http://0177.0.0.1/',
      'https://[::ffff:127.0.0.1]/',
      'https://[::1]/',
      '169.254.169.254',
      'localhost',
      'LOCALHOST',
      'foo.localhost',
      'metadata.google.internal',
    ]) {
      const normalized = normalizeExternalTarget(target)
      const decision = evaluateNormalizedDestination(normalized)
      expect(['IP_DENIED', 'BLOCKED_STATICALLY']).toContain(decision.kind)
    }

    for (const target of [
      'https://user:pass@example.com',
      'https://example.com@127.0.0.1',
      'https://127.0.0.1@example.com',
      'https://example.com:8443',
      'ftp://example.com',
      '10.0.0.0/8',
      'https://*',
      'https://example.com\r\nHost: evil',
      'https://example.com\u0000',
      '',
      '   ',
    ]) {
      let threw = false
      try {
        normalizeExternalTarget(target)
      } catch {
        threw = true
      }
      expect(threw, `expected reject for ${JSON.stringify(target)}`).toBe(true)
    }
  })
})

describe('External E1.8 IPv4/IPv6 and mapped classification', () => {
  it('denies range boundaries and mapped private addresses', () => {
    const deny = [
      '0.0.0.0',
      '0.255.255.255',
      '10.0.0.0',
      '10.255.255.255',
      '100.64.0.0',
      '100.127.255.255',
      '127.0.0.0',
      '127.255.255.255',
      '169.254.0.0',
      '169.254.169.254',
      '169.254.255.255',
      '172.16.0.0',
      '172.31.255.255',
      '192.0.0.0',
      '192.0.0.255',
      '192.0.2.0',
      '192.0.2.255',
      '192.168.0.0',
      '192.168.255.255',
      '198.18.0.0',
      '198.19.255.255',
      '198.51.100.0',
      '198.51.100.255',
      '203.0.113.0',
      '203.0.113.255',
      '224.0.0.0',
      '239.255.255.255',
      '240.0.0.0',
      '255.255.255.254',
      '255.255.255.255',
      '::',
      '::1',
      'fc00::',
      'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
      'fe80::',
      'ff00::',
      '2001:db8::',
      '::ffff:127.0.0.1',
      '::ffff:10.0.0.1',
      '::ffff:169.254.169.254',
      '::ffff:192.168.1.1',
      '0:0:0:0:0:ffff:7f00:1',
    ]
    for (const address of deny) {
      expect(classifyIpAddress(address).decision).toBe('DENY_NON_PUBLIC')
    }
    expect(classifyIpAddress('8.8.8.8').decision).toBe('ALLOW_PUBLIC')
    expect(classifyIpAddress('::ffff:8.8.8.8').decision).toBe('ALLOW_PUBLIC')
    expect(classifyIpAddress('2001:4860:4860::8888').decision).toBe('ALLOW_PUBLIC')
  })

  it('fail-closes mixed DNS answer sets regardless of order', () => {
    const mixed = [
      ['8.8.8.8', '10.0.0.1'],
      ['10.0.0.1', '8.8.8.8'],
      ['8.8.8.8', '127.0.0.1'],
      ['8.8.8.8', '169.254.169.254'],
      ['8.8.8.8', 'not-an-ip'],
      ['::ffff:10.0.0.1', '8.8.8.8'],
    ]
    for (const set of mixed) {
      expect(evaluateResolvedAddressSet('example.com', set).decision).toBe(
        'DENY_NON_PUBLIC',
      )
    }
    expect(evaluateResolvedAddressSet('example.com', []).decision).toBe('DENY_EMPTY')
  })
})

describe('External E1.8 DNS rebinding and pin order', () => {
  it('rejects connector remoteAddress outside the approved pin set', async () => {
    const { connector } = createFakeConnector({
      byUrl: new Map([
        [
          'https://example.com/',
          [
            {
              statusCode: 200,
              headers: [{ name: 'content-type', value: 'text/html' }],
              remoteAddress: '10.0.0.1',
            },
          ],
        ],
      ]),
    })
    const transport = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'example.com': [PUBLIC_V4] }),
      connect: connector,
      nowMs: () => FIXED_TIME,
    })
    await expect(
      transport.request(
        { target: 'https://example.com/', method: 'GET' },
        { budgets: budgets() },
      ),
    ).rejects.toMatchObject({ name: 'RemoteAddressMismatchError' })
  })

  it('rejects unapproved public remoteAddress even when also public', async () => {
    const { connector } = createFakeConnector({
      byUrl: new Map([
        [
          'https://example.com/',
          [
            {
              statusCode: 200,
              remoteAddress: '203.0.114.99',
            },
          ],
        ],
      ]),
    })
    const transport = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'example.com': [PUBLIC_V4] }),
      connect: connector,
      nowMs: () => FIXED_TIME,
    })
    await expect(
      transport.request(
        { target: 'https://example.com/', method: 'GET' },
        { budgets: budgets() },
      ),
    ).rejects.toMatchObject({ name: 'RemoteAddressMismatchError' })
  })
})

describe('External E1.8 redirect and asset origin budget', () => {
  it('blocks HTTPS→HTTP and accounts multi-hop same-origin→off-origin asset redirects', async () => {
    const { connector, calls } = createFakeConnector({
      byUrl: new Map([
        [
          'https://example.com/app.js',
          [
            {
              statusCode: 302,
              headers: [{ name: 'location', value: '/next.js' }],
            },
          ],
        ],
        [
          'https://example.com/next.js',
          [
            {
              statusCode: 302,
              headers: [{ name: 'location', value: 'https://cdn.example.com/app.js' }],
            },
          ],
        ],
      ]),
    })
    const transport = createOutboundHttpCapability({
      resolveDns: createFakeDns({
        'example.com': [PUBLIC_V4],
        'cdn.example.com': [PUBLIC_V4],
      }),
      connect: connector,
      nowMs: () => FIXED_TIME,
    })

    const inventory = await inventorySameOriginAssets({
      documentUrl: 'https://example.com/',
      documentOrigin: toExternalOrigin(normalizeExternalTarget('https://example.com/')),
      contentType: 'text/html',
      htmlBody: encode(
        '<script src="/app.js"></script><script src="/other.js"></script>',
      ),
      budgets: budgets({ maxRequests: 4, maxAssets: 8 }),
      requestsAlreadyUsed: 0,
      transport,
    })

    expect(inventory.assets[0]?.fetched).toBe(false)
    expect(inventory.assets[0]?.skipReason).toBe('redirect-left-origin')
    // Two hops were attempted before the off-origin block.
    expect(inventory.requestsConsumed).toBeGreaterThanOrEqual(2)
    expect(calls.length).toBeGreaterThanOrEqual(2)
    expect(calls.every((call) => call.hostname === 'example.com')).toBe(true)
  })

  it('never fetches off-origin asset redirect destinations', async () => {
    const { connector, calls } = createFakeConnector({
      byUrl: new Map([
        [
          'https://example.com/app.js',
          [
            {
              statusCode: 302,
              headers: [{ name: 'location', value: 'https://evil.example/x.js' }],
            },
          ],
        ],
      ]),
    })
    const transport = createOutboundHttpCapability({
      resolveDns: createFakeDns({
        'example.com': [PUBLIC_V4],
        'evil.example': [PUBLIC_V4],
      }),
      connect: connector,
      nowMs: () => FIXED_TIME,
    })
    await inventorySameOriginAssets({
      documentUrl: 'https://example.com/',
      documentOrigin: toExternalOrigin(normalizeExternalTarget('https://example.com/')),
      contentType: 'text/html',
      htmlBody: encode('<script src="/app.js"></script>'),
      budgets: budgets(),
      requestsAlreadyUsed: 0,
      transport,
    })
    expect(calls.some((call) => call.hostname === 'evil.example')).toBe(false)
  })
})

describe('External E1.8 secret and reporter boundaries', () => {
  it('keeps cookie/body/authorization canaries out of full pipeline outputs', async () => {
    const html = `<html><body>${CANARIES[4]}<script src="/a.js">${CANARIES[5]}</script><style>${CANARIES[6]}</style></body></html>`
    const transport = Object.freeze({
      request() {
        return Promise.resolve(
          Object.freeze({
            initialRequestUrl: 'http://example.com/',
            finalUrl: 'http://example.com/',
            method: 'GET' as const,
            hops: Object.freeze([
              Object.freeze({
                requestUrl: 'http://example.com/',
                method: 'GET' as const,
                statusCode: 200,
                headers: Object.freeze([
                  Object.freeze({
                    name: 'content-type',
                    value: 'text/html',
                  }),
                  Object.freeze({
                    name: 'set-cookie',
                    value: `session=${CANARIES[0]}; Path=/`,
                  }),
                  Object.freeze({
                    name: 'authorization',
                    value: CANARIES[3],
                  }),
                ]),
                body: encode(html),
                pinnedAddress: PUBLIC_V4,
                remoteAddress: PUBLIC_V4,
              }),
            ]),
            redirects: Object.freeze([]),
            requestsConsumed: 1,
          }),
        )
      },
    })

    const outcome = await runExternalScan('http://example.com/', {
      format: 'json',
      transport,
      evaluationTimeMs: FIXED_TIME,
    })
    for (const format of ['terminal', 'json', 'markdown'] as const) {
      const rendered = renderExternalReport(outcome.result, format)
      assertNoCanaries(rendered)
      if (format === 'json') {
        const parsed: unknown = JSON.parse(rendered)
        expect(parsed).toMatchObject({ schemaVersion: 'ext-1' })
      }
    }
    assertNoCanaries(JSON.stringify(outcome.result))
  })

  it('sanitizes terminal/markdown injection including bidi and fences', () => {
    const hostile = `https://example.com/\u001b[31m\u0007\u202Eevil\r\n# H | \`\`\` <script>alert(1)</script>`
    const findings = evaluateExternalRules(
      emptyGraph({
        finalUrl: hostile,
        responses: [
          httpsDoc({
            url: hostile,
            scheme: 'http',
            tlsUsed: false,
            hsts: { status: 'NOT_APPLICABLE' },
            headerStatus: {
              'content-security-policy': 'MISSING',
              'referrer-policy': 'MISSING',
              'x-content-type-options': 'MISSING',
              'strict-transport-security': 'MISSING',
            },
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    const result = createExternalScanResult({
      target: hostile,
      effectiveUrl: hostile,
      findings,
      limitations: Object.freeze([hostile]),
      evaluationTimeMs: FIXED_TIME,
      requestsConsumed: 1,
    })
    const terminal = renderExternalTerminalReport(result)
    const markdown = renderExternalMarkdownReport(result)
    for (const output of [terminal, markdown]) {
      expect(output).not.toContain('\u001b')
      expect(output).not.toContain('\u202E')
      expect(output).not.toContain('\u0007')
    }
    expect(markdown).not.toContain('<script>')
    expect(terminal.toLowerCase()).not.toMatch(
      /\bsecure\b|\bsafe\b|pentest passed|no vulnerabilities/,
    )
  })

  it('bounds hostile error payloads on stderr', async () => {
    const huge = `${CANARIES[0]}${'A'.repeat(200_000)}`
    const transport = Object.freeze({
      request() {
        return Promise.reject(new Error(huge))
      },
    })
    await expect(
      runExternalScan('https://example.com/', {
        format: 'json',
        transport,
        evaluationTimeMs: FIXED_TIME,
      }),
    ).rejects.toMatchObject({ name: 'ExternalScanError' })
    try {
      await runExternalScan('https://example.com/', {
        format: 'json',
        transport,
        evaluationTimeMs: FIXED_TIME,
      })
    } catch (error) {
      expect(error).toMatchObject({ name: 'ExternalScanError' })
      if (error instanceof Error) {
        expect(error.message.length).toBeLessThan(500)
        assertNoCanaries(error.message)
      }
    }
  })
})

describe('External E1.8 rule semantics and catalog', () => {
  it('keeps UNKNOWN from becoming MISSING and preserves SameSite correction', () => {
    const unknownGraph = emptyGraph({
      finalUrl: 'https://example.com/',
      // No responses → no positively established missing headers.
    })
    expect(
      evaluateExternalRules(unknownGraph, { evaluationTimeMs: FIXED_TIME }),
    ).toEqual([])

    const sameSiteUnknown = evaluateExternalRules(
      emptyGraph({
        finalUrl: 'https://example.com/',
        responses: [
          httpsDoc({
            cookies: Object.freeze([
              Object.freeze({
                name: 'x',
                secure: true,
                httpOnly: true,
                sameSite: 'unknown' as const,
                hostPrefix: false,
                securePrefix: false,
              }),
            ]),
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(sameSiteUnknown.some((finding) => finding.ruleId === 'VS-EXT-007')).toBe(
      false,
    )

    const sameSiteAbsent = evaluateExternalRules(
      emptyGraph({
        finalUrl: 'https://example.com/',
        responses: [
          httpsDoc({
            cookies: Object.freeze([
              Object.freeze({
                name: 'x',
                secure: true,
                httpOnly: true,
                sameSite: 'absent' as const,
                hostPrefix: false,
                securePrefix: false,
              }),
            ]),
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(sameSiteAbsent.some((finding) => finding.ruleId === 'VS-EXT-007')).toBe(true)
  })

  it('uses strict TLS clock inequality and hostname-only attribution', () => {
    const atBoundary = evaluateExternalRules(
      emptyGraph({
        finalUrl: 'https://example.com/',
        responses: [
          httpsDoc({
            tls: {
              authorized: true,
              validToIso: new Date(FIXED_TIME).toISOString(),
            },
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(atBoundary.some((finding) => finding.ruleId === 'VS-EXT-008')).toBe(false)

    const genericTls = evaluateExternalRules(
      emptyGraph({
        finalUrl: 'https://example.com/',
        responses: [
          httpsDoc({
            tls: { authorized: false, authorizationError: 'handshake failure' },
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(genericTls.some((finding) => finding.ruleId === 'VS-EXT-009')).toBe(false)
  })

  it('has exactly VS-EXT-001..011 with deterministic finding identity', () => {
    expect([...EXTERNAL_RULE_IDS]).toEqual([
      'VS-EXT-001',
      'VS-EXT-002',
      'VS-EXT-003',
      'VS-EXT-004',
      'VS-EXT-005',
      'VS-EXT-006',
      'VS-EXT-007',
      'VS-EXT-008',
      'VS-EXT-009',
      'VS-EXT-010',
      'VS-EXT-011',
    ])
    const graph = emptyGraph({
      finalUrl: 'https://example.com/',
      responses: [
        httpsDoc({
          cookies: Object.freeze([
            Object.freeze({
              name: 'sid',
              secure: false,
              httpOnly: false,
              sameSite: 'absent' as const,
              path: '/',
              hostPrefix: false,
              securePrefix: false,
            }),
            Object.freeze({
              name: 'sid',
              secure: false,
              httpOnly: false,
              sameSite: 'absent' as const,
              path: '/admin',
              hostPrefix: false,
              securePrefix: false,
            }),
          ]),
        }),
      ],
    })
    const left = evaluateExternalRules(graph, { evaluationTimeMs: FIXED_TIME })
    const right = evaluateExternalRules(graph, { evaluationTimeMs: FIXED_TIME })
    expect(JSON.stringify(left)).toBe(JSON.stringify(right))
    const cookieFindings = left.filter((finding) => finding.ruleId === 'VS-EXT-006')
    expect(new Set(cookieFindings.map((finding) => finding.id)).size).toBe(
      cookieFindings.length,
    )
  })
})

describe('External E1.8 architecture and Code isolation', () => {
  it('enforces import boundaries across External layers', () => {
    const checks: readonly { root: string; forbid: readonly string[] }[] = [
      {
        root: 'src/external/rules',
        forbid: [
          'external/infra',
          'external/orchestration',
          'external/reporters',
          'external/application',
          'node:dns',
          'node:net',
          'node:http',
          'node:https',
          'node:tls',
          'node:fs',
        ],
      },
      {
        root: 'src/external/extractors',
        forbid: ['external/infra', 'external/application', 'node:dns', 'node:http'],
      },
      {
        root: 'src/external/reporters',
        forbid: ['external/infra', 'external/orchestration', 'node:dns', 'node:http'],
      },
      {
        root: 'src/external/domain',
        forbid: ['external/infra', 'node:dns', 'node:http', 'node:https', 'node:tls'],
      },
      {
        root: 'src/rules',
        forbid: ['external/'],
      },
      {
        root: 'src/reporters',
        forbid: ['external/'],
      },
      {
        root: 'src/application',
        forbid: ['external/'],
      },
    ]

    for (const check of checks) {
      const absolute = path.resolve(check.root)
      const files = readdirSync(absolute, { recursive: true, encoding: 'utf8' }).filter(
        (file) => file.endsWith('.ts'),
      )
      for (const file of files) {
        const source = readFileSync(path.join(absolute, file), 'utf8')
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
            const specifier = node.moduleSpecifier.text
            for (const banned of check.forbid) {
              expect(specifier.includes(banned)).toBe(false)
            }
          }
          ts.forEachChild(node, visit)
        }
        visit(sourceFile)
      }
    }
  })

  it('does not initialize External production capability on Code scan dispatch', async () => {
    const source = readFileSync(path.resolve('src/cli/run.ts'), 'utf8')
    expect(source).toMatch(
      /import\(\s*['"]\.\.\/external\/infra\/production\.js['"]\s*\)/u,
    )
    expect(source).not.toMatch(/from ['"]\.\.\/external\/infra\/production\.js['"]/u)

    const root = await (
      await import('node:fs/promises')
    ).mkdtemp(path.join((await import('node:os')).tmpdir(), 'vibesec-e18-'))
    await (
      await import('node:fs/promises')
    ).writeFile(path.join(root, 'ok.txt'), 'hello')
    const exitCode = await runCli(
      ['scan', root, '--format', 'json'],
      { stdout: () => undefined, stderr: () => undefined },
      process.platform,
    )
    expect(exitCode).toBe(0)
    await (await import('node:fs/promises')).rm(root, { recursive: true, force: true })
  })

  it('keeps dangerous External primitives out of public API and avoids proxy agents', () => {
    const keys = Object.keys(publicApi)
    expect(keys).not.toContain('createProductionOutboundHttpCapability')
    expect(keys).not.toContain('createNodeDnsResolver')
    expect(keys).not.toContain('createNodePinnedHttpConnector')
    expect(keys).not.toContain('evaluateResolvedAddressSet')

    const connector = readFileSync(
      path.resolve('src/external/infra/node-connector.ts'),
      'utf8',
    )
    const connectorFile = ts.createSourceFile(
      'node-connector.ts',
      connector,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TS,
    )
    const codeWithoutComments = connectorFile
      .getFullText()
      .replaceAll(/\/\*[\s\S]*?\*\//gu, '')
      .replaceAll(/(^|[^:])\/\/.*$/gmu, '$1')
    expect(codeWithoutComments).not.toMatch(
      /HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|ProxyAgent|global-agent|proxy-from-env/u,
    )
    expect(codeWithoutComments).toMatch(/rejectUnauthorized:\s*true/u)
    expect(codeWithoutComments).not.toMatch(/rejectUnauthorized:\s*false/u)
    expect(codeWithoutComments).toMatch(/agent:\s*false/u)
  })

  it('preserves exit code matrix across formats', async () => {
    const okTransport = Object.freeze({
      request() {
        return Promise.resolve(
          Object.freeze({
            initialRequestUrl: 'https://example.com/',
            finalUrl: 'https://example.com/',
            method: 'GET' as const,
            hops: Object.freeze([
              Object.freeze({
                requestUrl: 'https://example.com/',
                method: 'GET' as const,
                statusCode: 200,
                headers: Object.freeze([
                  Object.freeze({
                    name: 'content-type',
                    value: 'text/html',
                  }),
                  Object.freeze({
                    name: 'strict-transport-security',
                    value: 'max-age=31536000',
                  }),
                  Object.freeze({
                    name: 'content-security-policy',
                    value: "default-src 'self'",
                  }),
                  Object.freeze({
                    name: 'x-content-type-options',
                    value: 'nosniff',
                  }),
                  Object.freeze({
                    name: 'referrer-policy',
                    value: 'no-referrer',
                  }),
                ]),
                body: encode('<html></html>'),
                pinnedAddress: PUBLIC_V4,
                remoteAddress: PUBLIC_V4,
                tls: Object.freeze({ authorized: true, protocol: 'TLSv1.3' }),
              }),
            ]),
            redirects: Object.freeze([]),
            requestsConsumed: 1,
          }),
        )
      },
    })

    for (const format of ['terminal', 'json', 'markdown'] as const) {
      const zero = await runExternalScan('https://example.com/', {
        format,
        transport: okTransport,
        evaluationTimeMs: FIXED_TIME,
      })
      expect(zero.findingCount === 0 ? 0 : 1).toBe(0)
      expect(zero.output.toLowerCase()).not.toMatch(
        /\bsite is secure\b|\bno vulnerabilities\b|pentest passed/,
      )
    }
  })
})
