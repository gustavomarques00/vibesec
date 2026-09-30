import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

import type {
  ExternalHttpResponseObservation,
  ExternalObservationGraph,
  ExternalSecurityHeaderObservation,
} from '../src/external/domain/observations.js'
import {
  EXTERNAL_RULE_IDS,
  evaluateExternalRules,
  getExternalRuleMetadata,
} from '../src/external/rules/index.js'

const CANARY_A = 'SUPER_SECRET_COOKIE_CANARY_123'
const CANARY_B = 'SESSION_TOKEN_DO_NOT_LEAK'
const CANARY_C = 'JWT_SHAPED_TEST_VALUE'
const FIXED_TIME = Date.parse('2024-06-15T12:00:00.000Z')

function allHeaders(
  overrides: Partial<Record<string, 'OBSERVED' | 'MISSING' | string[]>> = {},
): readonly ExternalSecurityHeaderObservation[] {
  const names = [
    'strict-transport-security',
    'content-security-policy',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'cross-origin-embedder-policy',
    'content-type',
    'content-encoding',
    'location',
    'set-cookie',
  ] as const

  return Object.freeze(
    names.map((name) => {
      const override = overrides[name]
      if (override === undefined || override === 'MISSING') {
        return Object.freeze({
          name,
          status: 'MISSING' as const,
          values: Object.freeze([]),
        })
      }
      if (override === 'OBSERVED') {
        return Object.freeze({
          name,
          status: 'OBSERVED' as const,
          values: Object.freeze(['present']),
        })
      }
      return Object.freeze({
        name,
        status: 'OBSERVED' as const,
        values: Object.freeze([...override]),
      })
    }),
  )
}

function documentResponse(
  overrides: Partial<ExternalHttpResponseObservation> & {
    url: string
    scheme: 'http' | 'https'
  },
): ExternalHttpResponseObservation {
  return Object.freeze({
    url: overrides.url,
    method: overrides.method ?? 'GET',
    statusCode: overrides.statusCode ?? 200,
    scheme: overrides.scheme,
    headers: overrides.headers ?? Object.freeze([]),
    securityHeaders: overrides.securityHeaders ?? allHeaders(),
    hsts:
      overrides.hsts ??
      Object.freeze({
        status:
          overrides.scheme === 'https'
            ? ('MISSING' as const)
            : ('NOT_APPLICABLE' as const),
      }),
    bodyByteLength: overrides.bodyByteLength ?? 0,
    cookies: overrides.cookies ?? Object.freeze([]),
    tlsUsed: overrides.tlsUsed ?? overrides.scheme === 'https',
    ...(overrides.contentType !== undefined
      ? { contentType: overrides.contentType }
      : {}),
    ...(overrides.tls !== undefined ? { tls: overrides.tls } : {}),
  })
}

function graph(
  partial: Partial<ExternalObservationGraph> & {
    initialRequestUrl: string
    finalUrl: string
  },
): ExternalObservationGraph {
  return Object.freeze({
    initialRequestUrl: partial.initialRequestUrl,
    finalUrl: partial.finalUrl,
    redirects: Object.freeze(partial.redirects ?? []),
    blockedRedirects: Object.freeze(partial.blockedRedirects ?? []),
    responses: Object.freeze(partial.responses ?? []),
    assets: Object.freeze(partial.assets ?? []),
  })
}

function ruleIds(findings: ReturnType<typeof evaluateExternalRules>): string[] {
  return findings.map((finding) => finding.ruleId)
}

describe('External E1.6 rule catalog', () => {
  it('exposes exactly VS-EXT-001..011 once each', () => {
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
    const ids = getExternalRuleMetadata().map((meta) => meta.id)
    expect(new Set(ids).size).toBe(11)
  })
})

describe('External E1.6 transport and header rules', () => {
  it('emits VS-EXT-001 only for final HTTP URLs', () => {
    const httpGraph = graph({
      initialRequestUrl: 'http://example.com/',
      finalUrl: 'http://example.com/',
      responses: [
        documentResponse({
          url: 'http://example.com/',
          scheme: 'http',
          securityHeaders: allHeaders({
            'content-security-policy': 'OBSERVED',
            'x-content-type-options': ['nosniff'],
            'referrer-policy': 'OBSERVED',
          }),
          hsts: { status: 'NOT_APPLICABLE' },
        }),
      ],
    })
    expect(
      ruleIds(evaluateExternalRules(httpGraph, { evaluationTimeMs: FIXED_TIME })),
    ).toContain('VS-EXT-001')

    const upgraded = graph({
      initialRequestUrl: 'http://example.com/',
      finalUrl: 'https://example.com/',
      responses: [
        documentResponse({
          url: 'https://example.com/',
          scheme: 'https',
          securityHeaders: allHeaders({
            'strict-transport-security': ['max-age=1'],
            'content-security-policy': ["default-src 'self'"],
            'x-content-type-options': ['nosniff'],
            'referrer-policy': ['no-referrer'],
          }),
          hsts: { status: 'OBSERVED', rawValue: 'max-age=1', maxAgeSeconds: 1 },
          tls: { authorized: true, protocol: 'TLSv1.3' },
        }),
      ],
    })
    expect(
      ruleIds(evaluateExternalRules(upgraded, { evaluationTimeMs: FIXED_TIME })),
    ).not.toContain('VS-EXT-001')
  })

  it('emits VS-EXT-002 only for https-to-http blocked redirects', () => {
    const findings = evaluateExternalRules(
      graph({
        initialRequestUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        blockedRedirects: [
          {
            index: 0,
            fromUrl: 'https://example.com/',
            toUrl: 'http://example.com/',
            statusCode: 302,
            reason: 'https-to-http',
          },
          {
            index: 1,
            fromUrl: 'https://example.com/',
            toUrl: 'https://127.0.0.1/',
            reason: 'blocked-destination',
          },
        ],
        responses: [
          documentResponse({
            url: 'https://example.com/',
            scheme: 'https',
            securityHeaders: allHeaders({
              'strict-transport-security': ['max-age=1'],
              'content-security-policy': 'OBSERVED',
              'x-content-type-options': ['nosniff'],
              'referrer-policy': 'OBSERVED',
            }),
            hsts: { status: 'OBSERVED', maxAgeSeconds: 1 },
            tls: { authorized: true },
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(ruleIds(findings).filter((id) => id === 'VS-EXT-002')).toHaveLength(1)
  })

  it('emits missing HSTS/CSP/XCTO/Referrer only when positively MISSING on HTTPS docs', () => {
    const missing = evaluateExternalRules(
      graph({
        initialRequestUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        responses: [
          documentResponse({
            url: 'https://example.com/',
            scheme: 'https',
            tls: { authorized: true },
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(ruleIds(missing)).toEqual(
      expect.arrayContaining(['VS-EXT-003', 'VS-EXT-004', 'VS-EXT-005', 'VS-EXT-011']),
    )

    const present = evaluateExternalRules(
      graph({
        initialRequestUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        responses: [
          documentResponse({
            url: 'https://example.com/',
            scheme: 'https',
            securityHeaders: allHeaders({
              'strict-transport-security': ['max-age=31536000'],
              'content-security-policy': ["default-src 'self'"],
              'x-content-type-options': ['NOSNIFF'],
              'referrer-policy': ['strict-origin'],
            }),
            hsts: {
              status: 'OBSERVED',
              rawValue: 'max-age=31536000',
              maxAgeSeconds: 31536000,
            },
            tls: { authorized: true },
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(ruleIds(present)).not.toEqual(
      expect.arrayContaining(['VS-EXT-003', 'VS-EXT-004', 'VS-EXT-005', 'VS-EXT-011']),
    )
  })

  it('does not treat UNKNOWN/empty header catalogs as missing', () => {
    const findings = evaluateExternalRules(
      graph({
        initialRequestUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        responses: [
          documentResponse({
            url: 'https://example.com/',
            scheme: 'https',
            securityHeaders: Object.freeze([]),
            hsts: { status: 'NOT_APPLICABLE' },
            tlsUsed: true,
            tls: { authorized: true },
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(ruleIds(findings)).not.toContain('VS-EXT-003')
    expect(ruleIds(findings)).not.toContain('VS-EXT-004')
    expect(ruleIds(findings)).not.toContain('VS-EXT-005')
    expect(ruleIds(findings)).not.toContain('VS-EXT-011')
  })
})

describe('External E1.6 cookie rules', () => {
  it('evaluates Secure/HttpOnly/SameSite without retaining cookie values', () => {
    const findings = evaluateExternalRules(
      graph({
        initialRequestUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        responses: [
          documentResponse({
            url: 'https://example.com/',
            scheme: 'https',
            securityHeaders: allHeaders({
              'strict-transport-security': ['max-age=1'],
              'content-security-policy': 'OBSERVED',
              'x-content-type-options': ['nosniff'],
              'referrer-policy': 'OBSERVED',
            }),
            hsts: { status: 'OBSERVED', maxAgeSeconds: 1 },
            tls: { authorized: true },
            cookies: Object.freeze([
              Object.freeze({
                name: 'ok',
                secure: true,
                httpOnly: true,
                sameSite: 'Strict' as const,
                hostPrefix: false,
                securePrefix: false,
              }),
              Object.freeze({
                name: 'session',
                secure: false,
                httpOnly: false,
                sameSite: 'absent' as const,
                path: '/',
                hostPrefix: false,
                securePrefix: false,
              }),
              Object.freeze({
                name: 'cross',
                secure: false,
                httpOnly: true,
                sameSite: 'None' as const,
                domain: '.example.com',
                hostPrefix: false,
                securePrefix: false,
              }),
            ]),
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )

    const cookieFindings = findings.filter(
      (finding) => finding.ruleId === 'VS-EXT-006' || finding.ruleId === 'VS-EXT-007',
    )
    expect(cookieFindings.length).toBeGreaterThanOrEqual(3)
    const serialized = JSON.stringify(findings)
    expect(serialized).not.toContain(CANARY_A)
    expect(serialized).not.toContain(CANARY_B)
    expect(serialized).not.toContain(CANARY_C)
    expect(serialized).not.toMatch(/cookieValue|rawSetCookie/i)
  })

  it('does not emit VS-EXT-007 when SameSite state is unknown', () => {
    const findings = evaluateExternalRules(
      graph({
        initialRequestUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        responses: [
          documentResponse({
            url: 'https://example.com/',
            scheme: 'https',
            securityHeaders: allHeaders({
              'strict-transport-security': ['max-age=1'],
              'content-security-policy': 'OBSERVED',
              'x-content-type-options': ['nosniff'],
              'referrer-policy': 'OBSERVED',
            }),
            hsts: { status: 'OBSERVED', maxAgeSeconds: 1 },
            tls: { authorized: true },
            cookies: Object.freeze([
              Object.freeze({
                name: 'weird',
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
    expect(ruleIds(findings)).not.toContain('VS-EXT-007')
  })
})

describe('External E1.6 TLS and source map rules', () => {
  it('uses injected clock for expired certificates and hostname-specific failures', () => {
    const expired = evaluateExternalRules(
      graph({
        initialRequestUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        responses: [
          documentResponse({
            url: 'https://example.com/',
            scheme: 'https',
            securityHeaders: allHeaders({
              'strict-transport-security': ['max-age=1'],
              'content-security-policy': 'OBSERVED',
              'x-content-type-options': ['nosniff'],
              'referrer-policy': 'OBSERVED',
            }),
            hsts: { status: 'OBSERVED', maxAgeSeconds: 1 },
            tls: {
              authorized: false,
              validToIso: '2020-01-01T00:00:00.000Z',
              authorizationError: 'CERT_HAS_EXPIRED',
            },
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(ruleIds(expired)).toContain('VS-EXT-008')
    expect(ruleIds(expired)).not.toContain('VS-EXT-009')

    const hostname = evaluateExternalRules(
      graph({
        initialRequestUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        responses: [
          documentResponse({
            url: 'https://example.com/',
            scheme: 'https',
            securityHeaders: allHeaders({
              'strict-transport-security': ['max-age=1'],
              'content-security-policy': 'OBSERVED',
              'x-content-type-options': ['nosniff'],
              'referrer-policy': 'OBSERVED',
            }),
            hsts: { status: 'OBSERVED', maxAgeSeconds: 1 },
            tls: {
              authorized: false,
              authorizationError: "Hostname/IP does not match certificate's altnames",
            },
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(ruleIds(hostname)).toContain('VS-EXT-009')

    const generic = evaluateExternalRules(
      graph({
        initialRequestUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        responses: [
          documentResponse({
            url: 'https://example.com/',
            scheme: 'https',
            securityHeaders: allHeaders({
              'strict-transport-security': ['max-age=1'],
              'content-security-policy': 'OBSERVED',
              'x-content-type-options': ['nosniff'],
              'referrer-policy': 'OBSERVED',
            }),
            hsts: { status: 'OBSERVED', maxAgeSeconds: 1 },
            tls: { authorized: false, authorizationError: 'unknown' },
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    expect(ruleIds(generic)).not.toContain('VS-EXT-009')
  })

  it('emits VS-EXT-010 for external map references but not inline maps', () => {
    const findings = evaluateExternalRules(
      graph({
        initialRequestUrl: 'https://example.com/',
        finalUrl: 'https://example.com/',
        responses: [
          documentResponse({
            url: 'https://example.com/',
            scheme: 'https',
            securityHeaders: allHeaders({
              'strict-transport-security': ['max-age=1'],
              'content-security-policy': 'OBSERVED',
              'x-content-type-options': ['nosniff'],
              'referrer-policy': 'OBSERVED',
            }),
            hsts: { status: 'OBSERVED', maxAgeSeconds: 1 },
            tls: { authorized: true },
          }),
        ],
        assets: [
          {
            sourceUrl: 'https://example.com/',
            requestUrl: 'https://example.com/app.js',
            kind: 'script',
            sameOrigin: true,
            fetched: true,
            sourceMapReferenced: true,
            sourceMapReference: '/app.js.map',
          },
          {
            sourceUrl: 'https://example.com/',
            requestUrl: 'https://example.com/app.css',
            kind: 'stylesheet',
            sameOrigin: true,
            fetched: true,
            sourceMapReferenced: true,
            inlineSourceMap: true,
          },
          {
            sourceUrl: 'https://example.com/',
            requestUrl: 'https://example.com/skip.js',
            kind: 'script',
            sameOrigin: true,
            fetched: false,
            sourceMapReferenced: true,
            sourceMapReference: '/skip.js.map',
            skipReason: 'budget',
          },
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    const maps = findings.filter((finding) => finding.ruleId === 'VS-EXT-010')
    expect(maps).toHaveLength(1)
    expect(maps[0]?.description).toMatch(/advertises a public sourceMappingURL/i)
    expect(maps[0]?.description).not.toMatch(/accessible/i)
  })
})

describe('External E1.6 determinism and architecture', () => {
  it('produces deterministic IDs and ordering', () => {
    const base = graph({
      initialRequestUrl: 'https://example.com/',
      finalUrl: 'https://example.com/',
      responses: [
        documentResponse({
          url: 'https://example.com/',
          scheme: 'https',
          tls: { authorized: true },
          cookies: Object.freeze([
            Object.freeze({
              name: 'b',
              secure: false,
              httpOnly: true,
              sameSite: 'Lax' as const,
              hostPrefix: false,
              securePrefix: false,
            }),
            Object.freeze({
              name: 'a',
              secure: true,
              httpOnly: false,
              sameSite: 'absent' as const,
              hostPrefix: false,
              securePrefix: false,
            }),
          ]),
        }),
      ],
    })
    const left = evaluateExternalRules(base, { evaluationTimeMs: FIXED_TIME })
    const right = evaluateExternalRules(base, { evaluationTimeMs: FIXED_TIME })
    expect(JSON.stringify(left)).toBe(JSON.stringify(right))
  })

  it('keeps rules free of network/filesystem/infra/orchestration imports', () => {
    const root = path.resolve('src/external/rules')
    const files = readdirSync(root, { recursive: true, encoding: 'utf8' }).filter(
      (file) => file.endsWith('.ts'),
    )
    const forbidden = new Set([
      'node:dns',
      'node:net',
      'node:http',
      'node:https',
      'node:tls',
      'node:fs',
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
        if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
          const specifier = node.moduleSpecifier.text
          expect(forbidden.has(specifier)).toBe(false)
          expect(specifier.includes('external/infra')).toBe(false)
          expect(specifier.includes('external/orchestration')).toBe(false)
        }
        ts.forEachChild(node, visit)
      }
      visit(sourceFile)
      expect(source).not.toMatch(/\bfetch\s*\(/u)
      expect(source).not.toMatch(/from ['"].*source-location/u)
      expect(source).not.toMatch(/cookieValue|rawCookie|rawBody/)
      // Ban wall-clock calls via AST (comments may mention the prohibition).
      const hasDateNow = (() => {
        let found = false
        const walk = (node: ts.Node): void => {
          if (
            ts.isCallExpression(node) &&
            ts.isPropertyAccessExpression(node.expression) &&
            node.expression.name.text === 'now' &&
            ts.isIdentifier(node.expression.expression) &&
            node.expression.expression.text === 'Date'
          ) {
            found = true
          }
          ts.forEachChild(node, walk)
        }
        walk(sourceFile)
        return found
      })()
      expect(hasDateNow).toBe(false)
    }
  })

  it('is not exported from the public package entry and not wired into Code scan', () => {
    const indexSource = readFileSync(path.resolve('src/index.ts'), 'utf8')
    expect(indexSource).not.toContain('external/rules')
    expect(indexSource).not.toContain('evaluateExternalRules')
    const scanSource = readFileSync(
      path.resolve('src/application/scan-local-project.ts'),
      'utf8',
    )
    expect(scanSource).not.toContain('external/')
    expect(scanSource).not.toContain('VS-EXT')
  })
})
