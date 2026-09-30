import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

import {
  buildExternalObservationGraph,
  extractCookieAttributeObservations,
  extractSecurityHeaderObservations,
  type ExternalTransportObservationInput,
} from '../src/external/extractors/index.js'

const CANARY_A = 'SUPER_SECRET_COOKIE_CANARY_123'
const CANARY_B = 'SESSION_TOKEN_DO_NOT_LEAK'
const CANARY_C = 'JWT_SHAPED_TEST_VALUE'

function assertNoCanaries(value: unknown, canaries: readonly string[]): void {
  const serialized = JSON.stringify(value)
  for (const canary of canaries) {
    expect(serialized).not.toContain(canary)
  }
}

function baseHop(overrides: {
  url?: string
  statusCode?: number
  headers?: { name: string; value: string }[]
  bodyByteLength?: number
  tls?: { authorized: boolean; protocol?: string; authorizationError?: string }
}): ExternalTransportObservationInput['hops'][number] {
  return {
    requestUrl: overrides.url ?? 'https://example.test/',
    method: 'GET',
    statusCode: overrides.statusCode ?? 200,
    headers: overrides.headers ?? [],
    bodyByteLength: overrides.bodyByteLength ?? 0,
    ...(overrides.tls !== undefined ? { tls: overrides.tls } : {}),
  }
}

describe('External E1.4 header observations', () => {
  it('canonicalizes header names case-insensitively and tracks presence', () => {
    const headers = extractSecurityHeaderObservations([
      { name: 'STRICT-TRANSPORT-SECURITY', value: 'max-age=31536000' },
      { name: 'Content-Security-Policy', value: "default-src 'self'" },
      { name: 'x-content-type-options', value: 'nosniff' },
    ])

    const hsts = headers.find((h) => h.name === 'strict-transport-security')
    const csp = headers.find((h) => h.name === 'content-security-policy')
    const referrer = headers.find((h) => h.name === 'referrer-policy')

    expect(hsts?.status).toBe('OBSERVED')
    expect(hsts?.values).toEqual(['max-age=31536000'])
    expect(csp?.status).toBe('OBSERVED')
    expect(referrer?.status).toBe('MISSING')
    expect(referrer?.values).toEqual([])
  })

  it('preserves duplicate CSP values and ignores forbidden headers', () => {
    const headers = extractSecurityHeaderObservations([
      { name: 'Content-Security-Policy', value: "default-src 'self'" },
      { name: 'content-security-policy', value: "img-src 'none'" },
      { name: 'Authorization', value: 'Bearer SECRET' },
      { name: 'Proxy-Authorization', value: 'Basic SECRET' },
      { name: 'WWW-Authenticate', value: 'Basic realm="x"' },
    ])
    const csp = headers.find((h) => h.name === 'content-security-policy')
    expect(csp?.values).toEqual(["default-src 'self'", "img-src 'none'"])
    const serialized = JSON.stringify(headers)
    expect(serialized).not.toContain('Bearer')
    expect(serialized).not.toContain('SECRET')
  })

  it('marks set-cookie present without retaining raw values', () => {
    const headers = extractSecurityHeaderObservations([
      { name: 'Set-Cookie', value: `session=${CANARY_A}; Secure; HttpOnly` },
    ])
    const setCookie = headers.find((h) => h.name === 'set-cookie')
    expect(setCookie?.status).toBe('OBSERVED')
    expect(setCookie?.values).toEqual([])
    assertNoCanaries(headers, [CANARY_A])
  })
})

describe('External E1.4 cookie attribute extraction', () => {
  it('parses attributes without retaining values', () => {
    const cookies = extractCookieAttributeObservations([
      {
        name: 'Set-Cookie',
        value: `session=${CANARY_A}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`,
      },
      {
        name: 'set-cookie',
        value: `__Host-id=${CANARY_B}; Secure; Path=/; SameSite=Lax`,
      },
      {
        name: 'SET-COOKIE',
        value: `__Secure-token=${CANARY_C}; Secure; SameSite=None; Domain=.example.test`,
      },
    ])

    expect(cookies).toHaveLength(3)
    expect(cookies.map((c) => c.name).sort()).toEqual(
      ['__Host-id', '__Secure-token', 'session'].sort(),
    )

    const session = cookies.find((c) => c.name === 'session')
    expect(session).toMatchObject({
      secure: true,
      httpOnly: true,
      sameSite: 'Strict',
      path: '/',
      maxAgeSeconds: 3600,
      hostPrefix: false,
      securePrefix: false,
    })
    expect(session).not.toHaveProperty('value')

    const host = cookies.find((c) => c.name === '__Host-id')
    expect(host?.hostPrefix).toBe(true)
    expect(host?.securePrefix).toBe(false)

    const secure = cookies.find((c) => c.name === '__Secure-token')
    expect(secure?.securePrefix).toBe(true)
    expect(secure?.sameSite).toBe('None')
    expect(secure?.domain).toBe('.example.test')

    assertNoCanaries(cookies, [CANARY_A, CANARY_B, CANARY_C])
  })

  it('handles missing SameSite, expires, unknown attrs, and malformed names', () => {
    const cookies = extractCookieAttributeObservations([
      {
        name: 'Set-Cookie',
        value: `plain=${CANARY_A}; HttpOnly; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Unknown=1`,
      },
      { name: 'Set-Cookie', value: `=novalue; Secure` },
      { name: 'Set-Cookie', value: '' },
    ])
    const plain = cookies.find((c) => c.name === 'plain')
    expect(plain?.sameSite).toBe('unknown')
    expect(plain?.httpOnly).toBe(true)
    expect(plain?.secure).toBe(false)
    expect(plain?.expiresAtIso).toBe('2015-10-21T07:28:00.000Z')
    assertNoCanaries(cookies, [CANARY_A])
  })

  it('is deterministic regardless of Set-Cookie input order', () => {
    const a = extractCookieAttributeObservations([
      { name: 'Set-Cookie', value: `b=${CANARY_A}; Secure` },
      { name: 'Set-Cookie', value: `a=${CANARY_B}; HttpOnly` },
    ])
    const b = extractCookieAttributeObservations([
      { name: 'Set-Cookie', value: `a=${CANARY_B}; HttpOnly` },
      { name: 'Set-Cookie', value: `b=${CANARY_A}; Secure` },
    ])
    expect(JSON.stringify(a)).toBe(JSON.stringify(b))
    assertNoCanaries(a, [CANARY_A, CANARY_B])
  })
})

describe('External E1.4 observation graph', () => {
  it('builds HTTP/TLS/header/cookie/redirect facts without bodies or verdicts', () => {
    const graph = buildExternalObservationGraph({
      initialRequestUrl: 'http://example.test/',
      finalUrl: 'https://example.test/',
      method: 'GET',
      redirects: [
        {
          index: 0,
          fromUrl: 'http://example.test/',
          toUrl: 'https://example.test/',
          statusCode: 301,
        },
      ],
      hops: [
        baseHop({
          url: 'http://example.test/',
          statusCode: 301,
          headers: [{ name: 'Location', value: 'https://example.test/' }],
        }),
        baseHop({
          url: 'https://example.test/',
          statusCode: 200,
          bodyByteLength: 42,
          headers: [
            {
              name: 'Strict-Transport-Security',
              value: 'max-age=100; includeSubDomains; preload',
            },
            { name: 'Content-Type', value: 'text/html; charset=utf-8' },
            { name: 'X-Content-Type-Options', value: 'nosniff' },
            {
              name: 'Set-Cookie',
              value: `sid=${CANARY_A}; Secure; HttpOnly; SameSite=Lax`,
            },
          ],
          tls: { authorized: true, protocol: 'TLSv1.3' },
        }),
      ],
    })

    expect(graph.initialRequestUrl).toBe('http://example.test/')
    expect(graph.finalUrl).toBe('https://example.test/')
    expect(graph.redirects).toHaveLength(1)
    expect(graph.redirects[0]?.index).toBe(0)
    expect(graph.responses).toHaveLength(2)

    const httpsHop = graph.responses[1]
    expect(httpsHop).toBeDefined()
    if (httpsHop === undefined) throw new Error('expected https hop')
    expect(httpsHop.scheme).toBe('https')
    expect(httpsHop.bodyByteLength).toBe(42)
    expect(httpsHop.tlsUsed).toBe(true)
    expect(httpsHop.tls?.protocol).toBe('TLSv1.3')
    expect(httpsHop.tls?.authorized).toBe(true)
    expect(httpsHop.hsts.status).toBe('OBSERVED')
    expect(httpsHop.hsts.maxAgeSeconds).toBe(100)
    expect(httpsHop.hsts.includeSubDomains).toBe(true)
    expect(httpsHop.hsts.preload).toBe(true)
    expect(httpsHop.contentType).toBe('text/html; charset=utf-8')
    expect(httpsHop.cookies[0]?.name).toBe('sid')
    expect(httpsHop).not.toHaveProperty('body')
    expect(JSON.stringify(graph)).not.toMatch(
      /severity|finding|ruleId|vulnerability|recommendation/i,
    )

    const httpHop = graph.responses[0]
    expect(httpHop).toBeDefined()
    if (httpHop === undefined) throw new Error('expected http hop')
    expect(httpHop.tlsUsed).toBe(false)
    expect(httpHop.hsts.status).toBe('NOT_APPLICABLE')

    assertNoCanaries(graph, [CANARY_A])
  })

  it('records blocked redirect facts without inventing findings', () => {
    const graph = buildExternalObservationGraph({
      initialRequestUrl: 'https://example.test/',
      finalUrl: 'https://example.test/',
      method: 'GET',
      redirects: [],
      blockedRedirects: [
        {
          index: 0,
          fromUrl: 'https://example.test/',
          toUrl: 'http://example.test/',
          statusCode: 302,
          reason: 'https-to-http',
        },
        {
          index: 1,
          fromUrl: 'https://example.test/',
          toUrl: 'https://127.0.0.1/',
          statusCode: 302,
          reason: 'blocked-destination',
        },
      ],
      hops: [
        baseHop({
          headers: [{ name: 'Location', value: 'http://example.test/' }],
          statusCode: 302,
        }),
      ],
    })
    expect(graph.blockedRedirects).toHaveLength(2)
    expect(graph.blockedRedirects[0]?.reason).toBe('https-to-http')
    expect(graph.blockedRedirects[1]?.reason).toBe('blocked-destination')
    expect(JSON.stringify(graph)).not.toMatch(/vulnerability|severity/i)
  })

  it('reads body length from Uint8Array without copying body into the graph', () => {
    const body = new TextEncoder().encode(`payload-${CANARY_B}`)
    const graph = buildExternalObservationGraph({
      initialRequestUrl: 'https://example.test/',
      finalUrl: 'https://example.test/',
      method: 'HEAD',
      redirects: [],
      hops: [
        {
          requestUrl: 'https://example.test/',
          method: 'HEAD',
          statusCode: 200,
          headers: [],
          body,
          tls: { authorized: true, protocol: 'TLSv1.2' },
        },
      ],
    })
    expect(graph.responses[0]?.bodyByteLength).toBe(body.byteLength)
    expect(JSON.stringify(graph)).not.toContain(CANARY_B)
    expect(JSON.stringify(graph)).not.toContain('payload-')
  })

  it('is deterministic for identical inputs', () => {
    const input: ExternalTransportObservationInput = {
      initialRequestUrl: 'https://example.test/',
      finalUrl: 'https://example.test/',
      method: 'GET',
      redirects: [],
      hops: [
        baseHop({
          headers: [
            { name: 'Referrer-Policy', value: 'no-referrer' },
            { name: 'Permissions-Policy', value: 'geolocation=()' },
            { name: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
            { name: 'Set-Cookie', value: `z=${CANARY_A}; Secure` },
            { name: 'Set-Cookie', value: `a=${CANARY_B}; HttpOnly` },
          ],
          tls: {
            authorized: false,
            authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
          },
        }),
      ],
    }
    const left = buildExternalObservationGraph(input)
    const right = buildExternalObservationGraph(input)
    expect(JSON.stringify(left)).toBe(JSON.stringify(right))
    assertNoCanaries(left, [CANARY_A, CANARY_B])
  })
})

describe('External E1.4 fact vs interpretation boundary', () => {
  it('does not emit severity, finding, ruleId, or recommendations in extractors', () => {
    const root = path.resolve('src/external/extractors')
    const files = readdirSync(root, { recursive: true, encoding: 'utf8' }).filter(
      (file) => file.endsWith('.ts'),
    )
    for (const file of files) {
      const source = readFileSync(path.join(root, file), 'utf8')
      expect(source).not.toMatch(/\bseverity\b/i)
      expect(source).not.toMatch(/\bfinding\b/i)
      expect(source).not.toMatch(/\bruleId\b/)
      expect(source).not.toMatch(/\bvulnerability\b/i)
      expect(source).not.toMatch(/\brecommendation\b/i)
      expect(source).not.toMatch(/cookieValue|rawCookie|rawSetCookie|rawResponse/)
    }
  })
})

describe('External E1.4 architecture boundary', () => {
  it('keeps extractors free of network modules and infra imports', () => {
    const root = path.resolve('src/external/extractors')
    const files = readdirSync(root, { recursive: true, encoding: 'utf8' }).filter(
      (file) => file.endsWith('.ts'),
    )
    const forbidden = new Set([
      'node:dns',
      'node:net',
      'node:http',
      'node:https',
      'node:tls',
      'dns',
      'net',
      'http',
      'https',
      'tls',
    ])
    const violations: string[] = []

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
          if (forbidden.has(specifier) || specifier.includes('external/infra')) {
            violations.push(`${file}:${specifier}`)
          }
        }
        if (
          ts.isCallExpression(node) &&
          ts.isIdentifier(node.expression) &&
          (node.expression.text === 'fetch' ||
            node.expression.text === 'connect' ||
            node.expression.text === 'request')
        ) {
          violations.push(`${file}:call:${node.expression.text}`)
        }
        ts.forEachChild(node, visit)
      }
      visit(sourceFile)
    }
    expect(violations).toEqual([])
  })

  it('keeps Code modules free of external extractors/infra/policy', () => {
    const roots = [
      'src/application',
      'src/extractors',
      'src/discovery',
      'src/targets',
      'src/rules',
      'src/core',
    ]
    const violations: string[] = []
    for (const root of roots) {
      const absoluteRoot = path.resolve(root)
      const files = readdirSync(absoluteRoot, {
        recursive: true,
        encoding: 'utf8',
      }).filter((file) => file.endsWith('.ts'))
      for (const file of files) {
        const source = readFileSync(path.join(absoluteRoot, file), 'utf8')
        if (source.includes('/external/')) violations.push(`${root}/${file}`)
      }
    }
    expect(violations).toEqual([])
  })

  it('does not export External extractors from the public package entry', () => {
    const source = readFileSync(path.resolve('src/index.ts'), 'utf8')
    expect(source).not.toContain('external/extractors')
    expect(source).not.toContain('buildExternalObservationGraph')
  })
})
