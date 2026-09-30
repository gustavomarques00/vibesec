import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

import {
  EXTERNAL_BUDGET_DEFAULTS,
  EXTERNAL_BUDGET_HARD_SAFETY_MAX,
  EXTERNAL_EVIDENCE_KINDS,
  InvalidExternalBudgetError,
  InvalidExternalTargetError,
  UnsupportedExternalPortError,
  UnsupportedExternalSchemeError,
  createEmptyExternalObservationGraph,
  createExternalScanBudgets,
  normalizeExternalTarget,
  toExternalOrigin,
} from '../src/external/domain/index.js'

describe('External E1.1 target normalization', () => {
  it.each([
    ['example.com', 'https://example.com/'],
    ['EXAMPLE.COM', 'https://example.com/'],
    ['example.com/', 'https://example.com/'],
    ['https://example.com', 'https://example.com/'],
    ['https://example.com/', 'https://example.com/'],
    ['https://example.com/path', 'https://example.com/path'],
    ['https://example.com/path?x=1', 'https://example.com/path?x=1'],
    ['http://example.com', 'http://example.com/'],
    ['https://example.com:443/', 'https://example.com/'],
    ['http://example.com:80/', 'http://example.com/'],
    ['example.com.', 'https://example.com/'],
    ['https://example.com.', 'https://example.com/'],
  ])('normalizes %j to %j', (input, expected) => {
    const target = normalizeExternalTarget(input)
    expect(target.requestUrl).toBe(expected)
    expect(target.displayTarget).toBe(expected)
    expect(target.requestUrl.includes('#')).toBe(false)
  })

  it('defaults bare hosts to HTTPS only and never invents an HTTP twin', () => {
    const target = normalizeExternalTarget('example.com')
    expect(target.scheme).toBe('https')
    expect(target.port).toBe(443)
    expect(target.requestUrl.startsWith('https://')).toBe(true)
    expect(target.requestUrl.startsWith('http://')).toBe(false)
  })

  it('preserves path and query while dropping fragments from request identity', () => {
    const target = normalizeExternalTarget('https://example.com/a/b?x=1&y=2#section')
    expect(target.pathname).toBe('/a/b')
    expect(target.search).toBe('?x=1&y=2')
    expect(target.requestUrl).toBe('https://example.com/a/b?x=1&y=2')
    expect(target.requestUrl.includes('#')).toBe(false)
  })

  it('canonicalizes IDN hostnames via URL punycode behavior', () => {
    const target = normalizeExternalTarget('https://bücher.example/')
    expect(target.hostname.includes('xn--')).toBe(true)
    expect(target.requestUrl.startsWith('https://')).toBe(true)
  })

  it('accepts syntactically valid literal IPv4 without SSRF classification', () => {
    const target = normalizeExternalTarget('https://203.0.113.10/path')
    expect(target.hostname).toBe('203.0.113.10')
    expect(target.requestUrl).toBe('https://203.0.113.10/path')
  })

  it('accepts syntactically valid literal IPv6 without SSRF classification', () => {
    const target = normalizeExternalTarget('https://[2001:db8::1]/')
    expect(target.hostname).toBe('2001:db8::1')
    expect(target.requestUrl).toBe('https://[2001:db8::1]/')
  })

  it('exposes origin helpers without credentials', () => {
    const target = normalizeExternalTarget('https://example.com:443/x')
    const origin = toExternalOrigin(target)
    expect(origin).toEqual({
      scheme: 'https',
      hostname: 'example.com',
      port: 443,
      origin: 'https://example.com',
    })
  })

  it.each([
    [''],
    ['   '],
    ['not a url'],
    ['ftp://example.com'],
    ['file:///etc/passwd'],
    ['data:text/plain,hi'],
    ['javascript:alert(1)'],
    ['ws://example.com'],
    ['wss://example.com'],
    ['https://user:pass@example.com'],
    ['https://user@example.com'],
    ['http://user:pass@example.com/path'],
    ['https://example.com:22'],
    ['https://example.com:3000'],
    ['http://example.com:8080'],
    ['*.example.com'],
    ['https://*.example.com'],
    ['10.0.0.0/8'],
    ['2001:db8::/32'],
    ['example.com example.org'],
    ['example.com,example.org'],
    ['https://example.com/path\nhttps://evil.test'],
    ['https://example.com/\u0000'],
  ])('rejects invalid input %j', (input) => {
    expect(() => normalizeExternalTarget(input)).toThrow()
  })

  it('rejects unsupported schemes with a typed error', () => {
    expect(() => normalizeExternalTarget('ftp://example.com')).toThrow(
      UnsupportedExternalSchemeError,
    )
  })

  it('rejects unsupported ports with a typed error', () => {
    expect(() => normalizeExternalTarget('https://example.com:8443')).toThrow(
      UnsupportedExternalPortError,
    )
  })

  it('rejects empty targets with a typed error', () => {
    expect(() => normalizeExternalTarget('')).toThrow(InvalidExternalTargetError)
  })

  it('never retains userinfo after a successful normalize path', () => {
    expect(() => normalizeExternalTarget('https://alice:secret@example.com')).toThrow(
      InvalidExternalTargetError,
    )
  })
})

describe('External E1.1 budgets', () => {
  it('exposes accepted plan defaults', () => {
    expect(EXTERNAL_BUDGET_DEFAULTS).toEqual({
      maxRequests: 12,
      maxRedirects: 5,
      maxAssets: 8,
      maxResponseBytes: 1 * 1024 * 1024,
      maxHtmlBytes: 512 * 1024,
      maxAssetBytes: 512 * 1024,
      maxDecompressedBytes: 2 * 1024 * 1024,
      maxHeaderBytes: 64 * 1024,
      connectTimeoutMs: 5_000,
      responseTimeoutMs: 10_000,
      overallDeadlineMs: 30_000,
      maxConcurrency: 2,
    })
  })

  it('exposes accepted hard safety maxima', () => {
    expect(EXTERNAL_BUDGET_HARD_SAFETY_MAX).toEqual({
      maxRequests: 32,
      maxRedirects: 10,
      maxAssets: 16,
      maxResponseBytes: 4 * 1024 * 1024,
      maxHtmlBytes: 2 * 1024 * 1024,
      maxAssetBytes: 2 * 1024 * 1024,
      maxDecompressedBytes: 8 * 1024 * 1024,
      maxHeaderBytes: 128 * 1024,
      connectTimeoutMs: 15_000,
      responseTimeoutMs: 30_000,
      overallDeadlineMs: 120_000,
      maxConcurrency: 4,
    })
  })

  it('returns frozen defaults when no overrides are provided', () => {
    const budgets = createExternalScanBudgets()
    expect(budgets).toEqual(EXTERNAL_BUDGET_DEFAULTS)
    expect(Object.isFrozen(budgets)).toBe(true)
  })

  it('accepts custom values at or below hard maxima', () => {
    const budgets = createExternalScanBudgets({
      maxRequests: 1,
      maxRedirects: 0,
      maxAssets: 0,
      maxConcurrency: 4,
    })
    expect(budgets.maxRequests).toBe(1)
    expect(budgets.maxRedirects).toBe(0)
    expect(budgets.maxAssets).toBe(0)
    expect(budgets.maxConcurrency).toBe(4)
  })

  it('accepts values equal to hard maxima', () => {
    const budgets = createExternalScanBudgets({ ...EXTERNAL_BUDGET_HARD_SAFETY_MAX })
    expect(budgets).toEqual(EXTERNAL_BUDGET_HARD_SAFETY_MAX)
  })

  it.each([
    [{ maxRequests: 33 }],
    [{ maxRedirects: 11 }],
    [{ maxAssets: 17 }],
    [{ maxResponseBytes: 4 * 1024 * 1024 + 1 }],
    [{ maxConcurrency: 5 }],
    [{ connectTimeoutMs: 15_001 }],
    [{ maxRequests: -1 }],
    [{ maxRequests: 0 }],
    [{ connectTimeoutMs: 0 }],
    [{ maxRequests: Number.NaN }],
    [{ maxRequests: Number.POSITIVE_INFINITY }],
    [{ maxRequests: 1.5 }],
  ])('rejects invalid override %j', (overrides) => {
    expect(() => createExternalScanBudgets(overrides)).toThrow(
      InvalidExternalBudgetError,
    )
  })
})

describe('External E1.1 DTO sensitive-data boundary', () => {
  it('defines External evidence kinds without Code SourceLocation coupling', () => {
    expect([...EXTERNAL_EVIDENCE_KINDS]).toEqual([
      'http',
      'tls',
      'header',
      'cookie-attr',
      'redirect',
      'asset',
    ])
  })

  it('creates an empty observation graph without body or secret fields', () => {
    const graph = createEmptyExternalObservationGraph('https://example.com/')
    expect(graph.initialRequestUrl).toBe('https://example.com/')
    expect(graph.redirects).toEqual([])
    expect(graph.blockedRedirects).toEqual([])
    expect(graph.responses).toEqual([])
    expect(graph.assets).toEqual([])
    expect(Object.isFrozen(graph)).toBe(true)
    expect(graph).not.toHaveProperty('body')
    expect(graph).not.toHaveProperty('rawResponse')
    expect(graph).not.toHaveProperty('authorization')
  })

  it('keeps cookie attribute DTOs free of a value field in source', () => {
    const source = readFileSync(
      path.join('src', 'external', 'domain', 'observations.ts'),
      'utf8',
    )
    expect(source).toMatch(/ExternalCookieAttributeObservation/)
    expect(source).not.toMatch(/cookieValue/)
    expect(source).not.toMatch(/^\s*value\?:/m)
    // Cookie type block must not declare a generic value property.
    const cookieBlock = source.slice(
      source.indexOf('ExternalCookieAttributeObservation'),
      source.indexOf('ExternalTlsObservation'),
    )
    expect(cookieBlock).not.toMatch(/\bvalue\s*\??:/u)
    expect(cookieBlock).toMatch(/secure:/u)
    expect(cookieBlock).toMatch(/httpOnly:/u)
  })

  it('avoids generic raw response body and Authorization storage fields', () => {
    const source = readFileSync(
      path.join('src', 'external', 'domain', 'observations.ts'),
      'utf8',
    )
    expect(source).not.toMatch(/\brawHeaders\s*\??:/u)
    expect(source).not.toMatch(/\bbody\s*\??:\s*string/u)
    expect(source).not.toMatch(/\brawResponse\s*\??:/u)
    expect(source).not.toMatch(/\bauthorization\s*\??:/iu)
  })

  it('defines External evidence locations as url kind, not file path locations', () => {
    const source = readFileSync(
      path.join('src', 'external', 'domain', 'evidence.ts'),
      'utf8',
    )
    expect(source).toMatch(/kind:\s*'url'/u)
    expect(source).toMatch(/\burl:\s*string/u)
    expect(source).not.toMatch(/from ['"].*source-location/u)
    expect(source).not.toMatch(/\bfile:\s*string/u)
  })
})

describe('External E1.1 architecture boundary', () => {
  const networkModules = new Set([
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

  it('keeps external/domain free of network module imports', () => {
    const root = path.resolve('src/external/domain')
    const files = readdirSync(root, { recursive: true, encoding: 'utf8' }).filter(
      (file) => file.endsWith('.ts'),
    )
    const violations: string[] = []
    for (const file of files) {
      const source = readFileSync(path.join(root, file), 'utf8')
      for (const moduleName of networkModules) {
        if (
          source.includes(`from '${moduleName}'`) ||
          source.includes(`from "${moduleName}"`)
        ) {
          violations.push(`${file}:${moduleName}`)
        }
      }
      if (source.includes('external/infra')) violations.push(`${file}:infra`)
      if (/\bfetch\s*\(/u.test(source)) violations.push(`${file}:fetch`)
    }
    expect(violations).toEqual([])
  })

  it('keeps Code application/extractors/discovery/targets free of external imports', () => {
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
        if (source.includes('/external/') || source.includes("from '../external")) {
          violations.push(`${root}/${file}`)
        }
      }
    }
    expect(violations).toEqual([])
  })
})
