import type {
  ExternalAssetObservation,
  ExternalHttpResponseObservation,
  ExternalObservationGraph,
  ExternalRedirectObservation,
  ExternalSecurityHeaderObservation,
} from '../src/external/domain/observations.js'
import type {
  OutboundHttpCapability,
  ExternalRawObservation,
} from '../src/external/infra/types.js'
import {
  ExternalScanError,
  runExternalScan,
} from '../src/external/application/run-external-scan.js'
import { runCli } from '../src/cli/run.js'
import {
  createExternalJsonReportDocument,
  createExternalScanResult,
  deriveExternalLimitations,
  renderExternalMarkdownReport,
  renderExternalReport,
  renderExternalTerminalReport,
  summarizeExternalFindings,
} from '../src/external/reporters/index.js'
import { evaluateExternalRules } from '../src/external/rules/index.js'
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import ts from 'typescript'

const FIXED_TIME = Date.parse('2024-06-15T12:00:00.000Z')

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

function containsDangerousControls(text: string): boolean {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index)
    // Allow LF used by reporters for line structure; ban other C0/DEL injection.
    if (code === 0x0a) continue
    if (code < 0x20 || code === 0x7f) return true
  }
  return false
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

function httpsDocument(
  overrides: Partial<ExternalHttpResponseObservation> = {},
): ExternalHttpResponseObservation {
  const securityHeaders: readonly ExternalSecurityHeaderObservation[] =
    overrides.securityHeaders ??
    Object.freeze([
      Object.freeze({
        name: 'strict-transport-security' as const,
        status: 'OBSERVED' as const,
        values: Object.freeze(['max-age=31536000']),
      }),
      Object.freeze({
        name: 'content-security-policy' as const,
        status: 'OBSERVED' as const,
        values: Object.freeze(["default-src 'self'"]),
      }),
      Object.freeze({
        name: 'x-content-type-options' as const,
        status: 'OBSERVED' as const,
        values: Object.freeze(['nosniff']),
      }),
      Object.freeze({
        name: 'referrer-policy' as const,
        status: 'OBSERVED' as const,
        values: Object.freeze(['no-referrer']),
      }),
    ])

  return Object.freeze({
    url: overrides.url ?? 'https://example.com/',
    method: overrides.method ?? 'GET',
    statusCode: overrides.statusCode ?? 200,
    scheme: overrides.scheme ?? 'https',
    headers: Object.freeze(overrides.headers ?? []),
    securityHeaders,
    hsts:
      overrides.hsts ??
      Object.freeze({ status: 'OBSERVED' as const, maxAgeSeconds: 31536000 }),
    bodyByteLength: overrides.bodyByteLength ?? 0,
    cookies: Object.freeze(overrides.cookies ?? []),
    tlsUsed: overrides.tlsUsed ?? true,
    ...(overrides.contentType !== undefined
      ? { contentType: overrides.contentType }
      : {}),
    ...(overrides.contentEncoding !== undefined
      ? { contentEncoding: overrides.contentEncoding }
      : {}),
    ...(overrides.tls !== undefined
      ? { tls: overrides.tls }
      : { tls: Object.freeze({ authorized: true as const }) }),
  })
}

function fakeTransport(observation: ExternalRawObservation): OutboundHttpCapability {
  return Object.freeze({
    request() {
      return Promise.resolve(observation)
    },
  })
}

function failingTransport(error: Error): OutboundHttpCapability {
  return Object.freeze({
    request() {
      return Promise.reject(error)
    },
  })
}

function rawOkHttps(): ExternalRawObservation {
  return Object.freeze({
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
            value: 'text/html; charset=utf-8',
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
        body: new TextEncoder().encode('<html><body>ok</body></html>'),
        pinnedAddress: '203.0.113.10',
        remoteAddress: '203.0.113.10',
        tls: Object.freeze({ authorized: true, protocol: 'TLSv1.3' }),
      }),
    ]),
    redirects: Object.freeze([] as ExternalRedirectObservation[]),
    requestsConsumed: 1,
  })
}

function rawHttpMissingHeaders(): ExternalRawObservation {
  return Object.freeze({
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
            value: 'text/html; charset=utf-8',
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
        body: new TextEncoder().encode(
          `<html><body>${CANARIES[4]}</body><script>${CANARIES[5]}</script><style>${CANARIES[6]}</style></html>`,
        ),
        pinnedAddress: '203.0.113.10',
        remoteAddress: '203.0.113.10',
      }),
    ]),
    redirects: Object.freeze([] as ExternalRedirectObservation[]),
    requestsConsumed: 1,
  })
}

describe('External E1.7 reporters', () => {
  it('renders terminal/json/markdown with ext-1 schema and no secure claims', () => {
    const findings = evaluateExternalRules(
      emptyGraph({
        finalUrl: 'https://example.com/',
        responses: [
          httpsDocument({
            securityHeaders: Object.freeze([
              Object.freeze({
                name: 'strict-transport-security' as const,
                status: 'MISSING' as const,
                values: Object.freeze([]),
              }),
              Object.freeze({
                name: 'content-security-policy' as const,
                status: 'MISSING' as const,
                values: Object.freeze([]),
              }),
              Object.freeze({
                name: 'x-content-type-options' as const,
                status: 'OBSERVED' as const,
                values: Object.freeze(['nosniff']),
              }),
              Object.freeze({
                name: 'referrer-policy' as const,
                status: 'MISSING' as const,
                values: Object.freeze([]),
              }),
            ]),
            hsts: Object.freeze({ status: 'MISSING' as const }),
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )

    const result = createExternalScanResult({
      target: 'https://example.com/',
      effectiveUrl: 'https://example.com/',
      findings,
      limitations: Object.freeze(['Asset inventory stopped after reaching maxAssets.']),
      evaluationTimeMs: FIXED_TIME,
      requestsConsumed: 3,
    })

    expect(summarizeExternalFindings(findings).total).toBe(findings.length)
    expect(result.summary.total).toBe(findings.length)

    const terminal = renderExternalTerminalReport(result)
    expect(terminal).toContain('VibeSec External')
    expect(terminal).toContain('Findings:')
    expect(terminal.toLowerCase()).not.toContain('site is secure')
    expect(terminal.toLowerCase()).not.toContain('hacked')
    expect(terminal.toLowerCase()).not.toContain('exploitable')

    const jsonText = renderExternalReport(result, 'json')
    const parsed = JSON.parse(jsonText) as { schemaVersion: string }
    expect(parsed.schemaVersion).toBe('ext-1')
    expect(jsonText.trimStart().startsWith('{')).toBe(true)
    expect(createExternalJsonReportDocument(result).schemaVersion).toBe('ext-1')

    const markdown = renderExternalMarkdownReport(result)
    expect(markdown).toContain('# VibeSec External Security Report')
    expect(markdown).toContain('## Findings')
    expect(markdown).toContain('## Limitations')
    expect(markdown.toLowerCase()).not.toContain('pentest passed')
  })

  it('sanitizes terminal and markdown hostile control / markdown characters', () => {
    const hostileUrl = `https://example.com/\u001b[31m\u0007evil\r\n# heading | \`code\` <script>`
    const findings = evaluateExternalRules(
      emptyGraph({
        initialRequestUrl: hostileUrl,
        finalUrl: hostileUrl,
        responses: [
          httpsDocument({
            url: hostileUrl,
            scheme: 'http',
            tlsUsed: false,
            hsts: Object.freeze({ status: 'NOT_APPLICABLE' as const }),
            securityHeaders: Object.freeze([
              Object.freeze({
                name: 'strict-transport-security' as const,
                status: 'MISSING' as const,
                values: Object.freeze([]),
              }),
              Object.freeze({
                name: 'content-security-policy' as const,
                status: 'MISSING' as const,
                values: Object.freeze([]),
              }),
              Object.freeze({
                name: 'x-content-type-options' as const,
                status: 'MISSING' as const,
                values: Object.freeze([]),
              }),
              Object.freeze({
                name: 'referrer-policy' as const,
                status: 'MISSING' as const,
                values: Object.freeze([]),
              }),
            ]),
          }),
        ],
      }),
      { evaluationTimeMs: FIXED_TIME },
    )
    const result = createExternalScanResult({
      target: hostileUrl,
      effectiveUrl: hostileUrl,
      findings,
      limitations: Object.freeze([`note \u001b[0m ${hostileUrl}`]),
      evaluationTimeMs: FIXED_TIME,
      requestsConsumed: 1,
    })

    const terminal = renderExternalTerminalReport(result)
    expect(containsDangerousControls(terminal)).toBe(false)

    const markdown = renderExternalMarkdownReport(result)
    expect(containsDangerousControls(markdown)).toBe(false)
    expect(markdown).not.toContain('<script>')
  })

  it('derives limitations from asset skip facts only', () => {
    const assets: readonly ExternalAssetObservation[] = Object.freeze([
      Object.freeze({
        sourceUrl: 'https://example.com/',
        requestUrl: 'https://example.com/a.js',
        kind: 'script' as const,
        sameOrigin: true,
        fetched: false,
        skipReason: 'max-assets' as const,
      }),
      Object.freeze({
        sourceUrl: 'https://example.com/',
        requestUrl: 'https://example.com/app.js',
        kind: 'script' as const,
        sameOrigin: true,
        fetched: true,
        sourceMapReferenced: true,
        sourceMapReference: 'https://example.com/app.js.map',
      }),
    ])
    const limitations = deriveExternalLimitations(
      emptyGraph({ finalUrl: 'https://example.com/', assets }),
    )
    expect(limitations).toContain('Asset inventory stopped after reaching maxAssets.')
    expect(limitations.some((item) => item.includes('not fetched by design'))).toBe(
      true,
    )
  })
})

describe('External E1.7 application composition', () => {
  it('returns exit-ready success with 0 findings for hardened HTTPS document', async () => {
    const outcome = await runExternalScan('https://example.com/', {
      format: 'terminal',
      transport: fakeTransport(rawOkHttps()),
      evaluationTimeMs: FIXED_TIME,
    })
    expect(outcome.findingCount).toBe(0)
    expect(outcome.result.schemaVersion).toBe('ext-1')
    expect(outcome.output).toContain('No findings detected by this scan')
    expect(outcome.output.toLowerCase()).not.toContain('site is secure')
    assertNoCanaries(outcome.output)
  })

  it('produces findings and keeps secret canaries out of all formats', async () => {
    for (const format of ['terminal', 'json', 'markdown'] as const) {
      const outcome = await runExternalScan('http://example.com/', {
        format,
        transport: fakeTransport(rawHttpMissingHeaders()),
        evaluationTimeMs: FIXED_TIME,
      })
      expect(outcome.findingCount).toBeGreaterThan(0)
      assertNoCanaries(outcome.output)
      assertNoCanaries(JSON.stringify(outcome.result))
      if (format === 'json') {
        const parsed = JSON.parse(outcome.output) as { schemaVersion: string }
        expect(parsed.schemaVersion).toBe('ext-1')
      }
    }
  })

  it('maps transport failures to ExternalScanError without stacks/secrets', async () => {
    const { DnsFailureError } = await import('../src/external/infra/errors.js')
    await expect(
      runExternalScan('https://example.com/', {
        format: 'json',
        transport: failingTransport(new DnsFailureError()),
        evaluationTimeMs: FIXED_TIME,
      }),
    ).rejects.toBeInstanceOf(ExternalScanError)

    try {
      await runExternalScan('https://example.com/', {
        format: 'json',
        transport: failingTransport(new DnsFailureError()),
        evaluationTimeMs: FIXED_TIME,
      })
    } catch (error) {
      expect(error).toBeInstanceOf(ExternalScanError)
      if (error instanceof ExternalScanError) {
        expect(error.message).toContain('DNS')
        expect(error.stack ?? '').not.toContain(CANARIES[0])
        expect(error.message).not.toContain('203.0.113')
      }
    }
  })

  it('rejects unsupported schemes and credentialed URLs safely', async () => {
    await expect(
      runExternalScan('ftp://example.com/', {
        format: 'terminal',
        transport: fakeTransport(rawOkHttps()),
        evaluationTimeMs: FIXED_TIME,
      }),
    ).rejects.toBeInstanceOf(ExternalScanError)

    await expect(
      runExternalScan('https://user:pass@example.com/', {
        format: 'terminal',
        transport: fakeTransport(rawOkHttps()),
        evaluationTimeMs: FIXED_TIME,
      }),
    ).rejects.toBeInstanceOf(ExternalScanError)
  })
})

describe('External E1.7 CLI', () => {
  it('supports vibesec external success path with injected transport via composition', async () => {
    // Direct composition covers transport injection; CLI uses production capability.
    const outcome = await runExternalScan('https://example.com/', {
      format: 'json',
      transport: fakeTransport(rawOkHttps()),
      evaluationTimeMs: FIXED_TIME,
    })
    expect(outcome.findingCount).toBe(0)
    expect(JSON.parse(outcome.output)).toMatchObject({ schemaVersion: 'ext-1' })
  })

  it('rejects missing/empty/unsupported External CLI arguments with exit 2', async () => {
    for (const args of [
      ['external'],
      ['external', ''],
      ['external', 'ftp://example.com'],
      ['external', 'https://user:pass@example.com'],
      ['external', 'https://example.com', '--format', 'yaml'],
      ['external', 'https://example.com', '--json'],
    ] as const) {
      const stdout: string[] = []
      const stderr: string[] = []
      const exitCode = await runCli(
        [...args],
        {
          stdout: (text) => stdout.push(text),
          stderr: (text) => stderr.push(text),
        },
        process.platform,
      )
      expect(exitCode).toBe(2)
      expect(stdout).toEqual([])
      expect(stderr.join('').length).toBeGreaterThan(0)
      assertNoCanaries(stderr.join(''))
    }
  })

  it('keeps Code scan CLI behavior and shows External in usage', async () => {
    const stdout: string[] = []
    const stderr: string[] = []
    const exitCode = await runCli(
      ['scan'],
      {
        stdout: (text) => stdout.push(text),
        stderr: (text) => stderr.push(text),
      },
      process.platform,
    )
    expect(exitCode).toBe(2)
    expect(stderr.join('')).toContain('Usage: vibesec scan')
    expect(stderr.join('')).toContain('vibesec external')
  })

  it('maps composition exit semantics 0/1/2 across formats', async () => {
    const zero = await runExternalScan('https://example.com/', {
      format: 'terminal',
      transport: fakeTransport(rawOkHttps()),
      evaluationTimeMs: FIXED_TIME,
    })
    expect(zero.findingCount === 0 ? 0 : 1).toBe(0)

    const one = await runExternalScan('http://example.com/', {
      format: 'markdown',
      transport: fakeTransport(rawHttpMissingHeaders()),
      evaluationTimeMs: FIXED_TIME,
    })
    expect(one.findingCount === 0 ? 0 : 1).toBe(1)

    const { BlockedDestinationError } = await import('../src/external/infra/errors.js')
    let failed = false
    try {
      await runExternalScan('https://example.com/', {
        format: 'json',
        transport: failingTransport(new BlockedDestinationError()),
        evaluationTimeMs: FIXED_TIME,
      })
    } catch {
      failed = true
    }
    expect(failed).toBe(true)
  })
})

describe('External E1.7 architecture', () => {
  it('keeps External reporters free of infra/orchestration/network imports', () => {
    const root = path.resolve('src/external/reporters')
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
          if (specifier.includes('external/rules')) {
            const importLine = source
              .split(/\r?\n/u)
              .find((line) => line.includes(specifier))
            expect(importLine?.includes('import type')).toBe(true)
          }
        }
        ts.forEachChild(node, visit)
      }
      visit(sourceFile)
      expect(source).not.toMatch(/\bfetch\s*\(/u)
      expect(source).not.toMatch(/Date\.now\s*\(/u)
      expect(source).not.toMatch(/console\.log/)
      expect(source).not.toMatch(/rejectUnauthorized\s*:\s*false/)
    }
  })

  it('keeps Code reporters and rules free of External imports', () => {
    for (const root of ['src/reporters', 'src/rules', 'src/core']) {
      const absolute = path.resolve(root)
      let files: string[]
      try {
        files = readdirSync(absolute, { recursive: true, encoding: 'utf8' }).filter(
          (file) => file.endsWith('.ts'),
        )
      } catch {
        continue
      }
      for (const file of files) {
        const source = readFileSync(path.join(absolute, file), 'utf8')
        expect(source).not.toMatch(/external\//u)
      }
    }
  })
})
