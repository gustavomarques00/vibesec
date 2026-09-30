import { createExternalScanBudgets } from '../src/external/domain/index.js'
import {
  BlockedDestinationError,
  ConnectTimeoutError,
  ConnectionFailedError,
  EXTERNAL_USER_AGENT,
  HeaderTooLargeError,
  InvalidExternalMethodError,
  OverallDeadlineExceededError,
  RedirectBlockedError,
  RedirectBudgetExceededError,
  RedirectLoopError,
  RemoteAddressMismatchError,
  RequestBudgetExceededError,
  ResponseTimeoutError,
  ResponseTooLargeError,
  createOutboundHttpCapability,
  selectPinnedAddressOrder,
  type DnsResolver,
  type PinnedConnectRequest,
  type PinnedConnectResponse,
  type PinnedHttpConnector,
} from '../src/external/infra/index.js'
import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const PUBLIC_V4 = '203.0.114.1'
const PUBLIC_V4_B = '203.0.114.2'
const PUBLIC_V6 = '2001:4860:4860::8888'
const PRIVATE_V4 = '10.0.0.1'

type FakeDnsMap = Readonly<Record<string, readonly string[]>>

function createFakeDns(map: FakeDnsMap): DnsResolver {
  return Object.freeze({
    lookupAll(hostname: string) {
      const addresses = map[hostname]
      if (addresses === undefined) {
        return Promise.reject(new Error('DnsFailure'))
      }
      return Promise.resolve(
        Object.freeze({ addresses: Object.freeze([...addresses]) }),
      )
    },
  })
}

type ConnectorCall = Readonly<{
  request: PinnedConnectRequest
}>

type FakeHopScript = Readonly<{
  statusCode: number
  headers?: readonly { name: string; value: string }[]
  body?: Uint8Array
  /** If set, connector reports this remoteAddress (for mismatch tests). */
  remoteAddress?: string
  error?: Error
}>

function createFakeConnector(script: {
  byUrl?: ReadonlyMap<string, FakeHopScript | FakeHopScript[]>
  defaultHop?: FakeHopScript
  onCall?: (call: ConnectorCall) => void
}): { connector: PinnedHttpConnector; calls: ConnectorCall[] } {
  const calls: ConnectorCall[] = []
  const indices = new Map<string, number>()

  const connector: PinnedHttpConnector = Object.freeze({
    connect(request: PinnedConnectRequest): Promise<PinnedConnectResponse> {
      const call = Object.freeze({ request })
      calls.push(call)
      script.onCall?.(call)

      const key = `${request.scheme}://${request.hostname}${request.pathname}${request.search}`
      const entry = script.byUrl?.get(key) ?? script.defaultHop
      if (entry === undefined) {
        return Promise.reject(new ConnectionFailedError())
      }

      let hop: FakeHopScript
      if (Array.isArray(entry)) {
        const index = indices.get(key) ?? 0
        indices.set(key, index + 1)
        const selected = entry[Math.min(index, entry.length - 1)]
        if (selected === undefined) {
          return Promise.reject(new ConnectionFailedError())
        }
        hop = selected
      } else {
        hop = entry
      }

      if (hop.error !== undefined) return Promise.reject(hop.error)

      const remoteAddress = hop.remoteAddress ?? request.pinnedAddress
      return Promise.resolve(
        Object.freeze({
          statusCode: hop.statusCode,
          headers: Object.freeze(hop.headers ?? []),
          body: hop.body ?? new Uint8Array(),
          pinnedAddress: request.pinnedAddress,
          remoteAddress,
        }),
      )
    },
  })

  return { connector, calls }
}

function budgets(overrides: Parameters<typeof createExternalScanBudgets>[0] = {}) {
  return createExternalScanBudgets(overrides)
}

function urlKey(target: string): string {
  // Match connector key construction for https defaults.
  const normalized = target.startsWith('http') ? target : `https://${target}`
  const parsed = new URL(normalized)
  return `${parsed.protocol}//${parsed.hostname}${parsed.pathname}${parsed.search}`
}

describe('External E1.3 pin selection', () => {
  it('orders IPv4 before IPv6 and is deterministic', () => {
    const order = selectPinnedAddressOrder([
      PUBLIC_V6,
      PUBLIC_V4,
      PUBLIC_V4_B,
      PUBLIC_V4,
    ])
    expect(order[0]).toBe(PUBLIC_V4)
    expect(order).toEqual(selectPinnedAddressOrder([PUBLIC_V4_B, PUBLIC_V4, PUBLIC_V6]))
  })
})

describe('External E1.3 destination authorization', () => {
  it('blocks private and mixed DNS sets before connector', async () => {
    const { connector, calls } = createFakeConnector({
      defaultHop: { statusCode: 200 },
    })

    const privateDns = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'example.test': [PRIVATE_V4] }),
      connect: connector,
    })
    await expect(
      privateDns.request(
        { target: 'https://example.test', method: 'GET' },
        { budgets: budgets() },
      ),
    ).rejects.toBeInstanceOf(BlockedDestinationError)
    expect(calls).toHaveLength(0)

    const mixed = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'example.test': [PUBLIC_V4, PRIVATE_V4] }),
      connect: connector,
    })
    await expect(
      mixed.request(
        { target: 'https://example.test', method: 'GET' },
        { budgets: budgets() },
      ),
    ).rejects.toBeInstanceOf(BlockedDestinationError)
    expect(calls).toHaveLength(0)
  })

  it('allows all-public sets and pins approved address', async () => {
    const { connector, calls } = createFakeConnector({
      defaultHop: { statusCode: 200, body: new Uint8Array([1]) },
    })
    const capability = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'example.test': [PUBLIC_V4, PUBLIC_V6] }),
      connect: connector,
    })
    const result = await capability.request(
      { target: 'https://example.test/path', method: 'GET' },
      { budgets: budgets() },
    )
    expect(result.finalUrl).toBe('https://example.test/path')
    expect(calls).toHaveLength(1)
    expect(calls[0]?.request.pinnedAddress).toBe(PUBLIC_V4)
    expect(calls[0]?.request.hostname).toBe('example.test')
    expect(calls[0]?.request.approvedAddresses).toContain(PUBLIC_V4)
  })

  it('classifies literal IPs without DNS', async () => {
    const dnsCalls: string[] = []
    const resolveDns: DnsResolver = {
      lookupAll(hostname: string) {
        dnsCalls.push(hostname)
        return Promise.resolve({ addresses: [PUBLIC_V4] })
      },
    }
    const { connector, calls } = createFakeConnector({
      defaultHop: { statusCode: 200 },
    })
    const capability = createOutboundHttpCapability({ resolveDns, connect: connector })

    await expect(
      capability.request(
        { target: 'https://127.0.0.1', method: 'GET' },
        { budgets: budgets() },
      ),
    ).rejects.toBeInstanceOf(BlockedDestinationError)
    expect(dnsCalls).toHaveLength(0)
    expect(calls).toHaveLength(0)

    await capability.request(
      { target: `https://${PUBLIC_V4}`, method: 'HEAD' },
      { budgets: budgets() },
    )
    expect(dnsCalls).toHaveLength(0)
    expect(calls[0]?.request.pinnedAddress).toBe(PUBLIC_V4)
    expect(calls[0]?.request.method).toBe('HEAD')
  })
})

describe('External E1.3 DNS rebinding defense', () => {
  it('connects only to the originally approved pin', async () => {
    let resolveCount = 0
    const resolveDns: DnsResolver = {
      lookupAll() {
        resolveCount += 1
        // Even if a second resolution would return loopback, connector must
        // receive the first authorized public pin — no second uncontrolled lookup.
        return Promise.resolve({
          addresses: resolveCount === 1 ? [PUBLIC_V4] : ['127.0.0.1'],
        })
      },
    }
    const { connector, calls } = createFakeConnector({
      defaultHop: { statusCode: 200 },
    })
    const capability = createOutboundHttpCapability({ resolveDns, connect: connector })
    await capability.request(
      { target: 'https://example.test', method: 'GET' },
      { budgets: budgets() },
    )
    expect(resolveCount).toBe(1)
    expect(calls[0]?.request.pinnedAddress).toBe(PUBLIC_V4)
    expect(calls[0]?.request.hostname).toBe('example.test')
  })

  it('fails closed when connector remoteAddress mismatches pin set', async () => {
    const { connector } = createFakeConnector({
      defaultHop: {
        statusCode: 200,
        remoteAddress: '127.0.0.1',
        error: new RemoteAddressMismatchError(),
      },
    })
    // Simulate connector detecting mismatch (production connector throws).
    const capability = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'example.test': [PUBLIC_V4] }),
      connect: connector,
    })
    await expect(
      capability.request(
        { target: 'https://example.test', method: 'GET' },
        { budgets: budgets() },
      ),
    ).rejects.toBeInstanceOf(RemoteAddressMismatchError)
  })
})

describe('External E1.3 redirects', () => {
  it('follows same-origin and cross-origin public redirects', async () => {
    const byUrl = new Map<string, FakeHopScript>([
      [
        urlKey('https://a.test/'),
        {
          statusCode: 302,
          headers: [{ name: 'Location', value: 'https://b.test/next' }],
        },
      ],
      [urlKey('https://b.test/next'), { statusCode: 200, body: new Uint8Array([9]) }],
    ])
    const { connector, calls } = createFakeConnector({ byUrl })
    const capability = createOutboundHttpCapability({
      resolveDns: createFakeDns({
        'a.test': [PUBLIC_V4],
        'b.test': [PUBLIC_V4_B],
      }),
      connect: connector,
    })
    const result = await capability.request(
      { target: 'https://a.test/', method: 'GET' },
      { budgets: budgets() },
    )
    expect(result.redirects).toHaveLength(1)
    expect(result.finalUrl).toBe('https://b.test/next')
    expect(calls).toHaveLength(2)
    expect(calls[1]?.request.pinnedAddress).toBe(PUBLIC_V4_B)
  })

  it('allows http→https and blocks https→http', async () => {
    const okMap = new Map<string, FakeHopScript>([
      [
        urlKey('http://a.test/'),
        {
          statusCode: 301,
          headers: [{ name: 'Location', value: 'https://a.test/' }],
        },
      ],
      [urlKey('https://a.test/'), { statusCode: 200 }],
    ])
    const ok = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'a.test': [PUBLIC_V4] }),
      connect: createFakeConnector({ byUrl: okMap }).connector,
    })
    await expect(
      ok.request({ target: 'http://a.test/', method: 'GET' }, { budgets: budgets() }),
    ).resolves.toMatchObject({ finalUrl: 'https://a.test/' })

    const downMap = new Map<string, FakeHopScript>([
      [
        urlKey('https://a.test/'),
        {
          statusCode: 302,
          headers: [{ name: 'Location', value: 'http://a.test/' }],
        },
      ],
    ])
    const { connector, calls } = createFakeConnector({ byUrl: downMap })
    const down = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'a.test': [PUBLIC_V4] }),
      connect: connector,
    })
    await expect(
      down.request(
        { target: 'https://a.test/', method: 'GET' },
        { budgets: budgets() },
      ),
    ).rejects.toBeInstanceOf(RedirectBlockedError)
    expect(calls).toHaveLength(1)
  })

  it('blocks redirects to private/metadata/localhost before connector', async () => {
    for (const location of [
      'http://127.0.0.1/',
      'https://10.0.0.1/',
      'https://169.254.169.254/',
      'https://[::1]/',
      'https://[::ffff:127.0.0.1]/',
      'https://localhost/',
    ]) {
      const byUrl = new Map<string, FakeHopScript>([
        [
          urlKey('https://a.test/'),
          {
            statusCode: 302,
            headers: [{ name: 'Location', value: location }],
          },
        ],
      ])
      const { connector, calls } = createFakeConnector({ byUrl })
      const capability = createOutboundHttpCapability({
        resolveDns: createFakeDns({ 'a.test': [PUBLIC_V4] }),
        connect: connector,
      })
      await expect(
        capability.request(
          { target: 'https://a.test/', method: 'GET' },
          { budgets: budgets() },
        ),
      ).rejects.toBeInstanceOf(RedirectBlockedError)
      expect(calls).toHaveLength(1)
    }
  })

  it('blocks redirect to private DNS hostname before connector on next hop', async () => {
    const byUrl = new Map<string, FakeHopScript>([
      [
        urlKey('https://a.test/'),
        {
          statusCode: 302,
          headers: [{ name: 'Location', value: 'https://evil.test/' }],
        },
      ],
    ])
    const { connector, calls } = createFakeConnector({ byUrl })
    const capability = createOutboundHttpCapability({
      resolveDns: createFakeDns({
        'a.test': [PUBLIC_V4],
        'evil.test': [PRIVATE_V4],
      }),
      connect: connector,
    })
    await expect(
      capability.request(
        { target: 'https://a.test/', method: 'GET' },
        { budgets: budgets() },
      ),
    ).rejects.toBeInstanceOf(BlockedDestinationError)
    expect(calls).toHaveLength(1)
  })

  it('blocks unsupported port, credentials, and schemes on redirect', async () => {
    for (const location of [
      'https://a.test:8443/',
      'https://user:pass@b.test/',
      'ftp://a.test/',
    ]) {
      const byUrl = new Map<string, FakeHopScript>([
        [
          urlKey('https://a.test/'),
          {
            statusCode: 302,
            headers: [{ name: 'Location', value: location }],
          },
        ],
      ])
      const capability = createOutboundHttpCapability({
        resolveDns: createFakeDns({ 'a.test': [PUBLIC_V4], 'b.test': [PUBLIC_V4] }),
        connect: createFakeConnector({ byUrl }).connector,
      })
      await expect(
        capability.request(
          { target: 'https://a.test/', method: 'GET' },
          { budgets: budgets() },
        ),
      ).rejects.toBeInstanceOf(RedirectBlockedError)
    }
  })

  it('detects redirect loops and redirect budget exhaustion', async () => {
    const loopMap = new Map<string, FakeHopScript>([
      [
        urlKey('https://a.test/'),
        {
          statusCode: 302,
          headers: [{ name: 'Location', value: 'https://a.test/' }],
        },
      ],
    ])
    const loop = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'a.test': [PUBLIC_V4] }),
      connect: createFakeConnector({ byUrl: loopMap }).connector,
    })
    await expect(
      loop.request(
        { target: 'https://a.test/', method: 'GET' },
        { budgets: budgets() },
      ),
    ).rejects.toBeInstanceOf(RedirectLoopError)

    const chainMap = new Map<string, FakeHopScript | FakeHopScript[]>()
    chainMap.set(urlKey('https://a.test/'), {
      statusCode: 302,
      headers: [{ name: 'Location', value: 'https://b.test/' }],
    })
    chainMap.set(urlKey('https://b.test/'), {
      statusCode: 302,
      headers: [{ name: 'Location', value: 'https://c.test/' }],
    })
    chainMap.set(urlKey('https://c.test/'), {
      statusCode: 302,
      headers: [{ name: 'Location', value: 'https://d.test/' }],
    })
    const chain = createOutboundHttpCapability({
      resolveDns: createFakeDns({
        'a.test': [PUBLIC_V4],
        'b.test': [PUBLIC_V4],
        'c.test': [PUBLIC_V4],
        'd.test': [PUBLIC_V4],
      }),
      connect: createFakeConnector({ byUrl: chainMap }).connector,
    })
    await expect(
      chain.request(
        { target: 'https://a.test/', method: 'GET' },
        { budgets: budgets({ maxRedirects: 2 }) },
      ),
    ).rejects.toBeInstanceOf(RedirectBudgetExceededError)
  })
})

describe('External E1.3 budgets and limits', () => {
  it('enforces request budget across connection attempts', async () => {
    const { connector, calls } = createFakeConnector({
      defaultHop: { statusCode: 200, error: new ConnectTimeoutError() },
    })
    const capability = createOutboundHttpCapability({
      resolveDns: createFakeDns({
        'example.test': [PUBLIC_V4, PUBLIC_V4_B, PUBLIC_V6],
      }),
      connect: connector,
    })
    await expect(
      capability.request(
        { target: 'https://example.test', method: 'GET' },
        { budgets: budgets({ maxRequests: 1 }) },
      ),
    ).rejects.toBeInstanceOf(RequestBudgetExceededError)
    expect(calls).toHaveLength(1)
  })

  it('maps oversized body/header/timeouts to typed errors via connector', async () => {
    for (const error of [
      new ResponseTooLargeError(),
      new HeaderTooLargeError(),
      new ResponseTimeoutError(),
      new OverallDeadlineExceededError(),
    ]) {
      const capability = createOutboundHttpCapability({
        resolveDns: createFakeDns({ 'example.test': [PUBLIC_V4] }),
        connect: createFakeConnector({
          defaultHop: { statusCode: 200, error },
        }).connector,
      })
      await expect(
        capability.request(
          { target: 'https://example.test', method: 'GET' },
          { budgets: budgets() },
        ),
      ).rejects.toBeInstanceOf(error.constructor)
    }
  })

  it('enforces overall deadline via aborted signal', async () => {
    const capability = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'example.test': [PUBLIC_V4] }),
      connect: createFakeConnector({ defaultHop: { statusCode: 200 } }).connector,
    })
    await expect(
      capability.request(
        { target: 'https://example.test', method: 'GET' },
        { budgets: budgets(), signal: AbortSignal.abort() },
      ),
    ).rejects.toBeInstanceOf(OverallDeadlineExceededError)
  })
})

describe('External E1.3 method and header policy', () => {
  it('allows GET/HEAD and rejects other methods at runtime', async () => {
    const { connector, calls } = createFakeConnector({
      defaultHop: { statusCode: 200 },
    })
    const capability = createOutboundHttpCapability({
      resolveDns: createFakeDns({ 'example.test': [PUBLIC_V4] }),
      connect: connector,
    })
    await capability.request(
      { target: 'https://example.test', method: 'GET' },
      { budgets: budgets() },
    )
    await capability.request(
      { target: 'https://example.test', method: 'HEAD' },
      { budgets: budgets() },
    )
    await expect(
      capability.request(
        {
          target: 'https://example.test',
          method: 'POST' as unknown as 'GET',
        },
        { budgets: budgets() },
      ),
    ).rejects.toBeInstanceOf(InvalidExternalMethodError)
    expect(
      calls.every((call) => {
        const method = call.request.method as string
        return method === 'GET' || method === 'HEAD'
      }),
    ).toBe(true)
  })

  it('never replays cookies or authorization across redirects', async () => {
    const byUrl = new Map<string, FakeHopScript>([
      [
        urlKey('https://a.test/'),
        {
          statusCode: 302,
          headers: [
            { name: 'Location', value: 'https://b.test/' },
            { name: 'Set-Cookie', value: 'session=secret' },
          ],
        },
      ],
      [urlKey('https://b.test/'), { statusCode: 200 }],
    ])
    const { connector, calls } = createFakeConnector({ byUrl })
    const capability = createOutboundHttpCapability({
      resolveDns: createFakeDns({
        'a.test': [PUBLIC_V4],
        'b.test': [PUBLIC_V4_B],
      }),
      connect: connector,
    })
    await capability.request(
      { target: 'https://a.test/', method: 'GET' },
      { budgets: budgets() },
    )
    expect(calls).toHaveLength(2)
    // Fake connector API has no header bag for outbound caller headers; production
    // connector hard-codes UA/Accept only. Assert request shape has no cookie fields.
    for (const call of calls) {
      expect(call.request).not.toHaveProperty('headers')
      expect(JSON.stringify(call.request)).not.toMatch(/Authorization/i)
      expect(JSON.stringify(call.request)).not.toMatch(/Cookie/i)
    }
  })
})

describe('External E1.3 constants', () => {
  it('uses the accepted User-Agent string', () => {
    expect(EXTERNAL_USER_AGENT).toBe(
      'VibeSec-External/1.1 (+https://github.com/gustavomarques00/vibesec)',
    )
  })
})

describe('External E1.3 architecture boundary', () => {
  it('confines network Node imports to external/infra', () => {
    const forbiddenOutsideInfra = new Set([
      'node:dns',
      'node:http',
      'node:https',
      'node:tls',
      'dns',
      'http',
      'https',
      'tls',
    ])
    const roots = [
      'src/external/domain',
      'src/external/policy',
      'src/application',
      'src/extractors',
      'src/discovery',
      'src/targets',
      'src/rules',
      'src/core',
      'src/reporters',
    ]
    const violations: string[] = []

    for (const root of roots) {
      const absoluteRoot = path.resolve(root)
      let files: string[]
      try {
        files = readdirSync(absoluteRoot, {
          recursive: true,
          encoding: 'utf8',
        }).filter((file) => file.endsWith('.ts'))
      } catch {
        continue
      }
      for (const file of files) {
        const source = readFileSync(path.join(absoluteRoot, file), 'utf8')
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
            if (forbiddenOutsideInfra.has(specifier)) {
              violations.push(`${root}/${file}:${specifier}`)
            }
            if (
              specifier.includes('/external/') &&
              root !== 'src/external/domain' &&
              root !== 'src/external/policy'
            ) {
              // Code path must not import external at all.
              if (!root.startsWith('src/external')) {
                violations.push(`${root}/${file}:external`)
              }
            }
          }
          ts.forEachChild(node, visit)
        }
        visit(sourceFile)
        if (!root.startsWith('src/external') && source.includes('/external/')) {
          violations.push(`${root}/${file}:text-external`)
        }
      }
    }
    expect(violations).toEqual([])
  })

  it('keeps policy free of http/dns/tls and allows node:net only for isIP', () => {
    const root = path.resolve('src/external/policy')
    const files = readdirSync(root, { recursive: true, encoding: 'utf8' }).filter(
      (file) => file.endsWith('.ts'),
    )
    for (const file of files) {
      const source = readFileSync(path.join(root, file), 'utf8')
      expect(source).not.toMatch(/from ['"]node:(dns|http|https|tls)['"]/u)
      expect(source).not.toMatch(/\bfetch\s*\(/u)
    }
  })

  it('does not export External infra from the public package entry', () => {
    const source = readFileSync(path.resolve('src/index.ts'), 'utf8')
    expect(source).not.toContain('external/infra')
    expect(source).not.toContain('OutboundHttpCapability')
    expect(source).not.toContain('createProductionOutboundHttpCapability')
  })

  it('infra source has no SSRF bypass or insecure TLS flags', () => {
    const root = path.resolve('src/external/infra')
    const files = readdirSync(root, { recursive: true, encoding: 'utf8' }).filter(
      (file) => file.endsWith('.ts'),
    )
    for (const file of files) {
      const source = readFileSync(path.join(root, file), 'utf8')
      expect(source).not.toMatch(/allowPrivate|allowLocalhost|skipSsrf|disableSsrf/u)
      expect(source).not.toMatch(/rejectUnauthorized:\s*false/u)
      expect(source).not.toMatch(/redirect:\s*['"]follow['"]/u)
      expect(source).not.toMatch(
        /child_process|\bexec\s*\(|\bspawn\s*\(|\beval\s*\(|new Function/u,
      )
    }
  })
})
