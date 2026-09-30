import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

import { normalizeExternalTarget } from '../src/external/domain/index.js'
import {
  classifyIpAddress,
  evaluateNormalizedDestination,
  evaluateResolvedAddressSet,
  evaluateStaticHostnamePolicy,
  parseIpAddress,
} from '../src/external/policy/index.js'

function expectDeny(input: string, category?: string): void {
  const result = classifyIpAddress(input)
  expect(result.decision).toBe('DENY_NON_PUBLIC')
  if (category !== undefined) expect(result.category).toBe(category)
}

function expectAllow(input: string): void {
  expect(classifyIpAddress(input).decision).toBe('ALLOW_PUBLIC')
}

describe('External E1.2 IPv4 classification', () => {
  it('denies plan and IANA non-global ranges at boundaries', () => {
    // 0.0.0.0/8
    expectDeny('0.0.0.0', 'unspecified')
    expectDeny('0.255.255.255', 'unspecified')
    expectAllow('1.0.0.0')

    // 10.0.0.0/8
    expectAllow('9.255.255.255')
    expectDeny('10.0.0.0', 'private')
    expectDeny('10.255.255.255', 'private')
    expectAllow('11.0.0.0')

    // 100.64.0.0/10
    expectAllow('100.63.255.255')
    expectDeny('100.64.0.0', 'carrier-grade-nat')
    expectDeny('100.127.255.255', 'carrier-grade-nat')
    expectAllow('100.128.0.0')

    // 127.0.0.0/8
    expectAllow('126.255.255.255')
    expectDeny('127.0.0.0', 'loopback')
    expectDeny('127.0.0.1', 'loopback')
    expectDeny('127.255.255.255', 'loopback')
    expectAllow('128.0.0.0')

    // 169.254.0.0/16 + metadata
    expectAllow('169.253.255.255')
    expectDeny('169.254.0.0', 'link-local')
    expectDeny('169.254.169.254', 'metadata')
    expectDeny('169.254.255.255', 'link-local')
    expectAllow('169.255.0.0')

    // 172.16.0.0/12
    expectAllow('172.15.255.255')
    expectDeny('172.16.0.0', 'private')
    expectDeny('172.31.255.255', 'private')
    expectAllow('172.32.0.0')

    // 192.168.0.0/16
    expectAllow('192.167.255.255')
    expectDeny('192.168.0.0', 'private')
    expectDeny('192.168.255.255', 'private')
    expectAllow('192.169.0.0')

    // documentation / protocol / benchmark
    expectDeny('192.0.0.1', 'protocol-assignment')
    expectDeny('192.0.2.1', 'documentation')
    expectDeny('198.18.0.1', 'benchmark')
    expectDeny('198.19.255.255', 'benchmark')
    expectAllow('198.20.0.0')
    expectDeny('198.51.100.1', 'documentation')
    expectDeny('203.0.113.1', 'documentation')

    // multicast / reserved / broadcast
    expectAllow('223.255.255.255')
    expectDeny('224.0.0.0', 'multicast')
    expectDeny('239.255.255.255', 'multicast')
    expectDeny('240.0.0.0', 'reserved')
    expectDeny('255.255.255.255', 'broadcast')
  })

  it('allows ordinary public IPv4 literals without connecting', () => {
    expectAllow('8.8.8.8')
    expectAllow('1.1.1.1')
    expectAllow('203.0.114.1')
  })
})

describe('External E1.2 IPv6 classification', () => {
  it('denies unspecified, loopback, ULA, link-local, multicast', () => {
    expectDeny('::', 'unspecified')
    expectDeny('::1', 'loopback')
    expectDeny('0:0:0:0:0:0:0:1', 'loopback')
    expectDeny('fc00::', 'unique-local')
    expectDeny('fc00::1', 'unique-local')
    expectDeny('fd00::1', 'unique-local')
    expectDeny('fe80::', 'link-local')
    expectDeny('fe80::1', 'link-local')
    expectDeny('ff00::', 'multicast')
    expectDeny('ff02::1', 'multicast')
  })

  it('denies documentation / discard / benchmark special ranges', () => {
    expectDeny('2001:db8::1', 'documentation')
    expectDeny('3fff::1', 'documentation')
    expectDeny('100::1', 'discard')
    expectDeny('2001:2::1', 'benchmark')
  })

  it('allows a global unicast example without connecting', () => {
    expectAllow('2001:4860:4860::8888')
  })

  it('denies non-global space outside 2000::/3', () => {
    expectDeny('::2', 'non-global')
  })
})

describe('External E1.2 IPv4-mapped IPv6', () => {
  it('reclassifies embedded IPv4 and never allows mapped private space', () => {
    expectDeny('::ffff:127.0.0.1', 'loopback')
    expectDeny('::ffff:10.0.0.1', 'private')
    expectDeny('::ffff:169.254.169.254', 'metadata')
    expectDeny('::ffff:192.168.1.1', 'private')
    expectAllow('::ffff:8.8.8.8')

    const mapped = classifyIpAddress('::ffff:10.0.0.1')
    expect(mapped.ipv4Mapped).toBe(true)
    expect(mapped.canonical).toBe('10.0.0.1')
  })

  it('accepts alternate mapped textual forms', () => {
    expectDeny('0:0:0:0:0:ffff:7f00:1', 'loopback')
  })
})

describe('External E1.2 static hostname policy', () => {
  it('blocks localhost variants and metadata hostnames', () => {
    for (const host of [
      'localhost',
      'LOCALHOST',
      'localhost.',
      'foo.localhost',
      'foo.localhost.',
      'metadata.google.internal',
      'METADATA.GOOGLE.INTERNAL.',
    ]) {
      expect(evaluateStaticHostnamePolicy(host).decision).toBe('BLOCKED_STATICALLY')
    }
  })

  it('requires resolution for ordinary hostnames', () => {
    expect(evaluateStaticHostnamePolicy('example.com').decision).toBe(
      'RESOLUTION_REQUIRED',
    )
  })
})

describe('External E1.2 destination evaluation', () => {
  it('denies literal private/loopback targets without DNS', () => {
    expect(
      evaluateNormalizedDestination(normalizeExternalTarget('https://127.0.0.1')).kind,
    ).toBe('IP_DENIED')
    expect(
      evaluateNormalizedDestination(normalizeExternalTarget('https://10.0.0.1')).kind,
    ).toBe('IP_DENIED')
    expect(
      evaluateNormalizedDestination(normalizeExternalTarget('https://[::1]/')).kind,
    ).toBe('IP_DENIED')
    expect(
      evaluateNormalizedDestination(normalizeExternalTarget('https://[fc00::1]/')).kind,
    ).toBe('IP_DENIED')
  })

  it('allows public literal IPs and requires resolution for hostnames', () => {
    expect(
      evaluateNormalizedDestination(normalizeExternalTarget('https://8.8.8.8')).kind,
    ).toBe('IP_ALLOWED')
    expect(
      evaluateNormalizedDestination(normalizeExternalTarget('https://example.com'))
        .kind,
    ).toBe('RESOLUTION_REQUIRED')
  })

  it('blocks localhost host targets statically', () => {
    expect(
      evaluateNormalizedDestination(normalizeExternalTarget('https://localhost')).kind,
    ).toBe('BLOCKED_STATICALLY')
  })
})

describe('External E1.2 resolved-set policy', () => {
  it('allows only all-public sets and is fail-closed on mixed answers', () => {
    expect(evaluateResolvedAddressSet('example.com', ['8.8.8.8']).decision).toBe(
      'ALLOW',
    )
    expect(evaluateResolvedAddressSet('example.com', ['10.0.0.1']).decision).toBe(
      'DENY_NON_PUBLIC',
    )
    expect(
      evaluateResolvedAddressSet('example.com', ['8.8.8.8', '10.0.0.1']).decision,
    ).toBe('DENY_NON_PUBLIC')
    expect(
      evaluateResolvedAddressSet('example.com', ['10.0.0.1', '8.8.8.8']).decision,
    ).toBe('DENY_NON_PUBLIC')
    expect(
      evaluateResolvedAddressSet('example.com', ['8.8.8.8', '2001:4860:4860::8888'])
        .decision,
    ).toBe('ALLOW')
    expect(
      evaluateResolvedAddressSet('example.com', ['::ffff:10.0.0.1', '8.8.8.8'])
        .decision,
    ).toBe('DENY_NON_PUBLIC')
  })

  it('deduplicates and ignores input order for authorization', () => {
    const a = evaluateResolvedAddressSet('example.com', ['8.8.8.8', '8.8.8.8'])
    expect(a.approved).toHaveLength(1)
    const left = evaluateResolvedAddressSet('example.com', ['1.1.1.1', '8.8.8.8'])
    const right = evaluateResolvedAddressSet('example.com', ['8.8.8.8', '1.1.1.1'])
    expect(left.decision).toBe(right.decision)
    expect(left.approved.map((item) => item.canonical)).toEqual(
      right.approved.map((item) => item.canonical),
    )
  })

  it('denies empty sets and statically blocked hostnames', () => {
    expect(evaluateResolvedAddressSet('example.com', []).decision).toBe('DENY_EMPTY')
    expect(evaluateResolvedAddressSet('localhost', ['8.8.8.8']).decision).toBe(
      'DENY_NON_PUBLIC',
    )
  })
})

describe('External E1.2 parser adversarial cases', () => {
  it('rejects invalid / ambiguous forms', () => {
    for (const input of [
      '127.0.0.01',
      '1.2.3.4.5',
      '256.0.0.1',
      'gggg::1',
      '1::2::3',
      'fe80::1%eth0',
      'not-an-ip',
      '',
    ]) {
      expect(parseIpAddress(input)).toBeUndefined()
      expect(classifyIpAddress(input).decision).toBe('INVALID')
    }
  })
})

describe('External E1.2 architecture boundary', () => {
  it('keeps policy free of DNS/HTTP/TLS I/O and connect/fetch calls', () => {
    const root = path.resolve('src/external/policy')
    const files = readdirSync(root, { recursive: true, encoding: 'utf8' }).filter(
      (file) => file.endsWith('.ts'),
    )
    const forbiddenModules = new Set([
      'node:dns',
      'node:http',
      'node:https',
      'node:tls',
      'dns',
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
          if (forbiddenModules.has(specifier) || specifier.includes('external/infra')) {
            violations.push(`${file}:import:${specifier}`)
          }
        }
        if (
          ts.isCallExpression(node) &&
          ts.isIdentifier(node.expression) &&
          (node.expression.text === 'fetch' || node.expression.text === 'connect')
        ) {
          violations.push(`${file}:call:${node.expression.text}`)
        }
        if (
          ts.isPropertyAccessExpression(node) &&
          node.name.text === 'connect' &&
          ts.isIdentifier(node.expression) &&
          (node.expression.text === 'net' || node.expression.text === 'tls')
        ) {
          violations.push(`${file}:member:connect`)
        }
        ts.forEachChild(node, visit)
      }
      visit(sourceFile)
    }

    expect(violations).toEqual([])
  })

  it('keeps Code modules free of external imports', () => {
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
})
