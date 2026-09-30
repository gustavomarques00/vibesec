import {
  embeddedIpv4FromMapped,
  ipv4ToUint32,
  ipv6ToBigInt,
  isIpv4MappedIpv6,
  parseIpAddress,
  type ParsedIpAddress,
} from './ip-address.js'

export type IpClassificationDecision = 'ALLOW_PUBLIC' | 'DENY_NON_PUBLIC' | 'INVALID'

/**
 * Stable denial categories derived from IANA special-purpose semantics and
 * the accepted E1 plan. Prefer fail-closed for non-globally-reachable space.
 */
export type IpDenialCategory =
  | 'unspecified'
  | 'loopback'
  | 'private'
  | 'carrier-grade-nat'
  | 'link-local'
  | 'metadata'
  | 'documentation'
  | 'benchmark'
  | 'multicast'
  | 'reserved'
  | 'broadcast'
  | 'unique-local'
  | 'discard'
  | 'protocol-assignment'
  | 'ipv4-mapped'
  | 'non-global'
  | 'invalid'

export type IpClassification = Readonly<{
  decision: IpClassificationDecision
  category?: IpDenialCategory
  /** Canonical address that was classified (embedded IPv4 for mapped). */
  canonical?: string
  version?: 4 | 6
  /** True when classification applied to an IPv4 embedded in ::ffff:/96. */
  ipv4Mapped?: boolean
}>

type Ipv4Cidr = Readonly<{
  network: number
  prefix: number
  category: IpDenialCategory
}>

type Ipv6Cidr = Readonly<{
  network: bigint
  prefix: number
  category: IpDenialCategory
}>

/**
 * IPv4 ranges that must not be used as ordinary public Internet destinations.
 * Baseline: accepted E1 plan + IANA special-purpose entries with
 * Globally Reachable = False (fail-closed).
 *
 * Note: 192.0.0.0/24 is denied wholesale (fail-closed) even though IANA marks
 * a few anycast singles as globally reachable; refine in a later slice if needed.
 * Additional IANA range included beyond the original plan list: 198.18.0.0/15
 * (benchmarking).
 */
const IPV4_DENY: readonly Ipv4Cidr[] = Object.freeze([
  { network: ipv4Network('0.0.0.0'), prefix: 8, category: 'unspecified' },
  { network: ipv4Network('10.0.0.0'), prefix: 8, category: 'private' },
  { network: ipv4Network('100.64.0.0'), prefix: 10, category: 'carrier-grade-nat' },
  { network: ipv4Network('127.0.0.0'), prefix: 8, category: 'loopback' },
  { network: ipv4Network('169.254.0.0'), prefix: 16, category: 'link-local' },
  { network: ipv4Network('172.16.0.0'), prefix: 12, category: 'private' },
  { network: ipv4Network('192.0.0.0'), prefix: 24, category: 'protocol-assignment' },
  { network: ipv4Network('192.0.2.0'), prefix: 24, category: 'documentation' },
  { network: ipv4Network('192.168.0.0'), prefix: 16, category: 'private' },
  { network: ipv4Network('198.18.0.0'), prefix: 15, category: 'benchmark' },
  { network: ipv4Network('198.51.100.0'), prefix: 24, category: 'documentation' },
  { network: ipv4Network('203.0.113.0'), prefix: 24, category: 'documentation' },
  { network: ipv4Network('224.0.0.0'), prefix: 4, category: 'multicast' },
  { network: ipv4Network('255.255.255.255'), prefix: 32, category: 'broadcast' },
  { network: ipv4Network('240.0.0.0'), prefix: 4, category: 'reserved' },
])

/**
 * IPv6 ranges denied for ordinary public destinations (IANA + E1 plan).
 * Addresses outside 2000::/3 are also denied as non-global (except mapped path).
 */
const IPV6_DENY: readonly Ipv6Cidr[] = Object.freeze([
  { network: ipv6Network('::'), prefix: 128, category: 'unspecified' },
  { network: ipv6Network('::1'), prefix: 128, category: 'loopback' },
  { network: ipv6Network('64:ff9b:1::'), prefix: 48, category: 'protocol-assignment' },
  { network: ipv6Network('100::'), prefix: 64, category: 'discard' },
  { network: ipv6Network('2001:2::'), prefix: 48, category: 'benchmark' },
  { network: ipv6Network('2001:db8::'), prefix: 32, category: 'documentation' },
  { network: ipv6Network('3fff::'), prefix: 20, category: 'documentation' },
  { network: ipv6Network('5f00::'), prefix: 16, category: 'protocol-assignment' },
  { network: ipv6Network('fc00::'), prefix: 7, category: 'unique-local' },
  { network: ipv6Network('fe80::'), prefix: 10, category: 'link-local' },
  { network: ipv6Network('ff00::'), prefix: 8, category: 'multicast' },
])

const IPV6_GLOBAL_UNICAST_PREFIX = 3
const IPV6_GLOBAL_UNICAST_NETWORK = ipv6Network('2000::')

export function classifyIpAddress(input: string): IpClassification {
  const parsed = parseIpAddress(input)
  if (parsed === undefined) {
    return Object.freeze({ decision: 'INVALID', category: 'invalid' })
  }
  return classifyParsedIpAddress(parsed)
}

export function classifyParsedIpAddress(parsed: ParsedIpAddress): IpClassification {
  if (parsed.version === 4) {
    return classifyIpv4(parsed.bytes, parsed.canonical, false)
  }

  if (isIpv4MappedIpv6(parsed.bytes)) {
    const embedded = embeddedIpv4FromMapped(parsed.bytes)
    const embeddedCanonical = formatEmbeddedIpv4(embedded)
    const inner = classifyIpv4(embedded, embeddedCanonical, true)
    if (inner.decision === 'ALLOW_PUBLIC') {
      return Object.freeze({
        decision: 'ALLOW_PUBLIC',
        canonical: embeddedCanonical,
        version: 4,
        ipv4Mapped: true,
      })
    }
    return Object.freeze({
      decision: 'DENY_NON_PUBLIC',
      category: inner.category ?? 'ipv4-mapped',
      canonical: embeddedCanonical,
      version: 4,
      ipv4Mapped: true,
    })
  }

  // Prefer metadata label for link-local cloud metadata when applicable later;
  // standard link-local remains link-local.
  if (
    !ipv6InCidr(
      ipv6ToBigInt(parsed.bytes),
      IPV6_GLOBAL_UNICAST_NETWORK,
      IPV6_GLOBAL_UNICAST_PREFIX,
    )
  ) {
    // Still check explicit categories for better evidence.
    const denied = matchIpv6Deny(parsed.bytes)
    return Object.freeze({
      decision: 'DENY_NON_PUBLIC',
      category: denied ?? 'non-global',
      canonical: parsed.canonical,
      version: 6,
    })
  }

  const denied = matchIpv6Deny(parsed.bytes)
  if (denied !== undefined) {
    return Object.freeze({
      decision: 'DENY_NON_PUBLIC',
      category: denied,
      canonical: parsed.canonical,
      version: 6,
    })
  }

  return Object.freeze({
    decision: 'ALLOW_PUBLIC',
    canonical: parsed.canonical,
    version: 6,
  })
}

function classifyIpv4(
  bytes: Uint8Array,
  canonical: string,
  ipv4Mapped: boolean,
): IpClassification {
  const value = ipv4ToUint32(bytes)
  for (const rule of IPV4_DENY) {
    if (ipv4InCidr(value, rule.network, rule.prefix)) {
      let category = rule.category
      // Cloud metadata IPv4 is within link-local; label specifically.
      if (value === ipv4Network('169.254.169.254')) {
        category = 'metadata'
      }
      return Object.freeze({
        decision: 'DENY_NON_PUBLIC',
        category,
        canonical,
        version: 4,
        ...(ipv4Mapped ? { ipv4Mapped: true } : {}),
      })
    }
  }
  return Object.freeze({
    decision: 'ALLOW_PUBLIC',
    canonical,
    version: 4,
    ...(ipv4Mapped ? { ipv4Mapped: true } : {}),
  })
}

function matchIpv6Deny(bytes: Uint8Array): IpDenialCategory | undefined {
  const value = ipv6ToBigInt(bytes)
  for (const rule of IPV6_DENY) {
    if (ipv6InCidr(value, rule.network, rule.prefix)) return rule.category
  }
  return undefined
}

function ipv4InCidr(address: number, network: number, prefix: number): boolean {
  if (prefix === 0) return true
  const mask = prefix === 32 ? 0xffffffff : (~0 << (32 - prefix)) >>> 0
  return (address & mask) === (network & mask)
}

function ipv6InCidr(address: bigint, network: bigint, prefix: number): boolean {
  if (prefix === 0) return true
  const shift = 128n - BigInt(prefix)
  const mask = ((1n << BigInt(prefix)) - 1n) << shift
  return (address & mask) === (network & mask)
}

function formatEmbeddedIpv4(bytes: Uint8Array): string {
  if (bytes.length !== 4) throw new TypeError('Embedded IPv4 requires 4 bytes.')
  const a = bytes[0]
  const b = bytes[1]
  const c = bytes[2]
  const d = bytes[3]
  if (a === undefined || b === undefined || c === undefined || d === undefined) {
    throw new TypeError('Embedded IPv4 requires 4 bytes.')
  }
  return `${String(a)}.${String(b)}.${String(c)}.${String(d)}`
}

function ipv4Network(text: string): number {
  const parsed = parseIpAddress(text)
  if (parsed?.version !== 4) {
    throw new Error(`Invalid IPv4 network constant: ${text}`)
  }
  return ipv4ToUint32(parsed.bytes)
}

function ipv6Network(text: string): bigint {
  const parsed = parseIpAddress(text)
  if (parsed?.version !== 6) {
    throw new Error(`Invalid IPv6 network constant: ${text}`)
  }
  return ipv6ToBigInt(parsed.bytes)
}
