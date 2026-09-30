import { compareExternalStrings } from '../domain/ordering.js'
import { parseIpAddress } from '../policy/ip-address.js'
import { EXTERNAL_MAX_ADDRESS_ATTEMPTS } from './constants.js'

/**
 * Deterministic connection-order among approved public addresses.
 *
 * Tradeoff (documented): prefer IPv4 before IPv6, then canonical textual order.
 * Avoids DNS-order dependence and unbounded Happy Eyeballs. Security over
 * dual-stack latency optimization.
 */
export function selectPinnedAddressOrder(
  approvedAddresses: readonly string[],
  maxAttempts: number = EXTERNAL_MAX_ADDRESS_ATTEMPTS,
): readonly string[] {
  const unique = new Map<string, { canonical: string; version: 4 | 6 }>()

  for (const address of approvedAddresses) {
    const parsed = parseIpAddress(address)
    if (parsed === undefined) continue
    if (!unique.has(parsed.canonical)) {
      unique.set(parsed.canonical, {
        canonical: parsed.canonical,
        version: parsed.version,
      })
    }
  }

  const ordered = [...unique.values()].sort((left, right) => {
    if (left.version !== right.version) {
      return left.version === 4 ? -1 : 1
    }
    return compareExternalStrings(left.canonical, right.canonical)
  })

  const limit = Math.max(0, Math.min(maxAttempts, ordered.length))
  return Object.freeze(ordered.slice(0, limit).map((entry) => entry.canonical))
}

export function addressFamily(address: string): 4 | 6 {
  const parsed = parseIpAddress(address)
  if (parsed === undefined) {
    throw new TypeError('Expected a previously approved IP address.')
  }
  return parsed.version
}

export function canonicalRemoteAddress(remoteAddress: string): string | undefined {
  // Node may return IPv4-mapped form for IPv4-on-IPv6 sockets.
  const trimmed = remoteAddress.trim()
  if (trimmed.startsWith('::ffff:')) {
    const embedded = trimmed.slice('::ffff:'.length)
    const parsedEmbedded = parseIpAddress(embedded)
    if (parsedEmbedded?.version === 4) return parsedEmbedded.canonical
  }
  return parseIpAddress(trimmed)?.canonical
}
