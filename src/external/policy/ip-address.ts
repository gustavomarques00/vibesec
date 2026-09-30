import { isIP } from 'node:net'

export type IpVersion = 4 | 6

export type ParsedIpAddress = Readonly<{
  version: IpVersion
  /** Canonical textual form without zone id. */
  canonical: string
  /** Network-order bytes: 4 for IPv4, 16 for IPv6. */
  bytes: Uint8Array
}>

/**
 * Strictly parse an IP address string. Rejects zone identifiers.
 * Uses Node `isIP` for acceptance, then expands to bytes for classification.
 */
export function parseIpAddress(input: string): ParsedIpAddress | undefined {
  if (typeof input !== 'string' || input.length === 0) return undefined
  if (input.includes('%')) return undefined

  const candidate = input.trim().normalize('NFC')
  if (candidate.length === 0) return undefined

  const version = isIP(candidate)
  if (version === 4) {
    const bytes = parseIpv4Bytes(candidate)
    if (bytes === undefined) return undefined
    return Object.freeze({
      version: 4 as const,
      canonical: formatIpv4(bytes),
      bytes,
    })
  }
  if (version === 6) {
    const bytes = parseIpv6Bytes(candidate)
    if (bytes === undefined) return undefined
    return Object.freeze({
      version: 6 as const,
      canonical: formatIpv6(bytes),
      bytes,
    })
  }
  return undefined
}

export function ipv4ToUint32(bytes: Uint8Array): number {
  if (bytes.length !== 4) throw new TypeError('IPv4 requires 4 bytes.')
  return (
    ((readByte(bytes, 0) << 24) |
      (readByte(bytes, 1) << 16) |
      (readByte(bytes, 2) << 8) |
      readByte(bytes, 3)) >>>
    0
  )
}

export function ipv6ToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length !== 16) throw new TypeError('IPv6 requires 16 bytes.')
  let value = 0n
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte)
  }
  return value
}

export function isIpv4MappedIpv6(bytes: Uint8Array): boolean {
  if (bytes.length !== 16) return false
  for (let index = 0; index < 10; index += 1) {
    if (bytes[index] !== 0) return false
  }
  return bytes[10] === 0xff && bytes[11] === 0xff
}

export function embeddedIpv4FromMapped(bytes: Uint8Array): Uint8Array {
  if (!isIpv4MappedIpv6(bytes)) {
    throw new TypeError('Address is not IPv4-mapped IPv6.')
  }
  return bytes.subarray(12, 16)
}

function readByte(bytes: Uint8Array, index: number): number {
  const value = bytes[index]
  if (value === undefined) {
    throw new TypeError(`Missing IP byte at index ${String(index)}.`)
  }
  return value
}

function parseIpv4Bytes(text: string): Uint8Array | undefined {
  const parts = text.split('.')
  if (parts.length !== 4) return undefined
  const bytes = new Uint8Array(4)
  for (let index = 0; index < 4; index += 1) {
    const part = parts[index]
    if (part === undefined) return undefined
    // Disallow leading zeros (except bare 0) for strictness beyond isIP.
    if (!/^(?:0|[1-9]\d{0,2})$/u.test(part)) return undefined
    const value = Number(part)
    if (!Number.isInteger(value) || value < 0 || value > 255) return undefined
    bytes[index] = value
  }
  return bytes
}

function parseIpv6Bytes(text: string): Uint8Array | undefined {
  let working = text.toLowerCase()
  if (working.includes('.')) {
    const lastColon = working.lastIndexOf(':')
    if (lastColon < 0) return undefined
    const ipv4Tail = parseIpv4Bytes(working.slice(lastColon + 1))
    if (ipv4Tail === undefined) return undefined
    const hi = ((readByte(ipv4Tail, 0) << 8) | readByte(ipv4Tail, 1)).toString(16)
    const lo = ((readByte(ipv4Tail, 2) << 8) | readByte(ipv4Tail, 3)).toString(16)
    working = `${working.slice(0, lastColon + 1)}${hi}:${lo}`
  }

  if ((working.match(/::/gu) ?? []).length > 1) return undefined

  let head: string[]
  let tail: string[]
  let fill: number
  if (working.includes('::')) {
    const sides = working.split('::')
    if (sides.length !== 2) return undefined
    const left = sides[0]
    const right = sides[1]
    if (left === undefined || right === undefined) return undefined
    head = left === '' ? [] : left.split(':')
    tail = right === '' ? [] : right.split(':')
    fill = 8 - (head.length + tail.length)
    if (fill < 0) return undefined
  } else {
    head = working.split(':')
    tail = []
    fill = 0
    if (head.length !== 8) return undefined
  }

  const groups = [...head, ...Array.from({ length: fill }, () => '0'), ...tail]
  if (groups.length !== 8) return undefined

  const bytes = new Uint8Array(16)
  for (let index = 0; index < 8; index += 1) {
    const group = groups[index]
    if (group === undefined) return undefined
    if (!/^[0-9a-f]{1,4}$/u.test(group)) return undefined
    const value = Number.parseInt(group, 16)
    bytes[index * 2] = (value >> 8) & 0xff
    bytes[index * 2 + 1] = value & 0xff
  }
  return bytes
}

function formatIpv4(bytes: Uint8Array): string {
  return `${String(readByte(bytes, 0))}.${String(readByte(bytes, 1))}.${String(readByte(bytes, 2))}.${String(readByte(bytes, 3))}`
}

function formatIpv6(bytes: Uint8Array): string {
  const groups: string[] = []
  for (let index = 0; index < 8; index += 1) {
    const value = (readByte(bytes, index * 2) << 8) | readByte(bytes, index * 2 + 1)
    groups.push(value.toString(16))
  }
  let bestStart = -1
  let bestLen = 0
  let start = -1
  let length = 0
  for (let index = 0; index <= 8; index += 1) {
    if (index < 8 && groups[index] === '0') {
      if (start === -1) start = index
      length += 1
    } else {
      if (length > bestLen) {
        bestStart = start
        bestLen = length
      }
      start = -1
      length = 0
    }
  }
  if (bestLen > 1) {
    const left = groups.slice(0, bestStart).join(':')
    const right = groups.slice(bestStart + bestLen).join(':')
    return `${left}::${right}`
  }
  return groups.join(':')
}
