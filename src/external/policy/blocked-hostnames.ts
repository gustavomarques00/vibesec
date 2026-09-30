/**
 * Defense-in-depth hostname denylist. IP classification remains primary.
 * Hostnames are compared after External target normalization conventions:
 * lowercase ASCII / punycode, trailing dots stripped.
 */

const EXACT_BLOCKED = new Set(['localhost', 'metadata.google.internal'])

export type StaticHostnameDecision = 'BLOCKED_STATICALLY' | 'RESOLUTION_REQUIRED'

export type StaticHostnamePolicyResult = Readonly<{
  decision: StaticHostnameDecision
  reason?: 'localhost' | 'localhost-suffix' | 'cloud-metadata'
  hostname: string
}>

export function canonicalizePolicyHostname(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/\.+$/u, '').normalize('NFC')
}

export function evaluateStaticHostnamePolicy(
  hostname: string,
): StaticHostnamePolicyResult {
  const canonical = canonicalizePolicyHostname(hostname)
  if (canonical.length === 0) {
    return Object.freeze({
      decision: 'BLOCKED_STATICALLY',
      reason: 'localhost',
      hostname: canonical,
    })
  }

  if (EXACT_BLOCKED.has(canonical)) {
    return Object.freeze({
      decision: 'BLOCKED_STATICALLY',
      reason: canonical === 'localhost' ? 'localhost' : 'cloud-metadata',
      hostname: canonical,
    })
  }

  if (canonical === 'localhost' || canonical.endsWith('.localhost')) {
    return Object.freeze({
      decision: 'BLOCKED_STATICALLY',
      reason: 'localhost-suffix',
      hostname: canonical,
    })
  }

  return Object.freeze({
    decision: 'RESOLUTION_REQUIRED',
    hostname: canonical,
  })
}
