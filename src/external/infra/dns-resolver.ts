import { promises as dnsPromises } from 'node:dns'

import { DnsFailureError } from './errors.js'
import type { DnsLookupResult, DnsResolver } from './types.js'

/**
 * Production DNS resolver. Uses OS lookup with all addresses.
 * Does not authorize — caller must run E1.2 evaluateResolvedAddressSet.
 */
export function createNodeDnsResolver(): DnsResolver {
  return Object.freeze({
    async lookupAll(hostname: string): Promise<DnsLookupResult> {
      try {
        const results = await dnsPromises.lookup(hostname, {
          all: true,
          verbatim: true,
        })
        const addresses = Object.freeze(
          results.map((entry) => entry.address).filter((address) => address.length > 0),
        )
        return Object.freeze({ addresses })
      } catch {
        throw new DnsFailureError()
      }
    },
  })
}
