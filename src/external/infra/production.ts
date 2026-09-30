import { createNodeDnsResolver } from './dns-resolver.js'
import { createNodePinnedHttpConnector } from './node-connector.js'
import { createOutboundHttpCapability } from './orchestrator.js'
import type { OutboundHttpCapability } from './types.js'

/**
 * Production External outbound capability.
 * Network I/O is confined to External infra; not wired into Code scan.
 */
export function createProductionOutboundHttpCapability(): OutboundHttpCapability {
  return createOutboundHttpCapability({
    resolveDns: createNodeDnsResolver(),
    connect: createNodePinnedHttpConnector(),
  })
}
