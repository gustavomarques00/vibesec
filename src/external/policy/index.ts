export {
  canonicalizePolicyHostname,
  evaluateStaticHostnamePolicy,
} from './blocked-hostnames.js'
export type {
  StaticHostnameDecision,
  StaticHostnamePolicyResult,
} from './blocked-hostnames.js'

export {
  evaluateNormalizedDestination,
  evaluateResolvedAddressSet,
} from './destination-policy.js'
export type {
  DestinationEvaluationKind,
  DestinationPolicyResult,
  ResolvedAddressSetDecision,
  ResolvedAddressSetPolicyResult,
  ResolvedAddressVerdict,
} from './destination-policy.js'

export {
  embeddedIpv4FromMapped,
  ipv4ToUint32,
  ipv6ToBigInt,
  isIpv4MappedIpv6,
  parseIpAddress,
} from './ip-address.js'
export type { IpVersion, ParsedIpAddress } from './ip-address.js'

export { classifyIpAddress, classifyParsedIpAddress } from './ip-classification.js'
export type {
  IpClassification,
  IpClassificationDecision,
  IpDenialCategory,
} from './ip-classification.js'
