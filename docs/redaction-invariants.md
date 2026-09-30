# Redaction invariants

Redaction is a security boundary, not a reporter feature. `ScanKernelContext` owns one
private boundary for its complete `active → finalized → closed` lifecycle.

## Sensitive value lifecycle

1. A detector passes raw material to `ScanKernelContext.protectSecret`.
2. The private boundary immediately creates opaque sanitized-text and fingerprint
   tokens.
3. Token payloads live in private `WeakMap` registries owned by that scan.
4. Draft evidence accepts only tokens issued by the current scan.
5. The finalizer verifies provenance before producing exportable strings.
6. Final output is an opaque `SafeOutput` token readable only by its issuing scan.

No public API can recover raw material. Internal rules and reporters are prohibited
from importing security capabilities.

## Fingerprints

Fingerprints use HMAC-SHA-256 with a random 256-bit key generated for each scan. Output
is truncated to 96 bits and prefixed with `hmac-sha256:`. This supports correlation
within one scan without enabling stable cross-scan tracking or straightforward
precomputed dictionary matching.

The HMAC key is never exported. Fingerprints and raw values are never used in finding
IDs. A token from another scan or a fabricated object is rejected at runtime.

## Mandatory invariants

- **INV-01:** Raw sensitive material cannot be serialized in a `Finding`.
- **INV-02:** Raw sensitive material cannot appear in formatted errors.
- **INV-03:** Raw sensitive material cannot appear in authorized output.
- **INV-04:** Finding IDs do not depend on a secret value or fingerprint.
- **INV-05:** Equal non-sensitive identity produces an equal finding ID.
- **INV-06:** Findings and their collections use deterministic ordering.
- **INV-07:** Paths used in IDs are normalized and target-relative.
- **INV-08:** Severity, confidence, and status are independent.
- **INV-09:** Missing evidence is never automatically converted to `confirmed`.
- **INV-10:** Facts do not carry final vulnerability classification.

## Failure behavior

If known raw material reaches a draft or output, the boundary throws
`UnsafeOutputError`. Direct strings are inspected before serialization. The final JSON
is serialized exactly once and that exact output is checked against both literal and
JSON-escaped forms of every registered secret.

Error formatting reads only own data descriptors, never includes stacks, and falls
back to a generic message for accessors, proxies, or malformed error objects.

The boundary protects exact known values plus NFC/NFD Unicode forms and their JSON
escaping. Other semantic transformations, such as Base64 or URL encoding, require
explicit bounded handling by future extractors and must not be logged during that
process.
