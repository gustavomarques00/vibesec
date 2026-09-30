# VibeSec kernel threat model

## Assets

- Secrets and personal data present in analyzed repositories.
- Source paths and host filesystem details.
- Integrity of findings and their evidence.
- Deterministic scan behavior.
- The machine running VibeSec.

## Trust boundaries

Repository content is fully untrusted. Filenames, source text, configuration, parser
errors, and metadata may be intentionally crafted to trigger disclosure or
nondeterministic behavior.

The redaction boundary separates short-lived raw sensitive values from export-safe
facts, findings, errors, logs, and future reporters.

## Threats addressed in Phase 1

### Accidental secret disclosure

Raw values could leak through evidence, JSON serialization, terminal formatting,
snapshots, object inspection, exception messages, or logs.

Mitigations:

- opaque scan-scoped tokens with private `WeakMap` provenance;
- direct string inspection before serialization;
- single-pass JSON serialization followed by escaped-secret inspection;
- runtime validation of all kernel DTOs;
- scan-scoped output tokens;
- generic unsafe-output errors;
- canary tests covering quotes, slashes, controls, and Unicode NFC/NFD.

### Fingerprint misuse

A stable hash could enable cross-project tracking or dictionary attacks against weak
passwords.

Mitigations:

- HMAC-SHA-256 rather than an unkeyed hash;
- random key per scan;
- truncated output;
- no key export;
- runtime provenance checks across scan contexts;
- no fingerprint use in finding IDs.

### Host path disclosure

Absolute paths may expose usernames or workstation layout and make IDs platform
dependent.

Mitigations:

- reject absolute and target-escaping paths in source locations;
- require explicit Windows or POSIX path flavor;
- normalize Unicode to NFC and separators to `/`;
- reject drive-relative, UNC, device, NUL, dot, and traversal paths;
- use only normalized relative paths in IDs.

### Nondeterministic or attacker-controlled IDs

Timestamps, randomness, secret values, filesystem roots, or evidence ordering could
change IDs between scans.

Mitigations:

- identity restricted to validated rule ID and complete source location;
- SHA-256 over non-sensitive identity only;
- locale-independent binary ordering and duplicate-ID rejection;
- no clock or random source in rule contracts.

### Rule side effects

Rules could access files, network, subprocesses, loggers, or reporters and bypass the
pipeline.

Mitigation: `RuleContext` exposes immutable runtime-validated facts only. ESLint and an
architectural test prohibit Node, network, and security-capability imports from rules
and reporters.

### Malicious error content

Parsers may throw messages containing source text or secrets.

Mitigation: errors cross the scan context. Formatting reads only own data descriptors,
does not call arbitrary `toString`, and never prints stacks.

### Cross-scan capability reuse

Fingerprint, sanitized-text, rule-context, and output tokens from another scan could
otherwise mix trust domains.

Mitigation: `ScanKernelContext` owns all registries, rejects foreign tokens, enforces
`active → finalized → closed`, and prevents operations after closure.

## Threats addressed in Phase 2

The local target inventory treats directory entries, filenames, file contents, and
filesystem errors as untrusted. It:

- rejects a symlink as the target and skips symlink entries;
- resolves every traversed directory and candidate file beneath the real target root;
- checks directory and file identities before use and aborts on observed mutation;
- bounds each read to `maxFileBytes + 1` bytes and rejects files that grow or change
  identity;
- caps visited entries, candidate files, and aggregate candidate bytes;
- skips binary and invalid UTF-8 content;
- never returns source contents from the discovery API;
- emits only canonical target-relative paths;
- escapes control and Unicode format characters in human-readable reports;
- never executes target code, package scripts, hooks, or binaries.

The scanner assumes the local target is not being maliciously mutated concurrently.
Node.js does not expose portable handle-relative directory traversal (`openat`) across
Windows, Linux, and macOS. Identity, containment, and repeat checks detect practical
mutations, but a process capable of winning filesystem races should first provide an
immutable snapshot to VibeSec.

## Deferred threats

Archive/decompression bombs, remote Git clone behavior, Git submodules/LFS abuse,
and dependency supply-chain risks belong to later phases. Phase 3 resolves local
Git provenance with fixed argv, hooks disabled, bounded output, and no shell, but
does not clone remote repositories or expand archives.

## Threats addressed in Phase 3

Local Git metadata, env files, and high-specificity secret candidates are untrusted:

- Git is invoked only with `spawn` argument arrays, hooks disabled, and output caps;
- repository absence or Git failure yields `unknown` provenance and never a
  “versioned” claim;
- typed secret extractors protect raw values before fact construction;
- generic entropy candidates remain `suspicious` and are suppressed when a
  high-specificity fact already covers the location;
- client env-prefix exposure and tracked `.env` findings require correlating
  validated facts rather than raw file dumps.

## Threats addressed in Phase 4

Supabase analysis treats migration SQL and key literals as untrusted local text:

- no network, database connection, or live Supabase project access;
- service-role/secret keys are protected before fact construction; anon/publishable
  keys are inventoried without becoming findings by default;
- RLS disable claims are limited to the final observed migration state and never
  assert production configuration;
- missing local RLS/policy evidence yields `requires_authorization`, never
  “disabled in production”;
- broad `USING (true)` / `WITH CHECK (true)` policies are `suspicious` only;
- SQL statement and fact counts are budgeted to resist migration DoS.

## Threats addressed in Phase 5

AUTH/AUTHZ/DANG analysis treats JS/TS source as untrusted text:

- comment/string heuristics reduce false positives; they are not a full parser;
- client-only auth/role checks are `suspicious`, never proof that production is open;
- storage role reads exclude standard Supabase session token keys;
- missing ownership/RLS correlation yields `requires_authorization`, never confirmed IDOR;
- dangerous sinks with non-constant input are `suspicious` only; constant and
  recognized-sanitizer cases are suppressed;
- no target code execution; analysis is same-file / scan-indexed fact correlation
  with explicit budgets.

## Threats addressed in Phase 6

Release hardening focuses on making existing promises reliable:

- malformed JS/SQL and unterminated comments/strings must not crash scans;
- sentinel target payloads must never execute;
- CLI exit codes are documented (`0` clean, `1` findings, `2` usage/failure);
- package metadata includes `engines.node >=20`, shebang, README, and pack dry-run;
- residual Phase 1–5 risks are classified as fixed, accepted for MVP, or deferred.

## Security assumptions

- Future extractors register a sensitive value before constructing facts or errors
  from it.
- Future output adapters accept only `SafeOutput` issued by their scan.
- No raw-access capability exists in the public package API.
- Memory inspection and a fully compromised scanner process are outside this boundary;
  JavaScript cannot guarantee zeroization of immutable strings.
