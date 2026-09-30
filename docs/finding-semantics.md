# Finding semantics

VibeSec reports repository evidence. It does not claim dynamic exploitability or the
state of a deployed system unless a future, separately authorized mode provides that
evidence.

## Facts and findings

A `Fact` is an intermediate observation produced by an extractor. Facts describe such
things as an environment binding, a database policy, an authentication guard, or a
dangerous sink. They never contain severity, impact, remediation, or final status.

A `Finding` is a narrowly worded security claim produced by a deterministic rule after
facts have been correlated. Every finding must include evidence, limitations, impact,
and remediation.

## Status

### `confirmed`

The exact condition claimed by the finding is directly verifiable in the analyzed
repository material.

It does **not** automatically mean:

- a confirmed exploit;
- a vulnerable production deployment;
- a valid credential;
- accessible data;
- successful privilege escalation.

For example, “a Supabase service-role literal is present in a tracked client file” may
be confirmed. Whether the credential is valid or deployed is not confirmed.

### `suspicious`

A potentially unsafe pattern is present, but the available evidence is insufficient to
make the stronger security claim. Frontend-only role checks and dynamic HTML sinks are
typical examples.

### `requires_authorization`

Confirmation would require validation in infrastructure or an application owned by
the target operator. VibeSec must not perform that validation automatically. A missing
local RLS migration is an example: it does not prove that production RLS is disabled.

## Independent dimensions

- `severity` estimates potential impact.
- `confidence` describes detector precision for the stated condition.
- `status` describes the evidence level of the claim.

No dimension is derived automatically from another. In particular, absence of evidence
must never be promoted to `confirmed`.

## Determinism

Finding IDs use only the validated rule ID and the complete canonical target-relative
source location. Global findings use only the rule ID. IDs never include timestamps,
randomness, absolute paths, discriminators, evidence, secret values, or secret
fingerprints.

Only one finding may exist for a given rule/location pair. Duplicate IDs are rejected
when the scan is finalized rather than silently ordered or deduplicated.

Ephemeral secret fingerprints intentionally differ between scans. Therefore the
security-relevant finding identity remains deterministic while the scan-scoped
fingerprint does not.

## Runtime validation

TypeScript types are not treated as a security boundary. Facts, rule metadata, finding
drafts, evidence, source locations, and final findings are validated at runtime.
Unknown properties, accessors, unexpected prototypes, invalid enums, sparse arrays,
and final vulnerability fields on facts are rejected.

Rule-controlled metadata is bound by the evaluator. A `FindingDraft` cannot override
the rule ID, version, title, category, or references of the rule that produced it.
