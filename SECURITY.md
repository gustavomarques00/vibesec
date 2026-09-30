# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |

Only the latest published 1.0.x line is in scope for security fixes until a
newer minor/major is announced.

## What to report

### A) Vulnerabilities in VibeSec itself

Please report issues that affect VibeSec as a product or as a package. Examples:

- raw secret leakage in findings, reporters, logs, or error messages;
- absolute host-path leakage in default outputs;
- unexpected execution of scanned target code, hooks, or package scripts;
- unexpected network access during a local scan;
- install-time or lifecycle script abuse in the published package;
- unsafe handling of malformed inputs that leads to denial of service beyond
  documented resource budgets, or to incorrect security claims that hide
  high-impact conditions.

Please **do not** disclose exploitable VibeSec vulnerabilities publicly before
coordinated remediation when the issue could harm users who install or run
the tool.

### B) Findings VibeSec reports in scanned projects

Findings produced by `vibesec scan` against a third-party or your own project
are **not** vulnerabilities in VibeSec. They are repository evidence about the
scanned target. Do not open security advisories against VibeSec solely because
a scan reported `VS-*` findings in another codebase.

If you believe a detector is wrong in a way that creates a security problem
_for VibeSec users_ (for example, a false negative that systematically misses
a supported pattern and leads operators to a false sense of safety), that may
qualify as a VibeSec product issue — describe it as a tool defect, not as a
finding against the scanned app.

## Reporting channel

Report vulnerabilities **in VibeSec itself** using GitHub private vulnerability
reporting on the canonical repository:

https://github.com/gustavomarques00/vibesec/security/advisories/new

Use that form so maintainers can coordinate disclosure privately. Do not open
a public issue for exploitable VibeSec defects until a coordinated fix or
advisory is available.

## Useful report contents

- VibeSec version (`package.json` / installed package version);
- Node.js version and OS;
- minimal reproduction steps (prefer synthetic fixtures, never live secrets);
- expected vs actual behavior;
- whether scanned material was executed or contacted remotely;
- impact assessment and suggested fix if known.

Do **not** include real production secrets, customer data, or live credentials
in reports or attachments. Use synthetic canaries.

## Scope limitations

VibeSec is a local, offline, heuristic static analyzer. It does not claim:

- complete vulnerability detection;
- equivalence to a penetration test;
- zero false positives or false negatives;
- validation of credentials against remote services;
- confirmation of production exploitability.

Resource budgets, Git provenance degradation, and heuristic detectors are
documented in `README.md`, `docs/threat-model.md`, and `docs/rules.md`.
