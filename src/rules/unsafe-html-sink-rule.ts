import type { FindingDraft, Rule, RuleMetadata } from '../core/rules/rule.js'
import type { RuleContext } from '../core/rules/rule-context.js'

const metadata: RuleMetadata = Object.freeze({
  id: 'VS-DANG-002',
  version: '1.0.0',
  title: 'Unsafe HTML sink without recognized sanitization',
  category: 'dangerous',
  defaultSeverity: 'medium',
  supportedFacts: Object.freeze(['dangerous.sink'] as const),
  references: Object.freeze(['https://cwe.mitre.org/data/definitions/79.html']),
})

export const unsafeHtmlSinkRule: Rule = Object.freeze({
  metadata,
  evaluate(context: RuleContext): readonly FindingDraft[] {
    const drafts = context
      .factsOfKind('dangerous.sink')
      .filter(
        (fact) =>
          (fact.sink === 'dangerously_set_inner_html' ||
            fact.sink === 'inner_html' ||
            fact.sink === 'document_write') &&
          fact.input !== 'constant' &&
          fact.sanitizer === undefined,
      )
      .map((fact): FindingDraft =>
        Object.freeze({
          description:
            'An HTML injection sink appears to receive non-literal input without a recognized sanitizer nearby.',
          confidence: fact.confidence,
          status: 'suspicious',
          primaryLocation: fact.location,
          relatedLocations: Object.freeze([]),
          evidence: Object.freeze([
            Object.freeze({
              kind: 'code',
              summary:
                'dangerouslySetInnerHTML, innerHTML, or document.write was observed with dynamic input heuristics.',
              locations: Object.freeze([fact.location]),
            }),
          ]),
          impact:
            'If untrusted HTML reaches this sink, it may enable script execution in the browser context.',
          remediation:
            'Avoid raw HTML sinks or sanitize with a maintained library and a strict allowlist.',
          limitations: Object.freeze([
            'This finding never claims confirmed XSS.',
            'Recognized sanitizers nearby suppress the finding; unknown sanitizers may still be safe.',
          ]),
          tags: Object.freeze(['dangerous', 'html', fact.sink]),
        }),
      )
    return Object.freeze(drafts)
  },
})
