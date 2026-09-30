import type { ExternalRule } from './types.js'
import { boundSnippet } from './helpers.js'

export const vsExt010: ExternalRule = Object.freeze({
  metadata: Object.freeze({
    id: 'VS-EXT-010',
    version: '1.0.0',
    title: 'Public source map reference advertised on first-party asset',
    category: 'assets',
    defaultSeverity: 'medium',
    evidenceKind: 'asset',
    description:
      'Emits when a fetched same-origin asset advertises an external sourceMappingURL.',
  }),
  evaluate(graph) {
    const drafts = []
    for (const asset of graph.assets) {
      if (!asset.fetched) continue
      if (!asset.sameOrigin) continue
      if (asset.sourceMapReferenced !== true) continue
      if (asset.inlineSourceMap === true) continue
      if (asset.sourceMapReference === undefined) continue

      drafts.push(
        Object.freeze({
          ruleId: 'VS-EXT-010' as const,
          primaryUrl: asset.requestUrl,
          discriminator: asset.sourceMapReference,
          description:
            'A fetched same-origin asset advertises a public sourceMappingURL reference.',
          confidence: 'high' as const,
          status: 'confirmed' as const,
          evidence: Object.freeze([
            Object.freeze({
              kind: 'asset' as const,
              summary: 'sourceMappingURL reference observed on asset.',
              location: Object.freeze({
                kind: 'url' as const,
                url: asset.requestUrl,
              }),
              redactedSnippet: boundSnippet(asset.sourceMapReference),
            }),
          ]),
          impact:
            'A source map reference is publicly advertised; map contents were not fetched by this scan.',
          remediation:
            'Avoid publishing sourceMappingURL references on production first-party assets.',
          limitations: Object.freeze([
            'This finding does not confirm that the source map file is accessible.',
            'Inline data: source maps are out of scope for this rule.',
          ]),
          tags: Object.freeze(['sourcemap', 'asset']),
        }),
      )
    }
    return Object.freeze(drafts)
  },
})
