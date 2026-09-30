import type { Fact, FactKind } from '../models/fact.js'
import type { ValidatedFact } from '../validation/fact.js'

export interface RuleContext {
  readonly facts: readonly Fact[]
  factsOfKind<Kind extends FactKind>(
    kind: Kind,
  ): readonly Extract<Fact, { kind: Kind }>[]
}

export function createRuleContext(facts: readonly ValidatedFact[]): RuleContext {
  const immutableFacts: readonly Fact[] = Object.freeze([...facts])

  return Object.freeze({
    facts: immutableFacts,
    factsOfKind<Kind extends FactKind>(
      kind: Kind,
    ): readonly Extract<Fact, { kind: Kind }>[] {
      return immutableFacts.filter(
        (fact): fact is Extract<Fact, { kind: Kind }> => fact.kind === kind,
      )
    },
  })
}
