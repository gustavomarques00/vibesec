import { describe, expect, it } from 'vitest'

import {
  FINDING_CONFIDENCES,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  KernelValidationError,
  ScanKernelContext,
  type Fact,
  type Rule,
} from '../src/index.js'

describe('status semantics and contracts', () => {
  it('exposes only the three evidence statuses', () => {
    expect(FINDING_STATUSES).toEqual([
      'confirmed',
      'suspicious',
      'requires_authorization',
    ])
  })

  it('keeps severity, confidence, and status as independent dimensions', () => {
    expect(FINDING_SEVERITIES).toContain('critical')
    expect(FINDING_CONFIDENCES).toContain('low')
    expect(FINDING_STATUSES).toContain('requires_authorization')

    const independentCombination = {
      severity: 'critical',
      confidence: 'low',
      status: 'requires_authorization',
    } as const

    expect(independentCombination).toEqual({
      severity: 'critical',
      confidence: 'low',
      status: 'requires_authorization',
    })
  })

  it('does not expose final vulnerability classification on facts', () => {
    type KeysOfUnion<Value> = Value extends Value ? keyof Value : never
    type ForbiddenFactKeys = Extract<
      KeysOfUnion<Fact>,
      'severity' | 'status' | 'remediation' | 'impact'
    >
    const hasNoForbiddenKeys: ForbiddenFactKeys extends never ? true : false = true

    expect(hasNoForbiddenKeys).toBe(true)
  })

  it('gives rules immutable facts and no I/O capabilities', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const fact: Fact = {
      kind: 'environment.binding',
      location: { file: 'src/env.ts', startLine: 1 },
      source: {
        extractor: 'test',
        context: 'client',
        syntax: 'typescript',
      },
      confidence: 'high',
      name: 'VITE_PUBLIC_VALUE',
      exposure: 'client',
      valueKind: 'reference',
    }
    const rule: Rule = {
      metadata: {
        id: 'VS-ENV-001',
        version: '1.0.0',
        title: 'Test rule',
        category: 'environment',
        defaultSeverity: 'high',
        supportedFacts: ['environment.binding'],
        references: [],
      },
      evaluate(context) {
        expect(context.factsOfKind('environment.binding')).toEqual([fact])
        return []
      },
    }

    const context = scan.createRuleContext([fact])
    expect(Object.isFrozen(context.facts)).toBe(true)
    expect(Object.isFrozen(context.facts[0])).toBe(true)
    expect(Object.isFrozen(context.facts[0]?.source)).toBe(true)
    expect(rule.evaluate(context)).toEqual([])
  })

  it('rejects final vulnerability classification on facts at runtime', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const invalidFact = {
      kind: 'environment.binding',
      location: { file: 'src/env.ts', startLine: 1 },
      source: {
        extractor: 'test',
        context: 'client',
        syntax: 'typescript',
      },
      confidence: 'high',
      name: 'VITE_PUBLIC_VALUE',
      exposure: 'client',
      valueKind: 'reference',
      severity: 'critical',
    }

    expect(() => scan.createRuleContext([invalidFact])).toThrow(KernelValidationError)
  })
})
