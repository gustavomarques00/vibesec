import { describe, expect, it } from 'vitest'

import { KernelValidationError, ScanKernelContext } from '../src/index.js'
import { createTestDraft, createTestRule } from './helpers/finding.js'

describe('runtime kernel validation', () => {
  it.each([
    ['invalid enum', { status: 'owned' }],
    ['extra discriminator', { discriminator: 'secret-derived-value' }],
    ['duplicated rule metadata', { ruleVersion: 'attacker-controlled' }],
  ])('rejects %s in finding drafts', (_name, extension) => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const draft = {
      ...createTestDraft(scan.protectSecret('VIBESEC_RUNTIME_VALIDATION')),
      ...extension,
    }

    expect(() =>
      scan.evaluateRule(unsafeRule(draft), scan.createRuleContext([])),
    ).toThrow(KernelValidationError)
  })

  it('rejects invalid and extra rule metadata', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const draft = createTestDraft(scan.protectSecret('VIBESEC_METADATA_VALIDATION'))

    expect(() =>
      scan.evaluateRule(
        unsafeRule(draft, { defaultSeverity: 'extreme' }),
        scan.createRuleContext([]),
      ),
    ).toThrow(KernelValidationError)
    expect(() =>
      scan.evaluateRule(
        unsafeRule(draft, { internalSecret: 'must-not-exist' }),
        scan.createRuleContext([]),
      ),
    ).toThrow(KernelValidationError)
  })

  it('binds title, version, category, references, and default severity to metadata', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret('VIBESEC_METADATA_BINDING')
    const { severity, ...draftWithoutSeverity } = createTestDraft(protectedValue)
    expect(severity).toBe('high')
    const [finding] = scan.evaluateRule(
      createTestRule(draftWithoutSeverity, {
        id: 'VS-META-001',
        version: '2.4.0',
        title: 'Metadata title',
        category: 'metadata-category',
        defaultSeverity: 'medium',
        references: ['https://example.invalid/metadata'],
      }),
      scan.createRuleContext([]),
    )

    expect(finding).toMatchObject({
      ruleId: 'VS-META-001',
      ruleVersion: '2.4.0',
      title: 'Metadata title',
      category: 'metadata-category',
      severity: 'medium',
      references: ['https://example.invalid/metadata'],
    })
  })

  it('rejects getters, hostile proxies, and unexpected prototypes', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    let getterExecutions = 0
    const getterDraft = Object.defineProperties(
      {},
      {
        description: {
          get() {
            getterExecutions += 1
            return 'unsafe'
          },
          enumerable: true,
        },
      },
    )
    const proxy = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error('VIBESEC_PROXY_CANARY')
        },
      },
    )
    const unexpectedPrototype = {}
    Reflect.setPrototypeOf(unexpectedPrototype, { inherited: true })

    expect(() =>
      scan.evaluateRule(unsafeRule(getterDraft), scan.createRuleContext([])),
    ).toThrow(KernelValidationError)
    expect(getterExecutions).toBe(0)
    expect(() => scan.evaluateRule(proxy, scan.createRuleContext([]))).toThrow(
      KernelValidationError,
    )
    expect(() =>
      scan.evaluateRule(unsafeRule(unexpectedPrototype), scan.createRuleContext([])),
    ).toThrow(KernelValidationError)
  })

  it('rejects transparent proxies without executing their traps', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const target = createTestDraft(scan.protectSecret('VIBESEC_PROXY_TARGET'))
    let traps = 0
    const proxy = new Proxy(target, {
      getPrototypeOf() {
        traps += 1
        return Reflect.getPrototypeOf(target)
      },
      ownKeys() {
        traps += 1
        return Reflect.ownKeys(target)
      },
    })

    expect(() =>
      scan.evaluateRule(unsafeRule(proxy), scan.createRuleContext([])),
    ).toThrow(KernelValidationError)
    expect(traps).toBe(0)
  })

  it('rejects an own __proto__ property', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const draft = createTestDraft(scan.protectSecret('VIBESEC_PROTO_VALIDATION'))
    Object.defineProperty(draft, '__proto__', {
      value: { polluted: true },
      enumerable: true,
    })

    expect(() =>
      scan.evaluateRule(unsafeRule(draft), scan.createRuleContext([])),
    ).toThrow(KernelValidationError)
  })

  it('copies and freezes validated fact arrays', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const facts = [
      {
        kind: 'environment.binding',
        location: { file: 'src/env.ts', startLine: 1 },
        source: {
          extractor: 'test',
          context: 'client',
          syntax: 'typescript',
        },
        confidence: 'high',
        name: 'VITE_VALUE',
        exposure: 'client',
        valueKind: 'reference',
      },
    ]
    const context = scan.createRuleContext(facts)
    facts.length = 0

    expect(context.facts).toHaveLength(1)
    expect(Object.isFrozen(context.facts)).toBe(true)
    expect(Object.isFrozen(context.facts[0])).toBe(true)
  })

  it('commits rule findings atomically', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const valid = createTestDraft(scan.protectSecret('VIBESEC_ATOMIC_RULE'))
    const invalid = { ...valid, status: 'invalid-status' }
    const rule = {
      metadata: {
        id: 'VS-ATOMIC-001',
        version: '1.0.0',
        title: 'Atomic evaluation',
        category: 'kernel',
        defaultSeverity: 'high',
        supportedFacts: [],
        references: [],
      },
      evaluate() {
        return [valid, invalid]
      },
    }

    expect(() => scan.evaluateRule(rule, scan.createRuleContext([]))).toThrow(
      KernelValidationError,
    )
    expect(scan.finalizeScan()).toEqual([])
  })
})

function unsafeRule(
  draft: unknown,
  metadataExtension: Readonly<Record<string, unknown>> = {},
): unknown {
  return {
    metadata: {
      id: 'VS-RUNTIME-001',
      version: '1.0.0',
      title: 'Runtime validation test',
      category: 'kernel',
      defaultSeverity: 'high',
      supportedFacts: [],
      references: [],
      ...metadataExtension,
    },
    evaluate() {
      return [draft]
    },
  }
}
