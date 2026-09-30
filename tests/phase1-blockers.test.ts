import { describe, expect, it, vi } from 'vitest'

import { ScanKernelContext, UnsafeOutputError } from '../src/index.js'
import { createTestDraft, createTestRule } from './helpers/finding.js'

describe('Phase 1 blocker regressions', () => {
  it.each([
    'VIBESEC"ESCAPED',
    'VIBESEC\\ESCAPED',
    'VIBESEC\nESCAPED',
    'VIBESEC\rESCAPED',
    'VIBESEC\0ESCAPED',
    'VIBESEC\u2028ESCAPED',
    'VIBESEC\u0001ESCAPED',
    'VIBESÉC',
    'VIBESE\u0301C',
  ])('blocks raw secret strings before JSON serialization: %j', (secret) => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret(secret)
    const draft = {
      ...createTestDraft(protectedValue),
      description: `Leaked value: ${secret}`,
    }

    expect(() =>
      scan.evaluateRule(createTestRule(draft), scan.createRuleContext([])),
    ).toThrow(UnsafeOutputError)
  })

  it('rejects stateful toJSON before it can execute', () => {
    const secret = 'VIBESEC_STATEFUL_TO_JSON_SECRET'
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret(secret)
    let calls = 0
    const hostileDraft = {
      ...createTestDraft(protectedValue),
      toJSON() {
        calls += 1
        return calls === 1 ? { safe: true } : { leaked: secret }
      },
    }

    expect(() =>
      scan.evaluateRule(unsafeRule(hostileDraft), scan.createRuleContext([])),
    ).toThrow()
    expect(calls).toBe(0)
  })

  it('serializes the final canonical DTO exactly once', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret('VIBESEC_SINGLE_PASS_SECRET')
    scan.evaluateRule(
      createTestRule(createTestDraft(protectedValue)),
      scan.createRuleContext([]),
    )
    scan.finalizeScan()
    const stringify = vi.spyOn(JSON, 'stringify')

    try {
      scan.serializeFindings()
      expect(stringify).toHaveBeenCalledTimes(1)
    } finally {
      stringify.mockRestore()
    }
  })

  it('rejects inherited toJSON hooks without executing them', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    scan.evaluateRule(
      createTestRule(createTestDraft(scan.protectSecret('VIBESEC_INHERITED_TO_JSON'))),
      scan.createRuleContext([]),
    )
    scan.finalizeScan()
    let calls = 0
    Reflect.defineProperty(Object.prototype, 'toJSON', {
      configurable: true,
      value() {
        calls += 1
        return { leaked: 'VIBESEC_INHERITED_TO_JSON' }
      },
    })

    try {
      expect(() => scan.serializeFindings()).toThrow(UnsafeOutputError)
      expect(calls).toBe(0)
    } finally {
      Reflect.deleteProperty(Object.prototype, 'toJSON')
    }
  })

  it('rejects a fabricated fingerprint even when its format is valid', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret('VIBESEC_REAL_SECRET')
    const draft = createTestDraft(protectedValue)
    const forgedDraft = {
      ...draft,
      evidence: draft.evidence.map((evidence) => ({
        ...evidence,
        secretFingerprint: 'hmac-sha256:000000000000000000000000',
      })),
    }

    expect(() =>
      scan.evaluateRule(unsafeRule(forgedDraft), scan.createRuleContext([])),
    ).toThrow()
  })

  it('does not let scan-scoped fingerprints influence finding IDs', () => {
    const firstScan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const secondScan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const firstProtected = firstScan.protectSecret('VIBESEC_SAME_SECRET')
    const secondProtected = secondScan.protectSecret('VIBESEC_SAME_SECRET')
    const firstDraft = createTestDraft(firstProtected)
    const secondDraft = createTestDraft(secondProtected)

    const [first] = firstScan.evaluateRule(
      createTestRule(firstDraft),
      firstScan.createRuleContext([]),
    )
    const [second] = secondScan.evaluateRule(
      createTestRule(secondDraft),
      secondScan.createRuleContext([]),
    )
    if (first === undefined || second === undefined) throw new Error('Missing finding.')

    expect(first.id).toBe(second.id)
  })
})

function unsafeRule(draft: unknown): unknown {
  return {
    metadata: {
      id: 'VS-SEC-001',
      version: '1.0.0',
      title: 'Test rule',
      category: 'secrets',
      defaultSeverity: 'high',
      supportedFacts: [],
      references: [],
    },
    evaluate() {
      return [draft]
    },
  }
}
