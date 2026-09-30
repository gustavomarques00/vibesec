import { inspect } from 'node:util'

import { describe, expect, it } from 'vitest'

import {
  ScanKernelContext,
  ScanKernelLifecycleError,
  UnsafeOutputError,
} from '../src/index.js'
import { createTestDraft, createTestRule } from './helpers/finding.js'

const CANARY = 'VIBESEC_CANARY_SECRET_DO_NOT_LEAK_7C91F2'

describe('redaction invariants', () => {
  it('never serializes or inspects raw material from protected tokens', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret(CANARY)

    expect(JSON.stringify(protectedValue)).not.toContain(CANARY)
    expect(inspect(protectedValue)).not.toContain(CANARY)
  })

  it('blocks raw secret material from finding drafts', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret(CANARY, {
      visiblePrefix: 10,
    })
    const safeDraft = createTestDraft(protectedValue)
    const unsafeDraft = {
      ...safeDraft,
      description: `Accidental leak: ${CANARY}`,
    }

    expect(() =>
      scan.evaluateRule(createTestRule(unsafeDraft), scan.createRuleContext([])),
    ).toThrow(UnsafeOutputError)
  })

  it('keeps the canary out of findings, errors, inspect, and final JSON', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret(CANARY, {
      visiblePrefix: 10,
    })
    const [finding] = scan.evaluateRule(
      createTestRule(createTestDraft(protectedValue)),
      scan.createRuleContext([]),
    )
    if (finding === undefined) throw new Error('Expected a finding.')
    scan.finalizeScan()
    const jsonOutput = scan.readOutput(scan.serializeFindings())
    const formattedError = scan.readOutput(
      scan.formatError(new Error(`Failed for ${CANARY}`)),
    )

    for (const output of [
      JSON.stringify(finding),
      jsonOutput,
      formattedError,
      inspect(finding),
      JSON.stringify(finding.evidence),
    ]) {
      expect(output).not.toContain(CANARY)
    }
  })

  it('accepts only fingerprint and sanitized-text tokens from the current scan', () => {
    const firstScan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const secondScan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const foreign = firstScan.protectSecret(CANARY)
    const local = secondScan.protectSecret('VIBESEC_LOCAL_SECRET')
    const localDraft = createTestDraft(local)
    const foreignTextDraft = {
      ...localDraft,
      evidence: localDraft.evidence.map((evidence) => ({
        ...evidence,
        redactedSnippet: foreign.redacted,
      })),
    }
    const foreignFingerprintDraft = {
      ...localDraft,
      evidence: localDraft.evidence.map((evidence) => ({
        ...evidence,
        secretFingerprint: foreign.fingerprint,
      })),
    }

    expect(() =>
      secondScan.evaluateRule(
        createTestRule(foreignTextDraft),
        secondScan.createRuleContext([]),
      ),
    ).toThrow(UnsafeOutputError)
    expect(() =>
      secondScan.evaluateRule(
        createTestRule(foreignFingerprintDraft),
        secondScan.createRuleContext([]),
      ),
    ).toThrow(UnsafeOutputError)
  })

  it('correlates equal secrets only inside the same scan', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const first = scan.protectSecret(CANARY)
    const repeated = scan.protectSecret(CANARY)
    const different = scan.protectSecret('VIBESEC_DIFFERENT_CANARY')
    const [firstFinding] = scan.evaluateRule(
      createTestRule(createTestDraft(first), { id: 'VS-CORRELATE-001' }),
      scan.createRuleContext([]),
    )
    const [repeatedFinding] = scan.evaluateRule(
      createTestRule(createTestDraft(repeated), { id: 'VS-CORRELATE-002' }),
      scan.createRuleContext([]),
    )
    const [differentFinding] = scan.evaluateRule(
      createTestRule(createTestDraft(different), { id: 'VS-CORRELATE-003' }),
      scan.createRuleContext([]),
    )

    const firstFingerprint = firstFinding?.evidence[0]?.secretFingerprint
    const repeatedFingerprint = repeatedFinding?.evidence[0]?.secretFingerprint
    const differentFingerprint = differentFinding?.evidence[0]?.secretFingerprint
    expect(firstFingerprint).toBe(repeatedFingerprint)
    expect(firstFingerprint).not.toBe(differentFingerprint)
    expect(firstFingerprint).toMatch(/^hmac-sha256:[a-f0-9]{24}$/)

    const otherScan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const [otherFinding] = otherScan.evaluateRule(
      createTestRule(createTestDraft(otherScan.protectSecret(CANARY)), {
        id: 'VS-CORRELATE-004',
      }),
      otherScan.createRuleContext([]),
    )
    expect(otherFinding?.evidence[0]?.secretFingerprint).not.toBe(firstFingerprint)
  })

  it('formats secret-bearing errors without leaking their message', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    scan.protectSecret(CANARY)

    const formatted = scan.readOutput(
      scan.formatError(new Error(`Parser rejected ${CANARY}`)),
    )

    expect(formatted).toBe('Error: Parser rejected [REDACTED]')
    expect(formatted).not.toContain(CANARY)
  })

  it('does not execute hostile error getters or toString methods', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    scan.protectSecret(CANARY)
    let executions = 0
    const hostile = Object.defineProperties(
      {},
      {
        name: {
          get() {
            executions += 1
            throw new Error(CANARY)
          },
        },
        message: {
          get() {
            executions += 1
            throw new Error(CANARY)
          },
        },
        toString: {
          value() {
            executions += 1
            throw new Error(CANARY)
          },
        },
      },
    )

    const formatted = scan.readOutput(scan.formatError(hostile))
    let proxyExecutions = 0
    const hostileProxy = new Proxy(
      {},
      {
        ownKeys() {
          proxyExecutions += 1
          throw new Error(CANARY)
        },
      },
    )
    const proxyFormatted = scan.readOutput(scan.formatError(hostileProxy))

    expect(executions).toBe(0)
    expect(proxyExecutions).toBe(0)
    expect(formatted).toBe('Error: An unknown error occurred.')
    expect(formatted).not.toContain(CANARY)
    expect(proxyFormatted).toBe('Error: An unknown error occurred.')
    expect(proxyFormatted).not.toContain(CANARY)
  })

  it('enforces active, finalized, and closed scan lifecycle states', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret(CANARY)
    scan.evaluateRule(
      createTestRule(createTestDraft(protectedValue)),
      scan.createRuleContext([]),
    )
    scan.finalizeScan()

    expect(() => scan.finalizeScan()).toThrow(ScanKernelLifecycleError)
    const output = scan.serializeFindings()
    expect(scan.readOutput(output)).not.toContain(CANARY)
    const otherScan = ScanKernelContext.create({ pathFlavor: 'posix' })
    expect(() => otherScan.readOutput(output)).toThrow(UnsafeOutputError)
    scan.close()

    expect(() => scan.protectSecret('another')).toThrow(ScanKernelLifecycleError)
    expect(() => scan.readOutput(output)).toThrow(ScanKernelLifecycleError)
  })

  it('rejects fabricated opaque token objects', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret(CANARY)
    const draft = createTestDraft(protectedValue)
    const forged = {
      ...draft,
      evidence: draft.evidence.map((evidence) => ({
        ...evidence,
        secretFingerprint: Object.freeze({}),
      })),
    }

    expect(() =>
      scan.evaluateRule(unsafeRule(forged), scan.createRuleContext([])),
    ).toThrow(UnsafeOutputError)
  })
})

function unsafeRule(draft: unknown): unknown {
  return {
    metadata: {
      id: 'VS-UNSAFE-001',
      version: '1.0.0',
      title: 'Unsafe test rule',
      category: 'kernel',
      defaultSeverity: 'high',
      supportedFacts: [],
      references: [],
    },
    evaluate() {
      return [draft]
    },
  }
}
