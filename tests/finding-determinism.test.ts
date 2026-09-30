import { describe, expect, it } from 'vitest'

import {
  DuplicateFindingIdError,
  ScanKernelContext,
  type FindingDraft,
} from '../src/index.js'
import { sortFindings } from '../src/utils/deterministic-sort.js'
import { createTestDraft, createTestRule } from './helpers/finding.js'

describe('finding determinism', () => {
  it('produces equal IDs for equivalent inputs across scans', () => {
    const firstScan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const secondScan = ScanKernelContext.create({ pathFlavor: 'posix' })

    const first = evaluateOne(
      firstScan,
      createTestDraft(firstScan.protectSecret('VIBESEC_TEST_SECRET_A_123456')),
    )
    const second = evaluateOne(
      secondScan,
      createTestDraft(secondScan.protectSecret('VIBESEC_TEST_SECRET_A_123456')),
    )

    expect(first.id).toBe(second.id)
  })

  it('does not include secret values or fingerprints in finding IDs', () => {
    const firstScan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const secondScan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const first = evaluateOne(
      firstScan,
      createTestDraft(firstScan.protectSecret('VIBESEC_TEST_SECRET_FIRST_123456')),
    )
    const second = evaluateOne(
      secondScan,
      createTestDraft(secondScan.protectSecret('VIBESEC_TEST_SECRET_SECOND_654321')),
    )

    expect(first.id).toBe(second.id)
  })

  it('sorts findings deterministically regardless of input order', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret('VIBESEC_TEST_SECRET_SORT_123456')
    const first = evaluateOne(scan, createTestDraft(protectedValue))
    const second = evaluateOne(scan, createTestDraft(protectedValue), 'VS-ENV-001')

    expect(sortFindings([first, second])).toEqual(sortFindings([second, first]))
  })

  it('canonicalizes every permutation of evidence, including Unicode', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret('VIBESEC_EVIDENCE_ORDER')
    const base = createTestDraft(protectedValue)
    const extraEvidence = {
      kind: 'code' as const,
      summary: 'cafe\u0301 evidence',
      redactedSnippet: scan.sanitizeText('safe snippet'),
      locations: [{ file: 'src/é.ts', startLine: 2 }],
    }
    const firstDraft = {
      ...base,
      evidence: [extraEvidence, ...base.evidence],
    }
    const secondDraft = {
      ...base,
      evidence: [...base.evidence, extraEvidence],
    }

    const first = evaluateOne(scan, firstDraft, 'VS-EVIDENCE-001')
    const second = evaluateOne(scan, secondDraft, 'VS-EVIDENCE-002')

    expect(first.evidence).toEqual(second.evidence)
  })

  it('preserves requires_authorization instead of inferring confirmed', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret('VIBESEC_TEST_SECRET_STATUS_123456')
    const finding = evaluateOne(
      scan,
      createTestDraft(protectedValue, {
        status: 'requires_authorization',
        confidence: 'high',
        severity: 'low',
      }),
    )

    expect(finding.status).toBe('requires_authorization')
    expect(finding.confidence).toBe('high')
    expect(finding.severity).toBe('low')
  })

  it('rejects duplicate rule/location IDs, including global duplicates', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const protectedValue = scan.protectSecret('VIBESEC_TEST_DUPLICATE_123456')
    const draft = createTestDraft(protectedValue)
    evaluateOne(scan, draft)
    evaluateOne(scan, draft)

    expect(() => scan.finalizeScan()).toThrow(DuplicateFindingIdError)

    const globalScan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const { primaryLocation, ...globalDraft } = createTestDraft(
      globalScan.protectSecret('VIBESEC_GLOBAL_DUPLICATE'),
    )
    expect(primaryLocation).toBeDefined()
    evaluateOne(globalScan, globalDraft)
    evaluateOne(globalScan, globalDraft)
    expect(() => globalScan.finalizeScan()).toThrow(DuplicateFindingIdError)
  })
})

function evaluateOne(
  scan: ScanKernelContext,
  draft: FindingDraft,
  ruleId = 'VS-SEC-001',
) {
  const findings = scan.evaluateRule(
    createTestRule(draft, { id: ruleId }),
    scan.createRuleContext([]),
  )
  const finding = findings[0]
  if (finding === undefined) throw new Error('Test rule did not emit a finding.')
  return finding
}
