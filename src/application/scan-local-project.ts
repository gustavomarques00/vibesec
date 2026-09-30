import path from 'node:path'

import type { ReportFormat, ScanReportSummary } from '../core/models/scan-report.js'
import { ScanKernelContext } from '../core/scan/scan-kernel-context.js'
import {
  readEnum,
  readExactObject,
  readPositiveInteger,
} from '../core/validation/primitives.js'
import { extractLocalScanFacts } from '../extractors/local-private-key-scan.js'
import { clientEnvExposureRule } from '../rules/client-env-exposure-rule.js'
import { clientQueryMissingAuthzRule } from '../rules/client-query-missing-authz-rule.js'
import { dynamicEvalRule } from '../rules/dynamic-eval-rule.js'
import { dynamicRawSqlRule } from '../rules/dynamic-raw-sql-rule.js'
import { dynamicShellExecRule } from '../rules/dynamic-shell-exec-rule.js'
import { frontendOnlyAuthRule } from '../rules/frontend-only-auth-rule.js'
import { genericCredentialCandidateRule } from '../rules/generic-credential-candidate-rule.js'
import { highSpecificityCredentialRule } from '../rules/high-specificity-credential-rule.js'
import { privateKeyMaterialRule } from '../rules/private-key-material-rule.js'
import { storageRoleAuthRule } from '../rules/storage-role-auth-rule.js'
import { supabaseBroadPolicyRule } from '../rules/supabase-broad-policy-rule.js'
import { supabaseMissingRlsRule } from '../rules/supabase-missing-rls-rule.js'
import { supabaseRlsDisabledRule } from '../rules/supabase-rls-disabled-rule.js'
import { supabaseServiceRoleClientRule } from '../rules/supabase-service-role-client-rule.js'
import { supabaseServiceRoleServerRule } from '../rules/supabase-service-role-server-rule.js'
import { trackedEnvSecretRule } from '../rules/tracked-env-secret-rule.js'
import { unsafeHtmlSinkRule } from '../rules/unsafe-html-sink-rule.js'
import type { PathFlavor } from '../utils/paths.js'

export type { ReportFormat } from '../core/models/scan-report.js'

export type LocalScanOptions = Readonly<{
  pathFlavor: PathFlavor
  format: ReportFormat
  maxFileBytes?: number
}>

export type LocalScanResult = Readonly<{
  output: string
  findingCount: number
  filesScanned: number
  filesSkipped: number
}>

export class LocalScanError extends Error {
  constructor() {
    super('The local scan could not be completed.')
    this.name = 'LocalScanError'
  }
}

const PHASE5_RULES = Object.freeze([
  privateKeyMaterialRule,
  highSpecificityCredentialRule,
  genericCredentialCandidateRule,
  clientEnvExposureRule,
  trackedEnvSecretRule,
  supabaseServiceRoleClientRule,
  supabaseServiceRoleServerRule,
  supabaseRlsDisabledRule,
  supabaseMissingRlsRule,
  supabaseBroadPolicyRule,
  frontendOnlyAuthRule,
  storageRoleAuthRule,
  clientQueryMissingAuthzRule,
  dynamicEvalRule,
  unsafeHtmlSinkRule,
  dynamicShellExecRule,
  dynamicRawSqlRule,
])

export async function scanLocalProject(
  targetRoot: string,
  options: LocalScanOptions,
): Promise<LocalScanResult> {
  let validatedTarget: string
  let validatedOptions: LocalScanOptions
  try {
    if (typeof targetRoot !== 'string' || targetRoot.length === 0) {
      throw new LocalScanError()
    }
    validatedTarget = targetRoot
    const object = readExactObject(
      options,
      ['pathFlavor', 'format', 'maxFileBytes'],
      ['pathFlavor', 'format'],
    )
    const maxFileBytes =
      object['maxFileBytes'] === undefined
        ? undefined
        : readPositiveInteger(object['maxFileBytes'])
    validatedOptions = Object.freeze({
      pathFlavor: readEnum(object['pathFlavor'], ['windows', 'posix'] as const),
      format: readEnum(object['format'], ['terminal', 'json', 'markdown'] as const),
      ...(maxFileBytes === undefined ? {} : { maxFileBytes }),
    })
  } catch {
    throw new LocalScanError()
  }
  const scan = ScanKernelContext.create({
    pathFlavor: validatedOptions.pathFlavor,
  })
  try {
    const extraction = await extractLocalScanFacts(scan, validatedTarget, {
      pathFlavor: validatedOptions.pathFlavor,
      ...(validatedOptions.maxFileBytes === undefined
        ? {}
        : { maxFileBytes: validatedOptions.maxFileBytes }),
    })
    const ruleContext = scan.createRuleContext(extraction.facts)
    for (const rule of PHASE5_RULES) {
      scan.evaluateRule(rule, ruleContext)
    }
    const findings = scan.finalizeScan()
    const target =
      path.basename(path.resolve(validatedTarget)).normalize('NFC') || 'target'
    const summary: ScanReportSummary = Object.freeze({
      target,
      filesScanned: extraction.filesScanned,
      filesSkipped: extraction.filesSkipped,
    })
    const safeOutput = scan.renderReport(summary, validatedOptions.format)
    const output = scan.readOutput(safeOutput)
    return Object.freeze({
      output,
      findingCount: findings.length,
      filesScanned: extraction.filesScanned,
      filesSkipped: extraction.filesSkipped,
    })
  } catch {
    throw new LocalScanError()
  } finally {
    try {
      if (scan.state === 'active') scan.finalizeScan()
    } catch {
      // Do not replace LocalScanError with a secondary finalize failure.
    }
    try {
      if (scan.state === 'finalized') scan.close()
    } catch {
      // Ignore close failures after a scan error.
    }
  }
}
