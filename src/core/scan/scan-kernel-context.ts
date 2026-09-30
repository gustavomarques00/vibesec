import { RedactionBoundary, type RedactionOptions } from '../../security/redaction.js'
import type {
  ProtectedSensitiveValue,
  SafeOutput,
  SanitizedText,
} from '../../security/tokens.js'
import { createJsonReportDocument } from '../../reporters/json-reporter.js'
import { renderMarkdownReport } from '../../reporters/markdown-reporter.js'
import { renderTerminalReport } from '../../reporters/terminal-reporter.js'
import { sortFindings } from '../../utils/deterministic-sort.js'
import { normalizeRelativePath, type PathFlavor } from '../../utils/paths.js'
import { finalizeFinding } from '../models/finalize-finding.js'
import type { Finding } from '../models/finding.js'
import type {
  ReportFormat,
  ScanReportDocument,
  ScanReportSummary,
} from '../models/scan-report.js'
import { createRuleContext, type RuleContext } from '../rules/rule-context.js'
import { validateFact } from '../validation/fact.js'
import { validateFindingDraft } from '../validation/finding-draft.js'
import {
  KernelValidationError,
  readArray,
  readEnum,
  readExactObject,
  readNonNegativeInteger,
  readString,
} from '../validation/primitives.js'
import { validateRuleMetadata } from '../validation/rule-metadata.js'

export type ScanKernelState = 'active' | 'finalized' | 'closed'

export type ScanKernelOptions = Readonly<{
  pathFlavor: PathFlavor
}>

export class ScanKernelLifecycleError extends Error {
  constructor() {
    super('The scan kernel context is not in the required lifecycle state.')
    this.name = 'ScanKernelLifecycleError'
  }
}

export class ScanKernelContext {
  readonly #pathFlavor: PathFlavor
  readonly #boundary: RedactionBoundary
  readonly #findings: Finding[] = []
  readonly #ruleContexts = new WeakSet<RuleContext>()
  #finalizedFindings: readonly Finding[] | undefined
  #state: ScanKernelState = 'active'

  private constructor(options: ScanKernelOptions) {
    this.#pathFlavor = options.pathFlavor
    this.#boundary = RedactionBoundary.create()
  }

  static create(options: ScanKernelOptions): ScanKernelContext {
    const validated = readExactObject(options, ['pathFlavor'], ['pathFlavor'])
    if (validated['pathFlavor'] !== 'windows' && validated['pathFlavor'] !== 'posix') {
      throw new KernelValidationError()
    }
    return new ScanKernelContext(Object.freeze({ pathFlavor: validated['pathFlavor'] }))
  }

  get state(): ScanKernelState {
    return this.#state
  }

  protectSecret(
    rawValue: string,
    options: RedactionOptions = {},
  ): ProtectedSensitiveValue {
    this.#requireActive()
    return this.#boundary.protect(rawValue, options)
  }

  sanitizeText(text: string): SanitizedText {
    this.#requireActive()
    return this.#boundary.sanitizeText(text)
  }

  createRuleContext(facts: readonly unknown[]): RuleContext {
    this.#requireActive()
    const validated = readArray(facts).map((fact) =>
      validateFact(fact, this.#boundary, this.#pathFlavor),
    )
    const context = createRuleContext(validated)
    this.#ruleContexts.add(context)
    return context
  }

  evaluateRule(rule: unknown, context: RuleContext): readonly Finding[] {
    this.#requireActive()
    if (!this.#ruleContexts.has(context)) throw new KernelValidationError()
    const object = readExactObject(
      rule,
      ['metadata', 'evaluate'],
      ['metadata', 'evaluate'],
    )
    if (typeof object['evaluate'] !== 'function') {
      throw new KernelValidationError()
    }
    const metadata = validateRuleMetadata(object['metadata'])

    let result: unknown
    try {
      result = Reflect.apply(object['evaluate'], undefined, [context])
    } catch {
      throw new Error('Rule evaluation failed.')
    }

    const findings = readArray(result).map((draft) => {
      const validatedDraft = validateFindingDraft(
        draft,
        this.#boundary,
        this.#pathFlavor,
      )
      const finding = finalizeFinding(
        metadata,
        validatedDraft,
        this.#boundary,
        this.#pathFlavor,
      )
      return finding
    })
    this.#findings.push(...findings)
    return Object.freeze(findings)
  }

  finalizeScan(): readonly Finding[] {
    this.#requireActive()
    const findings = sortFindings(this.#findings)
    this.#finalizedFindings = findings
    this.#state = 'finalized'
    return findings
  }

  serializeFindings(): SafeOutput {
    this.#requireFinalized()
    return this.#boundary.serializeCanonicalJson(this.#finalizedFindings, 2)
  }

  serializeReport(summary: ScanReportSummary): SafeOutput {
    return this.#boundary.serializeCanonicalJson(this.#createReport(summary), 2)
  }

  renderReport(summary: ScanReportSummary, format: ReportFormat): SafeOutput {
    const report = this.#createReport(summary)
    const validatedFormat = readEnum(format, ['terminal', 'json', 'markdown'] as const)
    if (validatedFormat === 'json') {
      return this.#boundary.serializeCanonicalJson(report, 2)
    }
    const rendered =
      validatedFormat === 'markdown'
        ? renderMarkdownReport(report, report.findings)
        : renderTerminalReport(report, report.findings)
    return this.#boundary.authorizeOutput(rendered)
  }

  #createReport(summary: ScanReportSummary): ScanReportDocument {
    this.#requireFinalized()
    const finalizedFindings = this.#finalizedFindings
    if (finalizedFindings === undefined) throw new ScanKernelLifecycleError()
    const record = readExactObject(
      summary,
      ['target', 'filesScanned', 'filesSkipped'],
      ['target', 'filesScanned', 'filesSkipped'],
    )
    const validatedSummary: ScanReportSummary = Object.freeze({
      target: normalizeRelativePath(readString(record['target']), this.#pathFlavor),
      filesScanned: readNonNegativeInteger(record['filesScanned']),
      filesSkipped: readNonNegativeInteger(record['filesSkipped']),
    })
    return createJsonReportDocument(validatedSummary, finalizedFindings)
  }

  formatError(error: unknown): SafeOutput {
    this.#requireOpen()
    return this.#boundary.formatError(error)
  }

  readOutput(output: SafeOutput): string {
    this.#requireOpen()
    return this.#boundary.readOutput(output)
  }

  close(): void {
    this.#requireFinalized()
    this.#boundary.destroy()
    this.#state = 'closed'
  }

  #requireActive(): void {
    if (this.#state !== 'active') throw new ScanKernelLifecycleError()
  }

  #requireFinalized(): void {
    if (this.#state !== 'finalized') throw new ScanKernelLifecycleError()
  }

  #requireOpen(): void {
    if (this.#state === 'closed') throw new ScanKernelLifecycleError()
  }
}
