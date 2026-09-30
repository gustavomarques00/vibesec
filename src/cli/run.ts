import {
  scanLocalProject,
  type ReportFormat,
} from '../application/scan-local-project.js'
import type { PathFlavor } from '../utils/paths.js'

const USAGE =
  'Usage: vibesec scan <path> [--format terminal|json|markdown]\n' +
  '       vibesec external <target> [--format terminal|json|markdown]\n'

export type CliIo = Readonly<{
  stdout: (text: string) => void
  stderr: (text: string) => void
}>

export async function runCli(
  arguments_: readonly string[],
  io: CliIo,
  platform: NodeJS.Platform,
): Promise<number> {
  const command = arguments_[0]
  if (command === 'scan') {
    return runScanCommand(arguments_, io, platform)
  }
  if (command === 'external') {
    return runExternalCommand(arguments_, io)
  }
  io.stderr(USAGE)
  return 2
}

async function runScanCommand(
  arguments_: readonly string[],
  io: CliIo,
  platform: NodeJS.Platform,
): Promise<number> {
  const parsed = parseScanArguments(arguments_)
  if (parsed === undefined) {
    io.stderr(USAGE)
    return 2
  }
  try {
    const result = await scanLocalProject(parsed.target, {
      pathFlavor: platformToPathFlavor(platform),
      format: parsed.format,
    })
    io.stdout(result.output)
    return result.findingCount === 0 ? 0 : 1
  } catch {
    io.stderr('VibeSec: scan failed.\n')
    return 2
  }
}

async function runExternalCommand(
  arguments_: readonly string[],
  io: CliIo,
): Promise<number> {
  const parsed = parseExternalArguments(arguments_)
  if (parsed === undefined) {
    io.stderr(USAGE)
    return 2
  }
  try {
    // Lazy-load External composition + production network only for this command.
    const [{ runExternalScan }, { createProductionOutboundHttpCapability }] =
      await Promise.all([
        import('../external/application/run-external-scan.js'),
        import('../external/infra/production.js'),
      ])
    const result = await runExternalScan(parsed.target, {
      format: parsed.format,
      transport: createProductionOutboundHttpCapability(),
    })
    io.stdout(result.output)
    return result.findingCount === 0 ? 0 : 1
  } catch (error) {
    const message =
      error instanceof Error && error.name === 'ExternalScanError'
        ? error.message
        : 'The External scan could not be completed.'
    io.stderr(`VibeSec: ${message}\n`)
    return 2
  }
}

function parseScanArguments(
  arguments_: readonly string[],
): Readonly<{ target: string; format: ReportFormat }> | undefined {
  if (arguments_[0] !== 'scan' || typeof arguments_[1] !== 'string') {
    return undefined
  }
  if (arguments_.length === 2) {
    return Object.freeze({ target: arguments_[1], format: 'terminal' })
  }
  if (
    arguments_.length !== 4 ||
    arguments_[2] !== '--format' ||
    !isReportFormat(arguments_[3])
  ) {
    return undefined
  }
  return Object.freeze({ target: arguments_[1], format: arguments_[3] })
}

function parseExternalArguments(arguments_: readonly string[]):
  | Readonly<{
      target: string
      format: 'terminal' | 'json' | 'markdown'
    }>
  | undefined {
  if (arguments_[0] !== 'external' || typeof arguments_[1] !== 'string') {
    return undefined
  }
  if (arguments_[1].trim().length === 0) {
    return undefined
  }
  if (arguments_.length === 2) {
    return Object.freeze({ target: arguments_[1], format: 'terminal' })
  }
  if (
    arguments_.length !== 4 ||
    arguments_[2] !== '--format' ||
    !isReportFormat(arguments_[3])
  ) {
    return undefined
  }
  return Object.freeze({ target: arguments_[1], format: arguments_[3] })
}

function isReportFormat(value: unknown): value is ReportFormat {
  return value === 'terminal' || value === 'json' || value === 'markdown'
}

function platformToPathFlavor(platform: NodeJS.Platform): PathFlavor {
  return platform === 'win32' ? 'windows' : 'posix'
}
