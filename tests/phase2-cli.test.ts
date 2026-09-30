import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { runCli } from '../src/cli/run.js'

const temporaryDirectories: string[] = []

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  )
})

describe('Phase 2 CLI', () => {
  it('supports vibesec scan <path> with explicit JSON format', async () => {
    const root = await temporaryDirectory()
    await writeFile(path.join(root, 'safe.txt'), 'no private key here')
    const stdout: string[] = []
    const stderr: string[] = []

    const exitCode = await runCli(
      ['scan', root, '--format', 'json'],
      {
        stdout: (text) => stdout.push(text),
        stderr: (text) => stderr.push(text),
      },
      process.platform,
    )

    expect(exitCode).toBe(0)
    expect(stderr).toEqual([])
    expect(JSON.parse(stdout.join(''))).toMatchObject({
      schemaVersion: '1',
      filesScanned: 1,
      findings: [],
    })
  })

  it('returns a finding exit code without leaking the detected value', async () => {
    const root = await temporaryDirectory()
    const privateKey = generateKeyPairSync('ed25519').privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    })
    const canary = privateKey.split('\n')[1]
    if (canary === undefined) throw new Error('Expected synthetic key material.')
    await writeFile(path.join(root, 'key.pem'), privateKey)
    const stdout: string[] = []
    const stderr: string[] = []

    const exitCode = await runCli(
      ['scan', root],
      {
        stdout: (text) => stdout.push(text),
        stderr: (text) => stderr.push(text),
      },
      process.platform,
    )

    expect(exitCode).toBe(1)
    expect(stdout.join('')).not.toContain(canary)
    expect(stderr).toEqual([])
  })

  it('uses generic errors and never echoes a missing absolute path', async () => {
    const root = await temporaryDirectory()
    const missing = path.join(root, 'private-missing-target')
    const stdout: string[] = []
    const stderr: string[] = []

    const exitCode = await runCli(
      ['scan', missing],
      {
        stdout: (text) => stdout.push(text),
        stderr: (text) => stderr.push(text),
      },
      process.platform,
    )

    expect(exitCode).toBe(2)
    expect(stdout).toEqual([])
    expect(stderr.join('')).toBe('VibeSec: scan failed.\n')
    expect(stderr.join('')).not.toContain(missing)
  })

  it('rejects malformed arguments without scanning', async () => {
    const stdout: string[] = []
    const stderr: string[] = []
    const exitCode = await runCli(
      ['scan'],
      {
        stdout: (text) => stdout.push(text),
        stderr: (text) => stderr.push(text),
      },
      process.platform,
    )
    expect(exitCode).toBe(2)
    expect(stdout).toEqual([])
    expect(stderr.join('')).toContain('Usage: vibesec scan')
  })
})

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), 'vibesec-cli-'))
  temporaryDirectories.push(directory)
  return directory
}
