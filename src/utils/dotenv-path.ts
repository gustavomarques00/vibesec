export function isDotenvPath(relativePath: string): boolean {
  const base = relativePath.normalize('NFC').split('/').at(-1) ?? relativePath
  return base === '.env' || base.startsWith('.env.')
}
