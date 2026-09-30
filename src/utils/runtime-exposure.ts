export type RuntimeExposure = 'client' | 'server' | 'unknown'

export function classifyRuntimeExposure(relativePath: string): RuntimeExposure {
  const normalized = relativePath.normalize('NFC').toLowerCase().replaceAll('\\', '/')
  if (
    /(^|\/)server\//u.test(normalized) ||
    /(^|\/)api\//u.test(normalized) ||
    /(^|\/)edge\//u.test(normalized) ||
    normalized.includes('/supabase/functions/') ||
    /(^|\/)backend\//u.test(normalized) ||
    /(^|\/)server\./u.test(normalized)
  ) {
    return 'server'
  }
  if (
    /(^|\/)client\//u.test(normalized) ||
    /(^|\/)components\//u.test(normalized) ||
    /(^|\/)pages\//u.test(normalized) ||
    /(^|\/)app\//u.test(normalized) ||
    /(^|\/)public\//u.test(normalized) ||
    /(^|\/)src\//u.test(normalized) ||
    normalized.endsWith('.tsx') ||
    normalized.endsWith('.jsx') ||
    normalized.includes('/.env') ||
    /(^|\/)\.env/u.test(normalized)
  ) {
    return 'client'
  }
  return 'unknown'
}
