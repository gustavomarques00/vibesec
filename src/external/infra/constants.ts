/** Production External User-Agent (accepted E1 decision). */
export const EXTERNAL_USER_AGENT =
  'VibeSec-External/1.1 (+https://github.com/gustavomarques00/vibesec)' as const

/**
 * Compression: E1.3 requests identity encoding only.
 * Bounded decompression is deferred; avoids decompression-bomb risk.
 */
export const EXTERNAL_ACCEPT_ENCODING = 'identity' as const

export const EXTERNAL_ACCEPT = '*/*' as const

/** Max fallback connection attempts across approved addresses for one hop. */
export const EXTERNAL_MAX_ADDRESS_ATTEMPTS = 3 as const

export const REDIRECT_STATUS_CODES = Object.freeze(new Set([301, 302, 303, 307, 308]))
