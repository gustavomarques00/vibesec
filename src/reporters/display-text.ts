const UNICODE_FORMAT_CHARACTER = /^\p{Cf}$/u

export function escapeDisplayText(value: string): string {
  let output = ''
  for (const character of value.normalize('NFC')) {
    const codePoint = character.codePointAt(0)
    if (
      codePoint === undefined ||
      codePoint < 0x20 ||
      codePoint === 0x7f ||
      (codePoint >= 0x80 && codePoint <= 0x9f) ||
      codePoint === 0x2028 ||
      codePoint === 0x2029 ||
      UNICODE_FORMAT_CHARACTER.test(character)
    ) {
      const hexadecimal = (codePoint ?? 0).toString(16)
      output +=
        hexadecimal.length <= 4
          ? `\\u${hexadecimal.padStart(4, '0')}`
          : `\\u{${hexadecimal}}`
    } else {
      output += character
    }
  }
  return output
}

export function escapeMarkdownText(value: string): string {
  return escapeDisplayText(value).replaceAll(/([\\`*_[\]<>#|])/gu, '\\$1')
}
