export class InvalidExternalTargetError extends Error {
  constructor() {
    super('The External target is invalid.')
    this.name = 'InvalidExternalTargetError'
  }
}

export class UnsupportedExternalSchemeError extends Error {
  constructor() {
    super('The External target scheme is not supported.')
    this.name = 'UnsupportedExternalSchemeError'
  }
}

export class UnsupportedExternalPortError extends Error {
  constructor() {
    super('The External target port is not supported.')
    this.name = 'UnsupportedExternalPortError'
  }
}

export class InvalidExternalBudgetError extends Error {
  constructor() {
    super('The External scan budget configuration is invalid.')
    this.name = 'InvalidExternalBudgetError'
  }
}
