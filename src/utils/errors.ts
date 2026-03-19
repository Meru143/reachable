// Custom error types for reachable.
export class ReachableError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ReachableError";
    this.code = code;
  }
}

export class OsvApiError extends ReachableError {
  statusCode: number;

  constructor(statusCode: number, message: string) {
    super("E003", message);
    this.name = "OsvApiError";
    this.statusCode = statusCode;
  }
}

export class ParseError extends ReachableError {
  file: string;

  constructor(file: string, message: string) {
    super("E004", message);
    this.name = "ParseError";
    this.file = file;
  }
}

export class ConfigError extends ReachableError {
  constructor(message: string) {
    super("CONFIG_ERROR", message);
    this.name = "ConfigError";
  }
}
