import type { ZodError, ZodIssue } from 'zod';

export interface EnvIssue {
  /**
   * The name of the environment variable that failed validation.
   */
  variable: string;

  /**
   * Safe, sanitized error message describing the failure reason.
   * Guarantees no sensitive input values are exposed.
   */
  message: string;
}

/**
 * Custom error thrown when environment variable validation fails.
 * Designed with security as a priority: never leaks environment variable values in error messages or logs.
 */
export class EnvValidationError extends Error {
  public readonly issues: ReadonlyArray<EnvIssue>;

  constructor(issues: EnvIssue[]) {
    const formattedIssues = issues
      .map((issue) => `  - ${issue.variable}: ${issue.message}`)
      .join('\n');

    super(
      `Environment configuration validation failed:\n${formattedIssues}\n\nPlease check your environment configuration or .env file.`
    );

    this.name = 'EnvValidationError';
    this.issues = Object.freeze([...issues]);

    const ErrorWithV8 = Error as unknown as {
      captureStackTrace?: (target: object, constructorOpt?: Function) => void;
    };
    if (typeof ErrorWithV8.captureStackTrace === 'function') {
      ErrorWithV8.captureStackTrace(this, EnvValidationError);
    }
  }

  /**
   * Transforms Zod issues into safe EnvIssue items with zero value leakage.
   */
  public static fromZodError(error: ZodError): EnvValidationError {
    const issues: EnvIssue[] = error.issues.map((issue: ZodIssue) => {
      const variable = issue.path.join('.') || 'UNKNOWN_VARIABLE';
      const safeMessage = EnvValidationError.sanitizeMessage(issue);
      return { variable, message: safeMessage };
    });

    return new EnvValidationError(issues);
  }

  /**
   * Sanitizes issue descriptions to prevent any accidental leakage of user input / secrets.
   */
  private static sanitizeMessage(issue: ZodIssue): string {
    switch (issue.code) {
      case 'invalid_type':
        if (issue.received === 'undefined') {
          return 'Missing required environment variable';
        }
        return `Expected ${issue.expected}, received ${issue.received}`;
      case 'invalid_enum_value':
        return `Invalid value. Expected one of: ${issue.options.map((o) => `'${o}'`).join(', ')}`;
      case 'too_small':
        return `Value is too short (minimum ${issue.minimum} characters required)`;
      case 'too_big':
        return `Value is too long (maximum ${issue.maximum} characters allowed)`;
      case 'invalid_string':
        if (issue.validation === 'url') {
          return 'Must be a valid URL';
        }
        if (issue.validation === 'email') {
          return 'Must be a valid email address';
        }
        return `Invalid string format (expected ${issue.validation})`;
      default:
        return issue.message.replace(/received\s+'[^']+'/gi, 'received [REDACTED]');
    }
  }
}
