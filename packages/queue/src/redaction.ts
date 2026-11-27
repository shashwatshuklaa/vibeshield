const REDIS_URL_PATTERN = /rediss?:\/\/[^\s'"`]+/gi;
const CREDENTIAL_SEGMENT_PATTERN = /([^\s/:@]+):([^\s/@]*)@/g;
const AUTH_TOKEN_PATTERN =
  /\b(?:gh[pousr]_[A-Za-z0-9_=-]{10,}|github_pat_[A-Za-z0-9_]{16,}|Bearer\s+[A-Za-z0-9._~+/=-]{6,})\b/gi;
const PASSWORD_KEY_VALUE_PATTERN =
  /\b(password|pass|auth|secret|token|apikey|api_key)\s*[:=]\s*(['"]?)[^\s,'";}]+\2/gi;

/**
 * Redacts `redis://` and `rediss://` URIs, embedded credentials, and inline secrets from logs
 * and error strings.
 */
export function redactRedisUrl(input: string): string {
  if (typeof input !== 'string' || input.length === 0) {
    return input;
  }

  return input
    .replace(REDIS_URL_PATTERN, '[REDACTED_REDIS_URL]')
    .replace(CREDENTIAL_SEGMENT_PATTERN, '[REDACTED_CREDENTIALS]@')
    .replace(AUTH_TOKEN_PATTERN, '[REDACTED_SECRET]')
    .replace(PASSWORD_KEY_VALUE_PATTERN, '$1=[REDACTED]');
}

/**
 * Formats an unknown error into a safe, credential-free string suitable for logs and API errors.
 */
export function formatSafeRedisError(
  error: unknown,
  extraSecrets: ReadonlyArray<string | undefined> = []
): string {
  let message: string;
  if (error instanceof Error) {
    message = error.message || error.name;
  } else if (typeof error === 'string') {
    message = error;
  } else {
    return 'Unknown Redis/Queue error';
  }

  let sanitized = redactRedisUrl(message);
  for (const secret of extraSecrets) {
    if (secret && secret.length >= 4) {
      const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      sanitized = sanitized.replace(new RegExp(escaped, 'g'), '[REDACTED_SECRET]');
    }
  }
  return sanitized;
}

/**
 * Validates that a candidate string is a well-formed `redis://` or `rediss://` URL with a
 * valid host, optional numeric port (`1-65535`), and optional database index (`0-15`).
 */
export function isValidRedisUrl(rawUrl: string): boolean {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0 || /\s/.test(rawUrl)) {
    return false;
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'redis:' && parsed.protocol !== 'rediss:') {
    return false;
  }

  if (!parsed.hostname) {
    return false;
  }

  if (parsed.port) {
    const portNum = Number(parsed.port);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      return false;
    }
  }

  if (parsed.pathname && parsed.pathname !== '/') {
    const dbSegment = parsed.pathname.slice(1);
    if (!/^\d+$/.test(dbSegment)) {
      return false;
    }
    const dbIndex = Number(dbSegment);
    if (!Number.isInteger(dbIndex) || dbIndex < 0 || dbIndex > 15) {
      return false;
    }
  }

  return true;
}

/**
 * Returns `true` when the Redis URL explicitly specifies TLS (`rediss://`).
 */
export function isTlsRedisUrl(rawUrl: string): boolean {
  try {
    return new URL(rawUrl).protocol === 'rediss:';
  } catch {
    return false;
  }
}

/**
 * Extracts any embedded password from a valid Redis URL for error redaction only.
 */
export function extractRedisUrlPassword(rawUrl: string): string | undefined {
  try {
    const password = new URL(rawUrl).password;
    return password ? decodeURIComponent(password) : undefined;
  } catch {
    return undefined;
  }
}
