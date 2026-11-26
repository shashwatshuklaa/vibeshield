const PEM_PRIVATE_KEY_PATTERN =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:\\n|[\s\S])*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;

const GITHUB_TOKEN_PATTERN = /\b(?:gh[pousr]_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{16,})\b/g;

const AUTH_HEADER_CREDENTIAL_PATTERN = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}\b/gi;

const X_ACCESS_TOKEN_URL_PATTERN = /(x-access-token:)[^\s@]+/gi;

const SENSITIVE_AUDIT_KEY_PATTERN =
  /token|secret|private.?key|password|authorization|cookie|pem|credential|signature|api.?key/i;

export const AUDIT_METADATA_MAX_BYTES = 4096;
const AUDIT_METADATA_MAX_DEPTH = 3;
const AUDIT_METADATA_MAX_KEYS = 25;
const AUDIT_METADATA_MAX_ARRAY_ITEMS = 20;
const AUDIT_METADATA_MAX_STRING_LENGTH = 500;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function expandSecretVariants(secrets: ReadonlyArray<string | undefined | null>): string[] {
  const variants = new Set<string>();

  for (const raw of secrets) {
    if (typeof raw !== 'string') {
      continue;
    }
    const trimmed = raw.trim();
    if (trimmed.length >= 4) {
      variants.add(raw);
      variants.add(trimmed);
      if (trimmed.includes('\\n')) {
        variants.add(trimmed.replace(/\\n/g, '\n'));
      }
      if (trimmed.includes('\n')) {
        variants.add(trimmed.replace(/\r?\n/g, '\\n'));
      }
    }
  }

  return Array.from(variants).sort((a, b) => b.length - a.length);
}

/**
 * Redacts GitHub token prefixes, authorization Bearer/Basic headers, PEM private-key blocks,
 * x-access-token URL credentials, and explicit secret values from logs or safe error strings.
 */
export function redactGitHubSecrets(
  input: string,
  extraSecrets: ReadonlyArray<string | undefined | null> = []
): string {
  if (typeof input !== 'string' || input.length === 0) {
    return input;
  }

  let sanitized = input
    .replace(PEM_PRIVATE_KEY_PATTERN, '[REDACTED_PEM_PRIVATE_KEY]')
    .replace(GITHUB_TOKEN_PATTERN, '[REDACTED_GITHUB_TOKEN]')
    .replace(AUTH_HEADER_CREDENTIAL_PATTERN, '$1 [REDACTED]')
    .replace(X_ACCESS_TOKEN_URL_PATTERN, '$1[REDACTED]');

  for (const secret of expandSecretVariants(extraSecrets)) {
    sanitized = sanitized.replace(new RegExp(escapeRegExp(secret), 'g'), '[REDACTED_SECRET]');
  }

  return sanitized;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value) as object | null;
  return proto === Object.prototype || proto === null;
}

function sanitizeAuditValue(
  value: unknown,
  extraSecrets: ReadonlyArray<string | undefined | null>,
  depth: number
): unknown {
  if (value === null || value === undefined) {
    return null;
  }

  if (typeof value === 'string') {
    const redacted = redactGitHubSecrets(value, extraSecrets);
    return redacted.length > AUDIT_METADATA_MAX_STRING_LENGTH
      ? redacted.slice(0, AUDIT_METADATA_MAX_STRING_LENGTH)
      : redacted;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (depth >= AUDIT_METADATA_MAX_DEPTH) {
    return '[TRUNCATED]';
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, AUDIT_METADATA_MAX_ARRAY_ITEMS)
      .map((item) => sanitizeAuditValue(item, extraSecrets, depth + 1));
  }

  if (isPlainObject(value)) {
    const sanitizedObj: Record<string, unknown> = {};
    let keyCount = 0;

    for (const [key, entryValue] of Object.entries(value)) {
      if (SENSITIVE_AUDIT_KEY_PATTERN.test(key)) {
        continue;
      }
      if (keyCount >= AUDIT_METADATA_MAX_KEYS) {
        break;
      }
      sanitizedObj[key.slice(0, 64)] = sanitizeAuditValue(entryValue, extraSecrets, depth + 1);
      keyCount += 1;
    }

    return sanitizedObj;
  }

  return String(value).slice(0, AUDIT_METADATA_MAX_STRING_LENGTH);
}

/**
 * Sanitizes and bounds audit metadata objects, stripping secret-bearing keys and redacting
 * embedded credentials. Non-object non-null inputs are preserved so schema validators reject them.
 */
export function sanitizeAuditMetadata(
  metadata: unknown,
  extraSecrets: ReadonlyArray<string | undefined | null> = []
): unknown {
  if (metadata === undefined || metadata === null) {
    return {};
  }

  if (!isPlainObject(metadata)) {
    return metadata;
  }

  return sanitizeAuditValue(metadata, extraSecrets, 0) as Record<string, unknown>;
}

/**
 * Validates that sanitized audit metadata is a plain object within size and key-safety bounds.
 */
export function isValidAuditMetadata(value: unknown): boolean {
  if (!isPlainObject(value)) {
    return false;
  }

  for (const key of Object.keys(value)) {
    if (SENSITIVE_AUDIT_KEY_PATTERN.test(key)) {
      return false;
    }
  }

  try {
    const serialized = JSON.stringify(value);
    return Buffer.byteLength(serialized, 'utf8') <= AUDIT_METADATA_MAX_BYTES;
  } catch {
    return false;
  }
}
