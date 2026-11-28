import { randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  realpath,
  rm,
  type FileHandle,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import zlib from 'node:zlib';
import { extract as createTarExtract, type Header as TarHeader } from 'tar-stream';
import { formatSafeWorkerMessage, type WorkerLogger, createWorkerLogger } from '../utils/logger.js';
import {
  HARD_MAX_COMPRESSED_ARCHIVE_BYTES,
  InternalAcquisitionError,
  type AcquiredRepositoryArchive,
} from './internal-acquisition-client.js';

export const DEFAULT_MAX_COMPRESSED_ARCHIVE_BYTES = HARD_MAX_COMPRESSED_ARCHIVE_BYTES; // 100 MiB
export const DEFAULT_MAX_DECOMPRESSED_ARCHIVE_BYTES = 512 * 1024 * 1024; // 512 MiB
export const DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024; // 25 MiB
export const DEFAULT_MAX_ARCHIVE_ENTRIES = 25_000;
export const DEFAULT_MAX_ARCHIVE_PATH_LENGTH = 240;
export const DEFAULT_MAX_ARCHIVE_PATH_DEPTH = 24;
export const DEFAULT_MAX_ENTRY_METADATA_BYTES = 64 * 1024; // 64 KiB
export const DEFAULT_MAX_TOTAL_METADATA_BYTES = 4 * 1024 * 1024; // 4 MiB across archive
export const DEFAULT_MAX_EXTENDED_HEADERS = 25_000;
export const DEFAULT_WORKSPACE_ROOT_DIRNAME = 'vibeshield-workspaces';
export const WORKSPACE_DIR_PREFIX = 'vs-ws-';

const WORKSPACE_DIR_MODE = 0o700;
const WORKSPACE_FILE_MODE = 0o600;
const ARCHIVE_STREAM_HIGH_WATER_MARK = 64 * 1024;
const MAX_COMPONENT_UTF8_BYTES = 255;
const MAX_CONSECUTIVE_EXTENDED_HEADERS = 8;
const MAX_GLOBAL_PAX_HEADERS = 4;
const TAR_BLOCK_BYTES = 512;

// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_REGEX = /[\u0000-\u001f\u007f]/;
const WINDOWS_DRIVE_REGEX = /^[A-Za-z]:/;

const ALLOWED_PAX_KEYS = new Set([
  'path',
  'size',
  'mtime',
  'atime',
  'ctime',
  'comment',
  'uid',
  'gid',
  'uname',
  'gname',
  'hdrcharset',
  'charset',
]);

const ALLOWED_GLOBAL_PAX_KEYS = new Set([
  'mtime',
  'atime',
  'ctime',
  'comment',
  'uid',
  'gid',
  'uname',
  'gname',
  'hdrcharset',
  'charset',
]);

export type ArchiveExtractionErrorCode =
  | 'INVALID_EXTRACTION_CONFIG'
  | 'INVALID_ARCHIVE_FORMAT'
  | 'MALFORMED_ARCHIVE'
  | 'COMPRESSED_SIZE_EXCEEDED'
  | 'DECOMPRESSED_SIZE_EXCEEDED'
  | 'FILE_SIZE_EXCEEDED'
  | 'INCONSISTENT_ENTRY_SIZE'
  | 'ENTRY_COUNT_EXCEEDED'
  | 'EXCESSIVE_ARCHIVE_METADATA'
  | 'INVALID_ARCHIVE_PATH'
  | 'INCONSISTENT_ARCHIVE_ROOT'
  | 'ARCHIVE_PATH_COLLISION'
  | 'FILE_DIRECTORY_CONFLICT'
  | 'UNSUPPORTED_ENTRY_TYPE'
  | 'UNSUPPORTED_ARCHIVE_METADATA'
  | 'WORKSPACE_ERROR'
  | 'WORKSPACE_CONTAINMENT_ERROR'
  | 'WORKSPACE_CLEANUP_FAILED'
  | 'EXTRACTION_CANCELLED'
  | 'WORKER_SHUTDOWN';

function isWellFormedUnicode(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) {
        return false;
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function redactHostPaths(
  message: string,
  pathsToRedact: readonly (string | undefined)[] = []
): string {
  let result = message;
  for (const rawPath of pathsToRedact) {
    if (typeof rawPath !== 'string' || rawPath.length < 2) {
      continue;
    }
    const escaped = rawPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    result = result.replace(new RegExp(escaped, 'g'), '[REDACTED_PATH]');
  }
  return formatSafeWorkerMessage(result);
}

/**
 * Operational error raised during archive validation, bounded decompression, extraction, or
 * isolated workspace lifecycle operations. Scrubs host filesystem paths from messages.
 */
export class ArchiveExtractionError extends Error {
  public readonly code: ArchiveExtractionErrorCode;

  constructor(
    code: ArchiveExtractionErrorCode,
    message: string,
    pathsToRedact: readonly (string | undefined)[] = []
  ) {
    super(redactHostPaths(message, pathsToRedact));
    this.name = 'ArchiveExtractionError';
    this.code = code;
  }

  public toJSON(): { name: string; code: ArchiveExtractionErrorCode; message: string } {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
    };
  }
}

export interface ArchiveExtractionLimits {
  readonly maxCompressedBytes: number;
  readonly maxDecompressedBytes: number;
  readonly maxFileBytes: number;
  readonly maxEntries: number;
  readonly maxPathLength: number;
  readonly maxPathDepth: number;
  readonly maxEntryMetadataBytes: number;
  readonly maxTotalMetadataBytes: number;
  readonly maxExtendedHeaders: number;
}

export interface ExtractionMetadata {
  readonly scanId: string;
  readonly rootDirectoryName: string | null;
  readonly compressedBytes: number;
  readonly decompressedBytes: number;
  readonly fileBytes: number;
  readonly fileCount: number;
  readonly directoryCount: number;
  readonly entryCount: number;
}

export interface WorkspaceCleanupResult {
  readonly cleaned: true;
  readonly alreadyCleaned: boolean;
}

export interface ExtractedWorkspaceHandle {
  readonly workspaceId: string;
  readonly workspacePath: string;
  readonly workspaceParentDir: string;
  readonly metadata: ExtractionMetadata;
  isCleanedUp(): boolean;
  cleanup(): Promise<WorkspaceCleanupResult>;
}

export interface WorkspaceFsOps {
  mkdtemp?: typeof mkdtemp;
  chmod?: typeof chmod;
  lstat?: typeof lstat;
  realpath?: typeof realpath;
  rm?: typeof rm;
}

export interface ExtractRepositoryArchiveInput {
  archive: Pick<AcquiredRepositoryArchive, 'scanId' | 'stream' | 'maxArchiveBytes' | 'abort'>;
  workspaceParentDir?: string;
  signal?: AbortSignal;
  shutdownSignal?: AbortSignal;
  limits?: Partial<ArchiveExtractionLimits>;
  logger?: WorkerLogger;
  workspaceFsOps?: WorkspaceFsOps;
}

function validateLimitBound(value: number, maxHardBound: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maxHardBound) {
    throw new ArchiveExtractionError(
      'INVALID_EXTRACTION_CONFIG',
      `${name} must be a positive integer not exceeding ${maxHardBound}.`
    );
  }
  return value;
}

/**
 * Resolves and validates extraction resource limits, ensuring caller overrides cannot exceed
 * the platform's hard maximum bounds.
 */
export function resolveArchiveExtractionLimits(
  overrides: Partial<ArchiveExtractionLimits> = {},
  archiveMaxBytes?: number
): ArchiveExtractionLimits {
  const requestedCompressedMax =
    overrides.maxCompressedBytes ??
    (archiveMaxBytes !== undefined
      ? Math.min(archiveMaxBytes, DEFAULT_MAX_COMPRESSED_ARCHIVE_BYTES)
      : DEFAULT_MAX_COMPRESSED_ARCHIVE_BYTES);

  const maxCompressedBytes = validateLimitBound(
    requestedCompressedMax,
    DEFAULT_MAX_COMPRESSED_ARCHIVE_BYTES,
    'maxCompressedBytes'
  );
  const maxDecompressedBytes = validateLimitBound(
    overrides.maxDecompressedBytes ?? DEFAULT_MAX_DECOMPRESSED_ARCHIVE_BYTES,
    DEFAULT_MAX_DECOMPRESSED_ARCHIVE_BYTES,
    'maxDecompressedBytes'
  );
  const maxFileBytes = validateLimitBound(
    overrides.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES,
    Math.min(DEFAULT_MAX_FILE_BYTES, maxDecompressedBytes),
    'maxFileBytes'
  );
  const maxEntries = validateLimitBound(
    overrides.maxEntries ?? DEFAULT_MAX_ARCHIVE_ENTRIES,
    DEFAULT_MAX_ARCHIVE_ENTRIES,
    'maxEntries'
  );
  const maxPathLength = validateLimitBound(
    overrides.maxPathLength ?? DEFAULT_MAX_ARCHIVE_PATH_LENGTH,
    DEFAULT_MAX_ARCHIVE_PATH_LENGTH,
    'maxPathLength'
  );
  const maxPathDepth = validateLimitBound(
    overrides.maxPathDepth ?? DEFAULT_MAX_ARCHIVE_PATH_DEPTH,
    DEFAULT_MAX_ARCHIVE_PATH_DEPTH,
    'maxPathDepth'
  );
  const maxEntryMetadataBytes = validateLimitBound(
    overrides.maxEntryMetadataBytes ?? DEFAULT_MAX_ENTRY_METADATA_BYTES,
    DEFAULT_MAX_ENTRY_METADATA_BYTES,
    'maxEntryMetadataBytes'
  );
  const maxTotalMetadataBytes = validateLimitBound(
    overrides.maxTotalMetadataBytes ?? DEFAULT_MAX_TOTAL_METADATA_BYTES,
    DEFAULT_MAX_TOTAL_METADATA_BYTES,
    'maxTotalMetadataBytes'
  );
  const maxExtendedHeaders = validateLimitBound(
    overrides.maxExtendedHeaders ?? DEFAULT_MAX_EXTENDED_HEADERS,
    DEFAULT_MAX_EXTENDED_HEADERS,
    'maxExtendedHeaders'
  );

  return Object.freeze({
    maxCompressedBytes,
    maxDecompressedBytes,
    maxFileBytes,
    maxEntries,
    maxPathLength,
    maxPathDepth,
    maxEntryMetadataBytes,
    maxTotalMetadataBytes,
    maxExtendedHeaders,
  });
}

function validateWorkspaceParentPathInput(rawParentDir?: string): string {
  const candidate = rawParentDir ?? path.join(os.tmpdir(), DEFAULT_WORKSPACE_ROOT_DIRNAME);

  if (typeof candidate !== 'string' || candidate.trim().length === 0 || candidate.includes('\0')) {
    throw new ArchiveExtractionError(
      'INVALID_EXTRACTION_CONFIG',
      'Workspace parent directory must be a valid non-empty path.'
    );
  }

  const trimmed = candidate.trim();
  if (!path.isAbsolute(trimmed)) {
    throw new ArchiveExtractionError(
      'INVALID_EXTRACTION_CONFIG',
      'Workspace parent directory must be an absolute path.'
    );
  }

  const resolved = path.resolve(trimmed);
  if (resolved === path.parse(resolved).root) {
    throw new ArchiveExtractionError(
      'INVALID_EXTRACTION_CONFIG',
      'Workspace parent directory must not be the filesystem root.'
    );
  }

  return resolved;
}

function validateTrustedWorkspaceParentStat(
  parentStat: Awaited<ReturnType<typeof lstat>>,
  resolvedPath: string
): void {
  if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) {
    throw new ArchiveExtractionError(
      'WORKSPACE_CONTAINMENT_ERROR',
      'Configured workspace parent path must be a non-symlink directory.',
      [resolvedPath]
    );
  }

  if (typeof process.getuid === 'function') {
    const workerUid = process.getuid();
    const modeBits = Number(parentStat.mode) & 0o7777;
    const parentUid = Number(parentStat.uid);
    const hasGroupWrite = (modeBits & 0o020) !== 0;
    const hasOtherWrite = (modeBits & 0o002) !== 0;
    const hasStickyBit = (modeBits & 0o1000) !== 0;

    const isOwnedByWorker = parentUid === workerUid;
    const isRootOwnedSticky = parentUid === 0 && hasStickyBit;

    if (!isOwnedByWorker && !isRootOwnedSticky) {
      throw new ArchiveExtractionError(
        'WORKSPACE_CONTAINMENT_ERROR',
        'Configured workspace parent directory ownership check failed.',
        [resolvedPath]
      );
    }

    if ((hasGroupWrite || hasOtherWrite) && !hasStickyBit) {
      throw new ArchiveExtractionError(
        'WORKSPACE_CONTAINMENT_ERROR',
        'Configured workspace parent directory has unsafe group or world writable permissions.',
        [resolvedPath]
      );
    }
  }
}

async function ensureTrustedWorkspaceParentDir(
  rawParentDir?: string,
  fsOps?: WorkspaceFsOps
): Promise<string> {
  const resolved = validateWorkspaceParentPathInput(rawParentDir);
  const lstatFn = fsOps?.lstat ?? lstat;
  const realpathFn = fsOps?.realpath ?? realpath;

  try {
    await mkdir(resolved, { recursive: true, mode: WORKSPACE_DIR_MODE });
  } catch {
    throw new ArchiveExtractionError(
      'WORKSPACE_ERROR',
      'Failed to initialize trusted workspace parent directory.',
      [resolved]
    );
  }

  let parentStat;
  try {
    parentStat = await lstatFn(resolved);
  } catch {
    throw new ArchiveExtractionError(
      'WORKSPACE_ERROR',
      'Failed to inspect trusted workspace parent directory.',
      [resolved]
    );
  }

  validateTrustedWorkspaceParentStat(parentStat, resolved);

  try {
    return await realpathFn(resolved);
  } catch {
    throw new ArchiveExtractionError(
      'WORKSPACE_ERROR',
      'Failed to resolve canonical path for workspace parent directory.',
      [resolved]
    );
  }
}

function sanitizeScanIdForPrefix(scanId: string): string {
  const safe = scanId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24);
  return safe.length > 0 ? safe : 'scan';
}

function assertWorkspaceContainment(
  parentRealpath: string,
  workspaceRealpath: string,
  workspaceDirName: string
): void {
  if (!workspaceDirName.startsWith(WORKSPACE_DIR_PREFIX)) {
    throw new ArchiveExtractionError(
      'WORKSPACE_CONTAINMENT_ERROR',
      'Workspace directory name failed containment prefix validation.',
      [parentRealpath, workspaceRealpath]
    );
  }

  if (path.dirname(workspaceRealpath) !== parentRealpath) {
    throw new ArchiveExtractionError(
      'WORKSPACE_CONTAINMENT_ERROR',
      'Workspace directory escaped the configured workspace parent directory.',
      [parentRealpath, workspaceRealpath]
    );
  }

  const relative = path.relative(parentRealpath, workspaceRealpath);
  if (
    relative.length === 0 ||
    relative === '.' ||
    relative.startsWith('..') ||
    path.isAbsolute(relative)
  ) {
    throw new ArchiveExtractionError(
      'WORKSPACE_CONTAINMENT_ERROR',
      'Workspace containment boundary check failed.',
      [parentRealpath, workspaceRealpath]
    );
  }
}

/**
 * Safely deletes a worker workspace directory after verifying ownership, non-symlink identity,
 * expected workspace prefix, and parent directory containment.
 */
export async function cleanupWorkspaceDirectory(
  workspacePath: string,
  workspaceParentDir: string,
  fsOps: Pick<WorkspaceFsOps, 'lstat' | 'realpath' | 'rm'> = {}
): Promise<WorkspaceCleanupResult> {
  const lstatFn = fsOps.lstat ?? lstat;
  const realpathFn = fsOps.realpath ?? realpath;
  const rmFn = fsOps.rm ?? rm;
  const resolvedParentInput = validateWorkspaceParentPathInput(workspaceParentDir);

  let parentRealpath: string;
  try {
    const parentStat = await lstatFn(resolvedParentInput);
    validateTrustedWorkspaceParentStat(parentStat, resolvedParentInput);
    parentRealpath = await realpathFn(resolvedParentInput);
  } catch (err) {
    if (err instanceof ArchiveExtractionError) {
      throw err;
    }
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
      return { cleaned: true, alreadyCleaned: true };
    }
    throw new ArchiveExtractionError(
      'WORKSPACE_CLEANUP_FAILED',
      'Unable to verify workspace parent directory before cleanup.',
      [resolvedParentInput, workspacePath]
    );
  }

  let wsStat;
  try {
    wsStat = await lstatFn(workspacePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
      return { cleaned: true, alreadyCleaned: true };
    }
    throw new ArchiveExtractionError(
      'WORKSPACE_CLEANUP_FAILED',
      'Unable to inspect workspace directory prior to cleanup.',
      [resolvedParentInput, workspacePath]
    );
  }

  if (wsStat.isSymbolicLink() || !wsStat.isDirectory()) {
    throw new ArchiveExtractionError(
      'WORKSPACE_CONTAINMENT_ERROR',
      'Refusing cleanup because workspace path is a symlink or non-directory.',
      [resolvedParentInput, workspacePath]
    );
  }

  if (typeof process.getuid === 'function' && wsStat.uid !== process.getuid()) {
    throw new ArchiveExtractionError(
      'WORKSPACE_CONTAINMENT_ERROR',
      'Refusing cleanup of workspace directory not owned by worker process.',
      [resolvedParentInput, workspacePath]
    );
  }

  let workspaceRealpath: string;
  try {
    workspaceRealpath = await realpathFn(workspacePath);
  } catch {
    throw new ArchiveExtractionError(
      'WORKSPACE_CLEANUP_FAILED',
      'Unable to canonicalize workspace directory prior to cleanup.',
      [resolvedParentInput, workspacePath]
    );
  }

  assertWorkspaceContainment(parentRealpath, workspaceRealpath, path.basename(workspaceRealpath));

  try {
    await rmFn(workspaceRealpath, { recursive: true, force: false });
    return { cleaned: true, alreadyCleaned: false };
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
      return { cleaned: true, alreadyCleaned: true };
    }
    throw new ArchiveExtractionError(
      'WORKSPACE_CLEANUP_FAILED',
      'Failed to remove temporary workspace directory.',
      [resolvedParentInput, workspacePath]
    );
  }
}

function validateEntryHeaderMetadata(
  header: TarHeader,
  limits: ArchiveExtractionLimits
): 'file' | 'directory' {
  // 1. Entry type allowlist: strictly regular files and directories.
  const entryType = header.type as string | null | undefined;
  if (entryType !== 'file' && entryType !== 'directory') {
    throw new ArchiveExtractionError(
      'UNSUPPORTED_ENTRY_TYPE',
      `Archive contains unsupported entry type "${String(entryType ?? 'unknown')}".`
    );
  }

  // 2. Reject any link target metadata on file/directory entries.
  if (typeof header.linkname === 'string' && header.linkname.length > 0) {
    throw new ArchiveExtractionError(
      'UNSUPPORTED_ENTRY_TYPE',
      'Archive regular entry unexpectedly contains link target metadata.'
    );
  }

  // 3. Reject non-finite, negative, or oversized entry sizes.
  if (typeof header.size !== 'number' || !Number.isSafeInteger(header.size) || header.size < 0) {
    throw new ArchiveExtractionError(
      'MALFORMED_ARCHIVE',
      'Archive entry declared an invalid or non-finite size.'
    );
  }

  if (entryType === 'directory' && header.size !== 0) {
    throw new ArchiveExtractionError(
      'MALFORMED_ARCHIVE',
      'Archive directory entry declared a non-zero payload size.'
    );
  }

  if (header.size > limits.maxFileBytes) {
    throw new ArchiveExtractionError(
      'FILE_SIZE_EXCEEDED',
      'Archive entry size exceeds maximum allowed regular file size limit.'
    );
  }

  // 4. Inspect PAX extended headers strictly for sparse files, xattrs, linkpaths, size tampering, and bloat.
  if (header.pax !== undefined && header.pax !== null) {
    if (typeof header.pax !== 'object' || Array.isArray(header.pax)) {
      throw new ArchiveExtractionError(
        'UNSUPPORTED_ARCHIVE_METADATA',
        'Archive entry contains malformed PAX metadata.'
      );
    }

    const paxRecord = header.pax as Record<string, unknown>;
    let serializedPaxBytes = 0;

    for (const [key, rawValue] of Object.entries(paxRecord)) {
      if (typeof rawValue !== 'string') {
        throw new ArchiveExtractionError(
          'UNSUPPORTED_ARCHIVE_METADATA',
          'Archive PAX metadata attribute has non-string value.'
        );
      }

      if (key.startsWith('GNU.sparse.') || key.startsWith('GNU.')) {
        throw new ArchiveExtractionError(
          'UNSUPPORTED_ARCHIVE_METADATA',
          'Sparse files and GNU PAX extensions are forbidden in repository archives.'
        );
      }

      if (!ALLOWED_PAX_KEYS.has(key)) {
        throw new ArchiveExtractionError(
          'UNSUPPORTED_ARCHIVE_METADATA',
          'Archive contains unsupported PAX extension metadata.'
        );
      }

      serializedPaxBytes += Buffer.byteLength(key, 'utf8') + Buffer.byteLength(rawValue, 'utf8');
      if (serializedPaxBytes > limits.maxEntryMetadataBytes) {
        throw new ArchiveExtractionError(
          'EXCESSIVE_ARCHIVE_METADATA',
          'Archive entry metadata exceeds maximum allowed metadata size.'
        );
      }
    }

    if (typeof paxRecord.path === 'string' && paxRecord.path.length === 0) {
      throw new ArchiveExtractionError(
        'INVALID_ARCHIVE_PATH',
        'Archive PAX path override must not be empty.'
      );
    }

    if (paxRecord.size !== undefined) {
      if (typeof paxRecord.size !== 'string' || !/^\d+$/.test(paxRecord.size)) {
        throw new ArchiveExtractionError(
          'MALFORMED_ARCHIVE',
          'Archive PAX size metadata is malformed.'
        );
      }
      const parsedPaxSize = Number(paxRecord.size);
      if (!Number.isSafeInteger(parsedPaxSize) || parsedPaxSize !== header.size) {
        throw new ArchiveExtractionError(
          'INCONSISTENT_ENTRY_SIZE',
          'Archive PAX size metadata conflicts with entry size.'
        );
      }
    }
  }

  return entryType;
}

interface ParsedArchivePath {
  rawNormalized: string;
  segments: string[];
}

function validateLexicalArchivePath(
  rawName: string,
  entryType: 'file' | 'directory',
  limits: ArchiveExtractionLimits
): ParsedArchivePath {
  if (typeof rawName !== 'string' || rawName.length === 0) {
    throw new ArchiveExtractionError('INVALID_ARCHIVE_PATH', 'Archive entry path is empty.');
  }

  if (!isWellFormedUnicode(rawName)) {
    throw new ArchiveExtractionError(
      'INVALID_ARCHIVE_PATH',
      'Archive entry path contains ill-formed Unicode surrogates.'
    );
  }

  if (CONTROL_CHAR_REGEX.test(rawName)) {
    throw new ArchiveExtractionError(
      'INVALID_ARCHIVE_PATH',
      'Archive entry path contains prohibited NUL or control characters.'
    );
  }

  if (rawName.includes('\\')) {
    throw new ArchiveExtractionError(
      'INVALID_ARCHIVE_PATH',
      'Archive entry path contains prohibited backslash characters.'
    );
  }

  if (WINDOWS_DRIVE_REGEX.test(rawName)) {
    throw new ArchiveExtractionError(
      'INVALID_ARCHIVE_PATH',
      'Archive entry path contains prohibited Windows drive prefix.'
    );
  }

  if (rawName.startsWith('//') || rawName.startsWith('/')) {
    throw new ArchiveExtractionError(
      'INVALID_ARCHIVE_PATH',
      'Archive entry path must be relative (absolute and UNC paths are forbidden).'
    );
  }

  if (rawName.includes('//')) {
    throw new ArchiveExtractionError(
      'INVALID_ARCHIVE_PATH',
      'Archive entry path contains empty path segments.'
    );
  }

  if (entryType === 'file' && rawName.endsWith('/')) {
    throw new ArchiveExtractionError(
      'INVALID_ARCHIVE_PATH',
      'Archive regular file entry must not end with a directory separator.'
    );
  }

  const trimmed =
    entryType === 'directory' && rawName.endsWith('/') ? rawName.slice(0, -1) : rawName;

  if (trimmed.length === 0) {
    throw new ArchiveExtractionError('INVALID_ARCHIVE_PATH', 'Archive entry path is empty.');
  }

  const rawSegments = trimmed.split('/');
  if (rawSegments.length > limits.maxPathDepth) {
    throw new ArchiveExtractionError(
      'INVALID_ARCHIVE_PATH',
      'Archive entry path exceeds maximum allowed directory depth.'
    );
  }

  const canonicalSegments: string[] = [];
  for (const rawSegment of rawSegments) {
    const segment = rawSegment.normalize('NFC');
    if (
      segment.length === 0 ||
      segment === '.' ||
      segment === '..' ||
      segment.includes('/') ||
      segment.includes('\\') ||
      CONTROL_CHAR_REGEX.test(segment)
    ) {
      throw new ArchiveExtractionError(
        'INVALID_ARCHIVE_PATH',
        'Archive entry path contains invalid dot or traversal segments.'
      );
    }
    if (WINDOWS_DRIVE_REGEX.test(segment)) {
      throw new ArchiveExtractionError(
        'INVALID_ARCHIVE_PATH',
        'Archive entry path contains invalid drive-like segment.'
      );
    }
    if (Buffer.byteLength(segment, 'utf8') > MAX_COMPONENT_UTF8_BYTES) {
      throw new ArchiveExtractionError(
        'INVALID_ARCHIVE_PATH',
        'Archive entry path segment exceeds maximum allowed UTF-8 byte length.'
      );
    }
    canonicalSegments.push(segment);
  }

  const canonicalNormalized = canonicalSegments.join('/');
  if (
    canonicalNormalized.length > limits.maxPathLength ||
    Buffer.byteLength(canonicalNormalized, 'utf8') > limits.maxPathLength
  ) {
    throw new ArchiveExtractionError(
      'INVALID_ARCHIVE_PATH',
      'Archive entry path exceeds maximum allowed path length.'
    );
  }

  return {
    rawNormalized: canonicalNormalized,
    segments: canonicalSegments,
  };
}

interface ArchivePathRegistration {
  readonly isRootDirectoryEntry: boolean;
  readonly relativePosixPath: string;
  readonly relativeSegments: string[];
}

class ArchiveLayoutValidator {
  private rootDirectoryName: string | null = null;
  private rootDirectoryNameLower: string | null = null;
  private seenExplicitRootEntry = false;
  private readonly seenExplicitEntries = new Set<string>();
  private readonly dirExactByLower = new Map<string, string>();
  private readonly fileLowerSet = new Set<string>();

  public getRootDirectoryName(): string | null {
    return this.rootDirectoryName;
  }

  public registerEntry(
    rawName: string,
    entryType: 'file' | 'directory',
    limits: ArchiveExtractionLimits
  ): ArchivePathRegistration {
    const parsed = validateLexicalArchivePath(rawName, entryType, limits);
    const topSegment = parsed.segments[0]!;
    const topSegmentLower = topSegment.toLowerCase();

    if (parsed.segments.length === 1 && entryType === 'file') {
      throw new ArchiveExtractionError(
        'INCONSISTENT_ARCHIVE_ROOT',
        'Archive must contain a single consistent top-level root directory rather than root-level files.'
      );
    }

    if (this.rootDirectoryName === null) {
      this.rootDirectoryName = topSegment;
      this.rootDirectoryNameLower = topSegmentLower;
    } else if (topSegment !== this.rootDirectoryName) {
      if (topSegmentLower === this.rootDirectoryNameLower) {
        throw new ArchiveExtractionError(
          'ARCHIVE_PATH_COLLISION',
          'Archive contains case-colliding top-level root directory names.'
        );
      }
      throw new ArchiveExtractionError(
        'INCONSISTENT_ARCHIVE_ROOT',
        'Archive contains inconsistent top-level root directories.'
      );
    }

    // Root directory itself (`<root>/`) maps cleanly to the workspace root directory.
    if (parsed.segments.length === 1 && entryType === 'directory') {
      if (this.seenExplicitRootEntry) {
        throw new ArchiveExtractionError(
          'ARCHIVE_PATH_COLLISION',
          'Archive contains duplicate top-level root directory entries.'
        );
      }
      this.seenExplicitRootEntry = true;
      return {
        isRootDirectoryEntry: true,
        relativePosixPath: '',
        relativeSegments: [],
      };
    }

    const relativeSegments = parsed.segments.slice(1);
    const relativePosixPath = relativeSegments.join('/');
    const relativeLower = relativePosixPath.toLowerCase();

    // Verify all ancestor prefixes are non-file directories with exact matching case.
    for (let i = 1; i < relativeSegments.length; i += 1) {
      const ancestor = relativeSegments.slice(0, i).join('/');
      const ancestorLower = ancestor.toLowerCase();

      if (this.fileLowerSet.has(ancestorLower)) {
        throw new ArchiveExtractionError(
          'FILE_DIRECTORY_CONFLICT',
          'Archive entry uses an existing regular file path as a parent directory.'
        );
      }

      const existingDirCase = this.dirExactByLower.get(ancestorLower);
      if (existingDirCase !== undefined && existingDirCase !== ancestor) {
        throw new ArchiveExtractionError(
          'ARCHIVE_PATH_COLLISION',
          'Archive contains case-insensitive parent directory path collision.'
        );
      }
    }

    if (entryType === 'directory') {
      if (this.fileLowerSet.has(relativeLower)) {
        throw new ArchiveExtractionError(
          'FILE_DIRECTORY_CONFLICT',
          'Archive directory entry conflicts with an existing regular file path.'
        );
      }

      if (this.seenExplicitEntries.has(relativePosixPath)) {
        throw new ArchiveExtractionError(
          'ARCHIVE_PATH_COLLISION',
          'Archive contains duplicate entry paths.'
        );
      }

      const existingDirCase = this.dirExactByLower.get(relativeLower);
      if (existingDirCase !== undefined && existingDirCase !== relativePosixPath) {
        throw new ArchiveExtractionError(
          'ARCHIVE_PATH_COLLISION',
          'Archive contains case-insensitive directory path collision.'
        );
      }

      this.seenExplicitEntries.add(relativePosixPath);
      this.registerAncestors(relativeSegments);
      this.dirExactByLower.set(relativeLower, relativePosixPath);
    } else {
      if (this.dirExactByLower.has(relativeLower)) {
        throw new ArchiveExtractionError(
          'FILE_DIRECTORY_CONFLICT',
          'Archive regular file entry conflicts with an existing directory path.'
        );
      }

      if (this.seenExplicitEntries.has(relativePosixPath)) {
        throw new ArchiveExtractionError(
          'ARCHIVE_PATH_COLLISION',
          'Archive contains duplicate entry paths.'
        );
      }

      if (this.fileLowerSet.has(relativeLower)) {
        throw new ArchiveExtractionError(
          'ARCHIVE_PATH_COLLISION',
          'Archive contains case-insensitive duplicate regular file paths.'
        );
      }

      this.seenExplicitEntries.add(relativePosixPath);
      this.registerAncestors(relativeSegments.slice(0, -1));
      this.fileLowerSet.add(relativeLower);
    }

    return {
      isRootDirectoryEntry: false,
      relativePosixPath,
      relativeSegments,
    };
  }

  private registerAncestors(dirSegments: readonly string[]): void {
    for (let i = 1; i <= dirSegments.length; i += 1) {
      const prefix = dirSegments.slice(0, i).join('/');
      const prefixLower = prefix.toLowerCase();
      if (!this.dirExactByLower.has(prefixLower)) {
        this.dirExactByLower.set(prefixLower, prefix);
      }
    }
  }
}

function classifyStreamError(
  err: unknown,
  workspacePathsToRedact: readonly string[]
): ArchiveExtractionError | InternalAcquisitionError {
  if (err instanceof ArchiveExtractionError || err instanceof InternalAcquisitionError) {
    return err;
  }

  const errno = (err as NodeJS.ErrnoException | undefined)?.code;
  const rawMessage = err instanceof Error ? err.message : String(err);

  if (errno === 'Z_DATA_ERROR' || errno === 'Z_VERSION_ERROR') {
    return new ArchiveExtractionError(
      'INVALID_ARCHIVE_FORMAT',
      'Repository archive is not a valid gzip-compressed stream.',
      workspacePathsToRedact
    );
  }

  if (errno === 'Z_BUF_ERROR') {
    return new ArchiveExtractionError(
      'MALFORMED_ARCHIVE',
      'Repository archive gzip stream was truncated or malformed.',
      workspacePathsToRedact
    );
  }

  if (/unknown format|needs to be gunzipped/i.test(rawMessage)) {
    return new ArchiveExtractionError(
      'INVALID_ARCHIVE_FORMAT',
      'Repository archive does not contain a supported USTAR or GNU tar header.',
      workspacePathsToRedact
    );
  }

  if (/pax path contains a null byte/i.test(rawMessage)) {
    return new ArchiveExtractionError(
      'INVALID_ARCHIVE_PATH',
      'Archive entry PAX path contains prohibited NUL characters.',
      workspacePathsToRedact
    );
  }

  if (
    /Invalid tar header|Unexpected end of data|Invalid header|Header exceeds max size|pax path/i.test(
      rawMessage
    )
  ) {
    return new ArchiveExtractionError(
      'MALFORMED_ARCHIVE',
      'Repository archive tar stream is malformed or truncated.',
      workspacePathsToRedact
    );
  }

  return new ArchiveExtractionError(
    'MALFORMED_ARCHIVE',
    `Repository archive extraction failed cleanly: ${redactHostPaths(rawMessage, workspacePathsToRedact)}`,
    workspacePathsToRedact
  );
}

function isAllZeroTarBlock(block: Buffer): boolean {
  for (let i = 0; i < block.length; i += 1) {
    if (block[i] !== 0) {
      return false;
    }
  }
  return true;
}

function computeTarChecksum(block: Buffer): number {
  let sum = 8 * 32;
  for (let i = 0; i < 148; i += 1) {
    sum += block[i] ?? 0;
  }
  for (let j = 156; j < TAR_BLOCK_BYTES; j += 1) {
    sum += block[j] ?? 0;
  }
  return sum;
}

function decodeStrictTarOctal(
  block: Buffer,
  offset: number,
  length: number,
  pathsToRedact: readonly string[],
  errorCode: ArchiveExtractionErrorCode = 'MALFORMED_ARCHIVE'
): number {
  const slice = block.subarray(offset, offset + length);
  let start = 0;
  while (start < slice.length && (slice[start] === 0 || slice[start] === 0x20)) {
    start += 1;
  }
  let end = slice.length;
  while (end > start && (slice[end - 1] === 0 || slice[end - 1] === 0x20)) {
    end -= 1;
  }
  if (start === end) {
    return 0;
  }
  const str = slice.subarray(start, end).toString('ascii');
  if (!/^[0-7]+$/.test(str)) {
    throw new ArchiveExtractionError(
      errorCode,
      'Archive tar header contains invalid octal numeric field.',
      pathsToRedact
    );
  }
  const value = Number.parseInt(str, 8);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ArchiveExtractionError(
      errorCode,
      'Archive tar header numeric field overflowed.',
      pathsToRedact
    );
  }
  return value;
}

function decodeStrictTarSize(block: Buffer, pathsToRedact: readonly string[]): number {
  const firstByte = block[124] ?? 0;
  if ((firstByte & 0x80) !== 0) {
    // GNU/PAX base-256 size must have MSB=1 and bit6=0 (positive); signed/negative encodings like 0x81 are malformed.
    if (firstByte !== 0x80) {
      throw new ArchiveExtractionError(
        'MALFORMED_ARCHIVE',
        'Archive tar header contains invalid base-256 size encoding.',
        pathsToRedact
      );
    }
    let size = 0n;
    for (let i = 125; i < 136; i += 1) {
      size = (size << 8n) | BigInt(block[i] ?? 0);
    }
    if (size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new ArchiveExtractionError(
        'MALFORMED_ARCHIVE',
        'Archive tar entry size exceeds safe integer range.',
        pathsToRedact
      );
    }
    return Number(size);
  }
  return decodeStrictTarOctal(block, 124, 12, pathsToRedact);
}

function isValidUstarOrGnuMagic(block: Buffer): boolean {
  const magic = block.subarray(257, 263).toString('latin1');
  if (magic === 'ustar\0') {
    return true;
  }
  if (magic === 'ustar ') {
    return block[263] === 0x20 && block[264] === 0x00;
  }
  return false;
}

function roundUpToTarBlock(byteLength: number): number {
  const remainder = byteLength % TAR_BLOCK_BYTES;
  return remainder === 0 ? byteLength : byteLength + (TAR_BLOCK_BYTES - remainder);
}

function validateAndParsePaxPayload(
  payload: Buffer,
  isGlobalHeader: boolean,
  pathsToRedact: readonly string[]
): { pendingPaxSize: number | null } {
  let offset = 0;
  let pendingPaxSize: number | null = null;
  const allowedKeys = isGlobalHeader ? ALLOWED_GLOBAL_PAX_KEYS : ALLOWED_PAX_KEYS;

  while (offset < payload.length) {
    const spaceIndex = payload.indexOf(0x20, offset);
    if (spaceIndex <= offset) {
      throw new ArchiveExtractionError(
        'MALFORMED_ARCHIVE',
        'Archive PAX extended header contains malformed record length.',
        pathsToRedact
      );
    }
    const lengthToken = payload.subarray(offset, spaceIndex).toString('ascii');
    if (!/^\d+$/.test(lengthToken)) {
      throw new ArchiveExtractionError(
        'MALFORMED_ARCHIVE',
        'Archive PAX extended header record length must be decimal.',
        pathsToRedact
      );
    }
    const recordLength = Number.parseInt(lengthToken, 10);
    if (
      !Number.isSafeInteger(recordLength) ||
      recordLength < 5 ||
      offset + recordLength > payload.length
    ) {
      throw new ArchiveExtractionError(
        'MALFORMED_ARCHIVE',
        'Archive PAX extended header record length is out of bounds.',
        pathsToRedact
      );
    }
    const recordEnd = offset + recordLength;
    if (payload[recordEnd - 1] !== 0x0a) {
      throw new ArchiveExtractionError(
        'MALFORMED_ARCHIVE',
        'Archive PAX extended header record is missing newline terminator.',
        pathsToRedact
      );
    }

    const eqIndex = payload.indexOf(0x3d, spaceIndex + 1);
    if (eqIndex <= spaceIndex + 1 || eqIndex >= recordEnd) {
      throw new ArchiveExtractionError(
        'MALFORMED_ARCHIVE',
        'Archive PAX extended header record is missing key-value separator.',
        pathsToRedact
      );
    }

    const key = payload.subarray(spaceIndex + 1, eqIndex).toString('utf8');
    const value = payload.subarray(eqIndex + 1, recordEnd - 1).toString('utf8');
    if (!isWellFormedUnicode(key) || !isWellFormedUnicode(value)) {
      throw new ArchiveExtractionError(
        'MALFORMED_ARCHIVE',
        'Archive PAX extended header contains ill-formed UTF-8 metadata.',
        pathsToRedact
      );
    }

    if (!isGlobalHeader && key === 'linkpath') {
      throw new ArchiveExtractionError(
        'UNSUPPORTED_ENTRY_TYPE',
        'Archive PAX linkpath metadata is forbidden.',
        pathsToRedact
      );
    }

    if (!allowedKeys.has(key)) {
      throw new ArchiveExtractionError(
        'UNSUPPORTED_ARCHIVE_METADATA',
        'Archive contains unsupported PAX extension metadata.',
        pathsToRedact
      );
    }

    if (!isGlobalHeader && key === 'path' && value.length === 0) {
      throw new ArchiveExtractionError(
        'INVALID_ARCHIVE_PATH',
        'Archive PAX path override must not be empty.',
        pathsToRedact
      );
    }

    if (!isGlobalHeader && key === 'size') {
      if (!/^\d+$/.test(value)) {
        throw new ArchiveExtractionError(
          'MALFORMED_ARCHIVE',
          'Archive PAX size metadata is malformed.',
          pathsToRedact
        );
      }
      const parsedSize = Number(value);
      if (!Number.isSafeInteger(parsedSize)) {
        throw new ArchiveExtractionError(
          'MALFORMED_ARCHIVE',
          'Archive PAX size metadata is out of range.',
          pathsToRedact
        );
      }
      pendingPaxSize = parsedSize;
    }

    offset = recordEnd;
  }

  return { pendingPaxSize };
}

/**
 * Pre-parser streaming tar guard positioned immediately before `tar-stream`.
 *
 * Enforces bounded extended metadata memory and header counts (`x`, `g`, `L`, `N`, `K`) before
 * `tar-stream` allocates internal extended-header buffers (`4 MiB` per header in tar-stream 3.3.0),
 * and validates malformed base-256 sizes (`0x81`), PAX records, and empty PAX path overrides cleanly.
 */
function createTarMetadataGuardTransform(
  limits: ArchiveExtractionLimits,
  pathsToRedact: readonly string[],
  recordFailure: (err: unknown) => Error
): Transform {
  type GuardState = 'HEADER' | 'EXTENDED_DATA' | 'PAYLOAD_SKIP';

  let state: GuardState = 'HEADER';
  let headerRemainder: Buffer = Buffer.alloc(0);

  let extendedHeaderBuffer: Buffer = Buffer.alloc(0);
  let extendedHeaderChunks: Buffer[] = [];
  let extendedDataBytesReceived = 0;
  let extendedDataTotalBytes = 0;
  let extendedDataPayloadBytes = 0;
  let extendedTypeflag = 0;

  let payloadBytesRemaining = 0;
  let pendingPaxSize: number | null = null;
  let totalMetadataBytes = 0;
  let extendedHeaderCount = 0;
  let consecutiveExtendedHeaders = 0;
  let globalPaxHeaderCount = 0;

  const processHeaderBlock = (block: Buffer, outChunks: Buffer[]) => {
    if (isAllZeroTarBlock(block)) {
      outChunks.push(block);
      return;
    }

    const expectedChecksum = computeTarChecksum(block);
    const actualChecksum = decodeStrictTarOctal(
      block,
      148,
      8,
      pathsToRedact,
      'INVALID_ARCHIVE_FORMAT'
    );
    if (expectedChecksum !== actualChecksum) {
      throw new ArchiveExtractionError(
        'INVALID_ARCHIVE_FORMAT',
        'Archive tar header checksum validation failed.',
        pathsToRedact
      );
    }

    if (!isValidUstarOrGnuMagic(block)) {
      throw new ArchiveExtractionError(
        'INVALID_ARCHIVE_FORMAT',
        'Archive tar header uses an unsupported or unknown format.',
        pathsToRedact
      );
    }

    const rawTypeByte = block[156] ?? 0;
    const typeflag = rawTypeByte === 0 ? 0 : rawTypeByte - 48;
    const ustarSize = decodeStrictTarSize(block, pathsToRedact);

    // Reject GNU long link path (`'K'`) before tar-stream parses it.
    if (typeflag === 27) {
      throw new ArchiveExtractionError(
        'UNSUPPORTED_ENTRY_TYPE',
        'Archive contains unsupported GNU long link path entry.',
        pathsToRedact
      );
    }

    if (typeflag === 72 || typeflag === 55 || typeflag === 28 || typeflag === 30) {
      consecutiveExtendedHeaders += 1;
      if (consecutiveExtendedHeaders > MAX_CONSECUTIVE_EXTENDED_HEADERS) {
        throw new ArchiveExtractionError(
          'EXCESSIVE_ARCHIVE_METADATA',
          'Archive contains too many consecutive extended metadata headers.',
          pathsToRedact
        );
      }

      extendedHeaderCount += 1;
      if (extendedHeaderCount > limits.maxExtendedHeaders) {
        throw new ArchiveExtractionError(
          'EXCESSIVE_ARCHIVE_METADATA',
          'Archive extended header count exceeds maximum allowed limit.',
          pathsToRedact
        );
      }

      if (typeflag === 55) {
        globalPaxHeaderCount += 1;
        if (globalPaxHeaderCount > MAX_GLOBAL_PAX_HEADERS) {
          throw new ArchiveExtractionError(
            'EXCESSIVE_ARCHIVE_METADATA',
            'Archive contains too many global PAX metadata headers.',
            pathsToRedact
          );
        }
      }

      if (ustarSize > limits.maxEntryMetadataBytes) {
        throw new ArchiveExtractionError(
          'EXCESSIVE_ARCHIVE_METADATA',
          'Archive extended metadata header exceeds maximum per-entry metadata size.',
          pathsToRedact
        );
      }

      totalMetadataBytes += ustarSize;
      if (totalMetadataBytes > limits.maxTotalMetadataBytes) {
        throw new ArchiveExtractionError(
          'EXCESSIVE_ARCHIVE_METADATA',
          'Archive total extended metadata exceeds maximum allowed metadata budget.',
          pathsToRedact
        );
      }

      extendedTypeflag = typeflag;
      extendedHeaderBuffer = block;
      extendedHeaderChunks = [];
      extendedDataPayloadBytes = ustarSize;
      extendedDataTotalBytes = roundUpToTarBlock(ustarSize);
      extendedDataBytesReceived = 0;

      if (extendedDataTotalBytes === 0) {
        if (typeflag === 28 || typeflag === 30) {
          throw new ArchiveExtractionError(
            'MALFORMED_ARCHIVE',
            'Archive GNU long path header has zero payload bytes.',
            pathsToRedact
          );
        }
        outChunks.push(extendedHeaderBuffer);
        state = 'HEADER';
      } else {
        state = 'EXTENDED_DATA';
      }
      return;
    }

    consecutiveExtendedHeaders = 0;
    const effectiveSize = pendingPaxSize ?? ustarSize;
    pendingPaxSize = null;
    if (effectiveSize > limits.maxDecompressedBytes) {
      throw new ArchiveExtractionError(
        'DECOMPRESSED_SIZE_EXCEEDED',
        'Archive entry size exceeds maximum allowed decompressed archive size.',
        pathsToRedact
      );
    }

    outChunks.push(block);
    const alignedPayloadBytes = roundUpToTarBlock(effectiveSize);
    if (alignedPayloadBytes > 0) {
      payloadBytesRemaining = alignedPayloadBytes;
      state = 'PAYLOAD_SKIP';
    }
  };

  const finalizeExtendedData = (outChunks: Buffer[]) => {
    const combined =
      extendedHeaderChunks.length === 1
        ? (extendedHeaderChunks[0] ?? Buffer.alloc(0))
        : Buffer.concat(extendedHeaderChunks, extendedDataTotalBytes);
    const payload = combined.subarray(0, extendedDataPayloadBytes);

    if (extendedTypeflag === 72 || extendedTypeflag === 55) {
      const { pendingPaxSize: parsedPaxSize } = validateAndParsePaxPayload(
        payload,
        extendedTypeflag === 55,
        pathsToRedact
      );
      if (extendedTypeflag === 72 && parsedPaxSize !== null) {
        pendingPaxSize = parsedPaxSize;
      }
    } else if (extendedTypeflag === 28 || extendedTypeflag === 30) {
      let end = payload.length;
      while (end > 0 && payload[end - 1] === 0) {
        end -= 1;
      }
      const longPath = payload.subarray(0, end).toString('utf8');
      if (longPath.length === 0 || !isWellFormedUnicode(longPath)) {
        throw new ArchiveExtractionError(
          'INVALID_ARCHIVE_PATH',
          'Archive GNU long path metadata is empty or ill-formed.',
          pathsToRedact
        );
      }
    }

    outChunks.push(extendedHeaderBuffer, combined);
    extendedHeaderBuffer = Buffer.alloc(0);
    extendedHeaderChunks = [];
    extendedDataBytesReceived = 0;
    extendedDataTotalBytes = 0;
    extendedDataPayloadBytes = 0;
    state = 'HEADER';
  };

  return new Transform({
    highWaterMark: ARCHIVE_STREAM_HIGH_WATER_MARK,
    transform(chunk, _encoding, callback) {
      try {
        const input = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const combined =
          headerRemainder.length > 0 ? Buffer.concat([headerRemainder, input]) : input;
        headerRemainder = Buffer.alloc(0);

        let offset = 0;
        const outChunks: Buffer[] = [];

        while (offset < combined.length) {
          if (state === 'PAYLOAD_SKIP') {
            const take = Math.min(payloadBytesRemaining, combined.length - offset);
            outChunks.push(combined.subarray(offset, offset + take));
            offset += take;
            payloadBytesRemaining -= take;
            if (payloadBytesRemaining === 0) {
              state = 'HEADER';
            }
            continue;
          }

          if (state === 'EXTENDED_DATA') {
            const needed = extendedDataTotalBytes - extendedDataBytesReceived;
            const take = Math.min(needed, combined.length - offset);
            const slice = Buffer.from(combined.subarray(offset, offset + take));
            extendedHeaderChunks.push(slice);
            extendedDataBytesReceived += take;
            offset += take;
            if (extendedDataBytesReceived === extendedDataTotalBytes) {
              finalizeExtendedData(outChunks);
            }
            continue;
          }

          const available = combined.length - offset;
          if (available < TAR_BLOCK_BYTES) {
            headerRemainder = Buffer.from(combined.subarray(offset));
            break;
          }

          const headerBlock = Buffer.from(combined.subarray(offset, offset + TAR_BLOCK_BYTES));
          offset += TAR_BLOCK_BYTES;
          processHeaderBlock(headerBlock, outChunks);
        }

        if (outChunks.length > 0) {
          this.push(outChunks.length === 1 ? outChunks[0] : Buffer.concat(outChunks));
        }
        callback();
      } catch (err) {
        callback(recordFailure(err));
      }
    },
    flush(callback) {
      if (state !== 'HEADER' || headerRemainder.length > 0) {
        callback(
          recordFailure(
            new ArchiveExtractionError(
              'MALFORMED_ARCHIVE',
              'Archive tar stream ended unexpectedly mid-header or mid-entry.',
              pathsToRedact
            )
          )
        );
        return;
      }
      callback();
    },
  });
}

/**
 * Consumes a bounded repository `.tar.gz` acquisition stream, enforces streaming size/path/entry/type
 * defenses, extracts validated files sequentially into a newly created `0700` isolated workspace with
 * `0600` non-executable regular files, and guarantees workspace cleanup on any error or cancellation.
 *
 * Security boundary: assumes the host OS kernel, worker UID, and dedicated workspace parent
 * directory are not shared with untrusted local actors (Node.js `fs/promises` path operations carry
 * inherent TOCTOU windows between symlink/containment verification and subsequent filesystem calls).
 */
export async function extractRepositoryArchive(
  input: ExtractRepositoryArchiveInput
): Promise<ExtractedWorkspaceHandle> {
  const limits = resolveArchiveExtractionLimits(input.limits, input.archive.maxArchiveBytes);
  const logger = input.logger ?? createWorkerLogger('warn');

  if (input.shutdownSignal?.aborted) {
    throw new ArchiveExtractionError(
      'WORKER_SHUTDOWN',
      'Worker shutdown prevented repository archive extraction.'
    );
  }

  if (input.signal?.aborted) {
    throw new ArchiveExtractionError(
      'EXTRACTION_CANCELLED',
      'Repository archive extraction was explicitly cancelled before start.'
    );
  }

  const mkdtempFn = input.workspaceFsOps?.mkdtemp ?? mkdtemp;
  const chmodFn = input.workspaceFsOps?.chmod ?? chmod;
  const lstatFn = input.workspaceFsOps?.lstat ?? lstat;
  const realpathFn = input.workspaceFsOps?.realpath ?? realpath;
  const rmFn = input.workspaceFsOps?.rm ?? rm;

  const trustedParentRealpath = await ensureTrustedWorkspaceParentDir(
    input.workspaceParentDir,
    input.workspaceFsOps
  );
  const scanPrefix = sanitizeScanIdForPrefix(input.archive.scanId);
  const randomSuffix = randomUUID().slice(0, 12);

  let createdWorkspacePath: string | null = null;
  let workspacePath: string;
  let workspaceRealpath: string;
  try {
    workspacePath = await mkdtempFn(
      path.join(trustedParentRealpath, `${WORKSPACE_DIR_PREFIX}${scanPrefix}-${randomSuffix}-`)
    );
    createdWorkspacePath = workspacePath;
    await chmodFn(workspacePath, WORKSPACE_DIR_MODE);
    const createdStat = await lstatFn(workspacePath);
    if (createdStat.isSymbolicLink() || !createdStat.isDirectory()) {
      throw new ArchiveExtractionError(
        'WORKSPACE_CONTAINMENT_ERROR',
        'Newly created workspace path failed directory verification.',
        [trustedParentRealpath, workspacePath]
      );
    }
    workspaceRealpath = await realpathFn(workspacePath);
    assertWorkspaceContainment(
      trustedParentRealpath,
      workspaceRealpath,
      path.basename(workspaceRealpath)
    );
  } catch (err) {
    if (createdWorkspacePath !== null) {
      try {
        await rmFn(createdWorkspacePath, { recursive: true, force: true });
      } catch (cleanupErr) {
        logger.warn(
          formatSafeWorkerMessage(
            `Failed to remove partially initialized workspace directory: ${redactHostPaths(
              cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr),
              [trustedParentRealpath, createdWorkspacePath]
            )}`
          )
        );
      }
    }
    if (err instanceof ArchiveExtractionError) {
      throw err;
    }
    throw new ArchiveExtractionError(
      'WORKSPACE_ERROR',
      'Failed to create isolated temporary workspace directory.',
      [trustedParentRealpath]
    );
  }

  const workspaceId = path.basename(workspaceRealpath);
  const pathsToRedact = [trustedParentRealpath, workspacePath, workspaceRealpath];

  let cleanedUp = false;
  let cleanupInFlight: Promise<WorkspaceCleanupResult> | null = null;

  const performCleanup = async (): Promise<WorkspaceCleanupResult> => {
    if (cleanupInFlight) {
      return await cleanupInFlight;
    }
    if (cleanedUp) {
      return { cleaned: true, alreadyCleaned: true };
    }
    cleanupInFlight = cleanupWorkspaceDirectory(workspaceRealpath, trustedParentRealpath)
      .then((res) => {
        cleanedUp = true;
        cleanupInFlight = null;
        return res;
      })
      .catch((cleanupErr) => {
        cleanupInFlight = null;
        const safeErr =
          cleanupErr instanceof ArchiveExtractionError
            ? cleanupErr
            : new ArchiveExtractionError(
                'WORKSPACE_CLEANUP_FAILED',
                'Failed to clean up temporary workspace directory.',
                pathsToRedact
              );
        logger.error('Repository workspace cleanup failed.', {
          scanId: input.archive.scanId,
          workspaceId,
          code: safeErr.code,
        });
        throw safeErr;
      });
    return await cleanupInFlight;
  };

  const verifiedDirectories = new Set<string>(['']);
  const layoutValidator = new ArchiveLayoutValidator();

  let compressedBytes = 0;
  let decompressedBytes = 0;
  let totalFileBytes = 0;
  let fileCount = 0;
  let directoryCount = 0;
  let entryCount = 0;

  let firstFailure: ArchiveExtractionError | InternalAcquisitionError | null = null;
  let activeEntryPromise: Promise<void> = Promise.resolve();
  let abortedFlag = false;

  const recordFailure = (err: unknown): ArchiveExtractionError | InternalAcquisitionError => {
    if (!firstFailure) {
      firstFailure = classifyStreamError(err, pathsToRedact);
    }
    return firstFailure;
  };

  const sourceStream = input.archive.stream;
  const compressedLimiter = new Transform({
    highWaterMark: ARCHIVE_STREAM_HIGH_WATER_MARK,
    transform(chunk: Buffer, _encoding, callback) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      compressedBytes += buf.byteLength;
      if (compressedBytes > limits.maxCompressedBytes) {
        const limitErr = recordFailure(
          new ArchiveExtractionError(
            'COMPRESSED_SIZE_EXCEEDED',
            'Compressed repository archive exceeds maximum allowed size limit.',
            pathsToRedact
          )
        );
        callback(limitErr);
        return;
      }
      callback(null, buf);
    },
  });

  const gunzipStream = zlib.createGunzip({
    chunkSize: 16 * 1024,
  });

  const decompressedLimiter = new Transform({
    highWaterMark: ARCHIVE_STREAM_HIGH_WATER_MARK,
    transform(chunk: Buffer, _encoding, callback) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      decompressedBytes += buf.byteLength;
      if (decompressedBytes > limits.maxDecompressedBytes) {
        const limitErr = recordFailure(
          new ArchiveExtractionError(
            'DECOMPRESSED_SIZE_EXCEEDED',
            'Decompressed tar stream exceeds maximum allowed size limit (potential decompression bomb).',
            pathsToRedact
          )
        );
        callback(limitErr);
        return;
      }
      callback(null, buf);
    },
  });

  const tarMetadataGuard = createTarMetadataGuardTransform(limits, pathsToRedact, recordFailure);

  // `allowUnknownFormat` defaults to false in tar-stream so only USTAR/GNU tar headers are accepted.
  const tarExtract = createTarExtract();

  const destroyAllStreams = (err: Error) => {
    if (!sourceStream.destroyed) {
      sourceStream.destroy(err);
    }
    if (!compressedLimiter.destroyed) {
      compressedLimiter.destroy(err);
    }
    if (!gunzipStream.destroyed) {
      gunzipStream.destroy(err);
    }
    if (!decompressedLimiter.destroyed) {
      decompressedLimiter.destroy(err);
    }
    if (!tarMetadataGuard.destroyed) {
      tarMetadataGuard.destroy(err);
    }
    if (!tarExtract.destroyed) {
      tarExtract.destroy(err);
    }
  };

  const onSourceError = (err: unknown) => {
    recordFailure(err);
  };
  const onGunzipError = (err: unknown) => {
    recordFailure(err);
  };
  const onGuardError = (err: unknown) => {
    recordFailure(err);
  };
  const onTarError = (err: unknown) => {
    recordFailure(err);
  };

  const triggerAbort = (isShutdown: boolean) => {
    if (abortedFlag) {
      return;
    }
    abortedFlag = true;
    const cancelErr = recordFailure(
      new ArchiveExtractionError(
        isShutdown ? 'WORKER_SHUTDOWN' : 'EXTRACTION_CANCELLED',
        isShutdown
          ? 'Worker shutdown interrupted repository archive extraction.'
          : 'Repository archive extraction was explicitly cancelled.',
        pathsToRedact
      )
    );
    try {
      input.archive.abort(isShutdown ? 'shutdown' : 'cancelled');
    } catch {
      // Upstream stream may already be settled/destroyed.
    }
    destroyAllStreams(cancelErr);
  };

  const onCancelled = () => triggerAbort(false);
  const onShutdown = () => triggerAbort(true);

  sourceStream.on('error', onSourceError);
  gunzipStream.on('error', onGunzipError);
  tarMetadataGuard.on('error', onGuardError);
  tarExtract.on('error', onTarError);
  input.signal?.addEventListener('abort', onCancelled, { once: true });
  input.shutdownSignal?.addEventListener('abort', onShutdown, { once: true });

  const ensureDirectoryChain = async (relativeSegments: readonly string[]): Promise<void> => {
    for (let i = 1; i <= relativeSegments.length; i += 1) {
      const relPosix = relativeSegments.slice(0, i).join('/');
      if (verifiedDirectories.has(relPosix)) {
        continue;
      }

      const targetAbs = path.join(workspaceRealpath, ...relativeSegments.slice(0, i));
      const relToRoot = path.relative(workspaceRealpath, targetAbs);
      if (
        relToRoot.length === 0 ||
        relToRoot === '.' ||
        relToRoot.startsWith('..') ||
        path.isAbsolute(relToRoot)
      ) {
        throw new ArchiveExtractionError(
          'WORKSPACE_CONTAINMENT_ERROR',
          'Resolved directory escaped workspace containment root.',
          pathsToRedact
        );
      }

      try {
        await mkdir(targetAbs, { mode: WORKSPACE_DIR_MODE });
      } catch (mkdirErr) {
        const errno = (mkdirErr as NodeJS.ErrnoException)?.code;
        if (errno === 'EEXIST') {
          let existingStat;
          try {
            existingStat = await lstat(targetAbs);
          } catch {
            throw new ArchiveExtractionError(
              'WORKSPACE_ERROR',
              'Failed to inspect existing workspace directory entry.',
              pathsToRedact
            );
          }
          if (existingStat.isSymbolicLink() || !existingStat.isDirectory()) {
            throw new ArchiveExtractionError(
              'FILE_DIRECTORY_CONFLICT',
              'Existing non-directory entry prevented workspace directory creation.',
              pathsToRedact
            );
          }
        } else {
          throw new ArchiveExtractionError(
            'WORKSPACE_ERROR',
            'Failed to create workspace subdirectory.',
            pathsToRedact
          );
        }
      }

      try {
        await chmod(targetAbs, WORKSPACE_DIR_MODE);
        const dirStat = await lstat(targetAbs);
        if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
          throw new ArchiveExtractionError(
            'WORKSPACE_CONTAINMENT_ERROR',
            'Workspace subdirectory failed symlink containment verification.',
            pathsToRedact
          );
        }
      } catch (verifyErr) {
        if (verifyErr instanceof ArchiveExtractionError) {
          throw verifyErr;
        }
        throw new ArchiveExtractionError(
          'WORKSPACE_ERROR',
          'Failed to verify workspace subdirectory permissions.',
          pathsToRedact
        );
      }

      verifiedDirectories.add(relPosix);
    }
  };

  tarExtract.on('entry', (header, entryStream, next) => {
    entryStream.on('error', () => undefined);

    const processEntry = async () => {
      if (abortedFlag || firstFailure) {
        throw (
          firstFailure ?? new ArchiveExtractionError('EXTRACTION_CANCELLED', 'Extraction aborted.')
        );
      }

      entryCount += 1;
      if (entryCount > limits.maxEntries) {
        throw new ArchiveExtractionError(
          'ENTRY_COUNT_EXCEEDED',
          'Archive entry count exceeds maximum allowed entry limit.'
        );
      }

      const entryType = validateEntryHeaderMetadata(header, limits);
      const registeredPath = layoutValidator.registerEntry(header.name, entryType, limits);

      if (registeredPath.isRootDirectoryEntry) {
        directoryCount += 1;
        entryStream.resume();
        return;
      }

      if (entryType === 'directory') {
        await ensureDirectoryChain(registeredPath.relativeSegments);
        directoryCount += 1;
        entryStream.resume();
        return;
      }

      const parentSegments = registeredPath.relativeSegments.slice(0, -1);
      if (parentSegments.length > 0) {
        await ensureDirectoryChain(parentSegments);
      }

      const fileAbs = path.join(workspaceRealpath, ...registeredPath.relativeSegments);
      const relCheck = path.relative(workspaceRealpath, fileAbs);
      if (
        relCheck.length === 0 ||
        relCheck === '.' ||
        relCheck.startsWith('..') ||
        path.isAbsolute(relCheck)
      ) {
        throw new ArchiveExtractionError(
          'WORKSPACE_CONTAINMENT_ERROR',
          'Resolved file destination escaped workspace containment root.',
          pathsToRedact
        );
      }

      const parentDirAbs = path.dirname(fileAbs);
      try {
        const parentStat = await lstat(parentDirAbs);
        if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) {
          throw new ArchiveExtractionError(
            'WORKSPACE_CONTAINMENT_ERROR',
            'Target file parent directory failed non-symlink verification.',
            pathsToRedact
          );
        }
      } catch (err) {
        if (err instanceof ArchiveExtractionError) {
          throw err;
        }
        throw new ArchiveExtractionError(
          'WORKSPACE_ERROR',
          'Target file parent directory could not be verified.',
          pathsToRedact
        );
      }

      const openFlags =
        fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0);

      let handle: FileHandle | null = null;
      let entryBytes = 0;

      try {
        try {
          handle = await open(fileAbs, openFlags, WORKSPACE_FILE_MODE);
          await handle.chmod(WORKSPACE_FILE_MODE);
        } catch (openErr) {
          const errno = (openErr as NodeJS.ErrnoException)?.code;
          if (errno === 'EEXIST' || errno === 'ELOOP') {
            throw new ArchiveExtractionError(
              'ARCHIVE_PATH_COLLISION',
              'Refusing to overwrite or follow symlink at destination file path.',
              pathsToRedact
            );
          }
          throw new ArchiveExtractionError(
            'WORKSPACE_ERROR',
            'Failed to open isolated workspace file for writing.',
            pathsToRedact
          );
        }

        for await (const rawChunk of entryStream) {
          if (abortedFlag || firstFailure) {
            throw (
              firstFailure ??
              new ArchiveExtractionError('EXTRACTION_CANCELLED', 'Extraction aborted.')
            );
          }

          const chunk = Buffer.isBuffer(rawChunk)
            ? rawChunk
            : typeof rawChunk === 'string'
              ? Buffer.from(rawChunk, 'utf8')
              : Buffer.from(rawChunk as Uint8Array);
          if (chunk.byteLength === 0) {
            continue;
          }

          entryBytes += chunk.byteLength;
          if (entryBytes > limits.maxFileBytes) {
            throw new ArchiveExtractionError(
              'FILE_SIZE_EXCEEDED',
              'Regular file payload exceeds maximum allowed individual file size limit.'
            );
          }

          if (entryBytes > header.size) {
            throw new ArchiveExtractionError(
              'INCONSISTENT_ENTRY_SIZE',
              'Regular file payload exceeded declared tar entry size.'
            );
          }

          await handle.write(chunk, 0, chunk.byteLength);
        }

        if (entryBytes !== header.size) {
          throw new ArchiveExtractionError(
            'INCONSISTENT_ENTRY_SIZE',
            'Regular file payload ended before matching declared tar entry size.'
          );
        }

        fileCount += 1;
        totalFileBytes += entryBytes;
      } finally {
        if (handle) {
          await handle.close().catch(() => undefined);
          handle = null;
        }
      }
    };

    const runPromise = processEntry().then(
      () => {
        next();
      },
      (err) => {
        const mapped = recordFailure(err);
        if (!entryStream.destroyed) {
          entryStream.destroy(mapped);
        }
        destroyAllStreams(mapped);
        next(mapped);
      }
    );

    activeEntryPromise = runPromise;
  });

  try {
    await pipeline(
      sourceStream,
      compressedLimiter,
      gunzipStream,
      decompressedLimiter,
      tarMetadataGuard,
      tarExtract
    );
    await activeEntryPromise;

    if (firstFailure) {
      throw firstFailure;
    }

    if (entryCount === 0) {
      throw new ArchiveExtractionError(
        'MALFORMED_ARCHIVE',
        'Repository archive contained zero entries.'
      );
    }

    const metadata: ExtractionMetadata = Object.freeze({
      scanId: input.archive.scanId,
      rootDirectoryName: layoutValidator.getRootDirectoryName(),
      compressedBytes,
      decompressedBytes,
      fileBytes: totalFileBytes,
      fileCount,
      directoryCount,
      entryCount,
    });

    return {
      workspaceId,
      workspacePath: workspaceRealpath,
      workspaceParentDir: trustedParentRealpath,
      metadata,
      isCleanedUp(): boolean {
        return cleanedUp;
      },
      async cleanup(): Promise<WorkspaceCleanupResult> {
        return await performCleanup();
      },
    };
  } catch (err) {
    const failureToThrow = recordFailure(err);

    await activeEntryPromise.catch(() => undefined);

    try {
      await performCleanup();
    } catch {
      // Partial workspace cleanup errors are logged safely; preserve original extraction failure for caller.
    }

    throw failureToThrow;
  } finally {
    input.signal?.removeEventListener('abort', onCancelled);
    input.shutdownSignal?.removeEventListener('abort', onShutdown);
    sourceStream.off('error', onSourceError);
    gunzipStream.off('error', onGunzipError);
    tarMetadataGuard.off('error', onGuardError);
    tarExtract.off('error', onTarError);
  }
}
