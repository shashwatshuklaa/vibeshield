import http from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
  symlink,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough, Readable } from 'node:stream';
import zlib from 'node:zlib';
import { pack as createTarPack } from 'tar-stream';
import { afterEach, describe, expect, it } from 'vitest';
import {
  ArchiveExtractionError,
  cleanupWorkspaceDirectory,
  createInternalAcquisitionClient,
  DEFAULT_MAX_ARCHIVE_ENTRIES,
  DEFAULT_MAX_ARCHIVE_PATH_DEPTH,
  DEFAULT_MAX_ARCHIVE_PATH_LENGTH,
  DEFAULT_MAX_COMPRESSED_ARCHIVE_BYTES,
  DEFAULT_MAX_DECOMPRESSED_ARCHIVE_BYTES,
  DEFAULT_MAX_ENTRY_METADATA_BYTES,
  DEFAULT_MAX_EXTENDED_HEADERS,
  DEFAULT_MAX_FILE_BYTES,
  DEFAULT_MAX_TOTAL_METADATA_BYTES,
  extractRepositoryArchive,
  loadWorkerConfig,
  resolveArchiveExtractionLimits,
  type AcquiredRepositoryArchive,
} from '../index.js';

const TEST_SCAN_ID = '507f1f77bcf86cd799439011';
const TEST_INTERNAL_SECRET = 'internal_worker_auth_secret_minimum_32_chars_long';
const TEST_LEASE_TOKEN = 'lease_token_fencing_secret_0123456789abcdef';

interface TarFixtureEntry {
  name: string;
  type?:
    | 'file'
    | 'directory'
    | 'link'
    | 'symlink'
    | 'character-device'
    | 'block-device'
    | 'fifo'
    | 'contiguous-file';
  content?: Buffer | string;
  linkname?: string;
  mode?: number;
  pax?: Record<string, string>;
}

async function packTarGz(entries: TarFixtureEntry[]): Promise<Buffer> {
  const pack = createTarPack();
  const gzip = zlib.createGzip();
  const chunks: Buffer[] = [];

  const collectPromise = new Promise<Buffer>((resolve, reject) => {
    gzip.on('data', (chunk: Buffer) => chunks.push(chunk));
    gzip.on('end', () => resolve(Buffer.concat(chunks)));
    gzip.on('error', reject);
    pack.on('error', reject);
  });

  pack.pipe(gzip);

  for (const entry of entries) {
    const type = entry.type ?? 'file';
    const body =
      type === 'file' || type === 'contiguous-file'
        ? Buffer.isBuffer(entry.content)
          ? entry.content
          : Buffer.from(entry.content ?? '', 'utf8')
        : undefined;

    await new Promise<void>((resolve, reject) => {
      const cb = (err?: Error | null) => (err ? reject(err) : resolve());
      if (body !== undefined) {
        pack.entry(
          {
            name: entry.name,
            type,
            mode: entry.mode,
            linkname: entry.linkname,
            pax: entry.pax,
          },
          body,
          cb
        );
      } else {
        pack.entry(
          {
            name: entry.name,
            type,
            mode: entry.mode,
            linkname: entry.linkname,
            pax: entry.pax,
          },
          cb
        );
      }
    });
  }

  pack.finalize();
  return await collectPromise;
}

/**
 * Crafts a raw 512-byte USTAR header (with valid tar checksum) + optional payload blocks,
 * allowing deterministic generation of malformed/sparse/control-char/base256 tar headers.
 */
function buildRawUstarTarGz(
  blocks: Array<{
    name: string;
    typeflag: number;
    size?: number;
    rawSizeBytes?: Buffer;
    payload?: Buffer;
    linkname?: string;
  }>
): Buffer {
  const parts: Buffer[] = [];

  for (const item of blocks) {
    const hdr = Buffer.alloc(512, 0);
    hdr.write(item.name, 0, Math.min(Buffer.byteLength(item.name), 100), 'utf8');
    hdr.write('0000644 ', 100, 8, 'ascii');
    hdr.write('0000000 ', 108, 8, 'ascii');
    hdr.write('0000000 ', 116, 8, 'ascii');
    if (item.rawSizeBytes) {
      item.rawSizeBytes.copy(hdr, 124, 0, Math.min(item.rawSizeBytes.length, 12));
    } else {
      const sz = item.size ?? item.payload?.byteLength ?? 0;
      hdr.write(`${sz.toString(8).padStart(11, '0')} `, 124, 12, 'ascii');
    }
    hdr.write('00000000000 ', 136, 12, 'ascii');
    hdr.fill(0x20, 148, 156); // placeholder spaces for checksum computation
    hdr[156] = item.typeflag;
    if (item.linkname) {
      hdr.write(item.linkname, 157, Math.min(Buffer.byteLength(item.linkname), 100), 'utf8');
    }
    hdr.write('ustar\0', 257, 6, 'ascii');
    hdr.write('00', 263, 2, 'ascii');

    let sum = 0;
    for (let i = 0; i < 512; i += 1) {
      sum += hdr[i]!;
    }
    hdr.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    parts.push(hdr);

    if (item.payload && item.payload.byteLength > 0) {
      parts.push(item.payload);
      const rem = item.payload.byteLength % 512;
      if (rem !== 0) {
        parts.push(Buffer.alloc(512 - rem, 0));
      }
    }
  }

  parts.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(Buffer.concat(parts));
}

function makeFakeAcquiredArchive(
  bufferOrStream: Buffer | Readable,
  overrides: Partial<AcquiredRepositoryArchive> = {}
): AcquiredRepositoryArchive {
  const stream = Buffer.isBuffer(bufferOrStream) ? Readable.from([bufferOrStream]) : bufferOrStream;

  return {
    scanId: TEST_SCAN_ID,
    contentType: 'application/gzip',
    declaredContentLength: Buffer.isBuffer(bufferOrStream) ? bufferOrStream.byteLength : null,
    maxArchiveBytes: DEFAULT_MAX_COMPRESSED_ARCHIVE_BYTES,
    stream,
    bytesReceived: () => (Buffer.isBuffer(bufferOrStream) ? bufferOrStream.byteLength : 0),
    abort: () => {
      if (!stream.destroyed) {
        stream.destroy();
      }
    },
    ...overrides,
  };
}

describe('Defensive Repository Archive Extraction & Workspace Isolation', () => {
  const tempParents: string[] = [];
  const serversToClose: Array<() => Promise<void>> = [];

  async function createIsolatedTestParent(): Promise<string> {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'vs-extract-test-parent-'));
    tempParents.push(dir);
    return dir;
  }

  async function startHttpServer(handler: http.RequestListener): Promise<string> {
    const server = http.createServer(handler);
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });
    serversToClose.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const addr = server.address() as AddressInfo;
    return `http://127.0.0.1:${addr.port}`;
  }

  afterEach(async () => {
    while (serversToClose.length > 0) {
      await serversToClose.pop()!();
    }
    while (tempParents.length > 0) {
      await rm(tempParents.pop()!, { recursive: true, force: true });
    }
  });

  describe('Limits, configuration & valid archive extraction', () => {
    it('enforces ceiling limits and validates WORKER_WORKSPACE_DIR configuration strictly', () => {
      const defaults = resolveArchiveExtractionLimits();
      expect(defaults).toEqual({
        maxCompressedBytes: DEFAULT_MAX_COMPRESSED_ARCHIVE_BYTES,
        maxDecompressedBytes: DEFAULT_MAX_DECOMPRESSED_ARCHIVE_BYTES,
        maxFileBytes: DEFAULT_MAX_FILE_BYTES,
        maxEntries: DEFAULT_MAX_ARCHIVE_ENTRIES,
        maxPathLength: DEFAULT_MAX_ARCHIVE_PATH_LENGTH,
        maxPathDepth: DEFAULT_MAX_ARCHIVE_PATH_DEPTH,
        maxEntryMetadataBytes: DEFAULT_MAX_ENTRY_METADATA_BYTES,
        maxTotalMetadataBytes: DEFAULT_MAX_TOTAL_METADATA_BYTES,
        maxExtendedHeaders: DEFAULT_MAX_EXTENDED_HEADERS,
      });

      expect(() =>
        resolveArchiveExtractionLimits({ maxFileBytes: DEFAULT_MAX_FILE_BYTES + 1 })
      ).toThrowError(ArchiveExtractionError);
      expect(() => resolveArchiveExtractionLimits({ maxEntries: 0 })).toThrowError(
        ArchiveExtractionError
      );
      expect(() => resolveArchiveExtractionLimits({ maxPathDepth: 25 })).toThrowError(
        ArchiveExtractionError
      );
      expect(() =>
        resolveArchiveExtractionLimits({
          maxTotalMetadataBytes: DEFAULT_MAX_TOTAL_METADATA_BYTES + 1,
        })
      ).toThrowError(ArchiveExtractionError);
      expect(() =>
        resolveArchiveExtractionLimits({ maxExtendedHeaders: DEFAULT_MAX_EXTENDED_HEADERS + 1 })
      ).toThrowError(ArchiveExtractionError);

      const cfg = loadWorkerConfig({
        NODE_ENV: 'test',
        LOG_LEVEL: 'silent',
        MONGODB_URI: 'mongodb://127.0.0.1:27017/vibeshield_test',
        REDIS_URL: 'redis://127.0.0.1:6379/0',
        WORKER_WORKSPACE_DIR: '/tmp/custom-vibeshield-ws',
      });
      expect(cfg.workspaceParentDir).toBe('/tmp/custom-vibeshield-ws');

      expect(() =>
        loadWorkerConfig({
          NODE_ENV: 'test',
          LOG_LEVEL: 'silent',
          MONGODB_URI: 'mongodb://127.0.0.1:27017/vibeshield_test',
          REDIS_URL: 'redis://127.0.0.1:6379/0',
          WORKER_WORKSPACE_DIR: 'relative/path',
        })
      ).toThrow(/WORKER_WORKSPACE_DIR/);

      expect(() =>
        loadWorkerConfig({
          NODE_ENV: 'test',
          LOG_LEVEL: 'silent',
          MONGODB_URI: 'mongodb://127.0.0.1:27017/vibeshield_test',
          REDIS_URL: 'redis://127.0.0.1:6379/0',
          WORKER_WORKSPACE_DIR: '/',
        })
      ).toThrow(/WORKER_WORKSPACE_DIR/);
    });

    it('extracts valid single-root archive cleanly with root stripping, empty/unicode files, restrictive permissions, and idempotent cleanup', async () => {
      const cwdBefore = process.cwd();
      const parentDir = await createIsolatedTestParent();

      const tgz = await packTarGz([
        { name: 'acme-web-app-a1b2c3d/', type: 'directory', mode: 0o777 },
        {
          name: 'acme-web-app-a1b2c3d/README.md',
          type: 'file',
          content: '# Acme Web App\n',
          mode: 0o4755, // executable + setuid bits MUST be stripped to 0o600
          pax: { comment: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678' },
        },
        { name: 'acme-web-app-a1b2c3d/empty.txt', type: 'file', content: '' },
        {
          name: 'acme-web-app-a1b2c3d/src/nested/café résumé-日本語.ts',
          type: 'file',
          content: 'export const ok = true;\n',
        },
        {
          name: 'acme-web-app-a1b2c3d/my folder/hello world.txt',
          type: 'file',
          content: 'space path ok',
        },
      ]);

      const workspace = await extractRepositoryArchive({
        archive: makeFakeAcquiredArchive(tgz),
        workspaceParentDir: parentDir,
        limits: {
          maxCompressedBytes: tgz.byteLength, // exact boundary succeeds
          maxFileBytes: 1024,
        },
      });

      expect(process.cwd()).toBe(cwdBefore);
      expect(workspace.isCleanedUp()).toBe(false);
      expect(workspace.metadata).toEqual({
        scanId: TEST_SCAN_ID,
        rootDirectoryName: 'acme-web-app-a1b2c3d',
        compressedBytes: tgz.byteLength,
        decompressedBytes: expect.any(Number),
        fileBytes:
          '# Acme Web App\n'.length + 'export const ok = true;\n'.length + 'space path ok'.length,
        fileCount: 4,
        directoryCount: 1,
        entryCount: 5,
      });

      // Verify root stripped and files readable with exact restrictive POSIX permissions
      const wsStat = await stat(workspace.workspacePath);
      expect(wsStat.mode & 0o777).toBe(0o700);

      const readmePath = path.join(workspace.workspacePath, 'README.md');
      expect(await readFile(readmePath, 'utf8')).toBe('# Acme Web App\n');
      expect((await stat(readmePath)).mode & 0o777).toBe(0o600);

      const emptyStat = await stat(path.join(workspace.workspacePath, 'empty.txt'));
      expect(emptyStat.size).toBe(0);
      expect(emptyStat.mode & 0o777).toBe(0o600);

      const subDirStat = await stat(path.join(workspace.workspacePath, 'src', 'nested'));
      expect(subDirStat.mode & 0o777).toBe(0o700);

      expect(
        await readFile(
          path.join(workspace.workspacePath, 'src/nested/café résumé-日本語.ts'),
          'utf8'
        )
      ).toBe('export const ok = true;\n');
      expect(
        await readFile(path.join(workspace.workspacePath, 'my folder/hello world.txt'), 'utf8')
      ).toBe('space path ok');

      // Explicit idempotent cleanup
      const firstClean = await workspace.cleanup();
      expect(firstClean).toEqual({ cleaned: true, alreadyCleaned: false });
      expect(workspace.isCleanedUp()).toBe(true);
      await expect(lstat(workspace.workspacePath)).rejects.toMatchObject({ code: 'ENOENT' });

      const secondClean = await workspace.cleanup();
      expect(secondClean).toEqual({ cleaned: true, alreadyCleaned: true });
    });
  });

  describe('Malicious paths & archive layout defenses', () => {
    it('rejects traversal, absolute, Windows drive, UNC, backslash, NUL/control chars, depth/length, duplicates, case collisions, root mismatches, and file/dir conflicts while cleaning workspace', async () => {
      const parentDir = await createIsolatedTestParent();
      const parentGrandDir = path.dirname(parentDir);

      const maliciousTars: Array<{ label: string; buf: Buffer; expectedCode: string }> = [
        {
          label: 'parent traversal ../',
          buf: await packTarGz([{ name: 'repo/../escaped.txt', content: 'pwn' }]),
          expectedCode: 'INVALID_ARCHIVE_PATH',
        },
        {
          label: 'nested traversal',
          buf: await packTarGz([{ name: 'repo/a/../b/c.txt', content: 'pwn' }]),
          expectedCode: 'INVALID_ARCHIVE_PATH',
        },
        {
          label: 'absolute POSIX path',
          buf: await packTarGz([{ name: '/etc/passwd', content: 'pwn' }]),
          expectedCode: 'INVALID_ARCHIVE_PATH',
        },
        {
          label: 'Windows drive path',
          buf: await packTarGz([{ name: 'C:/Windows/win.ini', content: 'pwn' }]),
          expectedCode: 'INVALID_ARCHIVE_PATH',
        },
        {
          label: 'UNC path',
          buf: await packTarGz([{ name: '//server/share/evil.txt', content: 'pwn' }]),
          expectedCode: 'INVALID_ARCHIVE_PATH',
        },
        {
          label: 'backslash path',
          buf: await packTarGz([{ name: 'repo\\sub\\evil.txt', content: 'pwn' }]),
          expectedCode: 'INVALID_ARCHIVE_PATH',
        },
        {
          label: 'control character newline',
          buf: await packTarGz([{ name: 'repo/bad\nname.txt', content: 'pwn' }]),
          expectedCode: 'INVALID_ARCHIVE_PATH',
        },
        {
          label: 'raw NUL byte in PAX path',
          buf: (() => {
            const paxLine = Buffer.from(' path=repo/evil\0name\n', 'utf8');
            const totalLen = paxLine.byteLength + 2;
            const paxPayload = Buffer.concat([Buffer.from(String(totalLen), 'ascii'), paxLine]);
            return buildRawUstarTarGz([
              { name: 'PaxHeader/repo', typeflag: 'x'.charCodeAt(0), payload: paxPayload },
              { name: 'repo/fallback', typeflag: 48, payload: Buffer.from('pwn') },
            ]);
          })(),
          expectedCode: 'INVALID_ARCHIVE_PATH',
        },
        {
          label: 'excessive depth',
          buf: await packTarGz([{ name: 'repo/a/b/c/d/e.txt', content: 'deep' }]),
          expectedCode: 'INVALID_ARCHIVE_PATH',
        },
        {
          label: 'excessive length',
          buf: await packTarGz([{ name: `repo/${'x'.repeat(70)}.txt`, content: 'long' }]),
          expectedCode: 'INVALID_ARCHIVE_PATH',
        },
        {
          label: 'duplicate file entry',
          buf: await packTarGz([
            { name: 'repo/dup.txt', content: 'first' },
            { name: 'repo/dup.txt', content: 'second' },
          ]),
          expectedCode: 'ARCHIVE_PATH_COLLISION',
        },
        {
          label: 'case-insensitive file collision',
          buf: await packTarGz([
            { name: 'repo/Config.json', content: '{}' },
            { name: 'repo/config.json', content: '{}' },
          ]),
          expectedCode: 'ARCHIVE_PATH_COLLISION',
        },
        {
          label: 'case-insensitive directory collision',
          buf: await packTarGz([
            { name: 'repo/Src/a.ts', content: 'a' },
            { name: 'repo/src/b.ts', content: 'b' },
          ]),
          expectedCode: 'ARCHIVE_PATH_COLLISION',
        },
        {
          label: 'inconsistent top-level roots',
          buf: await packTarGz([
            { name: 'root-a/a.txt', content: 'a' },
            { name: 'root-b/b.txt', content: 'b' },
          ]),
          expectedCode: 'INCONSISTENT_ARCHIVE_ROOT',
        },
        {
          label: 'directory then file conflict',
          buf: await packTarGz([
            { name: 'repo/item/', type: 'directory' },
            { name: 'repo/item', type: 'file', content: 'conflict' },
          ]),
          expectedCode: 'FILE_DIRECTORY_CONFLICT',
        },
        {
          label: 'file then directory conflict',
          buf: await packTarGz([
            { name: 'repo/item', type: 'file', content: 'conflict' },
            { name: 'repo/item/', type: 'directory' },
          ]),
          expectedCode: 'FILE_DIRECTORY_CONFLICT',
        },
        {
          label: 'regular file used as parent directory',
          buf: await packTarGz([
            { name: 'repo/parent', type: 'file', content: 'regular' },
            { name: 'repo/parent/child.txt', type: 'file', content: 'child' },
          ]),
          expectedCode: 'FILE_DIRECTORY_CONFLICT',
        },
      ];

      for (const tc of maliciousTars) {
        let caught: unknown = null;
        try {
          await extractRepositoryArchive({
            archive: makeFakeAcquiredArchive(tc.buf),
            workspaceParentDir: parentDir,
            limits: {
              maxPathDepth: 4,
              maxPathLength: 50,
            },
          });
        } catch (err) {
          caught = err;
        }

        expect(caught, tc.label).toBeInstanceOf(ArchiveExtractionError);
        expect((caught as ArchiveExtractionError).code, tc.label).toBe(tc.expectedCode);
        expect((caught as Error).message, tc.label).not.toContain(parentDir);

        // Partial workspace must be completely removed and nothing escaped to parentDir or /tmp parent
        expect(await readdir(parentDir), tc.label).toEqual([]);
        await expect(lstat(path.join(parentDir, 'escaped.txt'))).rejects.toMatchObject({
          code: 'ENOENT',
        });
        await expect(lstat(path.join(parentGrandDir, 'escaped.txt'))).rejects.toMatchObject({
          code: 'ENOENT',
        });
      }
    });
  });

  describe('Dangerous entry types & unsupported PAX/GNU metadata', () => {
    it('rejects symlinks, hardlinks, devices, FIFOs, unknown types, sparse metadata, and xattr/linkpath PAX extensions', async () => {
      const parentDir = await createIsolatedTestParent();

      const fixtures: Array<{ label: string; buf: Buffer; expectedCode: string }> = [
        {
          label: 'symbolic link',
          buf: await packTarGz([{ name: 'repo/escape', type: 'symlink', linkname: '/etc/passwd' }]),
          expectedCode: 'UNSUPPORTED_ENTRY_TYPE',
        },
        {
          label: 'hard link',
          buf: await packTarGz([
            { name: 'repo/a.txt', type: 'file', content: 'x' },
            { name: 'repo/b.txt', type: 'link', linkname: 'repo/a.txt' },
          ]),
          expectedCode: 'UNSUPPORTED_ENTRY_TYPE',
        },
        {
          label: 'character device',
          buf: await packTarGz([{ name: 'repo/null', type: 'character-device' }]),
          expectedCode: 'UNSUPPORTED_ENTRY_TYPE',
        },
        {
          label: 'block device',
          buf: await packTarGz([{ name: 'repo/disk', type: 'block-device' }]),
          expectedCode: 'UNSUPPORTED_ENTRY_TYPE',
        },
        {
          label: 'FIFO',
          buf: await packTarGz([{ name: 'repo/pipe', type: 'fifo' }]),
          expectedCode: 'UNSUPPORTED_ENTRY_TYPE',
        },
        {
          label: 'contiguous file',
          buf: await packTarGz([{ name: 'repo/contig', type: 'contiguous-file', content: 'data' }]),
          expectedCode: 'UNSUPPORTED_ENTRY_TYPE',
        },
        {
          label: 'unknown/GNU sparse typeflag S',
          buf: buildRawUstarTarGz([{ name: 'repo/sparse', typeflag: 'S'.charCodeAt(0) }]),
          expectedCode: 'UNSUPPORTED_ENTRY_TYPE',
        },
        {
          label: 'PAX sparse metadata',
          buf: await packTarGz([
            {
              name: 'repo/sparse-pax.bin',
              type: 'file',
              content: 'sparse',
              pax: { 'GNU.sparse.major': '1', 'GNU.sparse.realsize': '999999999' },
            },
          ]),
          expectedCode: 'UNSUPPORTED_ARCHIVE_METADATA',
        },
        {
          label: 'PAX xattr metadata',
          buf: await packTarGz([
            {
              name: 'repo/xattr.txt',
              type: 'file',
              content: 'ok',
              pax: { 'SCHILY.xattr.user.test': 'value' },
            },
          ]),
          expectedCode: 'UNSUPPORTED_ARCHIVE_METADATA',
        },
        {
          label: 'PAX linkpath smuggling on regular file',
          buf: await packTarGz([
            {
              name: 'repo/sneaky.txt',
              type: 'file',
              content: 'ok',
              pax: { linkpath: '/etc/shadow' },
            },
          ]),
          expectedCode: 'UNSUPPORTED_ENTRY_TYPE',
        },
      ];

      for (const tc of fixtures) {
        let caught: unknown = null;
        try {
          await extractRepositoryArchive({
            archive: makeFakeAcquiredArchive(tc.buf),
            workspaceParentDir: parentDir,
          });
        } catch (err) {
          caught = err;
        }
        expect(caught, tc.label).toBeInstanceOf(ArchiveExtractionError);
        expect((caught as ArchiveExtractionError).code, tc.label).toBe(tc.expectedCode);
        expect(await readdir(parentDir), tc.label).toEqual([]);
      }
    });
  });

  describe('Resource exhaustion, malformed archives & bomb protections', () => {
    it('enforces compressed, decompressed bomb, individual file, entry count, metadata, format, truncation & size-consistency limits', async () => {
      const parentDir = await createIsolatedTestParent();

      // 1. Compressed size exceeded
      const overCompressed = await packTarGz([
        { name: 'repo/data.bin', content: Buffer.alloc(1024, 0xab) },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(overCompressed),
          workspaceParentDir: parentDir,
          limits: { maxCompressedBytes: 50 },
        })
      ).rejects.toMatchObject({ code: 'COMPRESSED_SIZE_EXCEEDED' });

      // 2. Decompression bomb (small compressed payload expands beyond maxDecompressedBytes across valid-sized files)
      const bombTgz = await packTarGz([
        { name: 'repo/zero-1.bin', content: Buffer.alloc(12 * 1024, 0x00) },
        { name: 'repo/zero-2.bin', content: Buffer.alloc(12 * 1024, 0x00) },
        { name: 'repo/zero-3.bin', content: Buffer.alloc(12 * 1024, 0x00) },
        { name: 'repo/zero-4.bin', content: Buffer.alloc(12 * 1024, 0x00) },
        { name: 'repo/zero-5.bin', content: Buffer.alloc(12 * 1024, 0x00) },
      ]);
      expect(bombTgz.byteLength).toBeLessThan(2048);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(bombTgz),
          workspaceParentDir: parentDir,
          limits: {
            maxCompressedBytes: 10 * 1024,
            maxDecompressedBytes: 32 * 1024,
            maxFileBytes: 16 * 1024,
          },
        })
      ).rejects.toMatchObject({ code: 'DECOMPRESSED_SIZE_EXCEEDED' });

      // 3. Individual file limit exceeded
      const bigFileTgz = await packTarGz([
        { name: 'repo/big.bin', content: Buffer.alloc(2048, 0x41) },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(bigFileTgz),
          workspaceParentDir: parentDir,
          limits: { maxFileBytes: 1024 },
        })
      ).rejects.toMatchObject({ code: 'FILE_SIZE_EXCEEDED' });

      // 4. Entry count limit exceeded
      const manyEntriesTgz = await packTarGz([
        { name: 'repo/1.txt', content: '1' },
        { name: 'repo/2.txt', content: '2' },
        { name: 'repo/3.txt', content: '3' },
        { name: 'repo/4.txt', content: '4' },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(manyEntriesTgz),
          workspaceParentDir: parentDir,
          limits: { maxEntries: 3 },
        })
      ).rejects.toMatchObject({ code: 'ENTRY_COUNT_EXCEEDED' });

      // 5. Directory claiming non-zero size
      const dirWithSizeTgz = buildRawUstarTarGz([
        {
          name: 'repo/evil-dir/',
          typeflag: '5'.charCodeAt(0),
          size: 5,
          payload: Buffer.from('12345'),
        },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(dirWithSizeTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });

      // 6. Negative base-256 tar header size
      const negSizeBuf = Buffer.alloc(12, 0xff);
      const negSizeTgz = buildRawUstarTarGz([
        { name: 'repo/neg.bin', typeflag: 48, rawSizeBytes: negSizeBuf },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(negSizeTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });

      // 7. Malformed / non-gzip and truncated gzip and truncated tar
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(Buffer.from('not a gzip archive at all')),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'INVALID_ARCHIVE_FORMAT' });

      const truncatedGz = bombTgz.subarray(0, bombTgz.byteLength - 10);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(truncatedGz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });

      const rawTruncTarGz = zlib.gzipSync(Buffer.alloc(300, 0x41));
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(rawTruncTarGz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });

      const invalidTarHeaderGz = zlib.gzipSync(Buffer.alloc(512, 0x41));
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(invalidTarHeaderGz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'INVALID_ARCHIVE_FORMAT' });

      // 8. Empty zero-entry tar archive
      const emptyTarGz = zlib.gzipSync(Buffer.alloc(1024, 0));
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(emptyTarGz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });

      // 9. Excessive PAX metadata
      const excessiveMetaTgz = await packTarGz([
        {
          name: 'repo/meta.txt',
          content: 'ok',
          pax: { comment: 'z'.repeat(2048) },
        },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(excessiveMetaTgz),
          workspaceParentDir: parentDir,
          limits: { maxEntryMetadataBytes: 512 },
        })
      ).rejects.toMatchObject({ code: 'EXCESSIVE_ARCHIVE_METADATA' });

      // 10. Malformed non-numeric PAX size metadata
      const badPaxSizeTgz = await packTarGz([
        {
          name: 'repo/bad-pax-size.txt',
          content: 'abc',
          pax: { size: '3abc' },
        },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(badPaxSizeTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });

      // 11. Mid-stream tar truncation after file 1 written -> fails and cleans up file 1 workspace
      const firstFileTar = zlib.gunzipSync(
        await packTarGz([{ name: 'repo/first.txt', content: 'written-before-failure' }])
      );
      const withoutTrailer = firstFileTar.subarray(0, firstFileTar.byteLength - 1024);
      const partialEntryHeader = Buffer.alloc(512, 0);
      partialEntryHeader.write('repo/second.txt', 0, 15, 'utf8');
      partialEntryHeader.write('0000644 ', 100, 8, 'ascii');
      partialEntryHeader.write('0000000 ', 108, 8, 'ascii');
      partialEntryHeader.write('0000000 ', 116, 8, 'ascii');
      partialEntryHeader.write(`${(200).toString(8).padStart(11, '0')} `, 124, 12, 'ascii');
      partialEntryHeader.write('00000000000 ', 136, 12, 'ascii');
      partialEntryHeader.fill(0x20, 148, 156);
      partialEntryHeader[156] = 48;
      partialEntryHeader.write('ustar\0', 257, 6, 'ascii');
      partialEntryHeader.write('00', 263, 2, 'ascii');
      let sum = 0;
      for (let i = 0; i < 512; i += 1) {
        sum += partialEntryHeader[i]!;
      }
      partialEntryHeader.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
      const truncatedMidArchiveTgz = zlib.gzipSync(
        Buffer.concat([withoutTrailer, partialEntryHeader, Buffer.alloc(20, 0x78)])
      );

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(truncatedMidArchiveTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });

      expect(await readdir(parentDir)).toEqual([]);
    });

    it('cancels slow streaming cleanly via AbortSignal/shutdown and cleans up before rejecting', async () => {
      const parentDir = await createIsolatedTestParent();
      const firstPart = await packTarGz([{ name: 'repo/a.txt', content: 'first part' }]);

      const slowStream = new PassThrough();
      slowStream.write(firstPart.subarray(0, Math.floor(firstPart.byteLength / 2)));

      const controller = new AbortController();
      setTimeout(() => controller.abort(), 20);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(slowStream),
          workspaceParentDir: parentDir,
          signal: controller.signal,
        })
      ).rejects.toMatchObject({ code: 'EXTRACTION_CANCELLED' });

      // Partial workspace already removed BEFORE extractRepositoryArchive rejected
      expect(await readdir(parentDir)).toEqual([]);

      // Worker shutdown signal classifies separately as WORKER_SHUTDOWN
      const shutdownController = new AbortController();
      const slowShutdownStream = new PassThrough();
      slowShutdownStream.write(firstPart.subarray(0, 10));
      setTimeout(() => shutdownController.abort(), 20);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(slowShutdownStream),
          workspaceParentDir: parentDir,
          shutdownSignal: shutdownController.signal,
        })
      ).rejects.toMatchObject({ code: 'WORKER_SHUTDOWN' });

      expect(await readdir(parentDir)).toEqual([]);
    });
  });

  describe('Workspace containment & HTTP acquisition integration', () => {
    it('validates cleanupWorkspaceDirectory containment strictly and refuses symlinks or non-workspace dirs', async () => {
      const parentDir = await createIsolatedTestParent();
      const outsideDir = await createIsolatedTestParent();
      const unrelatedInside = path.join(parentDir, 'unrelated-folder');
      await mkdir(unrelatedInside, { mode: 0o700 });

      await expect(cleanupWorkspaceDirectory(outsideDir, parentDir)).rejects.toMatchObject({
        code: 'WORKSPACE_CONTAINMENT_ERROR',
      });
      await expect(cleanupWorkspaceDirectory(unrelatedInside, parentDir)).rejects.toMatchObject({
        code: 'WORKSPACE_CONTAINMENT_ERROR',
      });

      const symlinkPath = path.join(parentDir, 'vs-ws-fake-link');
      await symlink(outsideDir, symlinkPath);
      await expect(cleanupWorkspaceDirectory(symlinkPath, parentDir)).rejects.toMatchObject({
        code: 'WORKSPACE_CONTAINMENT_ERROR',
      });

      // Verify neither outsideDir nor unrelatedInside were deleted
      expect((await lstat(outsideDir)).isDirectory()).toBe(true);
      expect((await lstat(unrelatedInside)).isDirectory()).toBe(true);
    });

    it('integrates end-to-end with createInternalAcquisitionClient for valid, truncated, and cancelled streams', async () => {
      const parentDir = await createIsolatedTestParent();
      const validTgz = await packTarGz([
        { name: 'acme-web-sha/', type: 'directory' },
        { name: 'acme-web-sha/src/index.ts', type: 'file', content: 'console.log("safe");\n' },
      ]);

      let mode: 'valid' | 'truncated' | 'slow' = 'valid';
      const baseUrl = await startHttpServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'application/gzip',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
        });

        if (mode === 'valid') {
          res.end(validTgz);
          return;
        }

        if (mode === 'truncated') {
          res.write(validTgz.subarray(0, Math.floor(validTgz.byteLength / 2)));
          setTimeout(() => res.destroy(), 15);
          return;
        }

        // Slow mode: write partial gzip header then stall until aborted
        res.write(validTgz.subarray(0, 12));
      });

      const client = createInternalAcquisitionClient({
        baseUrl,
        workerAuthSecret: TEST_INTERNAL_SECRET,
      });

      // 1. Valid streamed archive extracts cleanly into workspace and cleans up
      mode = 'valid';
      const validArchive = await client.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      const ws = await extractRepositoryArchive({
        archive: validArchive,
        workspaceParentDir: parentDir,
      });
      expect(await readFile(path.join(ws.workspacePath, 'src', 'index.ts'), 'utf8')).toBe(
        'console.log("safe");\n'
      );
      await ws.cleanup();
      expect(await readdir(parentDir)).toEqual([]);

      // 2. Truncated HTTP response fails extraction and removes partial workspace
      mode = 'truncated';
      const truncArchive = await client.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
      });
      await expect(
        extractRepositoryArchive({
          archive: truncArchive,
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'INCOMPLETE_ARCHIVE_RESPONSE' });
      expect(await readdir(parentDir)).toEqual([]);

      // 3. Cancellation destroys active HTTP acquisition + extraction pipeline and cleans workspace
      mode = 'slow';
      const abortController = new AbortController();
      const slowArchive = await client.acquireRepositoryArchive({
        scanId: TEST_SCAN_ID,
        leaseToken: TEST_LEASE_TOKEN,
        signal: abortController.signal,
      });
      setTimeout(() => abortController.abort(), 20);

      await expect(
        extractRepositoryArchive({
          archive: slowArchive,
          workspaceParentDir: parentDir,
          signal: abortController.signal,
        })
      ).rejects.toMatchObject({
        code: expect.stringMatching(/^(EXTRACTION_CANCELLED|ACQUISITION_CANCELLED)$/),
      });
      expect(await readdir(parentDir)).toEqual([]);
    });
  });

  describe('Audit hardening regression tests (Task 1.7.3.4.2)', () => {
    function buildPaxRecord(key: string, value: string): Buffer {
      const suffix = Buffer.from(` ${key}=${value}\n`, 'utf8');
      let totalLength = suffix.byteLength + 1;
      while (Buffer.byteLength(String(totalLength), 'ascii') + suffix.byteLength !== totalLength) {
        totalLength = Buffer.byteLength(String(totalLength), 'ascii') + suffix.byteLength;
      }
      return Buffer.concat([Buffer.from(String(totalLength), 'ascii'), suffix]);
    }

    it('M1: rejects oversized PAX extended headers (> 64 KiB) before tar-stream buffering', async () => {
      const parentDir = await createIsolatedTestParent();
      // Exceeds 64 KiB cap (70 KiB) while staying well below tar-stream internal 4 MiB cap
      const hugePaxPayload = buildPaxRecord('comment', 'a'.repeat(70 * 1024));
      const archiveBytes = buildRawUstarTarGz([
        {
          name: 'PaxHeader/repo/file.txt',
          typeflag: 0x78, // 'x'
          payload: hugePaxPayload,
        },
        {
          name: 'repo/file.txt',
          typeflag: 0x30,
          payload: Buffer.from('ok\n', 'utf8'),
        },
      ]);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(archiveBytes),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'EXCESSIVE_ARCHIVE_METADATA' });
      expect(await readdir(parentDir)).toEqual([]);
    });

    it('M1: rejects oversized GNU long paths (L > 64 KiB) and GNU long link paths (K)', async () => {
      const parentDir = await createIsolatedTestParent();
      const hugeLongPathPayload = Buffer.from(`repo/${'a'.repeat(70 * 1024)}\0`, 'utf8');
      const longPathTgz = buildRawUstarTarGz([
        {
          name: '././@LongLink',
          typeflag: 0x4c, // 'L'
          payload: hugeLongPathPayload,
        },
        {
          name: 'repo/ignored',
          typeflag: 0x30,
          payload: Buffer.from('x', 'utf8'),
        },
      ]);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(longPathTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'EXCESSIVE_ARCHIVE_METADATA' });

      const gnuLongLinkTgz = buildRawUstarTarGz([
        {
          name: '././@LongLink',
          typeflag: 0x4b, // 'K'
          payload: Buffer.from('target\0', 'utf8'),
        },
        {
          name: 'repo/ignored',
          typeflag: 0x32,
        },
      ]);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(gnuLongLinkTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'UNSUPPORTED_ENTRY_TYPE' });
      expect(await readdir(parentDir)).toEqual([]);
    });

    it('M1: enforces total extended metadata budget, consecutive header cap, and global PAX cap while accepting legitimate GitHub PAX metadata', async () => {
      const parentDir = await createIsolatedTestParent();

      // Exceeding maxTotalMetadataBytes across multiple entries
      const paxComment = 'x'.repeat(350);
      const multiMetaTgz = await packTarGz([
        { name: 'repo-sha/a.ts', content: '1', pax: { comment: paxComment } },
        { name: 'repo-sha/b.ts', content: '2', pax: { comment: paxComment } },
        { name: 'repo-sha/c.ts', content: '3', pax: { comment: paxComment } },
        { name: 'repo-sha/d.ts', content: '4', pax: { comment: paxComment } },
      ]);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(multiMetaTgz),
          workspaceParentDir: parentDir,
          limits: {
            maxTotalMetadataBytes: 1024,
            maxEntryMetadataBytes: 512,
          },
        })
      ).rejects.toMatchObject({ code: 'EXCESSIVE_ARCHIVE_METADATA' });

      // Exceeding maxExtendedHeaders count
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(multiMetaTgz),
          workspaceParentDir: parentDir,
          limits: {
            maxExtendedHeaders: 2,
          },
        })
      ).rejects.toMatchObject({ code: 'EXCESSIVE_ARCHIVE_METADATA' });

      // Exceeding MAX_CONSECUTIVE_EXTENDED_HEADERS (9 consecutive 'x' blocks)
      const nineConsecutive = Array.from({ length: 9 }, (_, i) => ({
        name: `PaxHeader/${i}`,
        typeflag: 0x78,
        payload: buildPaxRecord('comment', 'step'),
      }));
      const consecutiveTgz = buildRawUstarTarGz([
        ...nineConsecutive,
        { name: 'repo/ok.txt', typeflag: 0x30, payload: Buffer.from('hi', 'utf8') },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(consecutiveTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'EXCESSIVE_ARCHIVE_METADATA' });

      // Exceeding MAX_GLOBAL_PAX_HEADERS (5 global 'g' blocks)
      const fiveGlobal = Array.from({ length: 5 }, (_, i) => ({
        name: `PaxGlobal/${i}`,
        typeflag: 0x67, // 'g'
        payload: buildPaxRecord('comment', 'deadbeef'),
      }));
      const globalSpamTgz = buildRawUstarTarGz([
        ...fiveGlobal,
        { name: 'repo/ok.txt', typeflag: 0x30, payload: Buffer.from('hi', 'utf8') },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(globalSpamTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'EXCESSIVE_ARCHIVE_METADATA' });

      // Legitimate GitHub archive with pax-global-header comment=<sha> and per-entry pax path succeeds
      const githubStyleTgz = buildRawUstarTarGz([
        {
          name: 'pax_global_header',
          typeflag: 0x67,
          payload: buildPaxRecord('comment', '0123456789abcdef0123456789abcdef01234567'),
        },
        {
          name: 'PaxHeader/repo-0123456/src/app.ts',
          typeflag: 0x78,
          payload: buildPaxRecord('path', 'repo-0123456/src/app.ts'),
        },
        {
          name: 'repo-0123456/src/app.ts',
          typeflag: 0x30,
          payload: Buffer.from('export const ok = true;\n', 'utf8'),
        },
      ]);
      const validHandle = await extractRepositoryArchive({
        archive: makeFakeAcquiredArchive(githubStyleTgz),
        workspaceParentDir: parentDir,
      });
      expect(await readFile(path.join(validHandle.workspacePath, 'src', 'app.ts'), 'utf8')).toBe(
        'export const ok = true;\n'
      );
      await validHandle.cleanup();
      expect(await readdir(parentDir)).toEqual([]);
    });

    it('M1: rejects malformed 0x81 negative base-256 sizes cleanly', async () => {
      const parentDir = await createIsolatedTestParent();
      const badSizeBytes = Buffer.alloc(12, 0);
      badSizeBytes[0] = 0x81;
      const tgz = buildRawUstarTarGz([
        {
          name: 'repo/file.txt',
          typeflag: 0x30,
          rawSizeBytes: badSizeBytes,
        },
      ]);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(tgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });
      expect(await readdir(parentDir)).toEqual([]);
    });

    it('M2 & L1: canonicalizes NFD/NFC paths for collision detection and extraction, and enforces UTF-8 byte path length limits', async () => {
      const parentDir = await createIsolatedTestParent();

      // NFD vs NFC collision must be rejected regardless of Unicode normalization form
      const collisionTgz = await packTarGz([
        { name: 'repo/caf\u0065\u0301.txt', content: 'nfd' },
        { name: 'repo/caf\u00e9.txt', content: 'nfc' },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(collisionTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'ARCHIVE_PATH_COLLISION' });

      // Single NFD entry extracts using NFC canonical path
      const nfdOnlyTgz = await packTarGz([
        { name: 'repo/caf\u0065\u0301.txt', content: 'normalized' },
      ]);
      const ws = await extractRepositoryArchive({
        archive: makeFakeAcquiredArchive(nfdOnlyTgz),
        workspaceParentDir: parentDir,
      });
      expect(await readFile(path.join(ws.workspacePath, 'caf\u00e9.txt'), 'utf8')).toBe(
        'normalized'
      );
      await ws.cleanup();

      // UTF-8 byte length check (> 240 UTF-8 bytes even when UTF-16 length is <= 90)
      const multiByteLongTgz = await packTarGz([
        { name: `repo/${'€'.repeat(85)}.txt`, content: 'utf8' },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(multiByteLongTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'INVALID_ARCHIVE_PATH' });
      expect(await readdir(parentDir)).toEqual([]);
    });

    it('L2: rejects empty PAX path overrides instead of falling back to USTAR header name', async () => {
      const parentDir = await createIsolatedTestParent();
      const emptyPaxPathTgz = buildRawUstarTarGz([
        {
          name: 'PaxHeader/repo/fallback.txt',
          typeflag: 0x78,
          payload: buildPaxRecord('path', ''),
        },
        {
          name: 'repo/fallback.txt',
          typeflag: 0x30,
          payload: Buffer.from('should-not-extract', 'utf8'),
        },
      ]);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(emptyPaxPathTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'INVALID_ARCHIVE_PATH' });
      expect(await readdir(parentDir)).toEqual([]);
    });

    it('M3: rejects unsafe group/world-writable non-sticky and untrusted-owner parent directories during both extraction and cleanup', async () => {
      const parentDir = await createIsolatedTestParent();
      const worldWritableNonSticky = path.join(parentDir, 'world-writable');
      await mkdir(worldWritableNonSticky, { mode: 0o777 });
      await chmod(worldWritableNonSticky, 0o777);

      const validTgz = await packTarGz([{ name: 'repo/a.txt', content: 'ok' }]);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(validTgz),
          workspaceParentDir: worldWritableNonSticky,
        })
      ).rejects.toMatchObject({ code: 'WORKSPACE_CONTAINMENT_ERROR' });

      const dummyChild = path.join(worldWritableNonSticky, 'vs-ws-scan-123');
      await mkdir(dummyChild, { mode: 0o700 });
      await expect(
        cleanupWorkspaceDirectory(dummyChild, worldWritableNonSticky)
      ).rejects.toMatchObject({ code: 'WORKSPACE_CONTAINMENT_ERROR' });

      // Restore safe permissions so afterEach cleanup removes it cleanly
      await chmod(worldWritableNonSticky, 0o700);

      // Simulate untrusted non-worker/non-root UID and non-sticky root via workspaceFsOps
      const trustedDir = await createIsolatedTestParent();
      const currentUid = typeof process.getuid === 'function' ? process.getuid() : 1000;
      const untrustedOwnerStat = Object.assign(await lstat(trustedDir), {
        uid: currentUid + 1,
        mode: 0o040700,
      });

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(validTgz),
          workspaceParentDir: trustedDir,
          workspaceFsOps: {
            lstat: async () => untrustedOwnerStat,
          },
        })
      ).rejects.toMatchObject({ code: 'WORKSPACE_CONTAINMENT_ERROR' });

      const nonStickyRootStat = Object.assign(await lstat(trustedDir), {
        uid: 0,
        mode: 0o040755,
      });
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(validTgz),
          workspaceParentDir: trustedDir,
          workspaceFsOps: {
            lstat: async () => nonStickyRootStat,
          },
        })
      ).rejects.toMatchObject({ code: 'WORKSPACE_CONTAINMENT_ERROR' });

      // Root-owned sticky dir (uid=0, 01777 like /tmp) is trusted
      const stickyRootStat = Object.assign(await lstat(trustedDir), {
        uid: 0,
        mode: 0o041777,
      });
      const wsRootParent = await extractRepositoryArchive({
        archive: makeFakeAcquiredArchive(validTgz),
        workspaceParentDir: trustedDir,
        workspaceFsOps: {
          lstat: async (targetPath) =>
            path.resolve(targetPath) === path.resolve(trustedDir)
              ? stickyRootStat
              : await lstat(targetPath),
        },
      });
      await wsRootParent.cleanup();
    });

    it('L3: removes partially initialized mkdtemp workspace directory when post-creation checks fail', async () => {
      const parentDir = await createIsolatedTestParent();
      const validTgz = await packTarGz([{ name: 'repo/a.txt', content: 'ok' }]);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(validTgz),
          workspaceParentDir: parentDir,
          workspaceFsOps: {
            chmod: async () => {
              throw new Error('simulated chmod failure');
            },
          },
        })
      ).rejects.toMatchObject({ code: 'WORKSPACE_ERROR' });

      expect(await readdir(parentDir)).toEqual([]);
    });
  });

  describe('Audit hardening regression tests (Task 1.7.3.4.4)', () => {
    function makeTarHeaderBlock(name: string, typeflag: number, size: number): Buffer {
      const hdr = Buffer.alloc(512, 0);
      hdr.write(name, 0, Math.min(Buffer.byteLength(name), 100), 'utf8');
      hdr.write('0000644 ', 100, 8, 'ascii');
      hdr.write('0000000 ', 108, 8, 'ascii');
      hdr.write('0000000 ', 116, 8, 'ascii');
      hdr.write(`${size.toString(8).padStart(11, '0')} `, 124, 12, 'ascii');
      hdr.write('00000000000 ', 136, 12, 'ascii');
      hdr.fill(0x20, 148, 156);
      hdr[156] = typeflag;
      hdr.write('ustar\0', 257, 6, 'ascii');
      hdr.write('00', 263, 2, 'ascii');
      let sum = 0;
      for (let i = 0; i < 512; i += 1) {
        sum += hdr[i]!;
      }
      hdr.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
      return hdr;
    }

    function padTarBlock(buf: Buffer): Buffer {
      const rem = buf.byteLength % 512;
      return rem === 0 ? buf : Buffer.concat([buf, Buffer.alloc(512 - rem, 0)]);
    }

    function buildPaxLine(key: string, value: string): Buffer {
      const suffix = Buffer.from(` ${key}=${value}\n`, 'utf8');
      let len = suffix.byteLength + 1;
      while (Buffer.byteLength(String(len), 'ascii') + suffix.byteLength !== len) {
        len = Buffer.byteLength(String(len), 'ascii') + suffix.byteLength;
      }
      return Buffer.concat([Buffer.from(String(len), 'ascii'), suffix]);
    }

    it('H1: prevents consecutive PAX x header desynchronization attack from blinding the metadata guard', async () => {
      const parentDir = await createIsolatedTestParent();

      // Exact audit bypass sequence:
      // 1) x #1 sets size=4815872
      // 2) x #2 sets harmless comment without size (tar-stream replaces _pax cleanly)
      // 3) regular file repo/trigger.txt has ustarSize=0
      // 4) smuggled 10 global PAX 'g' headers + 10 'x' headers + 90 entries (~4.5 MiB PAX)
      const p1 = buildPaxLine('size', '4815872');
      const p2 = buildPaxLine('comment', 'wipe');
      const gRec = buildPaxLine('comment', 'deadbeef');
      const bigComment = buildPaxLine('comment', 'Z'.repeat(50 * 1024));

      const smuggledParts: Buffer[] = [];
      for (let i = 0; i < 10; i += 1) {
        smuggledParts.push(
          makeTarHeaderBlock(`PaxGlobal/${i}`, 0x67, gRec.byteLength),
          padTarBlock(gRec)
        );
      }
      for (let i = 0; i < 10; i += 1) {
        smuggledParts.push(makeTarHeaderBlock(`Pax/${i}`, 0x78, p2.byteLength), padTarBlock(p2));
      }
      for (let i = 0; i < 90; i += 1) {
        smuggledParts.push(
          makeTarHeaderBlock(`PaxHeader/repo/f${i}.txt`, 0x78, bigComment.byteLength),
          padTarBlock(bigComment),
          makeTarHeaderBlock(`repo/f${i}.txt`, 0x30, 1),
          padTarBlock(Buffer.from('x', 'utf8'))
        );
      }

      const attackTar = Buffer.concat([
        makeTarHeaderBlock('PaxHeader/repo/trigger.txt', 0x78, p1.byteLength),
        padTarBlock(p1),
        makeTarHeaderBlock('PaxHeader/repo/trigger.txt', 0x78, p2.byteLength),
        padTarBlock(p2),
        makeTarHeaderBlock('repo/trigger.txt', 0x30, 0),
        ...smuggledParts,
        Buffer.alloc(1024, 0),
      ]);

      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(zlib.gzipSync(attackTar)),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'EXCESSIVE_ARCHIVE_METADATA' });
      expect(await readdir(parentDir)).toEqual([]);
    });

    it('H1: enforces PAX x state transitions (zero-length x, overriding valid size, malformed second size, valid override alignment, and L/N interleaving)', async () => {
      const parentDir = await createIsolatedTestParent();

      // 1. x #1 sets size -> x #2 has zero-length payload -> fails closed cleanly
      const p512 = buildPaxLine('size', '512');
      const zeroLengthSecondXTgz = zlib.gzipSync(
        Buffer.concat([
          makeTarHeaderBlock('PaxHeader/repo/a.txt', 0x78, p512.byteLength),
          padTarBlock(p512),
          makeTarHeaderBlock('PaxHeader/repo/a.txt', 0x78, 0),
          makeTarBlock('repo/a.txt', 0),
          Buffer.alloc(1024, 0),
        ])
      );
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(zeroLengthSecondXTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });
      expect(await readdir(parentDir)).toEqual([]);

      // 2. x #1 sets size=512 -> x #2 sets different valid size=12 -> second entry aligns cleanly
      const p12 = buildPaxLine('size', '12');
      const overrideSizeTgz = zlib.gzipSync(
        Buffer.concat([
          makeTarHeaderBlock('PaxHeader/repo/first.txt', 0x78, p512.byteLength),
          padTarBlock(p512),
          makeTarHeaderBlock('PaxHeader/repo/first.txt', 0x78, p12.byteLength),
          padTarBlock(p12),
          makeTarHeaderBlock('repo/first.txt', 0x30, 0),
          padTarBlock(Buffer.from('hello-world!', 'utf8')),
          makeTarHeaderBlock('repo/second.txt', 0x30, 4),
          padTarBlock(Buffer.from('next', 'utf8')),
          Buffer.alloc(1024, 0),
        ])
      );
      const wsOverride = await extractRepositoryArchive({
        archive: makeFakeAcquiredArchive(overrideSizeTgz),
        workspaceParentDir: parentDir,
      });
      expect(await readFile(path.join(wsOverride.workspacePath, 'first.txt'), 'utf8')).toBe(
        'hello-world!'
      );
      expect(await readFile(path.join(wsOverride.workspacePath, 'second.txt'), 'utf8')).toBe(
        'next'
      );
      await wsOverride.cleanup();

      // 3. x #1 sets size=512 -> x #2 sets malformed size=5bad -> fails closed
      const pBad = buildPaxLine('size', '5bad');
      const malformedSecondSizeTgz = zlib.gzipSync(
        Buffer.concat([
          makeTarHeaderBlock('PaxHeader/repo/a.txt', 0x78, p512.byteLength),
          padTarBlock(p512),
          makeTarHeaderBlock('PaxHeader/repo/a.txt', 0x78, pBad.byteLength),
          padTarBlock(pBad),
          makeTarHeaderBlock('repo/a.txt', 0x30, 0),
          Buffer.alloc(1024, 0),
        ])
      );
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(malformedSecondSizeTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });

      // 4. GNU 'L'/'N' preserves pending PAX size in tar-stream; interleaved x -> L -> entry & x1 -> L -> x2 -> entry align cleanly
      const longNameBuf = Buffer.from('repo/interleaved-long-entry-name.txt\0', 'utf8');
      const p7 = buildPaxLine('size', '7');
      const interleavedValidTgz = zlib.gzipSync(
        Buffer.concat([
          makeTarHeaderBlock('PaxHeader/repo/placeholder', 0x78, p7.byteLength),
          padTarBlock(p7),
          makeTarHeaderBlock('././@LongLink', 0x4c, longNameBuf.byteLength),
          padTarBlock(longNameBuf),
          makeTarHeaderBlock('repo/placeholder', 0x30, 0),
          padTarBlock(Buffer.from('payload', 'utf8')),
          makeTarHeaderBlock('repo/after-interleave.txt', 0x30, 2),
          padTarBlock(Buffer.from('ok', 'utf8')),
          Buffer.alloc(1024, 0),
        ])
      );
      const wsInterleaved = await extractRepositoryArchive({
        archive: makeFakeAcquiredArchive(interleavedValidTgz),
        workspaceParentDir: parentDir,
      });
      expect(
        await readFile(
          path.join(wsInterleaved.workspacePath, 'interleaved-long-entry-name.txt'),
          'utf8'
        )
      ).toBe('payload');
      expect(
        await readFile(path.join(wsInterleaved.workspacePath, 'after-interleave.txt'), 'utf8')
      ).toBe('ok');
      await wsInterleaved.cleanup();

      // x1(size=655360) -> L -> x2(comment) must reset pendingPaxSize and catch smuggled global PAX spam
      const wipeComment = buildPaxLine('comment', 'wipe');
      const gRec = buildPaxLine('comment', 'spam');
      const interleavedBypassTgz = zlib.gzipSync(
        Buffer.concat([
          makeTarHeaderBlock('PaxHeader/repo/t.txt', 0x78, p512.byteLength),
          padTarBlock(p512),
          makeTarHeaderBlock('././@LongLink', 0x4c, longNameBuf.byteLength),
          padTarBlock(longNameBuf),
          makeTarHeaderBlock('PaxHeader/repo/t.txt', 0x78, wipeComment.byteLength),
          padTarBlock(wipeComment),
          makeTarHeaderBlock('repo/t.txt', 0x30, 0),
          ...Array.from({ length: 6 }, (_, i) =>
            Buffer.concat([
              makeTarHeaderBlock(`PaxGlobal/${i}`, 0x67, gRec.byteLength),
              padTarBlock(gRec),
            ])
          ),
          makeTarHeaderBlock('repo/end.txt', 0x30, 1),
          padTarBlock(Buffer.from('a', 'utf8')),
          Buffer.alloc(1024, 0),
        ])
      );
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(interleavedBypassTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'EXCESSIVE_ARCHIVE_METADATA' });
      expect(await readdir(parentDir)).toEqual([]);

      function makeTarBlock(name: string, size: number): Buffer {
        return makeTarHeaderBlock(name, 0x30, size);
      }
    });

    it('L-new-1: rejects leading-NUL GNU L and N payloads while preserving valid GNU long paths', async () => {
      const parentDir = await createIsolatedTestParent();

      for (const typeflag of [0x4c, 0x4e]) {
        const leadingNulTgz = buildRawUstarTarGz([
          {
            name: '././@LongLink',
            typeflag,
            payload: Buffer.from('\0ignored\0', 'utf8'),
          },
          {
            name: 'repo/fallback.txt',
            typeflag: 0x30,
            payload: Buffer.from('should-not-extract', 'utf8'),
          },
        ]);

        await expect(
          extractRepositoryArchive({
            archive: makeFakeAcquiredArchive(leadingNulTgz),
            workspaceParentDir: parentDir,
          })
        ).rejects.toMatchObject({ code: 'INVALID_ARCHIVE_PATH' });
      }

      // Valid GNU L without trailing NUL inside declared payload length + with trailing NUL both work
      const validNoNul = Buffer.from(`repo/${'d'.repeat(110)}/a.txt`, 'utf8');
      const validWithNul = Buffer.from(`repo/${'e'.repeat(110)}/b.txt\0`, 'utf8');
      const validGnuLTgz = buildRawUstarTarGz([
        { name: '././@LongLink', typeflag: 0x4c, payload: validNoNul },
        { name: 'repo/truncated', typeflag: 0x30, payload: Buffer.from('one', 'utf8') },
        { name: '././@LongLink', typeflag: 0x4c, payload: validWithNul },
        { name: 'repo/truncated', typeflag: 0x30, payload: Buffer.from('two', 'utf8') },
      ]);
      const ws = await extractRepositoryArchive({
        archive: makeFakeAcquiredArchive(validGnuLTgz),
        workspaceParentDir: parentDir,
      });
      expect(await readFile(path.join(ws.workspacePath, 'd'.repeat(110), 'a.txt'), 'utf8')).toBe(
        'one'
      );
      expect(await readFile(path.join(ws.workspacePath, 'e'.repeat(110), 'b.txt'), 'utf8')).toBe(
        'two'
      );
      await ws.cleanup();
      expect(await readdir(parentDir)).toEqual([]);
    });

    it('rejects truncated extended headers, malformed PAX records, invalid tar checksums, nested NFD/NFC collisions, and enforces limits across concatenated gzip members', async () => {
      const parentDir = await createIsolatedTestParent();

      // 1. Truncated extended-header payload (declares 600 bytes, only 512 bytes provided)
      const truncExtPayloadTgz = zlib.gzipSync(
        Buffer.concat([
          makeTarHeaderBlock('PaxHeader/repo/a.txt', 0x78, 600),
          Buffer.alloc(512, 0x20),
        ])
      );
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(truncExtPayloadTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });

      // 2. Truncated extended-header 512-byte padding (declares 10 valid bytes, provides only 200 total bytes)
      const tenBytePax = buildPaxLine('size', '5');
      expect(tenBytePax.byteLength).toBeLessThan(20);
      const truncPaddingTgz = zlib.gzipSync(
        Buffer.concat([
          makeTarHeaderBlock('PaxHeader/repo/a.txt', 0x78, tenBytePax.byteLength),
          tenBytePax,
          Buffer.alloc(200 - tenBytePax.byteLength, 0),
        ])
      );
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(truncPaddingTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });

      // 3. Malformed PAX record lengths and syntax
      const badPaxPayloads = [
        Buffer.from('0 a=b\n', 'utf8'),
        Buffer.from('3 x\n', 'utf8'),
        Buffer.from('99999999999999999999 a=b\n', 'utf8'),
        Buffer.from('99 comment=abc\n', 'utf8'),
        Buffer.from('7 abcd\n', 'utf8'),
        Buffer.from('14 comment=abc', 'utf8'), // missing newline / truncated
        Buffer.from('14 comment=abX', 'utf8'), // missing trailing newline
      ];
      for (const badPayload of badPaxPayloads) {
        const badPaxTgz = buildRawUstarTarGz([
          { name: 'PaxHeader/repo/a.txt', typeflag: 0x78, payload: badPayload },
          { name: 'repo/a.txt', typeflag: 0x30, payload: Buffer.from('ok', 'utf8') },
        ]);
        await expect(
          extractRepositoryArchive({
            archive: makeFakeAcquiredArchive(badPaxTgz),
            workspaceParentDir: parentDir,
          })
        ).rejects.toMatchObject({ code: 'MALFORMED_ARCHIVE' });
      }

      // 4. Invalid tar header checksum (valid USTAR header with single flipped byte)
      const corruptedHdr = makeTarHeaderBlock('repo/a.txt', 0x30, 0);
      corruptedHdr[0] = 'X'.charCodeAt(0); // breaks checksum while keeping valid USTAR magic
      const badChecksumTgz = zlib.gzipSync(Buffer.concat([corruptedHdr, Buffer.alloc(1024, 0)]));
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(badChecksumTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'INVALID_ARCHIVE_FORMAT' });

      // 5. Nested directory Unicode NFC/NFD collisions (directory and file levels)
      const nestedDirCollisionTgz = await packTarGz([
        { name: 'repo/src/caf\u0065\u0301/nested/a.ts', content: '1' },
        { name: 'repo/src/caf\u00e9/Nested/b.ts', content: '2' },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(nestedDirCollisionTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'ARCHIVE_PATH_COLLISION' });

      const nestedDirFileConflictTgz = await packTarGz([
        { name: 'repo/src/caf\u0065\u0301', type: 'directory' },
        { name: 'repo/src/caf\u00e9', type: 'file', content: 'conflict' },
      ]);
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(nestedDirFileConflictTgz),
          workspaceParentDir: parentDir,
        })
      ).rejects.toMatchObject({ code: 'FILE_DIRECTORY_CONFLICT' });

      // 6. Concatenated gzip members: valid concatenation succeeds AND limits still apply across members
      const member1Tar = Buffer.concat([
        makeTarHeaderBlock('repo/part1.txt', 0x30, 5),
        padTarBlock(Buffer.from('part1', 'utf8')),
      ]);
      const member2Tar = Buffer.concat([
        makeTarHeaderBlock('repo/part2.txt', 0x30, 5),
        padTarBlock(Buffer.from('part2', 'utf8')),
        Buffer.alloc(1024, 0),
      ]);
      const concatValidTgz = Buffer.concat([zlib.gzipSync(member1Tar), zlib.gzipSync(member2Tar)]);
      const wsConcat = await extractRepositoryArchive({
        archive: makeFakeAcquiredArchive(concatValidTgz),
        workspaceParentDir: parentDir,
      });
      expect(await readFile(path.join(wsConcat.workspacePath, 'part1.txt'), 'utf8')).toBe('part1');
      expect(await readFile(path.join(wsConcat.workspacePath, 'part2.txt'), 'utf8')).toBe('part2');
      await wsConcat.cleanup();

      // Entry limit enforced across concatenated gzip members
      await expect(
        extractRepositoryArchive({
          archive: makeFakeAcquiredArchive(concatValidTgz),
          workspaceParentDir: parentDir,
          limits: { maxEntries: 1 },
        })
      ).rejects.toMatchObject({ code: 'ENTRY_COUNT_EXCEEDED' });

      expect(await readdir(parentDir)).toEqual([]);
    });
  });
});
