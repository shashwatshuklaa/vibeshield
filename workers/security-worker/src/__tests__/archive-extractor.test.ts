import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { lstat, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink } from 'node:fs/promises';
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
  DEFAULT_MAX_FILE_BYTES,
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
        maxEntryMetadataBytes: 64 * 1024,
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
});
