import { generateKeyPairSync, randomBytes } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  claimQueuedScanForAcquisition,
  connectDatabase,
  createQueuedScan,
  disconnectDatabase,
  GitHubInstallationModel,
  GitHubInstallationStatusValue,
  InstallationAvailabilityValue,
  OrganizationModel,
  ProjectModel,
  ProjectRepositoryConnectionModel,
  RepositoryAccessStateValue,
  requestScanCancellation,
  ScanModel,
} from '@vibeshield/database';
import { ScanTriggerSourceValue } from '@vibeshield/types';
import { createInternalApp } from '../internal-app.js';
import { createGitHubClient } from '../modules/github/github.client.js';
import {
  INTERNAL_NONCE_HEADER,
  INTERNAL_SERVICE_HEADER,
  INTERNAL_SIGNATURE_HEADER,
  INTERNAL_TIMESTAMP_HEADER,
  signInternalWorkerRequest,
} from '../modules/scans/internal-auth.js';

const REPLICA_URI = process.env.MONGODB_INTEGRATION_URI;
const TEST_INTERNAL_SECRET = 'integration_internal_worker_auth_secret_32_chars';
const RESOLVED_SHA = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
const RSA_KEY_PEM = generateKeyPairSync('rsa', {
  modulusLength: 2048,
}).privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;

describe.skipIf(!REPLICA_URI)(
  'Internal Archive Acquisition Proxy Real MongoDB Replica-Set Integration Tests',
  () => {
    const usedNonces = new Set<string>();
    const mintedToken = 'ghs_integration_scoped_token_123456';
    let revokedTokens: string[] = [];
    let codeloadAuthHeadersSeen: Array<string | undefined> = [];
    let delaySecondChunkMs = 0;

    let githubMockServer: http.Server;
    let codeloadMockServer: http.Server;
    let githubMockBaseUrl: string;
    let codeloadMockBaseUrl: string;

    let orgId: string;
    let userId: string;
    let projectId: string;
    let connId: string;

    beforeAll(async () => {
      await connectDatabase(REPLICA_URI!, { serverSelectionTimeoutMS: 10_000 });
      await Promise.all([
        OrganizationModel.syncIndexes(),
        ProjectModel.syncIndexes(),
        GitHubInstallationModel.syncIndexes(),
        ProjectRepositoryConnectionModel.syncIndexes(),
        ScanModel.syncIndexes(),
      ]);

      codeloadMockServer = http.createServer((req, res) => {
        codeloadAuthHeadersSeen.push(req.headers.authorization);
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/x-gzip');
        res.setHeader('X-Upstream-Secret', 'must-not-leak');
        res.write(Buffer.from('ARCHIVE_CHUNK_1_'));
        setTimeout(() => {
          if (!res.destroyed) {
            res.end(Buffer.from('ARCHIVE_CHUNK_2'));
          }
        }, delaySecondChunkMs);
      });
      await new Promise<void>((resolve) => codeloadMockServer.listen(0, '127.0.0.1', resolve));
      codeloadMockBaseUrl = `http://127.0.0.1:${(codeloadMockServer.address() as AddressInfo).port}`;

      githubMockServer = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/app/installations/5001/access_tokens') {
          res.statusCode = 201;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              token: mintedToken,
              expires_at: new Date(Date.now() + 300_000).toISOString(),
              repository_selection: 'selected',
              permissions: { contents: 'read' },
              repositories: [{ id: 8001 }],
            })
          );
          return;
        }
        if (req.method === 'DELETE' && req.url === '/installation/token') {
          revokedTokens.push(req.headers.authorization ?? '');
          res.statusCode = 204;
          res.end();
          return;
        }
        if (req.method === 'GET' && req.url === '/repositories/8001') {
          res.statusCode = 200;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              id: 8001,
              name: 'web-app',
              full_name: 'acme-sec/web-app',
              owner: { login: 'acme-sec' },
              default_branch: 'main',
              private: true,
              archived: false,
              html_url: 'https://github.com/acme-sec/web-app',
            })
          );
          return;
        }
        if (req.method === 'GET' && req.url === '/repos/acme-sec/web-app/commits/main') {
          res.statusCode = 200;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ sha: RESOLVED_SHA }));
          return;
        }
        if (req.method === 'GET' && req.url === `/repos/acme-sec/web-app/tarball/${RESOLVED_SHA}`) {
          res.statusCode = 302;
          res.setHeader(
            'Location',
            `${codeloadMockBaseUrl}/acme-sec/web-app/legacy.tar.gz/${RESOLVED_SHA}?token=codeload_signed_secret`
          );
          res.end();
          return;
        }
        res.statusCode = 404;
        res.end();
      });
      await new Promise<void>((resolve) => githubMockServer.listen(0, '127.0.0.1', resolve));
      githubMockBaseUrl = `http://127.0.0.1:${(githubMockServer.address() as AddressInfo).port}`;
    });

    beforeEach(async () => {
      usedNonces.clear();
      revokedTokens = [];
      codeloadAuthHeadersSeen = [];
      delaySecondChunkMs = 0;

      await Promise.all([
        OrganizationModel.deleteMany({}),
        ProjectModel.deleteMany({}),
        GitHubInstallationModel.deleteMany({}),
        ProjectRepositoryConnectionModel.deleteMany({}),
        ScanModel.deleteMany({}),
      ]);

      const creatorId = randomBytes(12).toString('hex');
      userId = creatorId;
      const org = await OrganizationModel.create({
        name: 'Stream Integration Org',
        slug: 'stream-integration-org',
        createdBy: creatorId,
      });
      orgId = org._id.toString();

      const project = await ProjectModel.create({
        organizationId: org._id,
        name: 'Web App',
        slug: 'web-app',
        createdBy: creatorId,
      });
      projectId = project._id.toString();

      const inst = await GitHubInstallationModel.create({
        organizationId: org._id,
        githubInstallationId: 5001,
        githubAppId: 9001,
        accountId: 7001,
        accountLogin: 'acme-sec',
        accountType: 'Organization',
        repositorySelection: 'selected',
        grantedPermissions: { contents: 'read' },
        status: GitHubInstallationStatusValue.ACTIVE,
        isActive: true,
        connectedByUserId: creatorId,
        lastSyncedAt: new Date(),
      });

      const conn = await ProjectRepositoryConnectionModel.create({
        organizationId: org._id,
        projectId: project._id,
        installationRecordId: inst._id,
        githubInstallationId: 5001,
        githubRepositoryId: 8001,
        ownerLogin: 'acme-sec',
        repoName: 'web-app',
        fullName: 'acme-sec/web-app',
        defaultBranch: 'main',
        isPrivate: true,
        isArchivedOnGitHub: false,
        repositoryAccessState: RepositoryAccessStateValue.CONNECTED,
        installationAvailability: InstallationAvailabilityValue.ACTIVE,
        connectedByUserId: creatorId,
        connectedAt: new Date(),
        lastSyncedAt: new Date(),
      });
      connId = conn._id.toString();
    });

    afterAll(async () => {
      await new Promise<void>((resolve) => githubMockServer.close(() => resolve()));
      await new Promise<void>((resolve) => codeloadMockServer.close(() => resolve()));
      await disconnectDatabase();
    });

    it('authorizes against MongoDB, persists resolvedCommitSha under lease fencing, follows manual codeload redirect without Authorization, streams archive, and revokes token', async () => {
      const scan = await createQueuedScan({
        organizationId: orgId,
        projectId,
        repositoryConnectionId: connId,
        githubInstallationId: 5001,
        githubRepositoryId: 8001,
        requestedRef: 'main',
        triggerSource: ScanTriggerSourceValue.MANUAL,
        createdByUserId: userId,
      });

      const claim = await claimQueuedScanForAcquisition({
        scanId: scan.id,
        organizationId: orgId,
        projectId,
        workerId: 'security-worker',
      });
      if (claim.status !== 'CLAIMED') {
        throw new Error('Expected scan claim to succeed');
      }

      const ghClient = createGitHubClient({
        config: {
          appId: 9001,
          appSlug: 'vibeshield-int',
          privateKeyPem: RSA_KEY_PEM,
          clientId: 'Iv1.int',
          clientSecret: 'integration_client_secret_123456',
          webhookSecret: 'integration_webhook_secret_32_chars_min',
          callbackUrl: 'http://localhost:5173/integrations/github/callback',
        },
        apiBaseUrl: githubMockBaseUrl,
        codeloadBaseUrl: codeloadMockBaseUrl,
        allowCustomBaseUrlForTests: true,
      });

      const internalApp = createInternalApp({
        auth: {
          workerAuthSecret: TEST_INTERNAL_SECRET,
          consumeNonce: async ({ nonce }) => {
            if (usedNonces.has(nonce)) {
              return 'REPLAYED';
            }
            usedNonces.add(nonce);
            return 'ACCEPTED';
          },
        },
        githubClient: ghClient,
        revalidationIntervalMs: 25,
      });

      const srv = await new Promise<http.Server>((resolve) => {
        const s = internalApp.listen(0, '127.0.0.1', () => resolve(s));
      });
      const port = (srv.address() as AddressInfo).port;

      try {
        const body = JSON.stringify({ scanId: scan.id, leaseToken: claim.leaseToken });
        const signed = signInternalWorkerRequest({
          secret: TEST_INTERNAL_SECRET,
          method: 'POST',
          path: '/internal/v1/scans/acquire',
          serviceId: 'security-worker',
          timestamp: String(Date.now()),
          nonce: 'mongo-int-acquire-001',
          rawBody: body,
        });

        const responseData = await new Promise<{
          statusCode: number;
          headers: http.IncomingHttpHeaders;
          body: Buffer;
        }>((resolve, reject) => {
          const req = http.request(
            {
              host: '127.0.0.1',
              port,
              method: 'POST',
              path: '/internal/v1/scans/acquire',
              headers: {
                'content-type': 'application/json',
                'content-length': String(Buffer.byteLength(body)),
                [INTERNAL_SERVICE_HEADER]: signed.serviceId,
                [INTERNAL_TIMESTAMP_HEADER]: signed.timestamp,
                [INTERNAL_NONCE_HEADER]: signed.nonce,
                [INTERNAL_SIGNATURE_HEADER]: signed.signature,
              },
            },
            (res) => {
              const chunks: Buffer[] = [];
              res.on('data', (chunk: Buffer) => chunks.push(chunk));
              res.on('end', () => {
                resolve({
                  statusCode: res.statusCode ?? 0,
                  headers: res.headers,
                  body: Buffer.concat(chunks),
                });
              });
            }
          );
          req.on('error', reject);
          req.write(body);
          req.end();
        });

        expect(responseData.statusCode).toBe(200);
        expect(responseData.headers['content-type']).toBe('application/gzip');
        expect(responseData.headers['x-upstream-secret']).toBeUndefined();
        expect(responseData.body.toString('utf8')).toBe('ARCHIVE_CHUNK_1_ARCHIVE_CHUNK_2');

        // Codeload NEVER received Authorization header
        expect(codeloadAuthHeadersSeen).toEqual([undefined]);
        // Ephemeral token was revoked asynchronously in finally right after streaming EOF
        await vi.waitFor(() => {
          expect(revokedTokens).toEqual([`Bearer ${mintedToken}`]);
        });

        // MongoDB Scan record persisted resolvedCommitSha without storing archive bytes or tokens
        const storedScan = await ScanModel.findById(scan.id).lean();
        expect(storedScan?.resolvedCommitSha).toBe(RESOLVED_SHA);
        expect(JSON.stringify(storedScan)).not.toContain(mintedToken);
        expect(JSON.stringify(storedScan)).not.toContain('ARCHIVE_CHUNK');

        // Real MongoDB cancellation mid-transfer aborts the stream before completion
        delaySecondChunkMs = 200;
        const signed2 = signInternalWorkerRequest({
          secret: TEST_INTERNAL_SECRET,
          method: 'POST',
          path: '/internal/v1/scans/acquire',
          serviceId: 'security-worker',
          timestamp: String(Date.now()),
          nonce: 'mongo-int-acquire-002',
          rawBody: body,
        });

        await expect(
          new Promise<void>((resolve, reject) => {
            const req = http.request(
              {
                host: '127.0.0.1',
                port,
                method: 'POST',
                path: '/internal/v1/scans/acquire',
                headers: {
                  'content-type': 'application/json',
                  'content-length': String(Buffer.byteLength(body)),
                  [INTERNAL_SERVICE_HEADER]: signed2.serviceId,
                  [INTERNAL_TIMESTAMP_HEADER]: signed2.timestamp,
                  [INTERNAL_NONCE_HEADER]: signed2.nonce,
                  [INTERNAL_SIGNATURE_HEADER]: signed2.signature,
                },
              },
              (res) => {
                res.once('data', () => {
                  void requestScanCancellation({
                    scanId: scan.id,
                    organizationId: orgId,
                    projectId,
                    requestedByUserId: userId,
                    reason: 'Cancelled mid-transfer',
                  });
                });
                res.on('error', reject);
                res.on('close', () => {
                  if (!res.complete) {
                    reject(new Error('Stream aborted before EOF'));
                  } else {
                    resolve();
                  }
                });
              }
            );
            req.on('error', reject);
            req.write(body);
            req.end();
          })
        ).rejects.toThrow();

        await vi.waitFor(() => {
          expect(revokedTokens).toHaveLength(2);
        });
      } finally {
        await new Promise<void>((resolve) => srv.close(() => resolve()));
      }
    });
  }
);
