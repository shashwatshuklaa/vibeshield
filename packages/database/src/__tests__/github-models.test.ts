import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { Error as MongooseError, Types, type Document } from 'mongoose';
import {
  AUDIT_METADATA_MAX_BYTES,
  computeConnectionIsActive,
  formatSafeError,
  getEffectiveConnectionStatus,
  GITHUB_ACCOUNT_TYPES,
  GITHUB_INSTALLATION_STATUSES,
  GITHUB_REPOSITORY_SELECTIONS,
  GitHubInstallationModel,
  githubInstallationSchema,
  GitHubInstallationStatusValue,
  GitHubOAuthStateModel,
  githubOAuthStateSchema,
  INSTALLATION_AVAILABILITIES,
  InstallationAvailabilityValue,
  INTEGRATION_AUDIT_ACTIONS,
  INTEGRATION_AUDIT_ACTOR_TYPES,
  IntegrationAuditActionValue,
  IntegrationAuditActorTypeValue,
  IntegrationAuditLogModel,
  integrationAuditLogSchema,
  ProjectRepositoryConnectionModel,
  projectRepositoryConnectionSchema,
  redactGitHubSecrets,
  REPOSITORY_ACCESS_STATES,
  RepositoryAccessStateValue,
  sanitizeAuditMetadata,
  WEBHOOK_DELIVERY_OUTCOMES,
  WebhookDeliveryModel,
  webhookDeliverySchema,
  WebhookDeliveryOutcomeValue,
} from '../index.js';

async function getValidationError(
  doc: Document
): Promise<MongooseError.ValidationError | undefined> {
  try {
    await doc.validate();
    return undefined;
  } catch (error) {
    if (error instanceof MongooseError.ValidationError) {
      return error;
    }
    throw error;
  }
}

describe('GitHub Integration Database Models and Redaction', () => {
  describe('Secret Redaction & Audit Metadata Sanitization', () => {
    it('redacts GitHub token prefixes, Bearer/Basic auth headers, x-access-token URLs, PEM keys, and explicit secrets', () => {
      const configuredSecret = 'whsec_configured_super_secret_value_12345';
      const pemBlock = [
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEAtokenmaterial',
        '-----END RSA PRIVATE KEY-----',
      ].join('\n');
      const escapedPem = pemBlock.replace(/\n/g, '\\n');

      const raw = [
        'ghp=ghp_1234567890abcdef',
        'gho=gho_abcdef1234567890',
        'ghu=ghu_1122334455667788',
        'ghs=ghs_installationToken998877',
        'ghs_jwt=ghs_77777_eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturePart99',
        'ghr=ghr_refreshToken11223344',
        'pat=github_pat_11ABCDEF0123456789_xyz',
        'auth=Bearer header.payload.signature',
        'basic=Basic dXNlcjpwYXNzd29yZA==',
        'url=https://x-access-token:ghs_secretInUrl123@github.com/org/repo.git',
        `pem=${pemBlock}`,
        `escaped=${escapedPem}`,
        `secret=${configuredSecret}`,
      ].join(' | ');

      const redacted = redactGitHubSecrets(raw, [configuredSecret]);

      expect(redacted).not.toContain('ghp_1234567890abcdef');
      expect(redacted).not.toContain('gho_abcdef1234567890');
      expect(redacted).not.toContain('ghu_1122334455667788');
      expect(redacted).not.toContain('ghs_installationToken998877');
      expect(redacted).not.toContain('eyJhbGciOiJFUzI1NiJ9');
      expect(redacted).not.toContain('signaturePart99');
      expect(redacted).not.toContain('ghr_refreshToken11223344');
      expect(redacted).not.toContain('github_pat_11ABCDEF0123456789_xyz');
      expect(redacted).not.toContain('header.payload.signature');
      expect(redacted).not.toContain('dXNlcjpwYXNzd29yZA==');
      expect(redacted).not.toContain('ghs_secretInUrl123');
      expect(redacted).not.toContain('MIIEowIBAAKCAQEAtokenmaterial');
      expect(redacted).not.toContain(configuredSecret);
      expect(redacted).toContain('[REDACTED_GITHUB_TOKEN]');
      expect(redacted).toContain('Bearer [REDACTED]');
      expect(redacted).toContain('[REDACTED_PEM_PRIVATE_KEY]');
      expect(redacted).toContain('[REDACTED_SECRET]');

      const safeErr = formatSafeError(
        new Error(
          'Upstream failed with ghs_secretTokenValue123 and mongodb://user:pass@localhost/db'
        )
      );
      expect(safeErr).not.toContain('ghs_secretTokenValue123');
      expect(safeErr).not.toContain('pass');
    });

    it('sanitizes secret-bearing keys, bounds nested strings, and preserves non-credential metadata', () => {
      const sanitized = sanitizeAuditMetadata({
        fullName: 'acme/web-app',
        accessToken: 'ghs_shouldBeRemovedCompletely',
        webhookSecret: 'secret_value',
        authorization: 'Bearer abcdef123456',
        nested: {
          privateKey: 'pem',
          note: 'Received token gho_nestedSecretToken123 for repo',
          longText: 'A'.repeat(700),
        },
      }) as Record<string, unknown>;

      expect(sanitized.fullName).toBe('acme/web-app');
      expect(sanitized).not.toHaveProperty('accessToken');
      expect(sanitized).not.toHaveProperty('webhookSecret');
      expect(sanitized).not.toHaveProperty('authorization');
      const nested = sanitized.nested as Record<string, unknown>;
      expect(nested).not.toHaveProperty('privateKey');
      expect(nested.note).toBe('Received token [REDACTED_GITHUB_TOKEN] for repo');
      expect((nested.longText as string).length).toBe(500);
    });
  });

  describe('GitHubInstallationModel', () => {
    it('exports expected model metadata and validates defaults, enums, and active-slot consistency', async () => {
      expect(GitHubInstallationModel.modelName).toBe('GitHubInstallation');
      expect(GitHubInstallationModel.collection.name).toBe('github_installations');
      expect(GITHUB_ACCOUNT_TYPES).toEqual(['User', 'Organization']);
      expect(GITHUB_REPOSITORY_SELECTIONS).toEqual(['all', 'selected']);
      expect(GITHUB_INSTALLATION_STATUSES).toEqual([
        'ACTIVE',
        'SUSPENDED',
        'REVOKED',
        'DISCONNECTED',
      ]);

      const validDoc = new GitHubInstallationModel({
        organizationId: new Types.ObjectId(),
        githubInstallationId: 1001,
        githubAppId: 42,
        accountId: 9001,
        accountLogin: '  acme-org  ',
        accountType: 'Organization',
        repositorySelection: 'selected',
        grantedPermissions: { contents: 'read', metadata: 'read' },
        connectedByUserId: new Types.ObjectId(),
      });

      expect(await getValidationError(validDoc)).toBeUndefined();
      expect(validDoc.status).toBe(GitHubInstallationStatusValue.ACTIVE);
      expect(validDoc.isActive).toBe(true);
      expect(validDoc.accountLogin).toBe('acme-org');

      const revokedDoc = new GitHubInstallationModel({
        organizationId: new Types.ObjectId(),
        githubInstallationId: 1002,
        githubAppId: 42,
        accountId: 9002,
        accountLogin: 'user-one',
        accountType: 'User',
        repositorySelection: 'all',
        status: GitHubInstallationStatusValue.REVOKED,
        connectedByUserId: new Types.ObjectId(),
      });
      expect(await getValidationError(revokedDoc)).toBeUndefined();
      expect(revokedDoc.isActive).toBe(false);

      const serialized = revokedDoc.toJSON() as unknown as Record<string, unknown>;
      expect(serialized.__v).toBeUndefined();
    });

    it('rejects missing fields, invalid enums, invalid IDs, and mismatched isActive/status', async () => {
      const missingDoc = new GitHubInstallationModel({});
      const missingErr = await getValidationError(missingDoc);
      expect(missingErr?.errors.organizationId?.kind).toBe('required');
      expect(missingErr?.errors.githubInstallationId?.kind).toBe('required');
      expect(missingErr?.errors.githubAppId?.kind).toBe('required');
      expect(missingErr?.errors.accountId?.kind).toBe('required');
      expect(missingErr?.errors.accountLogin?.kind).toBe('required');
      expect(missingErr?.errors.accountType?.kind).toBe('required');
      expect(missingErr?.errors.repositorySelection?.kind).toBe('required');
      expect(missingErr?.errors.connectedByUserId?.kind).toBe('required');

      const invalidDoc = new GitHubInstallationModel({
        organizationId: new Types.ObjectId(),
        githubInstallationId: 0,
        githubAppId: -1,
        accountId: 12.5,
        accountLogin: 'org',
        accountType: 'Enterprise',
        repositorySelection: 'none',
        status: 'DISCONNECTED',
        isActive: true,
        connectedByUserId: new Types.ObjectId(),
      });
      const invalidErr = await getValidationError(invalidDoc);
      expect(invalidErr?.errors.githubInstallationId).toBeDefined();
      expect(invalidErr?.errors.githubAppId).toBeDefined();
      expect(invalidErr?.errors.accountId).toBeDefined();
      expect(invalidErr?.errors.accountType).toBeDefined();
      expect(invalidErr?.errors.repositorySelection).toBeDefined();
      expect(invalidErr?.errors.isActive).toBeDefined();
    });

    it('defines partial unique active index without $ne', () => {
      const indexes = githubInstallationSchema.indexes();
      expect(indexes).toContainEqual([
        { githubInstallationId: 1 },
        {
          unique: true,
          partialFilterExpression: { isActive: true },
          name: 'github_installations_active_id_unique',
        },
      ]);
      expect(indexes).toContainEqual([
        { organizationId: 1, isActive: 1, status: 1 },
        { name: 'github_installations_org_active_status_idx' },
      ]);
    });
  });

  describe('GitHubOAuthStateModel', () => {
    it('normalizes and protects stateHash and encryptedCodeVerifier via select: false and serialization redaction', async () => {
      expect(GitHubOAuthStateModel.modelName).toBe('GitHubOAuthState');
      expect(GitHubOAuthStateModel.collection.name).toBe('github_oauth_states');
      expect(githubOAuthStateSchema.path('stateHash').options.select).toBe(false);
      expect(githubOAuthStateSchema.path('encryptedCodeVerifier').options.select).toBe(false);

      const digest = createHash('sha256').update('raw_state_token').digest('hex').toUpperCase();
      const doc = new GitHubOAuthStateModel({
        stateHash: `  ${digest}  `,
        kind: 'OAUTH_AUTHORIZE',
        userId: new Types.ObjectId(),
        organizationId: new Types.ObjectId(),
        encryptedCodeVerifier: 'v1.iv.tag.ciphertext',
        expiresAt: new Date(Date.now() + 600_000),
      });

      expect(await getValidationError(doc)).toBeUndefined();
      expect(doc.stateHash).toBe(digest.toLowerCase());

      const json = doc.toJSON() as unknown as Record<string, unknown>;
      const obj = doc.toObject() as unknown as Record<string, unknown>;
      expect(json.stateHash).toBeUndefined();
      expect(obj.stateHash).toBeUndefined();
      expect(json.encryptedCodeVerifier).toBeUndefined();
      expect(obj.encryptedCodeVerifier).toBeUndefined();
      expect(json.__v).toBeUndefined();

      const badDoc = new GitHubOAuthStateModel({
        stateHash: 'not-a-sha256-digest',
        userId: new Types.ObjectId(),
        organizationId: new Types.ObjectId(),
        expiresAt: new Date(),
      });
      expect((await getValidationError(badDoc))?.errors.stateHash).toBeDefined();
    });

    it('defines unique stateHash index and TTL index on expiresAt', () => {
      const indexes = githubOAuthStateSchema.indexes();
      expect(indexes).toContainEqual([
        { stateHash: 1 },
        { unique: true, name: 'github_oauth_states_hash_unique' },
      ]);
      expect(indexes).toContainEqual([
        { expiresAt: 1 },
        { expireAfterSeconds: 0, name: 'github_oauth_states_expires_at_ttl_idx' },
      ]);
    });
  });

  describe('ProjectRepositoryConnectionModel', () => {
    it('prevents installation suspend/unsuspend cycles from restoring ACCESS_REVOKED or REPO_DELETED', async () => {
      expect(ProjectRepositoryConnectionModel.modelName).toBe('ProjectRepositoryConnection');
      expect(ProjectRepositoryConnectionModel.collection.name).toBe(
        'project_repository_connections'
      );
      expect(REPOSITORY_ACCESS_STATES).toEqual([
        'CONNECTED',
        'ACCESS_REVOKED',
        'REPO_DELETED',
        'DISCONNECTED',
      ]);
      expect(INSTALLATION_AVAILABILITIES).toEqual([
        'ACTIVE',
        'SUSPENDED',
        'REVOKED',
        'DISCONNECTED',
      ]);

      // Healthy installation cycle: CONNECTED + ACTIVE -> SUSPENDED -> ACTIVE restores CONNECTED
      expect(
        getEffectiveConnectionStatus({
          repositoryAccessState: RepositoryAccessStateValue.CONNECTED,
          installationAvailability: InstallationAvailabilityValue.ACTIVE,
        })
      ).toBe('CONNECTED');
      expect(
        getEffectiveConnectionStatus({
          repositoryAccessState: RepositoryAccessStateValue.CONNECTED,
          installationAvailability: InstallationAvailabilityValue.SUSPENDED,
        })
      ).toBe('INSTALLATION_SUSPENDED');

      // Revoked repo stays ACCESS_REVOKED across suspend/unsuspend
      expect(
        getEffectiveConnectionStatus({
          repositoryAccessState: RepositoryAccessStateValue.ACCESS_REVOKED,
          installationAvailability: InstallationAvailabilityValue.SUSPENDED,
        })
      ).toBe('ACCESS_REVOKED');
      expect(
        getEffectiveConnectionStatus({
          repositoryAccessState: RepositoryAccessStateValue.ACCESS_REVOKED,
          installationAvailability: InstallationAvailabilityValue.ACTIVE,
        })
      ).toBe('ACCESS_REVOKED');

      // Deleted repo stays REPO_DELETED across suspend/unsuspend
      expect(
        getEffectiveConnectionStatus({
          repositoryAccessState: RepositoryAccessStateValue.REPO_DELETED,
          installationAvailability: InstallationAvailabilityValue.ACTIVE,
        })
      ).toBe('REPO_DELETED');

      expect(
        computeConnectionIsActive(
          RepositoryAccessStateValue.DISCONNECTED,
          InstallationAvailabilityValue.ACTIVE
        )
      ).toBe(false);
    });

    it('validates fields, defaults, disconnected isActive, and rejects invalid fullName or mismatch', async () => {
      const valid = new ProjectRepositoryConnectionModel({
        organizationId: new Types.ObjectId(),
        projectId: new Types.ObjectId(),
        installationRecordId: new Types.ObjectId(),
        githubInstallationId: 501,
        githubRepositoryId: 90001,
        ownerLogin: '  acme-sec  ',
        repoName: '  backend-api  ',
        fullName: '  acme-sec/backend-api  ',
        htmlUrl: '  https://github.com/acme-sec/backend-api  ',
        defaultBranch: '  main  ',
        isPrivate: true,
        connectedByUserId: new Types.ObjectId(),
      });

      expect(await getValidationError(valid)).toBeUndefined();
      expect(valid.isActive).toBe(true);
      expect(valid.repositoryAccessState).toBe('CONNECTED');
      expect(valid.installationAvailability).toBe('ACTIVE');
      expect(valid.fullName).toBe('acme-sec/backend-api');
      expect(valid.htmlUrl).toBe('https://github.com/acme-sec/backend-api');

      const invalidHtmlUrl = new ProjectRepositoryConnectionModel({
        organizationId: new Types.ObjectId(),
        projectId: new Types.ObjectId(),
        installationRecordId: new Types.ObjectId(),
        githubInstallationId: 501,
        githubRepositoryId: 90001,
        ownerLogin: 'acme-sec',
        repoName: 'backend-api',
        fullName: 'acme-sec/backend-api',
        htmlUrl: 'javascript:alert(1)',
        defaultBranch: 'main',
        isPrivate: true,
        connectedByUserId: new Types.ObjectId(),
      });
      expect(await getValidationError(invalidHtmlUrl)).toBeDefined();

      const disconnected = new ProjectRepositoryConnectionModel({
        organizationId: new Types.ObjectId(),
        projectId: new Types.ObjectId(),
        installationRecordId: new Types.ObjectId(),
        githubInstallationId: 501,
        githubRepositoryId: 90001,
        ownerLogin: 'acme-sec',
        repoName: 'backend-api',
        fullName: 'acme-sec/backend-api',
        defaultBranch: 'main',
        isPrivate: false,
        repositoryAccessState: RepositoryAccessStateValue.DISCONNECTED,
        connectedByUserId: new Types.ObjectId(),
      });
      expect(await getValidationError(disconnected)).toBeUndefined();
      expect(disconnected.isActive).toBe(false);

      const invalid = new ProjectRepositoryConnectionModel({
        organizationId: new Types.ObjectId(),
        projectId: new Types.ObjectId(),
        installationRecordId: new Types.ObjectId(),
        githubInstallationId: 501,
        githubRepositoryId: 90001,
        ownerLogin: 'acme',
        repoName: 'api',
        fullName: 'invalid-without-slash',
        defaultBranch: 'main',
        isPrivate: true,
        repositoryAccessState: RepositoryAccessStateValue.DISCONNECTED,
        isActive: true,
        connectedByUserId: new Types.ObjectId(),
      });
      const err = await getValidationError(invalid);
      expect(err?.errors.fullName).toBeDefined();
      expect(err?.errors.isActive).toBeDefined();
    });

    it('defines active partial unique indexes with { isActive: true } and zero $ne operators', () => {
      const indexes = projectRepositoryConnectionSchema.indexes();
      expect(indexes).toContainEqual([
        { projectId: 1 },
        {
          unique: true,
          partialFilterExpression: { isActive: true },
          name: 'proj_repo_conn_active_project_unique',
        },
      ]);
      expect(indexes).toContainEqual([
        { organizationId: 1, githubRepositoryId: 1 },
        {
          unique: true,
          partialFilterExpression: { isActive: true },
          name: 'proj_repo_conn_active_org_repo_unique',
        },
      ]);
      expect(indexes).toContainEqual([
        { githubInstallationId: 1, githubRepositoryId: 1, isActive: 1 },
        { name: 'proj_repo_conn_webhook_lookup_idx' },
      ]);
      expect(indexes).toContainEqual([
        { organizationId: 1, projectId: 1, isActive: 1 },
        { name: 'proj_repo_conn_org_project_active_idx' },
      ]);

      expect(JSON.stringify(indexes)).not.toContain('$ne');
    });
  });

  describe('WebhookDeliveryModel', () => {
    it('validates delivery fields, enums, sha256 digest, error redaction, unique deliveryId, and TTL index', async () => {
      expect(WebhookDeliveryModel.modelName).toBe('WebhookDelivery');
      expect(WebhookDeliveryModel.collection.name).toBe('webhook_deliveries');
      expect(WEBHOOK_DELIVERY_OUTCOMES).toEqual(['PROCESSING', 'PROCESSED', 'IGNORED', 'FAILED']);

      const sha = createHash('sha256').update('{"action":"created"}').digest('hex');
      const doc = new WebhookDeliveryModel({
        deliveryId: '  123e4567-e89b-12d3-a456-426614174000  ',
        event: 'installation',
        action: 'created',
        githubInstallationId: 999,
        payloadSha256: sha.toUpperCase(),
        outcome: WebhookDeliveryOutcomeValue.PROCESSED,
        errorMessage: 'Upstream error with Bearer secret_token_123456',
        expiresAt: new Date(Date.now() + 86_400_000),
      });

      expect(await getValidationError(doc)).toBeUndefined();
      expect(doc.deliveryId).toBe('123e4567-e89b-12d3-a456-426614174000');
      expect(doc.payloadSha256).toBe(sha);
      expect(doc.attemptCount).toBe(1);
      expect(doc.targetOrganizationIds).toEqual([]);
      expect(doc.completedOrganizationIds).toEqual([]);
      expect(doc.processedConnectionCount).toBe(0);
      expect(doc.errorMessage).toBe('Upstream error with Bearer [REDACTED]');

      const oversizedProgressDoc = new WebhookDeliveryModel({
        deliveryId: 'id-too-many-orgs',
        event: 'repository',
        payloadSha256: sha,
        outcome: WebhookDeliveryOutcomeValue.PROCESSING,
        targetOrganizationIds: Array.from({ length: 1001 }, () => new Types.ObjectId()),
        expiresAt: new Date(Date.now() + 86_400_000),
      });
      const progressErr = await getValidationError(oversizedProgressDoc);
      expect(progressErr?.errors.targetOrganizationIds).toBeDefined();

      const invalid = new WebhookDeliveryModel({
        deliveryId: 'id-1',
        event: 'push',
        payloadSha256: 'bad-hash',
        outcome: 'UNKNOWN',
        expiresAt: new Date(),
      });
      const err = await getValidationError(invalid);
      expect(err?.errors.payloadSha256).toBeDefined();
      expect(err?.errors.outcome).toBeDefined();

      const indexes = webhookDeliverySchema.indexes();
      expect(indexes).toContainEqual([
        { deliveryId: 1 },
        { unique: true, name: 'webhook_deliveries_delivery_id_unique' },
      ]);
      expect(indexes).toContainEqual([
        { expiresAt: 1 },
        { expireAfterSeconds: 0, name: 'webhook_deliveries_expires_at_ttl_idx' },
      ]);
    });
  });

  describe('IntegrationAuditLogModel', () => {
    it('validates enums, strips/redacts credentials from metadata, and rejects oversized metadata', async () => {
      expect(IntegrationAuditLogModel.modelName).toBe('IntegrationAuditLog');
      expect(IntegrationAuditLogModel.collection.name).toBe('integration_audit_logs');
      expect(INTEGRATION_AUDIT_ACTOR_TYPES).toEqual(['USER', 'GITHUB_WEBHOOK', 'SYSTEM']);
      expect(INTEGRATION_AUDIT_ACTIONS).toContain('REPOSITORY_CONNECTED');

      const doc = new IntegrationAuditLogModel({
        organizationId: new Types.ObjectId(),
        projectId: new Types.ObjectId(),
        actorType: IntegrationAuditActorTypeValue.USER,
        actorUserId: new Types.ObjectId(),
        action: IntegrationAuditActionValue.REPOSITORY_CONNECTED,
        githubInstallationId: 123,
        githubRepositoryId: 456,
        metadata: {
          fullName: 'acme/api',
          accessToken: 'ghs_leakedTokenMustBeStripped',
          summary: 'Linked repo with ghu_inlineToken123456',
        },
      });

      expect(await getValidationError(doc)).toBeUndefined();
      expect(doc.metadata).not.toHaveProperty('accessToken');
      expect(doc.metadata.fullName).toBe('acme/api');
      expect(doc.metadata.summary).toBe('Linked repo with [REDACTED_GITHUB_TOKEN]');

      // Reject oversized (>4096 bytes) metadata
      const bigEntries: Record<string, string> = {};
      for (let i = 0; i < 15; i++) {
        bigEntries[`key_${i}`] = 'X'.repeat(400);
      }
      const oversizedDoc = new IntegrationAuditLogModel({
        organizationId: new Types.ObjectId(),
        actorType: IntegrationAuditActorTypeValue.SYSTEM,
        action: IntegrationAuditActionValue.REPOSITORY_SYNCED,
        metadata: bigEntries,
      });
      expect(Buffer.byteLength(JSON.stringify(oversizedDoc.metadata), 'utf8')).toBeGreaterThan(
        AUDIT_METADATA_MAX_BYTES
      );
      expect((await getValidationError(oversizedDoc))?.errors.metadata).toBeDefined();

      // Reject non-object metadata
      const nonObjectDoc = new IntegrationAuditLogModel({
        organizationId: new Types.ObjectId(),
        actorType: IntegrationAuditActorTypeValue.SYSTEM,
        action: IntegrationAuditActionValue.REPOSITORY_SYNCED,
        metadata: ['not-an-object'],
      });
      expect((await getValidationError(nonObjectDoc))?.errors.metadata).toBeDefined();
    });

    it('rejects query-level updates to enforce append-only design', async () => {
      await expect(
        IntegrationAuditLogModel.updateOne(
          { _id: new Types.ObjectId() },
          { $set: { action: 'REPOSITORY_DELETED' } }
        )
      ).rejects.toThrow(/append-only/i);

      await expect(
        IntegrationAuditLogModel.findOneAndUpdate(
          { _id: new Types.ObjectId() },
          { $set: { action: 'REPOSITORY_DELETED' } }
        )
      ).rejects.toThrow(/append-only/i);

      const indexes = integrationAuditLogSchema.indexes();
      expect(indexes).toContainEqual([
        { organizationId: 1, createdAt: -1 },
        { name: 'integration_audit_logs_org_created_idx' },
      ]);
      expect(indexes).toContainEqual([
        { organizationId: 1, projectId: 1, createdAt: -1 },
        { name: 'integration_audit_logs_org_project_created_idx' },
      ]);
    });
  });
});
