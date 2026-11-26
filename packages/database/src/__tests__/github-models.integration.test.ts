import { createHash } from 'node:crypto';
import mongoose from 'mongoose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  connectDatabase,
  disconnectDatabase,
  GitHubInstallationModel,
  GitHubInstallationStatusValue,
  GitHubOAuthStateModel,
  InstallationAvailabilityValue,
  IntegrationAuditLogModel,
  ProjectRepositoryConnectionModel,
  RepositoryAccessStateValue,
  WebhookDeliveryModel,
  WebhookDeliveryOutcomeValue,
} from '../index.js';

const REPLICA_URI = process.env.MONGODB_INTEGRATION_URI;

describe.skipIf(!REPLICA_URI)(
  'GitHub Integration Models Real MongoDB Replica-Set Integration Tests',
  () => {
    beforeAll(async () => {
      await connectDatabase(REPLICA_URI!, { serverSelectionTimeoutMS: 10_000 });
      await Promise.all([
        GitHubInstallationModel.syncIndexes(),
        GitHubOAuthStateModel.syncIndexes(),
        ProjectRepositoryConnectionModel.syncIndexes(),
        WebhookDeliveryModel.syncIndexes(),
        IntegrationAuditLogModel.syncIndexes(),
      ]);
    });

    beforeEach(async () => {
      await Promise.all([
        GitHubInstallationModel.deleteMany({}),
        GitHubOAuthStateModel.deleteMany({}),
        ProjectRepositoryConnectionModel.deleteMany({}),
        WebhookDeliveryModel.deleteMany({}),
        IntegrationAuditLogModel.deleteMany({}),
      ]);
    });

    afterAll(async () => {
      await disconnectDatabase();
    });

    it('creates all expected unique partial and TTL indexes on real MongoDB without invalid operators', async () => {
      const [installIndexes, oauthIndexes, repoIndexes, webhookIndexes] = await Promise.all([
        GitHubInstallationModel.collection.indexes(),
        GitHubOAuthStateModel.collection.indexes(),
        ProjectRepositoryConnectionModel.collection.indexes(),
        WebhookDeliveryModel.collection.indexes(),
      ]);

      expect(installIndexes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: 'github_installations_active_id_unique',
            unique: true,
            partialFilterExpression: { isActive: true },
          }),
        ])
      );

      expect(oauthIndexes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: 'github_oauth_states_hash_unique',
            unique: true,
          }),
          expect.objectContaining({
            name: 'github_oauth_states_expires_at_ttl_idx',
            expireAfterSeconds: 0,
          }),
        ])
      );

      expect(repoIndexes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: 'proj_repo_conn_active_project_unique',
            unique: true,
            partialFilterExpression: { isActive: true },
          }),
          expect.objectContaining({
            name: 'proj_repo_conn_active_org_repo_unique',
            unique: true,
            partialFilterExpression: { isActive: true },
          }),
        ])
      );

      expect(webhookIndexes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: 'webhook_deliveries_delivery_id_unique',
            unique: true,
          }),
          expect.objectContaining({
            name: 'webhook_deliveries_expires_at_ttl_idx',
            expireAfterSeconds: 0,
          }),
        ])
      );
    });

    it('rejects duplicate active installation across organizations and allows re-linking after DISCONNECTED', async () => {
      const orgA = new mongoose.Types.ObjectId();
      const orgB = new mongoose.Types.ObjectId();
      const userId = new mongoose.Types.ObjectId();

      const first = await GitHubInstallationModel.create({
        organizationId: orgA,
        githubInstallationId: 77001,
        githubAppId: 10,
        accountId: 500,
        accountLogin: 'acme-gh',
        accountType: 'Organization',
        repositorySelection: 'selected',
        status: GitHubInstallationStatusValue.ACTIVE,
        connectedByUserId: userId,
      });

      await expect(
        GitHubInstallationModel.create({
          organizationId: orgB,
          githubInstallationId: 77001,
          githubAppId: 10,
          accountId: 500,
          accountLogin: 'acme-gh',
          accountType: 'Organization',
          repositorySelection: 'selected',
          status: GitHubInstallationStatusValue.ACTIVE,
          connectedByUserId: userId,
        })
      ).rejects.toMatchObject({ code: 11000 });

      await GitHubInstallationModel.findByIdAndUpdate(
        first._id,
        {
          $set: {
            status: GitHubInstallationStatusValue.DISCONNECTED,
            isActive: false,
            disconnectedByUserId: userId,
          },
        },
        { runValidators: true }
      );

      const relinked = await GitHubInstallationModel.create({
        organizationId: orgB,
        githubInstallationId: 77001,
        githubAppId: 10,
        accountId: 500,
        accountLogin: 'acme-gh',
        accountType: 'Organization',
        repositorySelection: 'selected',
        status: GitHubInstallationStatusValue.ACTIVE,
        connectedByUserId: userId,
      });
      expect(relinked.organizationId.toString()).toBe(orgB.toString());
    });

    it('enforces active project & org-repo uniqueness, allows same repo across orgs, and supports reconnection after disconnect', async () => {
      const orgA = new mongoose.Types.ObjectId();
      const orgB = new mongoose.Types.ObjectId();
      const projectA1 = new mongoose.Types.ObjectId();
      const projectA2 = new mongoose.Types.ObjectId();
      const projectB1 = new mongoose.Types.ObjectId();
      const installA = new mongoose.Types.ObjectId();
      const installB = new mongoose.Types.ObjectId();
      const userId = new mongoose.Types.ObjectId();

      const connA1 = await ProjectRepositoryConnectionModel.create({
        organizationId: orgA,
        projectId: projectA1,
        installationRecordId: installA,
        githubInstallationId: 101,
        githubRepositoryId: 8888,
        ownerLogin: 'shared-owner',
        repoName: 'target-repo',
        fullName: 'shared-owner/target-repo',
        defaultBranch: 'main',
        isPrivate: true,
        connectedByUserId: userId,
      });

      // Same project cannot have two active connections
      await expect(
        ProjectRepositoryConnectionModel.create({
          organizationId: orgA,
          projectId: projectA1,
          installationRecordId: installA,
          githubInstallationId: 101,
          githubRepositoryId: 9999,
          ownerLogin: 'shared-owner',
          repoName: 'other-repo',
          fullName: 'shared-owner/other-repo',
          defaultBranch: 'main',
          isPrivate: false,
          connectedByUserId: userId,
        })
      ).rejects.toMatchObject({ code: 11000 });

      // Same repo cannot be actively linked to two projects in the same organization
      await expect(
        ProjectRepositoryConnectionModel.create({
          organizationId: orgA,
          projectId: projectA2,
          installationRecordId: installA,
          githubInstallationId: 101,
          githubRepositoryId: 8888,
          ownerLogin: 'shared-owner',
          repoName: 'target-repo',
          fullName: 'shared-owner/target-repo',
          defaultBranch: 'main',
          isPrivate: true,
          connectedByUserId: userId,
        })
      ).rejects.toMatchObject({ code: 11000 });

      // Same GitHub repository IS allowed in a different VibeShield organization
      const connB1 = await ProjectRepositoryConnectionModel.create({
        organizationId: orgB,
        projectId: projectB1,
        installationRecordId: installB,
        githubInstallationId: 202,
        githubRepositoryId: 8888,
        ownerLogin: 'shared-owner',
        repoName: 'target-repo',
        fullName: 'shared-owner/target-repo',
        defaultBranch: 'main',
        isPrivate: false,
        connectedByUserId: userId,
      });
      expect(connB1.organizationId.toString()).toBe(orgB.toString());

      // Disconnecting connA1 frees both projectA1 and (orgA, 8888) slots for reconnection
      await ProjectRepositoryConnectionModel.findByIdAndUpdate(
        connA1._id,
        {
          $set: {
            repositoryAccessState: RepositoryAccessStateValue.DISCONNECTED,
            installationAvailability: InstallationAvailabilityValue.ACTIVE,
            isActive: false,
            disconnectedAt: new Date(),
            disconnectedByUserId: userId,
          },
        },
        { runValidators: true }
      );

      const reconnected = await ProjectRepositoryConnectionModel.create({
        organizationId: orgA,
        projectId: projectA1,
        installationRecordId: installA,
        githubInstallationId: 101,
        githubRepositoryId: 8888,
        ownerLogin: 'shared-owner',
        repoName: 'target-repo',
        fullName: 'shared-owner/target-repo',
        defaultBranch: 'main',
        isPrivate: true,
        connectedByUserId: userId,
      });
      expect(reconnected._id.toString()).not.toBe(connA1._id.toString());
      expect(await ProjectRepositoryConnectionModel.countDocuments({ projectId: projectA1 })).toBe(
        2
      );
    });

    it('enforces WebhookDelivery and GitHubOAuthState uniqueness and expires documents via MongoDB TTL', async () => {
      const deliverySha = createHash('sha256').update('payload').digest('hex');

      await WebhookDeliveryModel.create({
        deliveryId: 'delivery-uuid-1',
        event: 'push',
        action: null,
        githubInstallationId: 101,
        payloadSha256: deliverySha,
        outcome: WebhookDeliveryOutcomeValue.PROCESSED,
        expiresAt: new Date(Date.now() + 60_000),
      });

      await expect(
        WebhookDeliveryModel.create({
          deliveryId: 'delivery-uuid-1',
          event: 'push',
          action: null,
          githubInstallationId: 101,
          payloadSha256: deliverySha,
          outcome: WebhookDeliveryOutcomeValue.PROCESSED,
          expiresAt: new Date(Date.now() + 60_000),
        })
      ).rejects.toMatchObject({ code: 11000 });

      const stateHash = createHash('sha256').update('oauth-state-1').digest('hex');
      const expiredState = await GitHubOAuthStateModel.create({
        stateHash,
        userId: new mongoose.Types.ObjectId(),
        organizationId: new mongoose.Types.ObjectId(),
        expiresAt: new Date(Date.now() - 5_000),
      });

      // Default queries omit stateHash due to select: false
      const fetched = await GitHubOAuthStateModel.findById(expiredState._id);
      expect(fetched?.stateHash).toBeUndefined();

      await expect(
        GitHubOAuthStateModel.create({
          stateHash,
          userId: new mongoose.Types.ObjectId(),
          organizationId: new mongoose.Types.ObjectId(),
          expiresAt: new Date(Date.now() + 60_000),
        })
      ).rejects.toMatchObject({ code: 11000 });

      // Speed up MongoDB TTL monitor on ephemeral local container if admin setParameter is permitted
      const adminDb = mongoose.connection.db?.admin();
      let restoredTtlMonitor = false;
      try {
        await adminDb?.command({ setParameter: 1, ttlMonitorSleepSecs: 1 });
        restoredTtlMonitor = true;

        const deadline = Date.now() + 10_000;
        let remaining = 1;
        while (Date.now() < deadline) {
          remaining = await GitHubOAuthStateModel.countDocuments({ _id: expiredState._id });
          if (remaining === 0) {
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 250));
        }
        expect(remaining).toBe(0);
      } finally {
        if (restoredTtlMonitor) {
          await adminDb?.command({ setParameter: 1, ttlMonitorSleepSecs: 60 }).catch(() => {});
        }
      }
    });
  }
);
