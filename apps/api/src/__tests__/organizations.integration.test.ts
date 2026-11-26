import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  connectDatabase,
  disconnectDatabase,
  OrganizationMembershipModel,
  OrganizationModel,
  ProjectModel,
  UserModel,
} from '@vibeshield/database';
import { createOrganizationService } from '../modules/organizations/organization.service.js';
import {
  mongooseOrganizationStore,
  type OrganizationStore,
} from '../modules/organizations/organization.store.js';

const REPLICA_URI = process.env.MONGODB_INTEGRATION_URI;

describe.skipIf(!REPLICA_URI)('Organizations Real MongoDB Replica-Set Integration Tests', () => {
  beforeAll(async () => {
    await connectDatabase(REPLICA_URI!, { serverSelectionTimeoutMS: 10_000 });
    await Promise.all([
      UserModel.syncIndexes(),
      OrganizationModel.syncIndexes(),
      OrganizationMembershipModel.syncIndexes(),
      ProjectModel.syncIndexes(),
    ]);
  });

  beforeEach(async () => {
    await Promise.all([
      ProjectModel.deleteMany({}),
      OrganizationMembershipModel.deleteMany({}),
      OrganizationModel.deleteMany({}),
      UserModel.deleteMany({}),
    ]);
  });

  afterAll(async () => {
    await disconnectDatabase();
  });

  async function seedUser(email: string, displayName: string) {
    const doc = await UserModel.create({
      email,
      displayName,
      passwordHash: '$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$dummyhashvalueforintegrationtest',
      status: 'ACTIVE',
    });
    return { id: doc._id.toString(), email: doc.email, displayName: doc.displayName };
  }

  it('A. rolls back organization creation completely when membership write fails inside transaction', async () => {
    const user = await seedUser('rollback@realmongo.dev', 'Rollback User');

    const failingStore: OrganizationStore = {
      ...mongooseOrganizationStore,
      async createMembership() {
        throw new Error('Forced membership write failure after organization insert');
      },
    };

    const failingService = createOrganizationService({ store: failingStore });

    await expect(
      failingService.createOrganization(user.id, {
        name: 'Rollback Real Org',
        slug: 'rollback-real-org',
      })
    ).rejects.toThrow('Forced membership write failure after organization insert');

    expect(await OrganizationModel.countDocuments({ slug: 'rollback-real-org' })).toBe(0);
    expect(await OrganizationMembershipModel.countDocuments({})).toBe(0);
  });

  it('B. enforces concurrent last-OWNER protection under real WiredTiger snapshot isolation (removal & demotion)', async () => {
    const owner1 = await seedUser('owner1@realmongo.dev', 'Owner One');
    const owner2 = await seedUser('owner2@realmongo.dev', 'Owner Two');

    const service = createOrganizationService({ store: mongooseOrganizationStore });
    const org = await service.createOrganization(owner1.id, {
      name: 'Two Owner Real Org',
      slug: 'two-owner-real-org',
    });

    const m2Doc = await OrganizationMembershipModel.create({
      userId: owner2.id,
      organizationId: org.id,
      role: 'OWNER',
      status: 'ACTIVE',
    });
    const m1Doc = (await OrganizationMembershipModel.findOne({
      organizationId: org.id,
      userId: owner1.id,
    }))!;

    // Force genuine overlapping transactions holding the Organization write lock
    let callIndex = 0;
    let markSecondEntered!: () => void;
    const secondEntered = new Promise<void>((resolve) => {
      markSecondEntered = resolve;
    });

    const overlappingStore: OrganizationStore = {
      ...mongooseOrganizationStore,
      async acquireOrganizationLock(orgId, tx) {
        const myTurn = callIndex++;
        if (myTurn === 0) {
          const result = await mongooseOrganizationStore.acquireOrganizationLock(orgId, tx);
          // Hold WiredTiger write lock on Organization until T2 enters and competes for it
          await secondEntered;
          return result;
        }
        if (myTurn === 1) {
          markSecondEntered();
        }
        return mongooseOrganizationStore.acquireOrganizationLock(orgId, tx);
      },
    };

    const overlappingService = createOrganizationService({ store: overlappingStore });

    // 1. Concurrent mutual removal
    const removalResults = await Promise.allSettled([
      overlappingService.removeMember(owner1.id, org.id, m2Doc._id.toString()),
      overlappingService.removeMember(owner2.id, org.id, m1Doc._id.toString()),
    ]);

    const removalSuccesses = removalResults.filter((r) => r.status === 'fulfilled');
    const removalFailures = removalResults.filter((r) => r.status === 'rejected');
    expect(removalSuccesses).toHaveLength(1);
    expect(removalFailures).toHaveLength(1);

    expect(
      await OrganizationMembershipModel.countDocuments({
        organizationId: org.id,
        role: 'OWNER',
        status: 'ACTIVE',
      })
    ).toBe(1);

    // Restore second OWNER and test concurrent mutual demotion/suspension
    const survivingOwner = await OrganizationMembershipModel.findOne({
      organizationId: org.id,
      role: 'OWNER',
      status: 'ACTIVE',
    });
    const removedUserId = survivingOwner!.userId.toString() === owner1.id ? owner2.id : owner1.id;
    await OrganizationMembershipModel.create({
      userId: removedUserId,
      organizationId: org.id,
      role: 'OWNER',
      status: 'ACTIVE',
    });

    const ownersNow = await OrganizationMembershipModel.find({
      organizationId: org.id,
      role: 'OWNER',
      status: 'ACTIVE',
    });
    expect(ownersNow).toHaveLength(2);

    const [ownerADoc, ownerBDoc] = ownersNow;
    const demoteResults = await Promise.allSettled([
      service.updateMember(ownerADoc!.userId.toString(), org.id, ownerBDoc!._id.toString(), {
        role: 'ADMIN',
      }),
      service.updateMember(ownerBDoc!.userId.toString(), org.id, ownerADoc!._id.toString(), {
        status: 'SUSPENDED',
      }),
    ]);

    expect(demoteResults.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(demoteResults.filter((r) => r.status === 'rejected')).toHaveLength(1);
    expect(
      await OrganizationMembershipModel.countDocuments({
        organizationId: org.id,
        role: 'OWNER',
        status: 'ACTIVE',
      })
    ).toBe(1);
  });

  it('C. serializes concurrent ownership transfers and preserves valid ownership state', async () => {
    const owner = await seedUser('txowner@realmongo.dev', 'Primary Owner');
    const member1 = await seedUser('txm1@realmongo.dev', 'Member One');
    const member2 = await seedUser('txm2@realmongo.dev', 'Member Two');

    const service = createOrganizationService({ store: mongooseOrganizationStore });
    const org = await service.createOrganization(owner.id, {
      name: 'Transfer Real Org',
      slug: 'transfer-real-org',
    });

    await service.addMember(owner.id, org.id, { email: member1.email, role: 'ADMIN' });
    await service.addMember(owner.id, org.id, { email: member2.email, role: 'MEMBER' });

    const transferResults = await Promise.allSettled([
      service.transferOwnership(owner.id, org.id, { targetUserId: member1.id }),
      service.transferOwnership(owner.id, org.id, { targetUserId: member2.id }),
    ]);

    expect(transferResults.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(transferResults.filter((r) => r.status === 'rejected')).toHaveLength(1);

    const activeOwners = await OrganizationMembershipModel.find({
      organizationId: org.id,
      role: 'OWNER',
      status: 'ACTIVE',
    });
    expect(activeOwners).toHaveLength(1);
    expect([member1.id, member2.id]).toContain(activeOwners[0]!.userId.toString());

    const previousOwnerMembership = await OrganizationMembershipModel.findOne({
      organizationId: org.id,
      userId: owner.id,
    });
    expect(previousOwnerMembership?.role).toBe('ADMIN');
  });

  it('D. serializes concurrent addMember and deleteOrganization without orphaned memberships', async () => {
    const owner = await seedUser('delowner@realmongo.dev', 'Delete Owner');
    const candidate = await seedUser('delcand@realmongo.dev', 'Delete Candidate');

    const service = createOrganizationService({ store: mongooseOrganizationStore });

    for (let iteration = 0; iteration < 3; iteration++) {
      const org = await service.createOrganization(owner.id, {
        name: `Delete Race ${iteration}`,
        slug: `delete-race-${iteration}`,
      });

      const ops =
        iteration % 2 === 0
          ? [
              service.deleteOrganization(owner.id, org.id),
              service.addMember(owner.id, org.id, { email: candidate.email, role: 'MEMBER' }),
            ]
          : [
              service.addMember(owner.id, org.id, { email: candidate.email, role: 'MEMBER' }),
              service.deleteOrganization(owner.id, org.id),
            ];

      await Promise.allSettled(ops);

      const persistedOrg = await OrganizationModel.findById(org.id);
      const persistedMemberships = await OrganizationMembershipModel.find({
        organizationId: org.id,
      });

      if (persistedOrg === null) {
        expect(persistedMemberships).toHaveLength(0);
      } else {
        expect(persistedMemberships).toHaveLength(2);
      }
    }
  });

  it('E. allows concurrent mutations on different organizations without global lock blocking', async () => {
    const ownerA = await seedUser('par-a@realmongo.dev', 'Owner A');
    const ownerB = await seedUser('par-b@realmongo.dev', 'Owner B');

    const baseService = createOrganizationService({ store: mongooseOrganizationStore });
    const orgA = await baseService.createOrganization(ownerA.id, {
      name: 'Parallel A',
      slug: 'parallel-a',
    });
    const orgB = await baseService.createOrganization(ownerB.id, {
      name: 'Parallel B',
      slug: 'parallel-b',
    });

    // Barrier proves orgB acquires its lock and progresses while orgA is inside an open transaction
    let arrivedCount = 0;
    let releaseBoth!: () => void;
    const bothAcquired = new Promise<void>((resolve) => {
      releaseBoth = resolve;
    });

    const barrierStore: OrganizationStore = {
      ...mongooseOrganizationStore,
      async acquireOrganizationLock(orgId, tx) {
        const ok = await mongooseOrganizationStore.acquireOrganizationLock(orgId, tx);
        arrivedCount++;
        if (arrivedCount === 2) {
          releaseBoth();
        } else {
          await bothAcquired;
        }
        return ok;
      },
    };

    const parallelService = createOrganizationService({ store: barrierStore });

    const [updatedA, updatedB] = await Promise.all([
      parallelService.updateOrganization(ownerA.id, orgA.id, { name: 'Parallel A Updated' }),
      parallelService.updateOrganization(ownerB.id, orgB.id, { name: 'Parallel B Updated' }),
    ]);

    expect(updatedA.name).toBe('Parallel A Updated');
    expect(updatedB.name).toBe('Parallel B Updated');

    const persistedA = await OrganizationModel.findById(orgA.id);
    const persistedB = await OrganizationModel.findById(orgB.id);
    expect(persistedA?.name).toBe('Parallel A Updated');
    expect(persistedB?.name).toBe('Parallel B Updated');
    expect(persistedA?.membershipVersion).toBe(1);
    expect(persistedB?.membershipVersion).toBe(1);
  });

  it('F. enforces real MongoDB unique indexes for organization slugs and memberships', async () => {
    const owner = await seedUser('uniq-owner@realmongo.dev', 'Unique Owner');
    const member = await seedUser('uniq-member@realmongo.dev', 'Unique Member');

    const service = createOrganizationService({ store: mongooseOrganizationStore });
    const org = await service.createOrganization(owner.id, {
      name: 'Unique Org',
      slug: 'unique-org-slug',
    });

    await expect(
      service.createOrganization(owner.id, {
        name: 'Duplicate Slug Org',
        slug: '  UNIQUE-ORG-SLUG  ',
      })
    ).rejects.toMatchObject({ statusCode: 409, code: 'ORGANIZATION_SLUG_EXISTS' });

    expect(await OrganizationModel.countDocuments({ slug: 'unique-org-slug' })).toBe(1);

    const addResults = await Promise.allSettled([
      service.addMember(owner.id, org.id, { email: member.email, role: 'MEMBER' }),
      service.addMember(owner.id, org.id, {
        email: `  ${member.email.toUpperCase()}  `,
        role: 'VIEWER',
      }),
    ]);

    expect(addResults.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(addResults.filter((r) => r.status === 'rejected')).toHaveLength(1);
    expect(
      await OrganizationMembershipModel.countDocuments({
        organizationId: org.id,
        userId: member.id,
      })
    ).toBe(1);
  });

  it('blocks deletion when projects exist inside real MongoDB transaction', async () => {
    const owner = await seedUser('proj-owner@realmongo.dev', 'Proj Owner');
    const service = createOrganizationService({ store: mongooseOrganizationStore });
    const org = await service.createOrganization(owner.id, {
      name: 'Org With Project',
      slug: `org-with-project-${randomBytes(4).toString('hex')}`,
    });

    await ProjectModel.create({
      organizationId: org.id,
      name: 'Existing Project',
      slug: 'existing-project',
      createdBy: owner.id,
    });

    await expect(service.deleteOrganization(owner.id, org.id)).rejects.toMatchObject({
      statusCode: 409,
      code: 'ORGANIZATION_HAS_PROJECTS',
    });

    expect(await OrganizationModel.findById(org.id)).not.toBeNull();
    expect(await OrganizationMembershipModel.countDocuments({ organizationId: org.id })).toBe(1);
  });
});
