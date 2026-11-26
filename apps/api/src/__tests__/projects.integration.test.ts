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
import { mongooseOrganizationStore } from '../modules/organizations/organization.store.js';
import { createProjectService } from '../modules/projects/project.service.js';
import { mongooseProjectStore, type ProjectStore } from '../modules/projects/project.store.js';

const REPLICA_URI = process.env.MONGODB_INTEGRATION_URI;

describe.skipIf(!REPLICA_URI)('Projects Real MongoDB Replica-Set Integration Tests', () => {
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
    return { id: doc._id.toString(), email: doc.email };
  }

  it('enforces organization-scoped unique project slugs via MongoDB indexes while allowing same slug across organizations', async () => {
    const alice = await seedUser('proj-alice@realmongo.dev', 'Alice');
    const bob = await seedUser('proj-bob@realmongo.dev', 'Bob');

    const orgService = createOrganizationService({ store: mongooseOrganizationStore });
    const projectService = createProjectService({ store: mongooseProjectStore });

    const orgA = await orgService.createOrganization(alice.id, {
      name: 'Org Alpha',
      slug: 'org-alpha',
    });
    const orgB = await orgService.createOrganization(bob.id, {
      name: 'Org Beta',
      slug: 'org-beta',
    });

    const pB = await projectService.createProject(bob.id, orgB.id, {
      name: 'Core API',
      slug: 'core-api',
    });
    expect(pB.slug).toBe('core-api');

    // Concurrent duplicate project slug creation in Org A yields 1 success and 1 409 conflict
    const results = await Promise.allSettled([
      projectService.createProject(alice.id, orgA.id, {
        name: 'Core API A1',
        slug: 'core-api',
      }),
      projectService.createProject(alice.id, orgA.id, {
        name: 'Core API A2',
        slug: '  CORE-API  ',
      }),
    ]);

    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((r) => r.status === 'rejected')).toHaveLength(1);
    expect(await ProjectModel.countDocuments({ organizationId: orgA.id, slug: 'core-api' })).toBe(
      1
    );
    expect(await ProjectModel.countDocuments({ slug: 'core-api' })).toBe(2);
  });

  it('rolls back organization lock version and project write when project insert fails mid-transaction', async () => {
    const owner = await seedUser('proj-rb@realmongo.dev', 'Rollback Owner');
    const orgService = createOrganizationService({ store: mongooseOrganizationStore });

    const org = await orgService.createOrganization(owner.id, {
      name: 'Rollback Proj Org',
      slug: 'rollback-proj-org',
    });
    const beforeOrg = await OrganizationModel.findById(org.id);
    const initialVersion = beforeOrg!.membershipVersion;

    const failingStore: ProjectStore = {
      ...mongooseProjectStore,
      async createProject() {
        throw new Error('Forced project insert failure');
      },
    };
    const failingService = createProjectService({ store: failingStore });

    await expect(
      failingService.createProject(owner.id, org.id, {
        name: 'Should Rollback',
        slug: 'should-rollback',
      })
    ).rejects.toThrow('Forced project insert failure');

    const afterOrg = await OrganizationModel.findById(org.id);
    expect(afterOrg?.membershipVersion).toBe(initialVersion);
    expect(await ProjectModel.countDocuments({ organizationId: org.id })).toBe(0);
  });

  it('serializes concurrent createProject and deleteOrganization via the organization lock without orphaned projects', async () => {
    const owner = await seedUser('proj-race@realmongo.dev', 'Race Owner');
    const orgService = createOrganizationService({ store: mongooseOrganizationStore });
    const projectService = createProjectService({ store: mongooseProjectStore });

    for (let iteration = 0; iteration < 4; iteration++) {
      const org = await orgService.createOrganization(owner.id, {
        name: `Race Org ${iteration}`,
        slug: `proj-del-race-${iteration}`,
      });

      const ops =
        iteration % 2 === 0
          ? [
              orgService.deleteOrganization(owner.id, org.id),
              projectService.createProject(owner.id, org.id, {
                name: 'Concurrent Project',
                slug: 'concurrent-project',
              }),
            ]
          : [
              projectService.createProject(owner.id, org.id, {
                name: 'Concurrent Project',
                slug: 'concurrent-project',
              }),
              orgService.deleteOrganization(owner.id, org.id),
            ];

      await Promise.allSettled(ops);

      const persistedOrg = await OrganizationModel.findById(org.id);
      const persistedProjects = await ProjectModel.find({ organizationId: org.id });

      if (persistedOrg === null) {
        expect(persistedProjects).toHaveLength(0);
      } else {
        expect(persistedProjects).toHaveLength(1);
      }
    }
  });

  it('supports pagination, regex-safe search, archive/restore, and cross-organization isolation against MongoDB', async () => {
    const owner = await seedUser('proj-query@realmongo.dev', 'Query Owner');
    const orgService = createOrganizationService({ store: mongooseOrganizationStore });
    const projectService = createProjectService({ store: mongooseProjectStore });

    const orgA = await orgService.createOrganization(owner.id, {
      name: 'Query Org A',
      slug: 'query-org-a',
    });
    const orgB = await orgService.createOrganization(owner.id, {
      name: 'Query Org B',
      slug: 'query-org-b',
    });

    const p1 = await projectService.createProject(owner.id, orgA.id, {
      name: 'Payments (v1.0)',
      slug: 'payments-v1',
      description: 'Payment service',
    });
    const p2 = await projectService.createProject(owner.id, orgA.id, {
      name: 'Auth Service',
      slug: 'auth-service',
    });
    await projectService.createProject(owner.id, orgB.id, {
      name: 'Payments Other Org',
      slug: 'payments-other',
    });

    // Archive p2
    await projectService.archiveProject(owner.id, orgA.id, p2.id);

    // Search with regex metacharacters `(v1.0)` safely
    const searchRes = await projectService.listProjects(orgA.id, {
      page: 1,
      limit: 10,
      search: '(v1.0)',
      archived: 'false',
    });
    expect(searchRes.projects).toHaveLength(1);
    expect(searchRes.projects[0]?.id).toBe(p1.id);

    const archivedRes = await projectService.listProjects(orgA.id, {
      page: 1,
      limit: 10,
      archived: 'true',
    });
    expect(archivedRes.projects.map((p) => p.id)).toEqual([p2.id]);

    // Cross-org access to p1 via orgB returns 404
    await expect(projectService.getProject(orgB.id, p1.id)).rejects.toMatchObject({
      statusCode: 404,
      code: 'PROJECT_NOT_FOUND',
    });

    // Restore p2 and verify
    const restored = await projectService.restoreProject(owner.id, orgA.id, p2.id);
    expect(restored.archivedAt).toBeNull();
  });
});
