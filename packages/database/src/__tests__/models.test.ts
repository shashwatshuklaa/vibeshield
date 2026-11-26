import { describe, expect, it, vi } from 'vitest';
import { Error as MongooseError, Schema, Types, type ClientSession, type Document } from 'mongoose';
import {
  acquireOrganizationMutationLock,
  getDatabaseState,
  getOrCreateModel,
  isDatabaseConnected,
  MEMBERSHIP_STATUSES,
  MembershipStatusValue,
  ORGANIZATION_ROLES,
  OrganizationMembershipModel,
  organizationMembershipSchema,
  OrganizationModel,
  OrganizationRoleValue,
  organizationSchema,
  ProjectModel,
  projectSchema,
  USER_STATUSES,
  UserModel,
  userSchema,
  UserStatusValue,
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

describe('@vibeshield/database models (schema-level tests)', () => {
  describe('model exports and import stability', () => {
    it('does not automatically connect to MongoDB when importing models', () => {
      expect(getDatabaseState()).toBe('disconnected');
      expect(isDatabaseConnected()).toBe(false);
    });

    it('exports all core models with expected model and collection names', () => {
      expect(UserModel.modelName).toBe('User');
      expect(UserModel.collection.name).toBe('users');

      expect(OrganizationModel.modelName).toBe('Organization');
      expect(OrganizationModel.collection.name).toBe('organizations');

      expect(OrganizationMembershipModel.modelName).toBe('OrganizationMembership');
      expect(OrganizationMembershipModel.collection.name).toBe('organization_memberships');

      expect(ProjectModel.modelName).toBe('Project');
      expect(ProjectModel.collection.name).toBe('projects');
    });

    it('avoids OverwriteModelError on repeated model registration', async () => {
      const reusedUserModel = getOrCreateModel('User', userSchema);
      const reusedOrgModel = getOrCreateModel('Organization', organizationSchema);
      const reusedMembershipModel = getOrCreateModel(
        'OrganizationMembership',
        organizationMembershipSchema
      );
      const reusedProjectModel = getOrCreateModel('Project', projectSchema);

      const reimported = await import('../models/index.js');

      expect(reusedUserModel).toBe(UserModel);
      expect(reusedOrgModel).toBe(OrganizationModel);
      expect(reusedMembershipModel).toBe(OrganizationMembershipModel);
      expect(reusedProjectModel).toBe(ProjectModel);
      expect(reimported.UserModel).toBe(UserModel);
    });
  });

  describe('UserModel', () => {
    it('applies defaults, normalizes email and displayName, and validates successfully', async () => {
      const user = new UserModel({
        email: '  Alice.Admin@Example.COM  ',
        displayName: '  Alice Admin  ',
        passwordHash: '$2b$12$hashed_secret_value',
      });

      const validationError = await getValidationError(user);
      expect(validationError).toBeUndefined();
      expect(user.email).toBe('alice.admin@example.com');
      expect(user.displayName).toBe('Alice Admin');
      expect(user.status).toBe(UserStatusValue.ACTIVE);
    });

    it('requires email, displayName, and passwordHash (including explicit undefined)', async () => {
      const user = new UserModel({});
      const error = await getValidationError(user);

      expect(error).toBeDefined();
      expect(error?.errors.email?.kind).toBe('required');
      expect(error?.errors.displayName?.kind).toBe('required');
      expect(error?.errors.passwordHash?.kind).toBe('required');

      const explicitUndefinedUser = new UserModel({
        email: undefined,
        displayName: 'User',
        passwordHash: 'hash',
      });
      const undefinedError = await getValidationError(explicitUndefinedUser);
      expect(undefinedError?.errors.email?.name).toBe('ValidatorError');
      expect(undefinedError?.errors.email?.kind).toBe('required');
    });

    it('validates email format and status enum', async () => {
      const invalidUser = new UserModel({
        email: 'not-an-email',
        displayName: 'User',
        passwordHash: 'hash',
        status: 'DELETED',
      });

      const error = await getValidationError(invalidUser);
      expect(error?.errors.email).toBeDefined();
      expect(error?.errors.status).toBeDefined();

      for (const status of USER_STATUSES) {
        const valid = new UserModel({
          email: 'user@example.com',
          displayName: 'User',
          passwordHash: 'hash',
          status,
        });
        expect(await getValidationError(valid)).toBeUndefined();
      }
    });

    it('excludes passwordHash from default selection and JSON/object serialization even when loaded', () => {
      const passwordHashPath = userSchema.path('passwordHash');
      expect(passwordHashPath.options.select).toBe(false);

      const user = new UserModel({
        email: 'security@vibeshield.dev',
        displayName: 'Sec User',
        passwordHash: '$argon2id$very_sensitive_hash_value',
      });

      // Verify passwordHash is present in memory (as when explicitly selected via +passwordHash)
      expect(user.passwordHash).toBe('$argon2id$very_sensitive_hash_value');

      const jsonObj = user.toJSON() as unknown as Record<string, unknown>;
      const plainObj = user.toObject() as unknown as Record<string, unknown>;
      const serialized = JSON.stringify(user);

      expect(jsonObj.passwordHash).toBeUndefined();
      expect(jsonObj.__v).toBeUndefined();
      expect(plainObj.passwordHash).toBeUndefined();
      expect(plainObj.__v).toBeUndefined();
      expect(serialized).not.toContain('very_sensitive_hash_value');
      expect(serialized).not.toContain('passwordHash');
    });

    it('normalizes email in Mongoose update payloads', () => {
      const directUpdateQuery = UserModel.findOneAndUpdate(
        {},
        { email: '  Updated.User@Example.COM  ' }
      ) as unknown as {
        _castUpdate: (update: Record<string, unknown>) => Record<string, unknown>;
        getUpdate: () => Record<string, unknown>;
      };
      const setUpdateQuery = UserModel.updateOne(
        {},
        { $set: { email: '  Second.User@Example.COM  ' } }
      ) as unknown as {
        _castUpdate: (update: Record<string, unknown>) => Record<string, unknown>;
        getUpdate: () => Record<string, unknown>;
      };

      expect(directUpdateQuery._castUpdate(directUpdateQuery.getUpdate())).toEqual({
        $set: { email: 'updated.user@example.com' },
      });
      expect(setUpdateQuery._castUpdate(setUpdateQuery.getUpdate())).toEqual({
        $set: { email: 'second.user@example.com' },
      });
    });

    it('defines unique email index and status index', () => {
      const indexes = userSchema.indexes();
      expect(indexes).toContainEqual([
        { email: 1 },
        expect.objectContaining({ unique: true, name: 'users_email_unique' }),
      ]);
      expect(indexes).toContainEqual([
        { status: 1 },
        expect.objectContaining({ name: 'users_status_idx' }),
      ]);
    });
  });

  describe('OrganizationModel', () => {
    it('normalizes slug and name, stores User ObjectId reference, and validates', async () => {
      const creatorId = new Types.ObjectId();
      const org = new OrganizationModel({
        name: '  Acme Security  ',
        slug: '  Acme-Sec-01  ',
        createdBy: creatorId,
      });

      expect(await getValidationError(org)).toBeUndefined();
      expect(org.name).toBe('Acme Security');
      expect(org.slug).toBe('acme-sec-01');
      expect(org.membershipVersion).toBe(0);
      expect(org.createdBy).toBeInstanceOf(Types.ObjectId);
      expect(org.createdBy.equals(creatorId)).toBe(true);
      expect(
        (org.toJSON() as unknown as Record<string, unknown>).membershipVersion
      ).toBeUndefined();
    });

    it('acquireOrganizationMutationLock increments membershipVersion within the provided session', async () => {
      const orgId = new Types.ObjectId().toString();
      const mockSession = { id: 'mock-session' } as unknown as ClientSession;
      const findSpy = vi
        .spyOn(OrganizationModel, 'findOneAndUpdate')
        .mockResolvedValueOnce({ _id: orgId, membershipVersion: 1 } as never)
        .mockResolvedValueOnce(null as never);

      const acquired = await acquireOrganizationMutationLock(orgId, mockSession);
      expect(acquired).toBe(true);
      expect(findSpy).toHaveBeenCalledWith(
        { _id: orgId },
        { $inc: { membershipVersion: 1 } },
        { returnDocument: 'after', session: mockSession }
      );

      const missing = await acquireOrganizationMutationLock(orgId, mockSession);
      expect(missing).toBe(false);

      const invalid = await acquireOrganizationMutationLock('invalid-id', mockSession);
      expect(invalid).toBe(false);

      findSpy.mockRestore();
    });

    it('requires name, slug, and createdBy (including explicit undefined) and rejects malformed slugs', async () => {
      const missing = new OrganizationModel({});
      const missingErr = await getValidationError(missing);
      expect(missingErr?.errors.name?.kind).toBe('required');
      expect(missingErr?.errors.slug?.kind).toBe('required');
      expect(missingErr?.errors.createdBy?.kind).toBe('required');

      const undefinedSlug = new OrganizationModel({
        name: 'Valid Org',
        slug: undefined,
        createdBy: new Types.ObjectId(),
      });
      const undefinedSlugErr = await getValidationError(undefinedSlug);
      expect(undefinedSlugErr?.errors.slug?.name).toBe('ValidatorError');
      expect(undefinedSlugErr?.errors.slug?.kind).toBe('required');

      for (const badSlug of ['a', '-leading', 'trailing-', 'double--hyphen', 'has space', 'a_b']) {
        const badOrg = new OrganizationModel({
          name: 'Valid Org',
          slug: badSlug,
          createdBy: new Types.ObjectId(),
        });
        expect((await getValidationError(badOrg))?.errors.slug).toBeDefined();
      }
    });

    it('normalizes organization slug in Mongoose update payloads', () => {
      const query = OrganizationModel.findOneAndUpdate(
        {},
        { $set: { slug: '  New-Org-Slug  ' } }
      ) as unknown as {
        _castUpdate: (update: Record<string, unknown>) => Record<string, unknown>;
        getUpdate: () => Record<string, unknown>;
      };

      expect(query._castUpdate(query.getUpdate())).toEqual({
        $set: { slug: 'new-org-slug' },
      });
    });

    it('defines ObjectId ref to User and unique slug index', () => {
      const createdByPath = organizationSchema.path('createdBy');
      expect(createdByPath).toBeInstanceOf(Schema.Types.ObjectId);
      expect(createdByPath.options.ref).toBe('User');

      const indexes = organizationSchema.indexes();
      expect(indexes).toContainEqual([
        { slug: 1 },
        expect.objectContaining({ unique: true, name: 'organizations_slug_unique' }),
      ]);
      expect(indexes).toContainEqual([
        { createdBy: 1 },
        expect.objectContaining({ name: 'organizations_created_by_idx' }),
      ]);
    });
  });

  describe('OrganizationMembershipModel', () => {
    it('validates all controlled roles and membership statuses with ACTIVE default', async () => {
      const userId = new Types.ObjectId();
      const organizationId = new Types.ObjectId();

      for (const role of ORGANIZATION_ROLES) {
        const membership = new OrganizationMembershipModel({
          userId,
          organizationId,
          role,
        });
        expect(await getValidationError(membership)).toBeUndefined();
        expect(membership.status).toBe(MembershipStatusValue.ACTIVE);
      }

      for (const status of MEMBERSHIP_STATUSES) {
        const membership = new OrganizationMembershipModel({
          userId,
          organizationId,
          role: OrganizationRoleValue.MEMBER,
          status,
        });
        expect(await getValidationError(membership)).toBeUndefined();
      }
    });

    it('requires userId, organizationId, and explicit role (no unsafe default role)', async () => {
      const membership = new OrganizationMembershipModel({});
      const error = await getValidationError(membership);

      expect(error?.errors.userId).toBeDefined();
      expect(error?.errors.organizationId).toBeDefined();
      expect(error?.errors.role).toBeDefined();

      const invalidRole = new OrganizationMembershipModel({
        userId: new Types.ObjectId(),
        organizationId: new Types.ObjectId(),
        role: 'SUPERADMIN',
        status: 'UNKNOWN',
      });
      const invalidErr = await getValidationError(invalidRole);
      expect(invalidErr?.errors.role).toBeDefined();
      expect(invalidErr?.errors.status).toBeDefined();
    });

    it('defines ObjectId references and compound unique index preventing duplicate memberships', () => {
      const userPath = organizationMembershipSchema.path('userId');
      const orgPath = organizationMembershipSchema.path('organizationId');

      expect(userPath).toBeInstanceOf(Schema.Types.ObjectId);
      expect(userPath.options.ref).toBe('User');
      expect(orgPath).toBeInstanceOf(Schema.Types.ObjectId);
      expect(orgPath.options.ref).toBe('Organization');

      const indexes = organizationMembershipSchema.indexes();
      expect(indexes).toContainEqual([
        { organizationId: 1, userId: 1 },
        expect.objectContaining({ unique: true, name: 'org_memberships_org_user_unique' }),
      ]);
      expect(indexes).toContainEqual([
        { userId: 1, status: 1 },
        expect.objectContaining({ name: 'org_memberships_user_status_idx' }),
      ]);
      expect(indexes).toContainEqual([
        { organizationId: 1, role: 1, status: 1 },
        expect.objectContaining({ name: 'org_memberships_org_role_status_idx' }),
      ]);
    });
  });

  describe('ProjectModel', () => {
    it('normalizes slug and text fields, defaults archivedAt to null, and validates', async () => {
      const orgId = new Types.ObjectId();
      const creatorId = new Types.ObjectId();

      const project = new ProjectModel({
        organizationId: orgId,
        name: '  Payment Gateway API  ',
        slug: '  Payment-Gateway-API  ',
        description: '  Core checkout microservice  ',
        createdBy: creatorId,
      });

      expect(await getValidationError(project)).toBeUndefined();
      expect(project.name).toBe('Payment Gateway API');
      expect(project.slug).toBe('payment-gateway-api');
      expect(project.description).toBe('Core checkout microservice');
      expect(project.archivedAt).toBeNull();
      expect(project.organizationId.equals(orgId)).toBe(true);
      expect(project.createdBy.equals(creatorId)).toBe(true);
    });

    it('requires organizationId, name, slug, and createdBy (including explicit undefined)', async () => {
      const project = new ProjectModel({});
      const error = await getValidationError(project);

      expect(error?.errors.organizationId?.kind).toBe('required');
      expect(error?.errors.name?.kind).toBe('required');
      expect(error?.errors.slug?.kind).toBe('required');
      expect(error?.errors.createdBy?.kind).toBe('required');

      const undefinedSlug = new ProjectModel({
        organizationId: new Types.ObjectId(),
        name: 'Valid Project',
        slug: undefined,
        createdBy: new Types.ObjectId(),
      });
      const undefinedSlugErr = await getValidationError(undefinedSlug);
      expect(undefinedSlugErr?.errors.slug?.name).toBe('ValidatorError');
      expect(undefinedSlugErr?.errors.slug?.kind).toBe('required');
    });

    it('normalizes project slug in Mongoose update payloads', () => {
      const query = ProjectModel.updateOne(
        {},
        { $set: { slug: '  Updated-Project-Slug  ' } }
      ) as unknown as {
        _castUpdate: (update: Record<string, unknown>) => Record<string, unknown>;
        getUpdate: () => Record<string, unknown>;
      };

      expect(query._castUpdate(query.getUpdate())).toEqual({
        $set: { slug: 'updated-project-slug' },
      });
    });

    it('rejects malformed project slugs', async () => {
      for (const badSlug of ['x', '-proj', 'proj-', 'proj--one', 'bad slug', 'proj/1']) {
        const project = new ProjectModel({
          organizationId: new Types.ObjectId(),
          name: 'Valid Project',
          slug: badSlug,
          createdBy: new Types.ObjectId(),
        });
        expect((await getValidationError(project))?.errors.slug).toBeDefined();
      }
    });

    it('defines ObjectId references and organization-scoped unique slug index', () => {
      const orgPath = projectSchema.path('organizationId');
      const creatorPath = projectSchema.path('createdBy');

      expect(orgPath).toBeInstanceOf(Schema.Types.ObjectId);
      expect(orgPath.options.ref).toBe('Organization');
      expect(creatorPath).toBeInstanceOf(Schema.Types.ObjectId);
      expect(creatorPath.options.ref).toBe('User');

      const indexes = projectSchema.indexes();
      expect(indexes).toContainEqual([
        { organizationId: 1, slug: 1 },
        expect.objectContaining({ unique: true, name: 'projects_org_slug_unique' }),
      ]);
      expect(indexes).toContainEqual([
        { organizationId: 1, archivedAt: 1, createdAt: -1 },
        expect.objectContaining({ name: 'projects_org_archived_created_idx' }),
      ]);
      expect(indexes).toContainEqual([
        { createdBy: 1 },
        expect.objectContaining({ name: 'projects_created_by_idx' }),
      ]);
    });
  });
});
