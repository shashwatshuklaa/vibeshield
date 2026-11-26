import mongoose from 'mongoose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { organizationSchema, runInTransaction } from '../index.js';

const STANDALONE_URI = process.env.MONGODB_STANDALONE_URI;

describe.skipIf(!STANDALONE_URI)(
  'Standalone MongoDB Transaction Behavior (Integration Test)',
  () => {
    let standaloneClient: mongoose.Mongoose;
    let StandaloneOrganization: mongoose.Model<unknown>;

    beforeAll(async () => {
      standaloneClient = new mongoose.Mongoose();
      const separator = STANDALONE_URI!.includes('?') ? '&' : '?';
      await standaloneClient.connect(`${STANDALONE_URI!}${separator}retryWrites=false`, {
        serverSelectionTimeoutMS: 10_000,
        retryWrites: false,
      });
      StandaloneOrganization = standaloneClient.model('Organization', organizationSchema);
    });

    afterAll(async () => {
      await standaloneClient.disconnect();
    });

    it('G. fails loudly without falling back to non-transactional writes against standalone MongoDB', async () => {
      const creatorId = new mongoose.Types.ObjectId();

      await expect(
        runInTransaction(
          async (session) => {
            await StandaloneOrganization.create(
              [
                {
                  name: 'Standalone Should Fail',
                  slug: 'standalone-should-fail',
                  createdBy: creatorId,
                },
              ],
              { session }
            );
          },
          { client: standaloneClient }
        )
      ).rejects.toThrow(/replica set|mongos|Transaction|retryable writes/i);

      expect(await StandaloneOrganization.countDocuments({ slug: 'standalone-should-fail' })).toBe(
        0
      );
    });
  }
);
