import { execFile, spawn } from 'node:child_process';
import net from 'node:net';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const REDIS_IMAGE = `redis:${process.env.REDIS_IMAGE_TAG || '7-alpine'}`;
const EPHEMERAL_REDIS_PASSWORD = 'vibeshield_redis_integration_pass';

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close(() => reject(new Error('Unable to resolve ephemeral port')));
        return;
      }
      const { port } = address;
      server.close((err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(port);
      });
    });
  });
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function execDocker(args) {
  const { stdout } = await execFileAsync('docker', args, { encoding: 'utf8' });
  return stdout.trim();
}

async function waitForRedis(containerName, port, password) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      const output = await execDocker([
        'exec',
        containerName,
        'redis-cli',
        '-h',
        '127.0.0.1',
        '-p',
        String(port),
        '-a',
        password,
        '--no-auth-warning',
        'ping',
      ]);
      if (output.includes('PONG')) {
        return;
      }
    } catch {
      // Redis container is still starting
    }
    await sleep(200);
  }
  throw new Error(`Timed out waiting for Redis readiness in container ${containerName}`);
}

async function runVitestRedisIntegration(envOverrides) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'pnpm',
      ['exec', 'vitest', 'run', '--config', 'vitest.redis.integration.config.mts'],
      {
        stdio: 'inherit',
        env: {
          ...process.env,
          ...envOverrides,
        },
      }
    );

    child.on('error', reject);
    child.on('exit', (code) => {
      resolve(code ?? 1);
    });
  });
}

async function main() {
  if (process.env.REDIS_INTEGRATION_URI) {
    console.log('[redis-integration] Using pre-configured REDIS_INTEGRATION_URI.');
    const exitCode = await runVitestRedisIntegration({});
    process.exit(exitCode);
  }

  try {
    await execDocker(['info']);
  } catch {
    console.error(
      '[redis-integration] Docker daemon is not accessible and REDIS_INTEGRATION_URI is not set.'
    );
    process.exit(1);
  }

  const redisPort = await getFreePort();
  const suffix = `${process.pid}-${Date.now()}`;
  const containerName = `vibeshield-redis-${suffix}`;

  const cleanup = async () => {
    await Promise.allSettled([execDocker(['rm', '-f', containerName])]);
  };

  process.on('SIGINT', async () => {
    await cleanup();
    process.exit(130);
  });
  process.on('SIGTERM', async () => {
    await cleanup();
    process.exit(143);
  });

  try {
    console.log(
      `[redis-integration] Starting ephemeral Redis (${REDIS_IMAGE}) on port ${redisPort}...`
    );
    await execDocker([
      'run',
      '-d',
      '--rm',
      '--name',
      containerName,
      '-p',
      `127.0.0.1:${redisPort}:6379`,
      REDIS_IMAGE,
      'redis-server',
      '--requirepass',
      EPHEMERAL_REDIS_PASSWORD,
      '--save',
      '',
      '--appendonly',
      'no',
    ]);

    await waitForRedis(containerName, 6379, EPHEMERAL_REDIS_PASSWORD);

    const redisUri = `redis://:${EPHEMERAL_REDIS_PASSWORD}@127.0.0.1:${redisPort}/0`;
    const exitCode = await runVitestRedisIntegration({
      REDIS_INTEGRATION_URI: redisUri,
    });
    process.exitCode = exitCode;
  } finally {
    console.log('[redis-integration] Cleaning up ephemeral Redis container...');
    await cleanup();
  }
}

main().catch((error) => {
  console.error('[redis-integration] Runner failed:', error);
  process.exit(1);
});
