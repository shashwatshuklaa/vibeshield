import { execFile, spawn } from 'node:child_process';
import net from 'node:net';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const MONGO_IMAGE = `mongo:${process.env.MONGO_IMAGE_TAG || 'latest'}`;

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

async function waitForMongosh(containerName, port, evalScript, expectedOutput) {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    try {
      const output = await execDocker([
        'exec',
        containerName,
        'mongosh',
        '--port',
        String(port),
        '--quiet',
        '--eval',
        evalScript,
      ]);
      if (output.includes(expectedOutput)) {
        return;
      }
    } catch {
      // Container mongod is still initializing
    }
    await sleep(300);
  }
  throw new Error(`Timed out waiting for MongoDB readiness in container ${containerName}`);
}

async function runVitestIntegration(envOverrides) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'pnpm',
      ['exec', 'vitest', 'run', '--config', 'vitest.integration.config.mts'],
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
  if (process.env.MONGODB_INTEGRATION_URI && process.env.MONGODB_STANDALONE_URI) {
    console.log(
      '[integration] Using pre-configured MONGODB_INTEGRATION_URI and MONGODB_STANDALONE_URI.'
    );
    const exitCode = await runVitestIntegration({});
    process.exit(exitCode);
  }

  try {
    await execDocker(['info']);
  } catch {
    console.error(
      '[integration] Docker daemon is not accessible and MONGODB_INTEGRATION_URI / MONGODB_STANDALONE_URI are not set.'
    );
    process.exit(1);
  }

  const rsPort = await getFreePort();
  const standalonePort = await getFreePort();
  const suffix = `${process.pid}-${Date.now()}`;
  const rsContainer = `vibeshield-mongo-rs-${suffix}`;
  const standaloneContainer = `vibeshield-mongo-standalone-${suffix}`;

  const cleanup = async () => {
    await Promise.allSettled([
      execDocker(['rm', '-f', rsContainer]),
      execDocker(['rm', '-f', standaloneContainer]),
    ]);
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
      `[integration] Starting ephemeral MongoDB replica set (${MONGO_IMAGE}) on port ${rsPort}...`
    );
    await execDocker([
      'run',
      '-d',
      '--rm',
      '--name',
      rsContainer,
      '-p',
      `127.0.0.1:${rsPort}:${rsPort}`,
      MONGO_IMAGE,
      '--replSet',
      'rs0',
      '--port',
      String(rsPort),
      '--bind_ip_all',
    ]);

    console.log(
      `[integration] Starting ephemeral standalone MongoDB (${MONGO_IMAGE}) on port ${standalonePort}...`
    );
    await execDocker([
      'run',
      '-d',
      '--rm',
      '--name',
      standaloneContainer,
      '-p',
      `127.0.0.1:${standalonePort}:${standalonePort}`,
      MONGO_IMAGE,
      '--port',
      String(standalonePort),
      '--bind_ip_all',
    ]);

    await waitForMongosh(rsContainer, rsPort, 'db.runCommand({ ping: 1 }).ok', '1');
    await execDocker([
      'exec',
      rsContainer,
      'mongosh',
      '--port',
      String(rsPort),
      '--quiet',
      '--eval',
      `rs.initiate({_id: 'rs0', members: [{ _id: 0, host: '127.0.0.1:${rsPort}' }]})`,
    ]);
    await waitForMongosh(rsContainer, rsPort, 'db.hello().isWritablePrimary', 'true');
    await waitForMongosh(standaloneContainer, standalonePort, 'db.runCommand({ ping: 1 }).ok', '1');

    const replicaUri = `mongodb://127.0.0.1:${rsPort}/vibeshield_integration?replicaSet=rs0`;
    const standaloneUri = `mongodb://127.0.0.1:${standalonePort}/vibeshield_standalone`;

    const exitCode = await runVitestIntegration({
      MONGODB_INTEGRATION_URI: replicaUri,
      MONGODB_STANDALONE_URI: standaloneUri,
    });
    process.exitCode = exitCode;
  } finally {
    console.log('[integration] Cleaning up ephemeral MongoDB containers...');
    await cleanup();
  }
}

main().catch((error) => {
  console.error('[integration] Runner failed:', error);
  process.exit(1);
});
