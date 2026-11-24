import type { Server } from 'node:http';
import { createApp } from './app.js';
import { getApiConfig } from './config/env.js';

let server: Server | null = null;
let isShuttingDown = false;

export async function startServer(): Promise<Server> {
  try {
    // 1. Validate environment configuration before any network activity
    const config = getApiConfig();

    // 2. Instantiate Express application
    const app = createApp({ apiPrefix: config.API_PREFIX });

    // 3. Bind and listen
    const port = config.PORT ?? 4000;
    const host = config.HOST;

    return await new Promise<Server>((resolve, reject) => {
      const s = app.listen(port, host, () => {
        console.log(`[VibeShield API] Server listening on http://${host}:${port}`);
        console.log(
          `[VibeShield API] Health endpoint at http://${host}:${port}${config.API_PREFIX}/health`
        );
        resolve(s);
      });

      s.on('error', (err) => {
        reject(err);
      });

      server = s;
    });
  } catch (error) {
    console.error('[VibeShield API] Failed to start server:', error);
    process.exit(1);
  }
}

export function shutdownServer(signal: string): Promise<void> {
  if (isShuttingDown) {
    return Promise.resolve();
  }
  isShuttingDown = true;

  console.log(`[VibeShield API] Received ${signal}. Closing HTTP server gracefully...`);

  return new Promise((resolve) => {
    if (!server) {
      resolve();
      return;
    }

    server.close((err) => {
      if (err) {
        console.error('[VibeShield API] Error while closing HTTP server:', err);
        process.exit(1);
      }
      console.log('[VibeShield API] HTTP server closed gracefully.');
      resolve();
    });
  });
}

// Register process signal handlers only when directly executed as the main entrypoint
const isDirectExecution =
  process.argv[1] &&
  (process.argv[1].endsWith('server.ts') || process.argv[1].endsWith('server.js'));

if (isDirectExecution && process.env.NODE_ENV !== 'test') {
  const handleSignal = (signal: string) => {
    shutdownServer(signal).then(() => {
      process.exit(0);
    });
  };

  process.on('SIGINT', () => handleSignal('SIGINT'));
  process.on('SIGTERM', () => handleSignal('SIGTERM'));

  startServer();
}
