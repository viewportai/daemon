/**
 * Daemon startup and runtime lifecycle.
 *
 * Modes:
 * - `start` command: launches a dedicated supervisor (detached by default)
 * - `__supervisor`: supervisor process that owns pid-state and worker lifecycle
 * - `__worker`: daemon worker process (HTTP/WS runtime)
 */

import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import fastifyCors from '@fastify/cors';
import path from 'node:path';
import fs from 'node:fs/promises';
import { logger } from './core/output.js';
import { Daemon } from './core/daemon.js';
import { GitTracker } from './tracking/git-tracker.js';
import { registerHttpRoutes } from './server/http-server.js';
import { registerWsServer } from './server/ws-server.js';
import { HookRouter, SupervisionManager } from './hooks/index.js';
import { LocalAuthProvider } from './server/auth.js';
import type { AuthProvider } from './server/auth.js';
import type { GitTrackerConfig } from './core/types.js';
import {
  loadPersistedSessions,
  savePersistedSessions,
  clearPersistedSessions,
} from './core/session-state-file.js';
import type { PersistedSession } from './core/session-state-file.js';
import { hasFlag } from './cli/args.js';
import {
  readDaemonRuntimeState,
  isPidRunning,
  clearDaemonRuntimeState,
  readProcessInfo,
  isOwnershipMatch,
  stopPid,
} from './cli/daemon-lifecycle.js';
import { daemonFetch } from './cli/daemon-client.js';
import {
  runSupervisorForeground,
  runSupervisorFromEnv,
  startSupervisorDetached,
  loadWorkerConfigFromEnv,
} from './cli/supervisor.js';
import {
  WORKER_EXIT_RESTART,
  WORKER_EXIT_SHUTDOWN,
  type RuntimeLaunchConfig,
} from './cli/supervisor-protocol.js';
import { buildSecurityProfile, isOriginAllowed } from './server/security.js';
import { resolveDaemonSettingsFromSources } from './cli/daemon-settings.js';
import { loadAgents, autoRegisterDirectories, decodeAutoRegisterEntry } from './startup-agents.js';
import { startDiscoveryWatchers } from './startup-watchers.js';
import { maybeOfferAgentPrerequisites } from './startup-prereqs.js';
import { DaemonRelayBridge } from './relay/daemon-relay-bridge.js';
import { configDir } from './core/config.js';

export { decodeAutoRegisterEntry };

function printStartJson(payload: Record<string, unknown>): void {
  logger.log(JSON.stringify(payload, null, 2));
}

export const HTTP_LOG_REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
] as const;

async function readDaemonAuthToken(): Promise<string | null> {
  try {
    const raw = await fs.readFile(path.join(configDir(), 'auth-token'), 'utf-8');
    const token = raw.trim();
    return token.length > 0 ? token : null;
  } catch {
    return null;
  }
}

function localDaemonWsUrl(config: RuntimeLaunchConfig): string | null {
  if (config.socketPath) {
    // ws+unix is not currently supported by the ws client in this relay bridge.
    return null;
  }
  const host = config.host === '0.0.0.0' || config.host === '::' ? '127.0.0.1' : config.host;
  return `ws://${host}:${config.port}/ws`;
}

async function isRuntimeResponsive(): Promise<boolean> {
  const res = await daemonFetch('/health', { timeoutMs: 1_200 });
  return !!(res && res.ok);
}

export async function start(options?: { silent?: boolean; json?: boolean }): Promise<void> {
  const silent = options?.silent ?? false;
  const asJson = options?.json ?? hasFlag('json');
  const resolved = await resolveDaemonSettingsFromSources();
  const config = resolved.launch;

  await maybeOfferAgentPrerequisites({ silent, asJson });

  const existingRuntime = await readDaemonRuntimeState();
  if (existingRuntime) {
    const running = isPidRunning(existingRuntime.ownerPid);
    if (running) {
      const processInfo = readProcessInfo(existingRuntime.ownerPid);
      if (isOwnershipMatch(existingRuntime, processInfo)) {
        const responsive = await isRuntimeResponsive();
        if (responsive) {
          throw new Error(
            `Daemon already running (owner pid ${existingRuntime.ownerPid}, listen ${existingRuntime.listen ?? `${existingRuntime.host}:${existingRuntime.port}`})`,
          );
        }

        // Auto-heal stale supervisor state: owner PID is present but daemon is unreachable.
        try {
          const result = await stopPid(existingRuntime.ownerPid, {
            timeoutMs: 1_500,
            force: true,
            useProcessGroup: true,
          });
          if (!silent) {
            logger.warn(
              `Auto-healed stale daemon supervisor (pid ${existingRuntime.ownerPid}, result: ${result}).`,
            );
          }
        } catch (err) {
          throw new Error(
            `Daemon owner pid ${existingRuntime.ownerPid} is unresponsive and could not be auto-healed: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
      }
    }
    await clearDaemonRuntimeState();
  }

  if (config.detached) {
    const startup = await startSupervisorDetached(config);
    if (!silent) {
      if (asJson) {
        printStartJson({
          command: 'start',
          ok: true,
          mode: 'detached',
          ownerPid: startup.pid,
          logPath: startup.logPath,
          listen: config.listen,
          socketPath: config.socketPath ?? null,
          host: config.host,
          port: config.port,
          profile: config.profile,
        });
      } else {
        logger.log(`Daemon starting in background (owner pid ${startup.pid ?? 'unknown'}).`);
        logger.log(`Logs: ${startup.logPath}`);
        logger.log(`Listen: ${config.listen}`);
      }
    }
    return;
  }

  const status = await runSupervisorForeground(config);
  if (!silent && asJson) {
    printStartJson({
      command: 'start',
      ok: status === 0,
      mode: 'foreground',
      exitCode: status,
      listen: config.listen,
      socketPath: config.socketPath ?? null,
      host: config.host,
      port: config.port,
      profile: config.profile,
    });
  }
  process.exit(status);
}

export async function runSupervisorCommand(): Promise<void> {
  const status = await runSupervisorFromEnv();
  process.exit(status);
}

// ---------------------------------------------------------------------------
// worker command
// ---------------------------------------------------------------------------

export async function runWorkerCommand(): Promise<void> {
  const config = loadWorkerConfigFromEnv();
  await runDaemonWorker(config);
}

export async function runDaemonWorker(config: RuntimeLaunchConfig): Promise<void> {
  const { port, host, version, socketPath } = config;
  const runtimeStartedAt = Date.now();
  const daemon = new Daemon();
  await daemon.initialize();

  const registry = await loadAgents(daemon);
  await autoRegisterDirectories(daemon, registry);

  try {
    const models = await registry.fetchAllModels();
    logger.log(`Models:  ${models.map((m) => m.displayName).join(', ') || 'none'}`);
  } catch {
    logger.log('Models:  fetch failed (will use fallback)');
  }

  await daemon.runDiscovery();
  const discoveryWatches = await startDiscoveryWatchers(daemon, registry);

  daemon.setTrackerFactory(
    (trackerConfig: GitTrackerConfig, sessionId: string) =>
      new GitTracker(trackerConfig, sessionId),
  );

  // Wire session persistence
  const PERSIST_DEBOUNCE_MS = 2000;
  let persistTimer: ReturnType<typeof setTimeout> | null = null;
  const sessionMeta = new Map<string, { startedAt: number; lastStateChange: number }>();

  const persistSessions = async () => {
    try {
      const activeSessions = daemon.getActiveSessions();
      const entries: PersistedSession[] = activeSessions.map((sid) => {
        const info = daemon.getSessionInfo(sid);
        const dir = daemon.directoryManager.get(info.directoryId);
        const meta = sessionMeta.get(sid);
        return {
          sessionId: sid,
          directoryId: info.directoryId,
          agent: info.agent,
          startedAt: meta?.startedAt ?? Date.now(),
          lastStateChange: meta?.lastStateChange ?? Date.now(),
          state: info.state,
          cwd: dir?.path ?? '',
        };
      });
      await savePersistedSessions(entries);
    } catch (err) {
      logger.warn('persistSessions failed:', err);
    }
  };

  const debouncedPersist = () => {
    if (persistTimer) clearTimeout(persistTimer);
    persistTimer = setTimeout(() => {
      persistTimer = null;
      persistSessions().catch((err) => logger.warn('persistSessions failed:', err));
    }, PERSIST_DEBOUNCE_MS);
  };

  daemon.on('session:started', ({ sessionId }) => {
    const now = Date.now();
    sessionMeta.set(sessionId, { startedAt: now, lastStateChange: now });
    debouncedPersist();
  });
  daemon.on('session:ended', ({ sessionId }) => {
    sessionMeta.delete(sessionId);
    debouncedPersist();
  });
  daemon.on('session:state-changed', ({ sessionId }) => {
    const existing = sessionMeta.get(sessionId);
    if (!existing) return;
    existing.lastStateChange = Date.now();
    debouncedPersist();
  });

  const orphaned = await loadPersistedSessions();
  if (orphaned.length > 0) {
    logger.log(`Found ${orphaned.length} orphaned session(s) from previous run (cleaned up)`);
    await clearPersistedSessions();
  }

  const securityProfile = buildSecurityProfile({
    profile: config.profile,
    host: config.host,
    allowedHostsRaw: config.allowedHostsRaw,
    allowedOriginsRaw: config.allowedOriginsRaw,
    explicitAuthFlag: config.authEnabled,
  });

  // Auth
  let auth: AuthProvider | undefined;
  if (securityProfile.requireAuth) {
    const localAuth = new LocalAuthProvider();
    await localAuth.initialize();
    auth = localAuth;
    logger.log(`Auth:    token-based (see ~/.viewport/auth-token)`);
  } else {
    logger.log(`Auth:    disabled (local mode)`);
  }

  // Hook system — enables remote supervision of terminal-started sessions
  const supervision = new SupervisionManager();
  const hookRouter = new HookRouter(daemon, supervision);

  const app = Fastify({
    logger: {
      level: process.env['VIEWPORT_HTTP_LOG_LEVEL'] ?? 'info',
      // Prevent auth material from landing in request logs.
      redact: {
        paths: [...HTTP_LOG_REDACT_PATHS],
        censor: '[REDACTED]',
      },
    },
  });
  await app.register(fastifyCors, {
    origin: (origin, callback) => {
      const allowed = isOriginAllowed(origin, securityProfile);
      callback(null, allowed);
    },
  });
  await app.register(fastifyWebsocket);

  let shutdownExitCode = 0;
  let shuttingDown = false;
  let shutdownPromise: Promise<void> | null = null;
  let relayBridge: DaemonRelayBridge | null = null;

  const shutdown = async (exitCode = 0) => {
    if (shuttingDown) return;
    shuttingDown = true;
    shutdownExitCode = exitCode;
    logger.log('\nShutting down...');

    if (persistTimer) {
      clearTimeout(persistTimer);
      persistTimer = null;
    }
    await persistSessions();
    discoveryWatches.stop();
    hookRouter.shutdown();
    if (relayBridge) {
      await relayBridge.stop();
      relayBridge = null;
    }
    await daemon.shutdown();
    await clearPersistedSessions();
    await app.close();
    if (socketPath) {
      await fs.rm(socketPath, { force: true }).catch(() => undefined);
    }
    process.exit(shutdownExitCode);
  };

  registerHttpRoutes(app, daemon, registry, {
    auth,
    hookRouter,
    securityProfile,
    runtime: {
      pid: process.pid,
      host,
      port,
      listen: config.listen,
      socketPath: config.socketPath,
      startedAt: runtimeStartedAt,
      version,
    },
    onLifecycleShutdown: async () => {
      if (!shutdownPromise) {
        shutdownPromise = shutdown(WORKER_EXIT_SHUTDOWN);
      }
      await shutdownPromise;
    },
    onLifecycleRestart: async () => {
      if (!shutdownPromise) {
        shutdownPromise = shutdown(WORKER_EXIT_RESTART);
      }
      await shutdownPromise;
    },
  });
  registerWsServer(app, daemon, registry, { hookRouter, supervision, auth, securityProfile });

  let address = '';
  try {
    if (socketPath) {
      await fs.rm(socketPath, { force: true });
      await fs.mkdir(path.dirname(socketPath), { recursive: true });
      address = await app.listen({ path: socketPath });
    } else {
      address = await app.listen({ port, host });
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EADDRINUSE') {
      if (socketPath) {
        throw new Error(`Socket ${socketPath} is already in use. Try a different --listen path.`);
      }
      throw new Error(`Port ${port} is already in use. Try a different --listen target.`);
    }
    throw err;
  }

  const publicAddress = socketPath ? `unix://${socketPath}` : address;
  logger.log(`Viewport daemon listening at ${publicAddress}`);
  if (socketPath) {
    logger.log(`  HTTP:      unix://${socketPath}:/health`);
    logger.log(`  WebSocket: ws+unix://${socketPath}:/ws`);
  } else {
    logger.log(`  HTTP:      ${address}/health`);
    logger.log(`  WebSocket: ${address.replace('http', 'ws')}/ws`);
  }
  logger.log(`  Agents:    ${registry.getIds().join(', ') || 'none'}`);

  if (config.relayEnabled) {
    const missing: string[] = [];
    if (!config.relayEndpoint) missing.push('relay endpoint');
    if (!config.relayServerUrl) missing.push('relay server URL');
    if (!config.relayWorkspaceId) missing.push('relay workspace ID');
    if (!config.relayEnrollToken) missing.push('relay enroll token');
    const daemonWsUrl = localDaemonWsUrl(config);
    if (!daemonWsUrl) {
      missing.push(
        'tcp listen target (relay runtime currently requires tcp listen, not unix socket)',
      );
    }

    if (missing.length > 0) {
      logger.warn(`[relay] disabled due to incomplete config: ${missing.join(', ')}`);
    } else {
      const daemonToken = securityProfile.requireAuth ? await readDaemonAuthToken() : null;
      relayBridge = new DaemonRelayBridge({
        relayEndpoint: config.relayEndpoint!,
        relayServerUrl: config.relayServerUrl!,
        workspaceId: config.relayWorkspaceId!,
        enrollToken: config.relayEnrollToken!,
        daemonWsUrl: daemonWsUrl!,
        daemonAuthToken: daemonToken ?? undefined,
        relayTlsVerify: config.relayTlsVerify ?? 'auto',
        relayCaCertPath: config.relayCaCertPath,
      });
      await relayBridge.start();
      logger.log(
        `[relay] enabled (workspace=${config.relayWorkspaceId}, endpoint=${config.relayEndpoint})`,
      );
    }
  }

  process.on('SIGINT', () => {
    if (!shutdownPromise) {
      shutdownPromise = shutdown(0);
    }
  });
  process.on('SIGTERM', () => {
    if (!shutdownPromise) {
      shutdownPromise = shutdown(0);
    }
  });
}
