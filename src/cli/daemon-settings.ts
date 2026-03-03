import { getFlag, hasFlag } from './args.js';
import { loadConfig } from '../core/config.js';
import { buildSecurityProfile } from '../server/security.js';
import type { DeploymentProfile } from '../server/security.js';
import { parseListenTarget, type DaemonListenTarget } from './listen-target.js';
import type { RuntimeLaunchConfig } from './supervisor-protocol.js';

export interface DaemonResolvedSettings {
  launch: RuntimeLaunchConfig;
  listenTarget: DaemonListenTarget;
  allowedOriginsRaw?: string;
}

type AllowedValue = string[] | true | undefined;

function parseProfile(value: string | undefined): DeploymentProfile | undefined {
  if (!value) return undefined;
  const lowered = value.trim().toLowerCase();
  if (lowered === 'local' || lowered === 'lan' || lowered === 'relay') {
    return lowered;
  }
  throw new Error(`Invalid profile value: ${value}. Expected local|lan|relay.`);
}

function parseAllowedValue(raw: string | undefined): AllowedValue {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (trimmed.toLowerCase() === 'true') return true;
  return trimmed
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function mergeAllowed(values: AllowedValue[]): AllowedValue {
  let merged: string[] = [];
  for (const value of values) {
    if (value === true) return true;
    if (!value) continue;
    merged = merged.concat(value);
  }
  return Array.from(new Set(merged));
}

function stringifyAllowedValue(value: AllowedValue): string | undefined {
  if (value === true) return 'true';
  if (!value || value.length === 0) return undefined;
  return value.join(',');
}

function parseBoolean(value: string | undefined): boolean | undefined {
  if (!value) return undefined;
  const lowered = value.trim().toLowerCase();
  if (lowered === '1' || lowered === 'true' || lowered === 'yes' || lowered === 'on') return true;
  if (lowered === '0' || lowered === 'false' || lowered === 'no' || lowered === 'off') return false;
  throw new Error(`Invalid boolean value: ${value}`);
}

function envValue(...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = process.env[key];
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim();
    }
  }
  return undefined;
}

function resolveListenInput(configListen: string | undefined): string {
  const explicitListen = getFlag('listen');
  if (explicitListen) return explicitListen;

  const host = getFlag('host');
  const port = getFlag('port');
  if (host && port) return `${host}:${port}`;
  if (port) return port;
  if (host) return `${host}:7070`;

  const envListen = envValue('VPD_LISTEN', 'VIEWPORT_LISTEN');
  if (envListen) return envListen;

  if (configListen && configListen.trim().length > 0) return configListen.trim();
  return '127.0.0.1:7070';
}

function resolveProfile(configProfile: DeploymentProfile | undefined): DeploymentProfile {
  const cliProfile = parseProfile(getFlag('profile'));
  if (cliProfile) return cliProfile;
  const envProfile = parseProfile(envValue('VPD_PROFILE', 'VIEWPORT_PROFILE'));
  if (envProfile) return envProfile;
  return configProfile ?? 'local';
}

function resolveAuthEnabled(configAuthEnabled: boolean | undefined): boolean {
  if (hasFlag('auth')) return true;
  const envAuth = parseBoolean(envValue('VPD_AUTH', 'VIEWPORT_AUTH'));
  if (envAuth !== undefined) return envAuth;
  return configAuthEnabled ?? false;
}

function resolveDetachedDefault(configDetached?: boolean): boolean {
  if (hasFlag('foreground')) return false;
  if (hasFlag('detached')) return true;
  if (configDetached !== undefined) return configDetached;
  return true;
}

export async function resolveDaemonSettingsFromSources(): Promise<DaemonResolvedSettings> {
  const config = await loadConfig();
  const daemonConfig = config.daemon;

  const listenInput = resolveListenInput(daemonConfig?.listen);
  const listenTarget = parseListenTarget(listenInput);
  const hostForSecurity = listenTarget.type === 'tcp' ? listenTarget.host : '127.0.0.1';

  const profile = resolveProfile(daemonConfig?.profile);

  const mergedAllowedHosts = mergeAllowed([
    daemonConfig?.allowedHosts,
    parseAllowedValue(envValue('VPD_ALLOWED_HOSTS', 'VIEWPORT_ALLOWED_HOSTS')),
    parseAllowedValue(getFlag('allowed-hosts')),
  ]);
  const allowedHostsRaw = stringifyAllowedValue(mergedAllowedHosts);

  const mergedAllowedOrigins = mergeAllowed([
    daemonConfig?.allowedOrigins,
    parseAllowedValue(envValue('VPD_ALLOWED_ORIGINS', 'VIEWPORT_ALLOWED_ORIGINS')),
    parseAllowedValue(getFlag('allowed-origins')),
  ]);
  const allowedOriginsRaw = stringifyAllowedValue(mergedAllowedOrigins);

  const authEnabled = resolveAuthEnabled(daemonConfig?.authEnabled);
  const securityProfile = buildSecurityProfile({
    profile,
    host: hostForSecurity,
    allowedHostsRaw,
    allowedOriginsRaw,
    explicitAuthFlag: authEnabled,
  });

  const logPath =
    getFlag('log-file') ??
    envValue('VPD_LOG_FILE', 'VIEWPORT_LOG_FILE') ??
    daemonConfig?.logFile ??
    undefined;

  const relayEnabledFromEnv = parseBoolean(envValue('VPD_RELAY_ENABLED', 'VIEWPORT_RELAY_ENABLED'));
  const relayEnabled = hasFlag('no-relay')
    ? false
    : (relayEnabledFromEnv ?? daemonConfig?.relay?.enabled ?? false);
  const relayEndpoint =
    getFlag('relay-endpoint') ??
    envValue('VPD_RELAY_ENDPOINT', 'VIEWPORT_RELAY_ENDPOINT') ??
    daemonConfig?.relay?.endpoint;

  const launch: RuntimeLaunchConfig = {
    listen: listenTarget.listen,
    host: listenTarget.type === 'tcp' ? listenTarget.host : '127.0.0.1',
    port: listenTarget.type === 'tcp' ? listenTarget.port : 0,
    socketPath: listenTarget.type === 'socket' ? listenTarget.path : undefined,
    version: '0.3.0',
    profile: securityProfile.profile,
    allowedHostsRaw,
    allowedOriginsRaw,
    authEnabled: securityProfile.requireAuth,
    detached: resolveDetachedDefault(undefined),
    logPath,
    relayEnabled,
    relayEndpoint,
  };

  return {
    launch,
    listenTarget,
    allowedOriginsRaw,
  };
}
