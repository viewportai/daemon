import fs from 'node:fs';
import type { WebSocket as WsType } from 'ws';
import { DAEMON_CONNECT_TIMEOUT_MS, RELAY_CONNECT_TIMEOUT_MS } from './bridge-constants.js';
import { BridgeError } from './bridge-errors.js';

type RelayWs = WsType;

export function wsOpen(ws: RelayWs): Promise<void> {
  return new Promise((resolve, reject) => {
    const onOpen = () => {
      cleanup();
      resolve();
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const timeout = setTimeout(
      () => {
        cleanup();
        reject(new BridgeError('WEBSOCKET_CONNECT_TIMEOUT', 'websocket connect timeout'));
      },
      ws.url.startsWith('ws://127.0.0.1') ? DAEMON_CONNECT_TIMEOUT_MS : RELAY_CONNECT_TIMEOUT_MS,
    );

    const cleanup = () => {
      clearTimeout(timeout);
      ws.off('open', onOpen);
      ws.off('error', onError);
    };

    ws.once('open', onOpen);
    ws.once('error', onError);
  });
}

export function resolveRelayTlsOptions(
  relayUrl: string,
  mode: 'auto' | '0' | '1',
  caCertPath?: string,
): { rejectUnauthorized?: boolean; ca?: Buffer } {
  let parsed: URL;
  try {
    parsed = new URL(relayUrl);
  } catch {
    return {};
  }
  if (parsed.protocol !== 'wss:') return {};

  let rejectUnauthorized: boolean;
  if (mode === '1') {
    rejectUnauthorized = true;
  } else if (mode === '0') {
    rejectUnauthorized = false;
  } else {
    rejectUnauthorized = !(parsed.hostname.endsWith('.test') || parsed.hostname === 'localhost');
  }

  const result: { rejectUnauthorized?: boolean; ca?: Buffer } = { rejectUnauthorized };
  if (caCertPath) {
    result.ca = fs.readFileSync(caCertPath);
  }
  return result;
}

export function closeQuietly(ws: RelayWs | null | undefined): void {
  if (!ws) return;
  try {
    ws.close();
  } catch {
    // ignore
  }
}
