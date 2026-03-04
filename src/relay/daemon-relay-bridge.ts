import crypto from 'node:crypto';
import fs from 'node:fs';
import type { WebSocket as WsType } from 'ws';
import WebSocket from 'ws';
import { logger as out } from '../core/output.js';

interface RelayTokenResponse {
  ok: boolean;
  relayToken?: string;
  claims?: {
    e2eeKey?: string;
  };
  reason?: string;
  error?: string;
}

export interface DaemonRelayBridgeOptions {
  relayEndpoint: string;
  relayServerUrl: string;
  workspaceId: string;
  enrollToken: string;
  daemonWsUrl: string;
  relayTlsVerify?: 'auto' | '0' | '1';
  relayCaCertPath?: string;
}

type RelayWs = WsType;

const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;
const RELAY_CONNECT_TIMEOUT_MS = 8_000;
const DAEMON_CONNECT_TIMEOUT_MS = 8_000;
const MAX_PENDING_OUTBOUND = 500;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function computeBackoffMs(attempt: number): number {
  const exp = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** Math.max(0, attempt - 1));
  const jitter = Math.floor(Math.random() * 250);
  return Math.min(RECONNECT_MAX_MS, exp + jitter);
}

function toBase64Url(buffer: Buffer): string {
  return buffer.toString('base64url');
}

function fromBase64Url(value: string): Buffer {
  return Buffer.from(value, 'base64url');
}

function encryptEnvelope(key: Buffer, plaintext: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    type: 'e2ee',
    iv: toBase64Url(iv),
    tag: toBase64Url(tag),
    ciphertext: toBase64Url(ciphertext),
  });
}

function decryptEnvelope(key: Buffer, raw: string): string {
  const parsed = JSON.parse(raw) as {
    type?: string;
    iv?: string;
    tag?: string;
    ciphertext?: string;
  };
  if (
    parsed.type !== 'e2ee' ||
    typeof parsed.iv !== 'string' ||
    typeof parsed.tag !== 'string' ||
    typeof parsed.ciphertext !== 'string'
  ) {
    throw new Error('Invalid relay envelope');
  }

  const iv = fromBase64Url(parsed.iv);
  const tag = fromBase64Url(parsed.tag);
  const ciphertext = fromBase64Url(parsed.ciphertext);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

async function parseRelayIssueResponse(res: Response): Promise<RelayTokenResponse> {
  const json = (await res.json().catch(() => null)) as RelayTokenResponse | null;
  if (!json) {
    return {
      ok: false,
      reason: `relay token endpoint returned non-JSON (${res.status})`,
    };
  }
  return json;
}

function wsOpen(ws: RelayWs): Promise<void> {
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
        reject(new Error('websocket connect timeout'));
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

function resolveRelayTlsOptions(
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

function closeQuietly(ws: RelayWs | null | undefined): void {
  if (!ws) return;
  try {
    ws.close();
  } catch {
    // ignore
  }
}

export class DaemonRelayBridge {
  private relayWs: RelayWs | null = null;
  private daemonWs: RelayWs | null = null;
  private running = false;
  private reconnecting = false;
  private reconnectAttempt = 0;
  private readonly pendingOutbound: string[] = [];
  private e2eeKey: Buffer | null = null;

  constructor(private readonly options: DaemonRelayBridgeOptions) {}

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.reconnectAttempt = 0;
    await this.connectLoop('start');
  }

  async stop(): Promise<void> {
    this.running = false;
    this.reconnecting = false;
    closeQuietly(this.relayWs);
    closeQuietly(this.daemonWs);
    this.relayWs = null;
    this.daemonWs = null;
    this.e2eeKey = null;
    this.pendingOutbound.length = 0;
  }

  private async connectLoop(reason: string): Promise<void> {
    if (!this.running) return;
    if (this.reconnecting) return;
    this.reconnecting = true;

    try {
      this.reconnectAttempt += 1;
      const attempt = this.reconnectAttempt;
      out.log(`[relay] daemon bridge connect attempt ${attempt} (${reason})`);

      const issue = await this.issueRelayToken();
      if (!issue.relayToken || !issue.e2eeKey) {
        throw new Error('relay token response missing relayToken/e2eeKey');
      }
      this.e2eeKey = issue.e2eeKey;

      const daemonWs = new WebSocket(this.options.daemonWsUrl);
      await wsOpen(daemonWs);
      this.daemonWs = daemonWs;

      const relayUrl =
        `${this.options.relayEndpoint}?role=workspace-daemon` +
        `&workspaceId=${encodeURIComponent(this.options.workspaceId)}` +
        `&token=${encodeURIComponent(issue.relayToken)}`;

      const relayTlsOptions = resolveRelayTlsOptions(
        relayUrl,
        this.options.relayTlsVerify ?? 'auto',
        this.options.relayCaCertPath,
      );
      const relayWs = new WebSocket(relayUrl, relayTlsOptions);
      await wsOpen(relayWs);
      this.relayWs = relayWs;

      out.log('[relay] daemon bridge connected');
      this.reconnectAttempt = 0;
      this.installSocketHandlers(daemonWs, relayWs);
      this.flushPendingOutbound();
    } catch (error) {
      closeQuietly(this.relayWs);
      closeQuietly(this.daemonWs);
      this.relayWs = null;
      this.daemonWs = null;
      this.e2eeKey = null;

      const msg = error instanceof Error ? error.message : String(error);
      out.warn(`[relay] daemon bridge connect failed: ${msg}`);
      if (this.running) {
        const waitMs = computeBackoffMs(this.reconnectAttempt);
        out.log(`[relay] daemon bridge reconnect in ${waitMs}ms`);
        await sleep(waitMs);
        this.reconnecting = false;
        await this.connectLoop('retry');
        return;
      }
    }

    this.reconnecting = false;
  }

  private installSocketHandlers(daemonWs: RelayWs, relayWs: RelayWs): void {
    daemonWs.on('message', (raw) => {
      const payload = raw.toString('utf8');
      const key = this.e2eeKey;
      if (!key) return;
      const envelope = encryptEnvelope(key, payload);
      if (relayWs.readyState === WebSocket.OPEN) {
        relayWs.send(envelope);
        return;
      }
      this.pendingOutbound.push(envelope);
      if (this.pendingOutbound.length > MAX_PENDING_OUTBOUND) {
        this.pendingOutbound.splice(0, this.pendingOutbound.length - MAX_PENDING_OUTBOUND);
      }
    });

    relayWs.on('message', (raw) => {
      const text = raw.toString('utf8');
      try {
        const control = JSON.parse(text) as { type?: string; code?: string; message?: string };
        if (control.type === 'relay_status') {
          out.log(
            `[relay] status ${control.code ?? 'UNKNOWN'}: ${
              control.message ?? 'no additional detail'
            }`,
          );
          return;
        }
      } catch {
        // Non-control, likely encrypted payload.
      }

      const key = this.e2eeKey;
      if (!key) return;

      try {
        const plaintext = decryptEnvelope(key, text);
        if (daemonWs.readyState === WebSocket.OPEN) {
          daemonWs.send(plaintext);
        }
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        out.warn(`[relay] failed to decrypt relay payload: ${msg}`);
      }
    });

    const reconnect = (source: string) => {
      if (!this.running) return;
      if (this.reconnecting) return;
      out.warn(`[relay] ${source} disconnected; reconnecting`);
      closeQuietly(relayWs);
      closeQuietly(daemonWs);
      this.relayWs = null;
      this.daemonWs = null;
      this.e2eeKey = null;
      void this.connectLoop(source);
    };

    relayWs.on('close', () => reconnect('relay'));
    daemonWs.on('close', () => reconnect('daemon'));
    relayWs.on('error', (err) => out.warn(`[relay] relay ws error: ${err.message}`));
    daemonWs.on('error', (err) => out.warn(`[relay] daemon ws error: ${err.message}`));
  }

  private flushPendingOutbound(): void {
    const relayWs = this.relayWs;
    if (!relayWs || relayWs.readyState !== WebSocket.OPEN) return;
    while (this.pendingOutbound.length > 0 && relayWs.readyState === WebSocket.OPEN) {
      const next = this.pendingOutbound.shift();
      if (!next) break;
      relayWs.send(next);
    }
  }

  private async issueRelayToken(): Promise<{ relayToken: string; e2eeKey: Buffer }> {
    const url = `${this.options.relayServerUrl.replace(/\/+$/, '')}/api/poc/relay-token`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        role: 'workspace-daemon',
        workspaceId: this.options.workspaceId,
        credential: this.options.enrollToken,
      }),
    });
    const parsed = await parseRelayIssueResponse(res);
    if (!res.ok || !parsed.ok || !parsed.relayToken) {
      const reason = parsed.reason ?? parsed.error ?? `HTTP ${res.status}`;
      throw new Error(`issue relay token failed: ${reason}`);
    }

    const e2eeKeyRaw = parsed.claims?.e2eeKey;
    if (!e2eeKeyRaw) {
      throw new Error('issue relay token response missing claims.e2eeKey');
    }
    const key = fromBase64Url(e2eeKeyRaw);
    if (key.length !== 32) {
      throw new Error('invalid e2eeKey length from relay token claims');
    }

    return {
      relayToken: parsed.relayToken,
      e2eeKey: key,
    };
  }
}
