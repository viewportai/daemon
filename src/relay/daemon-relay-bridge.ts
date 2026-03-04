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
  daemonAuthToken?: string;
  relayTlsVerify?: 'auto' | '0' | '1';
  relayCaCertPath?: string;
  maxPendingOutbound?: number;
}

type RelayWs = WsType;

export const RECONNECT_BASE_MS = 1_000;
export const RECONNECT_MAX_MS = 30_000;
export const RELAY_CONNECT_TIMEOUT_MS = 8_000;
export const DAEMON_CONNECT_TIMEOUT_MS = 8_000;
export const DEFAULT_MAX_PENDING_OUTBOUND = 500;
export const ISSUE_FAILURE_THRESHOLD = 5;
export const CIRCUIT_BREAKER_MS = 60_000;

export type BridgeErrorCode =
  | 'TOKEN_ISSUE_FAILED'
  | 'TOKEN_RESPONSE_INVALID'
  | 'TOKEN_KEY_INVALID'
  | 'WEBSOCKET_CONNECT_TIMEOUT'
  | 'ENVELOPE_DECRYPT_FAILED'
  | 'CIRCUIT_OPEN'
  | 'WEBSOCKET_ERROR'
  | 'UNKNOWN';

export interface DaemonRelayBridgeStatus {
  state: 'stopped' | 'connecting' | 'connected' | 'waiting_retry' | 'circuit_open';
  reconnectAttempt: number;
  lastErrorCode?: BridgeErrorCode;
  lastErrorMessage?: string;
  lastErrorAt?: number;
  circuitOpenUntil?: number;
}

class BridgeError extends Error {
  constructor(
    readonly code: BridgeErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'BridgeError';
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function computeBackoffMs(attempt: number): number {
  const exp = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** Math.max(0, attempt - 1));
  const jitter = Math.floor(Math.random() * 250);
  return Math.min(RECONNECT_MAX_MS, exp + jitter);
}

export function toBase64Url(buffer: Buffer): string {
  return buffer.toString('base64url');
}

export function fromBase64Url(value: string): Buffer {
  return Buffer.from(value, 'base64url');
}

export function encryptEnvelope(key: Buffer, plaintext: string): string {
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

export function decryptEnvelope(key: Buffer, raw: string): string {
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
  private consecutiveIssueFailures = 0;
  private circuitOpenUntilMs = 0;
  private lastErrorCode: BridgeErrorCode | undefined;
  private lastErrorMessage: string | undefined;
  private lastErrorAt: number | undefined;
  private state: DaemonRelayBridgeStatus['state'] = 'stopped';

  constructor(private readonly options: DaemonRelayBridgeOptions) {}

  getStatus(): DaemonRelayBridgeStatus {
    return {
      state: this.state,
      reconnectAttempt: this.reconnectAttempt,
      lastErrorCode: this.lastErrorCode,
      lastErrorMessage: this.lastErrorMessage,
      lastErrorAt: this.lastErrorAt,
      circuitOpenUntil: this.circuitOpenUntilMs > 0 ? this.circuitOpenUntilMs : undefined,
    };
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.reconnectAttempt = 0;
    this.state = 'connecting';
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
    this.state = 'stopped';
  }

  private async connectLoop(reason: string): Promise<void> {
    if (!this.running) return;
    if (this.reconnecting) return;
    this.reconnecting = true;
    this.state = 'connecting';

    try {
      const now = Date.now();
      if (this.circuitOpenUntilMs > now) {
        const waitMs = this.circuitOpenUntilMs - now;
        this.state = 'circuit_open';
        this.reportStatus('CIRCUIT_OPEN', `circuit open, waiting ${waitMs}ms before retry`);
        await sleep(waitMs);
      }

      this.reconnectAttempt += 1;
      const attempt = this.reconnectAttempt;
      out.log(`[relay] daemon bridge connect attempt ${attempt} (${reason})`);

      const issue = await this.issueRelayToken();
      if (!issue.relayToken || !issue.e2eeKey) {
        throw new BridgeError(
          'TOKEN_RESPONSE_INVALID',
          'relay token response missing relayToken/e2eeKey',
        );
      }
      this.e2eeKey = issue.e2eeKey;
      this.consecutiveIssueFailures = 0;
      this.circuitOpenUntilMs = 0;

      const daemonHeaders: Record<string, string> = {};
      if (this.options.daemonAuthToken) {
        daemonHeaders.authorization = `Bearer ${this.options.daemonAuthToken}`;
      }
      const daemonWs = new WebSocket(this.options.daemonWsUrl, {
        headers: Object.keys(daemonHeaders).length > 0 ? daemonHeaders : undefined,
      });
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
      this.state = 'connected';
      this.reconnectAttempt = 0;
      this.installSocketHandlers(daemonWs, relayWs);
      this.flushPendingOutbound();
    } catch (error) {
      closeQuietly(this.relayWs);
      closeQuietly(this.daemonWs);
      this.relayWs = null;
      this.daemonWs = null;
      this.e2eeKey = null;

      const bridgeError = this.normalizeError(error);
      this.recordError(bridgeError.code, bridgeError.message);
      out.warn(
        `[relay] daemon bridge connect failed [${bridgeError.code}]: ${bridgeError.message}`,
      );

      if (
        bridgeError.code === 'TOKEN_ISSUE_FAILED' ||
        bridgeError.code === 'TOKEN_RESPONSE_INVALID'
      ) {
        this.consecutiveIssueFailures += 1;
        if (this.consecutiveIssueFailures >= ISSUE_FAILURE_THRESHOLD) {
          this.circuitOpenUntilMs = Date.now() + CIRCUIT_BREAKER_MS;
          this.reportStatus(
            'CIRCUIT_OPEN',
            `opened after ${this.consecutiveIssueFailures} consecutive token-issue failures`,
          );
        }
      }

      if (this.running) {
        const waitMs = computeBackoffMs(this.reconnectAttempt);
        out.log(`[relay] daemon bridge reconnect in ${waitMs}ms`);
        this.state = 'waiting_retry';
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
      const maxPendingOutbound = this.options.maxPendingOutbound ?? DEFAULT_MAX_PENDING_OUTBOUND;
      if (this.pendingOutbound.length > maxPendingOutbound) {
        this.pendingOutbound.splice(0, this.pendingOutbound.length - maxPendingOutbound);
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
        this.recordError('ENVELOPE_DECRYPT_FAILED', msg);
        out.warn(`[relay] failed to decrypt relay payload [ENVELOPE_DECRYPT_FAILED]: ${msg}`);
      }
    });

    const reconnect = (source: string) => {
      if (!this.running) return;
      if (this.reconnecting) return;
      this.recordError('WEBSOCKET_ERROR', `${source} disconnected`);
      out.warn(`[relay] ${source} disconnected; reconnecting`);
      closeQuietly(relayWs);
      closeQuietly(daemonWs);
      this.relayWs = null;
      this.daemonWs = null;
      this.e2eeKey = null;
      this.state = 'waiting_retry';
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
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8_000);
    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          role: 'workspace-daemon',
          workspaceId: this.options.workspaceId,
          credential: this.options.enrollToken,
        }),
        signal: controller.signal,
      });
    } catch (error) {
      clearTimeout(timeout);
      throw new BridgeError(
        'TOKEN_ISSUE_FAILED',
        error instanceof Error ? error.message : String(error),
      );
    }
    clearTimeout(timeout);
    const parsed = await parseRelayIssueResponse(res);
    if (!res.ok || !parsed.ok || !parsed.relayToken) {
      const reason = parsed.reason ?? parsed.error ?? `HTTP ${res.status}`;
      throw new BridgeError('TOKEN_ISSUE_FAILED', `issue relay token failed: ${reason}`);
    }

    const e2eeKeyRaw = parsed.claims?.e2eeKey;
    if (!e2eeKeyRaw) {
      throw new BridgeError(
        'TOKEN_RESPONSE_INVALID',
        'issue relay token response missing claims.e2eeKey',
      );
    }
    const key = fromBase64Url(e2eeKeyRaw);
    if (key.length !== 32) {
      throw new BridgeError('TOKEN_KEY_INVALID', 'invalid e2eeKey length from relay token claims');
    }

    return {
      relayToken: parsed.relayToken,
      e2eeKey: key,
    };
  }

  private normalizeError(error: unknown): BridgeError {
    if (error instanceof BridgeError) {
      return error;
    }
    if (error instanceof Error) {
      return new BridgeError('UNKNOWN', error.message);
    }
    return new BridgeError('UNKNOWN', String(error));
  }

  private recordError(code: BridgeErrorCode, message: string): void {
    this.lastErrorCode = code;
    this.lastErrorMessage = message;
    this.lastErrorAt = Date.now();
  }

  private reportStatus(code: BridgeErrorCode | 'CIRCUIT_OPEN', message: string): void {
    out.warn(`[relay] bridge-status [${code}]: ${message}`);
  }
}
