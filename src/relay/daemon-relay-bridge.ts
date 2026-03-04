import type { WebSocket as WsType } from 'ws';
import WebSocket from 'ws';
import { computeBackoffMs, sleep } from './bridge-backoff.js';
import {
  CIRCUIT_BREAKER_MS,
  DEFAULT_MAX_PENDING_OUTBOUND,
  DEFAULT_MAX_PENDING_OUTBOUND_BYTES,
  ISSUE_FAILURE_THRESHOLD,
  RELAY_KEY_ROTATE_AFTER_MESSAGES,
  RELAY_REPLAY_WINDOW,
  RELAY_SESSION_IDLE_TTL_MS,
} from './bridge-constants.js';
import {
  decryptEnvelope,
  encryptEnvelope,
  fromBase64Url,
  parseRelayEnvelope,
  toBase64Url,
} from './bridge-crypto.js';
import {
  deriveSessionFromKeyExchange,
  type DaemonRelayIdentity,
  loadOrCreateIdentity,
  parseRelayHandshakeProfile,
  parseRelayKeyExchangeInitFrame,
  type RelayHandshakeProfile,
  type RelayKeyExchangeInitFrame,
} from './bridge-key-exchange.js';
import { BridgeError, type BridgeErrorCode } from './bridge-errors.js';
import { type RelayTokenClaims, verifyRelayTokenClaims } from './bridge-jwt.js';
import { closeQuietly, resolveRelayTlsOptions, wsOpen } from './bridge-network.js';
import { logger as out } from '../core/output.js';

interface RelayTokenResponse {
  ok: boolean;
  relayToken?: string;
  claims?: RelayTokenClaims;
  reason?: string;
  error?: string;
}

interface RelayStatusFrame {
  type: 'relay_status';
  code?: string;
  message?: string;
  relayWsBaseUrl?: string;
}

interface RelayKeyUpdateRequiredFrame {
  type: 'relay_key_update_required';
  sessionId: string;
  nextEpoch: number;
  reason: 'message_threshold';
}

type RelayControlFrame = RelayStatusFrame | RelayKeyUpdateRequiredFrame;

export interface DaemonRelayBridgeOptions {
  relayEndpoint: string;
  relayServerUrl: string;
  workspaceId: string;
  enrollToken: string;
  issueToken?: string;
  daemonWsUrl: string;
  daemonAuthToken?: string;
  relayTlsVerify?: 'auto' | '0' | '1';
  relayCaCertPath?: string;
  relayTlsPins?: string[];
  relayTokenIssuer?: string;
  relayTokenAudience?: string;
  relayTokenSigningKeys?: Record<string, string>;
  relayTokenClockSkewSec?: number;
  maxPendingOutbound?: number;
  maxPendingOutboundBytes?: number;
}

interface RelaySessionState {
  key: Buffer;
  profile: RelayHandshakeProfile;
  sessionId: string;
  epoch: number;
  txSeq: number;
  rxHighestSeq: number;
  rxSeenSeq: Set<number>;
  lastActivityAt: number;
  keyRotationRequested: boolean;
}

type RelayWs = WsType;

export { CIRCUIT_BREAKER_MS } from './bridge-constants.js';
export { computeBackoffMs, decryptEnvelope, encryptEnvelope, fromBase64Url, toBase64Url };

export interface DaemonRelayBridgeStatus {
  state: 'stopped' | 'connecting' | 'connected' | 'waiting_retry' | 'circuit_open';
  reconnectAttempt: number;
  lastErrorCode?: BridgeErrorCode;
  lastErrorMessage?: string;
  lastErrorAt?: number;
  circuitOpenUntil?: number;
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

function isRelayControlFrame(value: unknown): value is RelayControlFrame {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const frame = value as Record<string, unknown>;
  if (frame['type'] === 'relay_status') return true;
  return (
    frame['type'] === 'relay_key_update_required' &&
    typeof frame['sessionId'] === 'string' &&
    typeof frame['nextEpoch'] === 'number'
  );
}

function decodePairingSecret(input: string | undefined): Buffer | undefined {
  if (!input || input.trim().length === 0) return undefined;
  const decoded = fromBase64Url(input);
  if (decoded.length !== 32) {
    throw new Error('pairing secret must be 32 bytes');
  }
  return decoded;
}

export class DaemonRelayBridge {
  private relayWs: RelayWs | null = null;
  private daemonWs: RelayWs | null = null;
  private running = false;
  private reconnecting = false;
  private reconnectAttempt = 0;
  private readonly pendingOutbound: string[] = [];
  private pendingOutboundBytes = 0;
  private daemonIdentity: DaemonRelayIdentity | null = null;
  private daemonIssueToken: string | null;
  private requiredProfile: RelayHandshakeProfile = 'noise-ik';
  private pairingSecret: Buffer | undefined;
  private readonly relayTokenSigningKeys: Record<string, string>;
  private readonly relaySessions = new Map<string, RelaySessionState>();
  private consecutiveIssueFailures = 0;
  private circuitOpenUntilMs = 0;
  private lastErrorCode: BridgeErrorCode | undefined;
  private lastErrorMessage: string | undefined;
  private lastErrorAt: number | undefined;
  private state: DaemonRelayBridgeStatus['state'] = 'stopped';
  private relayEndpoint: string;

  constructor(private readonly options: DaemonRelayBridgeOptions) {
    this.relayEndpoint = options.relayEndpoint;
    this.daemonIssueToken = options.issueToken ?? null;
    this.relayTokenSigningKeys =
      options.relayTokenSigningKeys && Object.keys(options.relayTokenSigningKeys).length > 0
        ? options.relayTokenSigningKeys
        : {
            v1: 'viewport-poc-signing-key-change-me',
          };
  }

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
    this.pendingOutbound.length = 0;
    this.pendingOutboundBytes = 0;
    this.relaySessions.clear();
    this.state = 'stopped';
  }

  private async ensureKeyMaterial(): Promise<void> {
    if (!this.daemonIdentity) {
      this.daemonIdentity = await loadOrCreateIdentity(this.options.workspaceId);
    }
  }

  private async registerDaemonPublicKey(): Promise<void> {
    if (!this.daemonIdentity) {
      throw new BridgeError('DAEMON_KEY_REGISTER_FAILED', 'daemon identity unavailable');
    }

    const url =
      `${this.options.relayServerUrl.replace(/\/+$/, '')}` +
      `/api/poc/workspaces/${encodeURIComponent(this.options.workspaceId)}/daemon-key`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8_000);

    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          credential: this.options.enrollToken,
          daemonPublicKey: this.daemonIdentity.publicKey,
        }),
        signal: controller.signal,
      });
    } catch (error) {
      clearTimeout(timeout);
      throw new BridgeError(
        'DAEMON_KEY_REGISTER_FAILED',
        error instanceof Error ? error.message : String(error),
      );
    }
    clearTimeout(timeout);

    const parsed = (await res.json().catch(() => null)) as {
      ok?: boolean;
      reason?: string;
      error?: string;
      daemonIssueToken?: string;
    } | null;

    if (!res.ok || !parsed?.ok) {
      const reason = parsed?.reason ?? parsed?.error ?? `HTTP ${res.status}`;
      throw new BridgeError(
        'DAEMON_KEY_REGISTER_FAILED',
        `daemon key registration failed: ${reason}`,
      );
    }
    if (!parsed?.daemonIssueToken || parsed.daemonIssueToken.trim().length === 0) {
      throw new BridgeError(
        'DAEMON_KEY_REGISTER_FAILED',
        'daemon key registration succeeded but daemon issue token was missing',
      );
    }
    this.daemonIssueToken = parsed.daemonIssueToken;
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

      await this.ensureKeyMaterial();
      await this.registerDaemonPublicKey();

      const issue = await this.issueRelayToken();
      if (!issue.relayToken) {
        throw new BridgeError('TOKEN_RESPONSE_INVALID', 'relay token response missing relayToken');
      }

      this.requiredProfile = issue.profile;
      this.pairingSecret = issue.pairingSecret;
      this.relaySessions.clear();

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
        `${this.relayEndpoint}?role=workspace-daemon` +
        `&workspaceId=${encodeURIComponent(this.options.workspaceId)}` +
        `&token=${encodeURIComponent(issue.relayToken)}`;

      const relayTlsOptions = resolveRelayTlsOptions(
        relayUrl,
        this.options.relayTlsVerify ?? 'auto',
        this.options.relayCaCertPath,
        this.options.relayTlsPins,
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
      this.relaySessions.clear();

      const bridgeError = this.normalizeError(error);
      this.recordError(bridgeError.code, bridgeError.message);
      out.warn(
        `[relay] daemon bridge connect failed [${bridgeError.code}]: ${bridgeError.message}`,
      );

      if (
        bridgeError.code === 'TOKEN_ISSUE_FAILED' ||
        bridgeError.code === 'TOKEN_RESPONSE_INVALID' ||
        bridgeError.code === 'DAEMON_KEY_REGISTER_FAILED'
      ) {
        this.consecutiveIssueFailures += 1;
        if (this.consecutiveIssueFailures >= ISSUE_FAILURE_THRESHOLD) {
          this.circuitOpenUntilMs = Date.now() + CIRCUIT_BREAKER_MS;
          this.reportStatus(
            'CIRCUIT_OPEN',
            `opened after ${this.consecutiveIssueFailures} consecutive control-plane failures`,
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
      if (relayWs.readyState === WebSocket.OPEN) {
        this.sendToAllRelaySessions(relayWs, payload);
        return;
      }
      const payloadBytes = Buffer.byteLength(payload);
      this.pendingOutbound.push(payload);
      this.pendingOutboundBytes += payloadBytes;
      const maxPendingOutbound = this.options.maxPendingOutbound ?? DEFAULT_MAX_PENDING_OUTBOUND;
      const maxPendingBytes =
        this.options.maxPendingOutboundBytes ?? DEFAULT_MAX_PENDING_OUTBOUND_BYTES;
      while (
        this.pendingOutbound.length > maxPendingOutbound ||
        this.pendingOutboundBytes > maxPendingBytes
      ) {
        const dropped = this.pendingOutbound.shift();
        if (!dropped) break;
        this.pendingOutboundBytes -= Buffer.byteLength(dropped);
      }
    });

    relayWs.on('message', (raw) => {
      const text = raw.toString('utf8');

      const handledControl = this.handleRelayControlFrame(text, relayWs, daemonWs);
      if (handledControl) return;

      let envelope;
      try {
        envelope = parseRelayEnvelope(text);
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        this.recordError('ENVELOPE_DECRYPT_FAILED', msg);
        out.warn(`[relay] invalid relay envelope [ENVELOPE_DECRYPT_FAILED]: ${msg}`);
        return;
      }

      const session = this.relaySessions.get(envelope.sessionId);
      if (!session) return;
      if (session.profile !== envelope.profile || session.epoch !== envelope.epoch) return;
      if (!this.acceptInboundSeq(session, envelope.seq)) {
        out.warn(`[relay] dropped replay/old frame for session ${session.sessionId}`);
        return;
      }

      try {
        const plaintext = decryptEnvelope(session.key, envelope);
        session.lastActivityAt = Date.now();
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
      this.relaySessions.clear();
      this.state = 'waiting_retry';
      void this.connectLoop(source);
    };

    relayWs.on('close', () => reconnect('relay'));
    daemonWs.on('close', () => reconnect('daemon'));
    relayWs.on('error', (err) => out.warn(`[relay] relay ws error: ${err.message}`));
    daemonWs.on('error', (err) => out.warn(`[relay] daemon ws error: ${err.message}`));
  }

  private sendToAllRelaySessions(relayWs: RelayWs, payload: string): void {
    this.pruneIdleSessions();
    for (const session of this.relaySessions.values()) {
      session.txSeq += 1;
      session.lastActivityAt = Date.now();
      const envelope = encryptEnvelope(session.key, payload, {
        profile: session.profile,
        sessionId: session.sessionId,
        epoch: session.epoch,
        seq: session.txSeq,
      });
      relayWs.send(envelope);

      if (!session.keyRotationRequested && session.txSeq >= RELAY_KEY_ROTATE_AFTER_MESSAGES) {
        const rotateNotice: RelayKeyUpdateRequiredFrame = {
          type: 'relay_key_update_required',
          sessionId: session.sessionId,
          nextEpoch: session.epoch + 1,
          reason: 'message_threshold',
        };
        relayWs.send(JSON.stringify(rotateNotice));
        session.keyRotationRequested = true;
      }
    }
  }

  private acceptInboundSeq(session: RelaySessionState, seq: number): boolean {
    if (seq < 1) return false;
    if (session.rxSeenSeq.has(seq)) return false;
    if (seq > session.rxHighestSeq + RELAY_REPLAY_WINDOW) return false;
    const minimumAllowed = Math.max(1, session.rxHighestSeq - RELAY_REPLAY_WINDOW + 1);
    if (seq < minimumAllowed) return false;

    session.rxSeenSeq.add(seq);
    if (seq > session.rxHighestSeq) session.rxHighestSeq = seq;

    const pruneBelow = Math.max(1, session.rxHighestSeq - RELAY_REPLAY_WINDOW + 1);
    for (const seen of session.rxSeenSeq) {
      if (seen < pruneBelow) session.rxSeenSeq.delete(seen);
    }
    return true;
  }

  private pruneIdleSessions(): void {
    const now = Date.now();
    for (const [sessionId, session] of this.relaySessions.entries()) {
      if (now - session.lastActivityAt > RELAY_SESSION_IDLE_TTL_MS) {
        this.relaySessions.delete(sessionId);
      }
    }
  }

  private handleRelayControlFrame(text: string, relayWs: RelayWs, daemonWs: RelayWs): boolean {
    let parsedUnknown: unknown;
    try {
      parsedUnknown = JSON.parse(text);
    } catch {
      return false;
    }

    const keyExchangeInit = parseRelayKeyExchangeInitFrame(parsedUnknown);
    if (keyExchangeInit) {
      this.handleKeyExchangeInit(keyExchangeInit, relayWs);
      return true;
    }

    if (!isRelayControlFrame(parsedUnknown)) {
      return false;
    }
    const parsed = parsedUnknown as RelayControlFrame;

    if (parsed.type === 'relay_status') {
      if (
        parsed.code === 'RELAY_REDIRECT' &&
        typeof parsed.relayWsBaseUrl === 'string' &&
        parsed.relayWsBaseUrl.trim().length > 0 &&
        parsed.relayWsBaseUrl !== this.relayEndpoint
      ) {
        this.relayEndpoint = parsed.relayWsBaseUrl;
        this.recordError('WEBSOCKET_ERROR', `relay redirect requested: ${parsed.relayWsBaseUrl}`);
        out.log(`[relay] redirecting daemon bridge to ${parsed.relayWsBaseUrl}`);
        closeQuietly(relayWs);
        closeQuietly(daemonWs);
        return true;
      }
      out.log(
        `[relay] status ${parsed.code ?? 'UNKNOWN'}: ${parsed.message ?? 'no additional detail'}`,
      );
      return true;
    }

    if (parsed.type === 'relay_key_update_required') {
      const session = this.relaySessions.get(parsed.sessionId);
      if (!session) {
        out.warn(`[relay] key update request ignored for unknown session ${parsed.sessionId}`);
        return true;
      }
      if (!Number.isInteger(parsed.nextEpoch) || parsed.nextEpoch !== session.epoch + 1) {
        out.warn(
          `[relay] key update request rejected for session ${parsed.sessionId}: invalid nextEpoch=${parsed.nextEpoch} expected=${session.epoch + 1}`,
        );
        return true;
      }
      session.keyRotationRequested = true;
      return true;
    }

    return true;
  }

  private handleKeyExchangeInit(init: RelayKeyExchangeInitFrame, relayWs: RelayWs): void {
    if (!this.daemonIdentity) {
      out.warn('[relay] key exchange init ignored: daemon identity not ready');
      return;
    }

    if (init.profile !== this.requiredProfile) {
      out.warn(
        `[relay] key exchange profile mismatch (got=${init.profile}, expected=${this.requiredProfile})`,
      );
      return;
    }

    let previous: RelaySessionState | undefined;
    let nextEpoch = 1;
    if (init.previousSessionId) {
      previous = this.relaySessions.get(init.previousSessionId);
      if (!previous) {
        out.warn(
          `[relay] key exchange rejected: unknown previous session ${init.previousSessionId}`,
        );
        return;
      }
      if (previous.profile !== init.profile) {
        out.warn(
          `[relay] key exchange rejected: profile mismatch for previous session ${init.previousSessionId}`,
        );
        return;
      }
      if (!previous.keyRotationRequested) {
        out.warn(
          `[relay] key exchange rejected: previous session ${init.previousSessionId} has no pending key rotation`,
        );
        return;
      }
      nextEpoch = previous.epoch + 1;
    }

    try {
      const derived = deriveSessionFromKeyExchange({
        init,
        daemonIdentity: this.daemonIdentity,
        nextEpoch,
        pairingSecret: this.requiredProfile === 'noise-ikpsk2' ? this.pairingSecret : undefined,
      });
      if (previous && init.previousSessionId) {
        this.relaySessions.delete(init.previousSessionId);
      }
      this.relaySessions.set(derived.session.sessionId, {
        ...derived.session,
        txSeq: 0,
        rxHighestSeq: 0,
        rxSeenSeq: new Set<number>(),
        lastActivityAt: Date.now(),
        keyRotationRequested: false,
      });
      if (relayWs.readyState === WebSocket.OPEN) {
        relayWs.send(JSON.stringify(derived.response));
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.recordError('KEY_EXCHANGE_FAILED', message);
      out.warn(`[relay] key exchange failed [KEY_EXCHANGE_FAILED]: ${message}`);
    }
  }

  private flushPendingOutbound(): void {
    const relayWs = this.relayWs;
    if (!relayWs || relayWs.readyState !== WebSocket.OPEN) return;
    while (this.pendingOutbound.length > 0 && relayWs.readyState === WebSocket.OPEN) {
      const next = this.pendingOutbound.shift();
      if (!next) break;
      this.pendingOutboundBytes -= Buffer.byteLength(next);
      this.sendToAllRelaySessions(relayWs, next);
    }
    if (this.pendingOutboundBytes < 0) this.pendingOutboundBytes = 0;
  }

  private async issueRelayToken(): Promise<{
    relayToken: string;
    profile: RelayHandshakeProfile;
    pairingSecret?: Buffer;
  }> {
    const url = `${this.options.relayServerUrl.replace(/\/+$/, '')}/api/poc/relay-token`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8_000);
    let res: Response;
    if (!this.daemonIssueToken) {
      throw new BridgeError('TOKEN_ISSUE_FAILED', 'missing daemon issue token');
    }
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          role: 'workspace-daemon',
          workspaceId: this.options.workspaceId,
          credential: this.daemonIssueToken,
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

    const tokenClaims = verifyRelayTokenClaims(parsed.relayToken, {
      issuer: this.options.relayTokenIssuer ?? 'viewport-server-poc',
      audience: this.options.relayTokenAudience ?? 'viewport-relay',
      signingKeys: this.relayTokenSigningKeys,
      clockSkewSec: this.options.relayTokenClockSkewSec ?? 30,
    });
    const profile = parseRelayHandshakeProfile(tokenClaims.e2eeProfile ?? 'noise-ik');
    if (!profile) {
      throw new BridgeError('TOKEN_RESPONSE_INVALID', 'missing/invalid e2eeProfile claim');
    }

    let pairingSecret: Buffer | undefined;
    try {
      pairingSecret = decodePairingSecret(tokenClaims.pairingSecret);
    } catch (error) {
      throw new BridgeError(
        'TOKEN_RESPONSE_INVALID',
        error instanceof Error ? error.message : String(error),
      );
    }
    if (profile === 'noise-ikpsk2' && !pairingSecret) {
      throw new BridgeError(
        'TOKEN_RESPONSE_INVALID',
        'noise-ikpsk2 requires pairingSecret in token claims',
      );
    }

    return {
      relayToken: parsed.relayToken,
      profile,
      pairingSecret,
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
