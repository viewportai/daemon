import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { computeBackoffMs } from '../../src/relay/bridge-backoff.js';
import {
  CIRCUIT_BREAKER_MS,
  RELAY_KEY_ROTATE_AFTER_MESSAGES,
  RELAY_REPLAY_WINDOW,
} from '../../src/relay/bridge-constants.js';
import {
  decryptEnvelope,
  encryptEnvelope,
  fromBase64Url,
  parseRelayEnvelope,
  toBase64Url,
} from '../../src/relay/bridge-crypto.js';
import {
  deriveSessionFromKeyExchange,
  parseRelayKeyExchangeInitFrame,
} from '../../src/relay/bridge-key-exchange.js';
import { DaemonRelayBridge } from '../../src/relay/daemon-relay-bridge.js';

function deriveClientSessionKey(params: {
  daemonPublicKey: string;
  clientPrivateKey: Buffer;
  clientNonce: Buffer;
  daemonNonce: Buffer;
  profile: 'noise-ik' | 'noise-ikpsk2';
  sessionId: string;
  epoch: number;
  pairingSecret?: Buffer;
}): Buffer {
  const clientEcdh = crypto.createECDH('prime256v1');
  clientEcdh.setPrivateKey(params.clientPrivateKey);
  const sharedSecret = clientEcdh.computeSecret(fromBase64Url(params.daemonPublicKey));
  const ikm =
    params.profile === 'noise-ikpsk2' && params.pairingSecret
      ? Buffer.concat([sharedSecret, params.pairingSecret])
      : sharedSecret;
  const salt = Buffer.concat([params.clientNonce, params.daemonNonce]);
  const info = Buffer.from(
    `viewport-relay-session-v2|${params.profile}|${params.sessionId}|${params.epoch}`,
    'utf8',
  );
  const key = crypto.hkdfSync('sha256', ikm, salt, info, 32);
  return Buffer.isBuffer(key) ? key : Buffer.from(key);
}

function deriveClientProof(params: {
  key: Buffer;
  requestId: string;
  profile: 'noise-ik' | 'noise-ikpsk2';
  clientPublicKey: string;
  daemonPublicKey: string;
  clientNonce: string;
  daemonNonce: string;
  sessionId: string;
  epoch: number;
}): string {
  const transcript = Buffer.from(
    [
      'viewport-relay-transcript-v2',
      params.requestId,
      params.profile,
      params.clientPublicKey,
      params.daemonPublicKey,
      params.clientNonce,
      params.daemonNonce,
      params.sessionId,
      String(params.epoch),
    ].join('|'),
    'utf8',
  );
  return toBase64Url(
    crypto.createHmac('sha256', params.key).update(transcript).digest().subarray(0, 16),
  );
}

function deriveClientInitProof(params: {
  daemonPublicKey: string;
  clientPrivateKey: Buffer;
  profile: 'noise-ik' | 'noise-ikpsk2';
  requestId: string;
  clientPublicKey: string;
  clientNonce: string;
  previousSessionId?: string;
  pairingSecret?: Buffer;
}): string {
  const clientEcdh = crypto.createECDH('prime256v1');
  clientEcdh.setPrivateKey(params.clientPrivateKey);
  const sharedSecret = clientEcdh.computeSecret(fromBase64Url(params.daemonPublicKey));
  const ikm =
    params.profile === 'noise-ikpsk2' && params.pairingSecret
      ? Buffer.concat([sharedSecret, params.pairingSecret])
      : sharedSecret;

  const info = Buffer.from(
    [
      'viewport-relay-kex-init-v1',
      params.requestId,
      params.profile,
      params.clientPublicKey,
      params.daemonPublicKey,
      params.clientNonce,
      params.previousSessionId ?? '',
    ].join('|'),
    'utf8',
  );
  const salt = fromBase64Url(params.clientNonce);
  const key = crypto.hkdfSync('sha256', ikm, salt, info, 32);
  const normalizedKey = Buffer.isBuffer(key) ? key : Buffer.from(key);
  return toBase64Url(
    crypto
      .createHmac('sha256', normalizedKey)
      .update('client-proof', 'utf8')
      .digest()
      .subarray(0, 16),
  );
}

function makeUnsignedJwt(payload: Record<string, unknown>): string {
  const header = toBase64Url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }), 'utf8'));
  const body = toBase64Url(Buffer.from(JSON.stringify(payload), 'utf8'));
  return `${header}.${body}.signature`;
}

describe('daemon relay bridge helpers', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('computeBackoffMs is bounded and positive', () => {
    const values = Array.from({ length: 15 }, (_, i) => computeBackoffMs(i + 1));
    expect(values.every((v) => v >= 1000)).toBe(true);
    expect(values.every((v) => v <= 30_000)).toBe(true);
  });

  it('encrypt/decrypt envelope round-trips with v2 metadata-bound aad', () => {
    const key = Buffer.alloc(32, 7);
    const plaintext = JSON.stringify({ hello: 'world', n: 42 });
    const encoded = encryptEnvelope(key, plaintext, {
      profile: 'noise-ik',
      sessionId: 'rs_test',
      epoch: 1,
      seq: 1,
    });
    const envelope = parseRelayEnvelope(encoded);
    const decrypted = decryptEnvelope(key, envelope);
    expect(decrypted).toBe(plaintext);
  });

  it('parseRelayEnvelope rejects invalid envelope shape', () => {
    expect(() => parseRelayEnvelope(JSON.stringify({ type: 'x' }))).toThrow(
      'Invalid relay envelope',
    );
  });

  it('base64url helpers round-trip', () => {
    const original = Buffer.from('viewport-relay-key-material');
    const encoded = toBase64Url(original);
    const decoded = fromBase64Url(encoded);
    expect(decoded.equals(original)).toBe(true);
  });

  it('issueRelayToken rejects missing relayToken payloads', async () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token',
      issueToken: 'daemon-issue-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
    });

    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: true,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ) as typeof fetch;

    await expect((bridge as any).issueRelayToken()).rejects.toThrow('issue relay token failed');
  });

  it('registerDaemonPublicKey requires daemonIssueToken in response', async () => {
    const daemon = crypto.createECDH('prime256v1');
    const daemonPublic = daemon.generateKeys();
    const daemonPrivate = daemon.getPrivateKey();

    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
    });
    (bridge as any).daemonIdentity = {
      algorithm: 'p256',
      publicKey: toBase64Url(daemonPublic),
      privateKey: toBase64Url(daemonPrivate),
    };

    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    ) as typeof fetch;

    await expect((bridge as any).registerDaemonPublicKey()).rejects.toThrow(
      'daemon issue token was missing',
    );
  });

  it('issueRelayToken uses daemon issue token credential (not enroll token)', async () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token-not-for-issue',
      issueToken: 'daemon-issue-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
    });

    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: true,
          relayToken: makeUnsignedJwt({
            role: 'workspace-daemon',
            workspaceId: 'workspace_demo',
            e2eeProfile: 'noise-ik',
          }),
          claims: {
            e2eeProfile: 'noise-ik',
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );
    global.fetch = fetchMock;

    await (bridge as any).issueRelayToken();
    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body ?? '{}')) as {
      credential?: string;
    };
    expect(body.credential).toBe('daemon-issue-token');
  });

  it('issueRelayToken derives profile from relay token payload, not response claims object', async () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token-not-for-issue',
      issueToken: 'daemon-issue-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
    });

    const pairingSecret = toBase64Url(crypto.randomBytes(32));
    const relayToken = makeUnsignedJwt({
      role: 'workspace-daemon',
      workspaceId: 'workspace_demo',
      e2eeProfile: 'noise-ikpsk2',
      pairingSecret,
    });

    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: true,
          relayToken,
          claims: {
            e2eeProfile: 'noise-ik',
            pairingSecret: null,
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ) as typeof fetch;

    const issued = await (bridge as any).issueRelayToken();
    expect(issued.profile).toBe('noise-ikpsk2');
    expect(toBase64Url(issued.pairingSecret)).toBe(pairingSecret);
  });

  it('deriveSessionFromKeyExchange returns proof verifiable by client for noise-ik', () => {
    const client = crypto.createECDH('prime256v1');
    const clientPublic = client.generateKeys();
    const clientPrivate = client.getPrivateKey();

    const daemon = crypto.createECDH('prime256v1');
    const daemonPublic = daemon.generateKeys();
    const daemonPrivate = daemon.getPrivateKey();

    const requestId = 'kex-1';
    const clientNonce = crypto.randomBytes(16);
    const clientPublicKey = toBase64Url(clientPublic);

    const init = parseRelayKeyExchangeInitFrame({
      type: 'relay_key_exchange_init',
      version: 2,
      profile: 'noise-ik',
      requestId,
      clientPublicKey,
      clientNonce: toBase64Url(clientNonce),
      clientProof: deriveClientInitProof({
        daemonPublicKey: toBase64Url(daemonPublic),
        clientPrivateKey: clientPrivate,
        profile: 'noise-ik',
        requestId,
        clientPublicKey,
        clientNonce: toBase64Url(clientNonce),
      }),
    });
    expect(init).toBeTruthy();

    const derived = deriveSessionFromKeyExchange({
      init: init!,
      daemonIdentity: {
        algorithm: 'p256',
        publicKey: toBase64Url(daemonPublic),
        privateKey: toBase64Url(daemonPrivate),
      },
      nextEpoch: 1,
    });

    const expectedKey = deriveClientSessionKey({
      daemonPublicKey: derived.response.daemonPublicKey,
      clientPrivateKey: clientPrivate,
      clientNonce,
      daemonNonce: fromBase64Url(derived.response.daemonNonce),
      profile: derived.response.profile,
      sessionId: derived.response.sessionId,
      epoch: derived.response.epoch,
    });
    expect(expectedKey.equals(derived.session.key)).toBe(true);

    const expectedProof = deriveClientProof({
      key: expectedKey,
      requestId,
      profile: derived.response.profile,
      clientPublicKey: toBase64Url(clientPublic),
      daemonPublicKey: derived.response.daemonPublicKey,
      clientNonce: toBase64Url(clientNonce),
      daemonNonce: derived.response.daemonNonce,
      sessionId: derived.response.sessionId,
      epoch: derived.response.epoch,
    });
    expect(expectedProof).toBe(derived.response.proof);
  });

  it('deriveSessionFromKeyExchange requires pairing secret for noise-ikpsk2', () => {
    const client = crypto.createECDH('prime256v1');
    const clientPublic = client.generateKeys();

    const daemon = crypto.createECDH('prime256v1');
    const daemonPublic = daemon.generateKeys();
    const daemonPrivate = daemon.getPrivateKey();

    const init = parseRelayKeyExchangeInitFrame({
      type: 'relay_key_exchange_init',
      version: 2,
      profile: 'noise-ikpsk2',
      requestId: 'kex-psk',
      clientPublicKey: toBase64Url(clientPublic),
      clientNonce: toBase64Url(crypto.randomBytes(16)),
      clientProof: 'test-proof',
    });
    expect(init).toBeTruthy();

    expect(() =>
      deriveSessionFromKeyExchange({
        init: init!,
        daemonIdentity: {
          algorithm: 'p256',
          publicKey: toBase64Url(daemonPublic),
          privateKey: toBase64Url(daemonPrivate),
        },
        nextEpoch: 1,
      }),
    ).toThrow('pairing secret required for noise-ikpsk2');
  });

  it('opens circuit breaker window after repeated token issue failures', async () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'bad-token',
      issueToken: 'daemon-issue-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
    });

    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: false,
          reason: 'INVALID_WORKSPACE_ENROLL_TOKEN',
        }),
        { status: 403, headers: { 'content-type': 'application/json' } },
      ),
    ) as typeof fetch;

    for (let i = 0; i < 5; i += 1) {
      await expect((bridge as any).issueRelayToken()).rejects.toThrow();
      (bridge as any).consecutiveIssueFailures += 1;
    }
    (bridge as any).circuitOpenUntilMs = Date.now() + CIRCUIT_BREAKER_MS;

    const status = bridge.getStatus();
    expect(status.circuitOpenUntil).toBeDefined();
  });

  it('requests key rotation after message threshold and dedupes replay sequence', () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
    });

    const sent: string[] = [];
    const relayWs = {
      send(payload: string): void {
        sent.push(payload);
      },
      readyState: 1,
    };

    const session = {
      key: Buffer.alloc(32, 4),
      profile: 'noise-ik' as const,
      sessionId: 'rs_rotate',
      epoch: 1,
      txSeq: RELAY_KEY_ROTATE_AFTER_MESSAGES - 1,
      rxHighestSeq: 0,
      rxSeenSeq: new Set<number>(),
      lastActivityAt: Date.now(),
      keyRotationRequested: false,
    };
    (bridge as any).relaySessions.set(session.sessionId, session);
    (bridge as any).sendToAllRelaySessions(relayWs, JSON.stringify({ type: 'ping' }));

    expect(sent.length).toBe(2);
    expect(JSON.parse(sent[1] ?? '{}')).toMatchObject({
      type: 'relay_key_update_required',
      sessionId: 'rs_rotate',
      nextEpoch: 2,
      reason: 'message_threshold',
    });
    expect(session.keyRotationRequested).toBe(true);

    expect((bridge as any).acceptInboundSeq(session, 1)).toBe(true);
    expect((bridge as any).acceptInboundSeq(session, 1)).toBe(false);
    expect((bridge as any).acceptInboundSeq(session, RELAY_REPLAY_WINDOW + 10)).toBe(false);
  });

  it('bounds pending outbound queue by bytes as well as message count', () => {
    class FakeWs extends EventEmitter {
      readyState = 3;
      send = vi.fn();
      close = vi.fn();
      terminate = vi.fn();
    }

    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
      maxPendingOutbound: 100,
      maxPendingOutboundBytes: 20,
    });

    const daemonWs = new FakeWs();
    const relayWs = new FakeWs();
    (bridge as any).installSocketHandlers(daemonWs, relayWs);

    daemonWs.emit('message', Buffer.from('1234567890', 'utf8'));
    daemonWs.emit('message', Buffer.from('abcdefghij', 'utf8'));
    daemonWs.emit('message', Buffer.from('KLMNOPQRST', 'utf8'));

    expect((bridge as any).pendingOutbound).toEqual(['abcdefghij', 'KLMNOPQRST']);
    expect((bridge as any).pendingOutboundBytes).toBe(20);
  });

  it('parseRelayKeyExchangeInitFrame rejects missing client proof', () => {
    expect(
      parseRelayKeyExchangeInitFrame({
        type: 'relay_key_exchange_init',
        version: 2,
        profile: 'noise-ik',
        requestId: 'kex-missing-proof',
        clientPublicKey: 'abc',
        clientNonce: 'def',
      }),
    ).toBeNull();
  });

  it('deriveSessionFromKeyExchange rejects invalid client proof', () => {
    const client = crypto.createECDH('prime256v1');
    const clientPublic = client.generateKeys();
    const clientPrivate = client.getPrivateKey();

    const daemon = crypto.createECDH('prime256v1');
    const daemonPublic = daemon.generateKeys();
    const daemonPrivate = daemon.getPrivateKey();

    const requestId = 'kex-invalid-proof';
    const clientNonce = toBase64Url(crypto.randomBytes(16));
    const clientPublicKey = toBase64Url(clientPublic);

    const init = parseRelayKeyExchangeInitFrame({
      type: 'relay_key_exchange_init',
      version: 2,
      profile: 'noise-ik',
      requestId,
      clientPublicKey,
      clientNonce,
      clientProof: deriveClientInitProof({
        daemonPublicKey: toBase64Url(daemonPublic),
        clientPrivateKey: clientPrivate,
        profile: 'noise-ik',
        requestId,
        clientPublicKey,
        clientNonce,
      }),
    });

    expect(init).toBeTruthy();

    expect(() =>
      deriveSessionFromKeyExchange({
        init: {
          ...init!,
          clientProof: toBase64Url(crypto.randomBytes(16)),
        },
        daemonIdentity: {
          algorithm: 'p256',
          publicKey: toBase64Url(daemonPublic),
          privateKey: toBase64Url(daemonPrivate),
        },
        nextEpoch: 1,
      }),
    ).toThrow('invalid client key exchange proof');
  });
});
