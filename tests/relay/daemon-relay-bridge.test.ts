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

function makeRelayJwt(
  payload: Record<string, unknown>,
  options?: { kid?: string; key?: string; tamperPayloadAfterSign?: Record<string, unknown> },
): string {
  const kid = options?.kid ?? 'v1';
  const key = options?.key ?? 'viewport-poc-signing-key-change-me';
  const header = toBase64Url(
    Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid }), 'utf8'),
  );
  const body = toBase64Url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signingInput = `${header}.${body}`;
  const signature = toBase64Url(crypto.createHmac('sha256', key).update(signingInput).digest());
  if (!options?.tamperPayloadAfterSign) {
    return `${signingInput}.${signature}`;
  }
  const tamperedBody = toBase64Url(
    Buffer.from(JSON.stringify(options.tamperPayloadAfterSign), 'utf8'),
  );
  return `${header}.${tamperedBody}.${signature}`;
}

function makeRelayJwtRs256(
  payload: Record<string, unknown>,
  options: {
    privateKeyPem: string;
    kid?: string;
    tamperPayloadAfterSign?: Record<string, unknown>;
  },
): string {
  const kid = options.kid ?? 'v1';
  const header = toBase64Url(
    Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid }), 'utf8'),
  );
  const body = toBase64Url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signingInput = `${header}.${body}`;
  const signature = toBase64Url(
    crypto.sign('RSA-SHA256', Buffer.from(signingInput, 'utf8'), options.privateKeyPem),
  );
  if (!options.tamperPayloadAfterSign) {
    return `${signingInput}.${signature}`;
  }
  const tamperedBody = toBase64Url(
    Buffer.from(JSON.stringify(options.tamperPayloadAfterSign), 'utf8'),
  );
  return `${header}.${tamperedBody}.${signature}`;
}

function rsaPublicJwkFromPrivatePem(privateKeyPem: string): { n: string; e: string } {
  const publicKey = crypto.createPublicKey(privateKeyPem);
  const exported = publicKey.export({ format: 'jwk' }) as { n?: string; e?: string };
  if (!exported?.n || !exported?.e) {
    throw new Error('failed to export RSA JWK');
  }
  return { n: exported.n, e: exported.e };
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
          relayToken: makeRelayJwt({
            role: 'workspace-daemon',
            workspaceId: 'workspace_demo',
            e2eeProfile: 'noise-ik',
            iss: 'viewport-server-poc',
            aud: 'viewport-relay',
            exp: Math.floor(Date.now() / 1000) + 120,
            iat: Math.floor(Date.now() / 1000) - 5,
            jti: 'jti-1',
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
    const relayToken = makeRelayJwt({
      role: 'workspace-daemon',
      workspaceId: 'workspace_demo',
      e2eeProfile: 'noise-ikpsk2',
      pairingSecret,
      iss: 'viewport-server-poc',
      aud: 'viewport-relay',
      exp: Math.floor(Date.now() / 1000) + 120,
      iat: Math.floor(Date.now() / 1000) - 5,
      jti: 'jti-2',
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

  it('issueRelayToken rejects relay tokens with invalid signature', async () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token-not-for-issue',
      issueToken: 'daemon-issue-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
      relayTokenSigningKeys: {
        v1: 'expected-signing-key',
      },
      relayTokenIssuer: 'viewport-server-poc',
      relayTokenAudience: 'viewport-relay',
    });

    const validPayload = {
      role: 'workspace-daemon',
      workspaceId: 'workspace_demo',
      e2eeProfile: 'noise-ik',
      iss: 'viewport-server-poc',
      aud: 'viewport-relay',
      exp: Math.floor(Date.now() / 1000) + 120,
      iat: Math.floor(Date.now() / 1000) - 5,
      jti: 'jti-invalid-signature',
    };

    const tamperedToken = makeRelayJwt(validPayload, {
      key: 'expected-signing-key',
      tamperPayloadAfterSign: { ...validPayload, e2eeProfile: 'noise-ikpsk2' },
    });

    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: true,
          relayToken: tamperedToken,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ) as typeof fetch;

    await expect((bridge as any).issueRelayToken()).rejects.toThrow('signature');
  });

  it('issueRelayToken rejects relay tokens with wrong issuer', async () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token-not-for-issue',
      issueToken: 'daemon-issue-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
      relayTokenSigningKeys: {
        v1: 'expected-signing-key',
      },
      relayTokenIssuer: 'viewport-server-poc',
      relayTokenAudience: 'viewport-relay',
    });

    const relayToken = makeRelayJwt(
      {
        role: 'workspace-daemon',
        workspaceId: 'workspace_demo',
        e2eeProfile: 'noise-ik',
        iss: 'other-issuer',
        aud: 'viewport-relay',
        exp: Math.floor(Date.now() / 1000) + 120,
        iat: Math.floor(Date.now() / 1000) - 5,
        jti: 'jti-wrong-issuer',
      },
      { key: 'expected-signing-key' },
    );

    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: true,
          relayToken,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ) as typeof fetch;

    await expect((bridge as any).issueRelayToken()).rejects.toThrow('issuer');
  });

  it('issueRelayToken validates RS256 relay token signatures using JWKS', async () => {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs1' }).toString();
    const jwk = rsaPublicJwkFromPrivatePem(privateKeyPem);

    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token-not-for-issue',
      issueToken: 'daemon-issue-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
      relayTokenIssuer: 'viewport-server-poc',
      relayTokenAudience: 'viewport-relay',
      relayTokenJwksUrl: 'https://server.test/api/.well-known/jwks.json',
    });

    const relayToken = makeRelayJwtRs256(
      {
        role: 'workspace-daemon',
        workspaceId: 'workspace_demo',
        e2eeProfile: 'noise-ik',
        iss: 'viewport-server-poc',
        aud: 'viewport-relay',
        exp: Math.floor(Date.now() / 1000) + 120,
        iat: Math.floor(Date.now() / 1000) - 5,
        jti: 'jti-rs256',
      },
      { privateKeyPem, kid: 'v1' },
    );

    global.fetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ok: true,
            relayToken,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            keys: [
              {
                kty: 'RSA',
                kid: 'v1',
                alg: 'RS256',
                n: jwk.n,
                e: jwk.e,
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      ) as typeof fetch;

    const issued = await (bridge as any).issueRelayToken();
    expect(issued.profile).toBe('noise-ik');
    expect((global.fetch as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(2);
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

  it('supports overriding key rotation threshold for test harnesses', () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
      keyRotateAfterMessages: 2,
    });

    const sent: string[] = [];
    const relayWs = {
      send(payload: string): void {
        sent.push(payload);
      },
      readyState: 1,
    };

    (bridge as any).relaySessions.set('rs_override', {
      key: Buffer.alloc(32, 7),
      profile: 'noise-ik',
      sessionId: 'rs_override',
      epoch: 1,
      txSeq: 1,
      rxHighestSeq: 0,
      rxSeenSeq: new Set<number>(),
      lastActivityAt: Date.now(),
      keyRotationRequested: false,
    });

    (bridge as any).sendToAllRelaySessions(relayWs, JSON.stringify({ type: 'ping' }));
    expect(sent.length).toBe(2);
    expect(JSON.parse(sent[1] ?? '{}')).toMatchObject({
      type: 'relay_key_update_required',
      sessionId: 'rs_override',
      nextEpoch: 2,
      reason: 'message_threshold',
    });
  });

  it('rejects key exchange rekey requests for unknown previous session ids', () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
    });
    const daemon = crypto.createECDH('prime256v1');
    const daemonPublic = daemon.generateKeys();
    const daemonPrivate = daemon.getPrivateKey();
    (bridge as any).daemonIdentity = {
      algorithm: 'p256',
      publicKey: toBase64Url(daemonPublic),
      privateKey: toBase64Url(daemonPrivate),
    };
    (bridge as any).requiredProfile = 'noise-ik';

    const client = crypto.createECDH('prime256v1');
    const clientPublic = client.generateKeys();
    const clientPrivate = client.getPrivateKey();
    const requestId = 'kex-unknown-previous';
    const clientNonce = toBase64Url(crypto.randomBytes(16));
    const clientPublicKey = toBase64Url(clientPublic);

    const init = parseRelayKeyExchangeInitFrame({
      type: 'relay_key_exchange_init',
      version: 2,
      profile: 'noise-ik',
      requestId,
      clientPublicKey,
      clientNonce,
      previousSessionId: 'missing-session-id',
      clientProof: deriveClientInitProof({
        daemonPublicKey: toBase64Url(daemonPublic),
        clientPrivateKey: clientPrivate,
        profile: 'noise-ik',
        requestId,
        clientPublicKey,
        clientNonce,
        previousSessionId: 'missing-session-id',
      }),
    });
    expect(init).toBeTruthy();

    const relayWs = {
      readyState: 1,
      send: vi.fn(),
    };
    (bridge as any).handleKeyExchangeInit(init!, relayWs);
    expect((bridge as any).relaySessions.size).toBe(0);
    expect(relayWs.send).not.toHaveBeenCalled();
  });

  it('validates relay_key_update_required epoch transitions before enabling rekey', () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
    });

    (bridge as any).relaySessions.set('session-1', {
      key: Buffer.alloc(32, 9),
      profile: 'noise-ik',
      sessionId: 'session-1',
      epoch: 2,
      txSeq: 10,
      rxHighestSeq: 10,
      rxSeenSeq: new Set<number>(),
      lastActivityAt: Date.now(),
      keyRotationRequested: false,
    });

    const handledInvalid = (bridge as any).handleRelayControlFrame(
      JSON.stringify({
        type: 'relay_key_update_required',
        sessionId: 'session-1',
        nextEpoch: 4,
        reason: 'message_threshold',
      }),
      { readyState: 1, close: vi.fn() },
      { readyState: 1, close: vi.fn() },
    );

    expect(handledInvalid).toBe(true);
    expect((bridge as any).relaySessions.get('session-1')?.keyRotationRequested).toBe(false);

    const handledValid = (bridge as any).handleRelayControlFrame(
      JSON.stringify({
        type: 'relay_key_update_required',
        sessionId: 'session-1',
        nextEpoch: 3,
        reason: 'message_threshold',
      }),
      { readyState: 1, close: vi.fn() },
      { readyState: 1, close: vi.fn() },
    );

    expect(handledValid).toBe(true);
    expect((bridge as any).relaySessions.get('session-1')?.keyRotationRequested).toBe(true);
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
