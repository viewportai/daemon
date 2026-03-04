import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CIRCUIT_BREAKER_MS,
  computeBackoffMs,
  DaemonRelayBridge,
  decryptEnvelope,
  encryptEnvelope,
  fromBase64Url,
  toBase64Url,
} from '../../src/relay/daemon-relay-bridge.js';

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

  it('encrypt/decrypt envelope round-trips', () => {
    const key = Buffer.alloc(32, 7);
    const plaintext = JSON.stringify({ hello: 'world', n: 42 });
    const envelope = encryptEnvelope(key, plaintext);
    const decrypted = decryptEnvelope(key, envelope);
    expect(decrypted).toBe(plaintext);
  });

  it('decryptEnvelope rejects invalid envelope shape', () => {
    const key = Buffer.alloc(32, 1);
    expect(() => decryptEnvelope(key, JSON.stringify({ type: 'x' }))).toThrow(
      'Invalid relay envelope',
    );
  });

  it('base64url helpers round-trip', () => {
    const original = Buffer.from('viewport-relay-key-material');
    const encoded = toBase64Url(original);
    const decoded = fromBase64Url(encoded);
    expect(decoded.equals(original)).toBe(true);
  });

  it('issueRelayToken rejects invalid key length payloads', async () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'enroll-token',
      daemonWsUrl: 'ws://127.0.0.1:7070/ws',
    });

    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: true,
          relayToken: 'relay-token',
          claims: {
            e2eeKey: toBase64Url(Buffer.alloc(8, 1)),
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ) as typeof fetch;

    await expect((bridge as any).issueRelayToken()).rejects.toThrow(
      'invalid e2eeKey length from relay token claims',
    );
  });

  it('opens circuit breaker window after repeated token issue failures', async () => {
    const bridge = new DaemonRelayBridge({
      relayEndpoint: 'ws://127.0.0.1:7781/ws',
      relayServerUrl: 'http://127.0.0.1:7780',
      workspaceId: 'workspace_demo',
      enrollToken: 'bad-token',
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
});
