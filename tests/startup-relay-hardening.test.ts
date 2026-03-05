import { describe, expect, it } from 'vitest';
import { validateRelayRuntimeSecurity } from '../src/startup-relay-security.js';
import type { RuntimeLaunchConfig } from '../src/cli/supervisor-protocol.js';

function baseLaunch(overrides: Partial<RuntimeLaunchConfig> = {}): RuntimeLaunchConfig {
  return {
    listen: '127.0.0.1:7070',
    host: '127.0.0.1',
    port: 7070,
    version: '0.3.0',
    profile: 'relay',
    authEnabled: true,
    detached: false,
    relayEnabled: true,
    relayEndpoint: 'wss://relay.example.com/ws',
    relayServerUrl: 'https://api.example.com',
    relayWorkspaceId: 'workspace_demo',
    relayEnrollToken: 'enroll-token',
    relayTlsVerify: '1',
    relayTlsPins: ['AA:BB:CC'],
    relayTokenSigningKeys: {
      v1: 'relay_signing_key_material_0123456789',
    },
    relayTokenJwksUrl: 'https://getviewport.test/api/.well-known/jwks.json',
    ...overrides,
  };
}

describe('startup relay hardening', () => {
  it('requires relay token verification source for relay profile', () => {
    const config = baseLaunch({ relayTokenSigningKeys: undefined, relayTokenJwksUrl: undefined });
    expect(() => validateRelayRuntimeSecurity(config)).toThrow('relay token verification');
  });

  it('requires JWKS URL to be https when used in relay profile', () => {
    const config = baseLaunch({
      relayTokenSigningKeys: undefined,
      relayTokenJwksUrl: 'http://getviewport.test/api/.well-known/jwks.json',
    });
    expect(() => validateRelayRuntimeSecurity(config)).toThrow('relay token verification');
  });

  it('requires strict TLS verification in relay profile', () => {
    const config = baseLaunch({ relayTlsVerify: '0' });
    expect(() => validateRelayRuntimeSecurity(config)).toThrow('relay tls verify');
  });

  it('requires relay TLS pins for wss endpoints in relay profile', () => {
    const config = baseLaunch({ relayTlsPins: [] });
    expect(() => validateRelayRuntimeSecurity(config)).toThrow('relay tls pins');
  });

  it('allows local profile without strict relay controls', () => {
    const config = baseLaunch({
      profile: 'local',
      relayTokenSigningKeys: undefined,
      relayTlsVerify: '0',
      relayTlsPins: [],
    });
    expect(() => validateRelayRuntimeSecurity(config)).not.toThrow();
  });
});
