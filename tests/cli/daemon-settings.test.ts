import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

describe('daemon settings resolution', () => {
  let homeDir = '';
  let originalArgv: string[] = [];

  beforeEach(async () => {
    originalArgv = process.argv.slice();
    homeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'viewport-daemon-settings-'));
    process.env['VIEWPORT_HOME'] = homeDir;
    delete process.env['VPD_LISTEN'];
    delete process.env['VPD_ALLOWED_HOSTS'];
    delete process.env['VPD_ALLOWED_ORIGINS'];
    delete process.env['VPD_PROFILE'];
    delete process.env['VPD_AUTH'];
  });

  afterEach(async () => {
    process.argv = originalArgv;
    delete process.env['VIEWPORT_HOME'];
    delete process.env['VPD_LISTEN'];
    delete process.env['VPD_ALLOWED_HOSTS'];
    delete process.env['VPD_ALLOWED_ORIGINS'];
    delete process.env['VPD_PROFILE'];
    delete process.env['VPD_AUTH'];
    await fs.rm(homeDir, { recursive: true, force: true });
    vi.resetModules();
  });

  it('applies precedence cli > env > config', async () => {
    await fs.mkdir(homeDir, { recursive: true });
    await fs.writeFile(
      path.join(homeDir, 'config.json'),
      JSON.stringify({
        daemon: {
          listen: '127.0.0.1:7000',
          profile: 'local',
          allowedHosts: ['config.test'],
          allowedOrigins: ['origin.config.test'],
        },
      }),
      'utf-8',
    );

    process.env['VPD_LISTEN'] = '127.0.0.1:8000';
    process.env['VPD_ALLOWED_HOSTS'] = 'env.test';
    process.env['VPD_ALLOWED_ORIGINS'] = 'origin.env.test';

    process.argv = [
      'node',
      'vpd',
      'start',
      '--listen',
      '127.0.0.1:9000',
      '--allowed-hosts',
      'cli.test',
      '--allowed-origins',
      'origin.cli.test',
    ];

    const { resolveDaemonSettingsFromSources } = await import('../../src/cli/daemon-settings.js');
    const resolved = await resolveDaemonSettingsFromSources();

    expect(resolved.launch.listen).toBe('127.0.0.1:9000');
    expect(resolved.launch.host).toBe('127.0.0.1');
    expect(resolved.launch.port).toBe(9000);
    expect(resolved.launch.allowedHostsRaw).toBe('config.test,env.test,cli.test');
    expect(resolved.launch.allowedOriginsRaw).toBe(
      'origin.config.test,origin.env.test,origin.cli.test',
    );
  });

  it('supports unix socket listen mode', async () => {
    process.argv = ['node', 'vpd', 'start', '--listen', './runtime/daemon.sock'];
    const { resolveDaemonSettingsFromSources } = await import('../../src/cli/daemon-settings.js');
    const resolved = await resolveDaemonSettingsFromSources();

    expect(resolved.launch.socketPath).toBe(path.resolve('./runtime/daemon.sock'));
    expect(resolved.launch.listen).toBe(`unix://${path.resolve('./runtime/daemon.sock')}`);
    expect(resolved.launch.port).toBe(0);
    expect(resolved.launch.host).toBe('127.0.0.1');
  });

  it('resolves profile/auth precedence as cli > env > config', async () => {
    await fs.mkdir(homeDir, { recursive: true });
    await fs.writeFile(
      path.join(homeDir, 'config.json'),
      JSON.stringify({
        daemon: {
          listen: '0.0.0.0:7070',
          profile: 'lan',
          authEnabled: false,
          allowedHosts: ['config.example.test'],
        },
      }),
      'utf-8',
    );

    process.env['VPD_PROFILE'] = 'relay';
    process.env['VPD_AUTH'] = 'false';
    process.argv = [
      'node',
      'vpd',
      'start',
      '--profile',
      'lan',
      '--auth',
      '--allowed-hosts',
      'cli.example.test',
    ];

    const { resolveDaemonSettingsFromSources } = await import('../../src/cli/daemon-settings.js');
    const resolved = await resolveDaemonSettingsFromSources();

    expect(resolved.launch.profile).toBe('lan');
    expect(resolved.launch.authEnabled).toBe(true);
    expect(resolved.launch.allowedHostsRaw).toBe('config.example.test,cli.example.test');
  });
});
