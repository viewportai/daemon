import { describe, it, expect } from 'vitest';
import { decodeAutoRegisterEntry } from '../src/startup.js';

describe('startup auto-register decode', () => {
  it('preserves path hyphens encoded as double-dash', () => {
    expect(decodeAutoRegisterEntry('-Users-dev--user-my--project')).toBe(
      '/Users/dev-user/my-project',
    );
  });

  it('preserves absolute leading slash semantics for non-prefixed entries', () => {
    expect(decodeAutoRegisterEntry('Users-dev-work')).toBe('/Users/dev/work');
  });
});
