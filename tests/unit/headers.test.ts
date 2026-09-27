import { describe, it, expect } from 'vitest';
import { activationHeaders, isParafeActivated, PARAFE_EXTENSION_URI } from '../../src/index.js';

describe('activationHeaders', () => {
  it('A2A 1.0: A2A-Version and A2A-Extensions', () => {
    expect(activationHeaders()).toEqual({ 'A2A-Version': '1.0', 'A2A-Extensions': PARAFE_EXTENSION_URI });
  });

  it('A2A 0.3: X-A2A-Extensions and no version header', () => {
    expect(activationHeaders('0.3')).toEqual({ 'X-A2A-Extensions': PARAFE_EXTENSION_URI });
  });

  it('adds other extensions without duplicating Parafe', () => {
    expect(activationHeaders('1.0', ['https://example.com/ext/x/v1', PARAFE_EXTENSION_URI])['A2A-Extensions']).toBe(
      `${PARAFE_EXTENSION_URI},https://example.com/ext/x/v1`
    );
  });
});

describe('isParafeActivated', () => {
  it('reads A2A-Extensions in any casing, among other URIs', () => {
    expect(isParafeActivated({ 'a2a-extensions': `https://example.com/ext/x/v1, ${PARAFE_EXTENSION_URI}` })).toBe(true);
  });

  it('reads the A2A 0.3 X-A2A-Extensions header', () => {
    expect(isParafeActivated({ 'X-A2A-Extensions': PARAFE_EXTENSION_URI })).toBe(true);
  });

  it('reads array-valued headers', () => {
    expect(isParafeActivated({ 'a2a-extensions': ['https://example.com/ext/x/v1', PARAFE_EXTENSION_URI] })).toBe(true);
  });

  it('reads a Fetch Headers object', () => {
    expect(isParafeActivated(new Headers({ 'A2A-Extensions': PARAFE_EXTENSION_URI }))).toBe(true);
  });

  it('is false without the header, or with only other extensions', () => {
    expect(isParafeActivated({})).toBe(false);
    expect(isParafeActivated({ 'A2A-Extensions': 'https://example.com/ext/x/v1' })).toBe(false);
  });

  it('does not match a URI that merely starts with the Parafe URI', () => {
    expect(isParafeActivated({ 'A2A-Extensions': `${PARAFE_EXTENSION_URI}-beta` })).toBe(false);
  });
});
