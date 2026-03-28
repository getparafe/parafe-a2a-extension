import { describe, it, expect } from 'vitest';
import {
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
} from '../../src/index.js';

describe('error classes', () => {
  it('MissingParafeExtensionError has correct code and name', () => {
    const err = new MissingParafeExtensionError(['agent-id']);
    expect(err.code).toBe('MISSING_PARAFE_EXTENSION');
    expect(err.name).toBe('MissingParafeExtensionError');
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toContain('agent-id');
  });

  it('InvalidConsentTokenError has correct code and name', () => {
    const err = new InvalidConsentTokenError('bad signature');
    expect(err.code).toBe('INVALID_CONSENT_TOKEN');
    expect(err.name).toBe('InvalidConsentTokenError');
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toContain('bad signature');
  });

  it('InvalidConsentTokenError works without detail', () => {
    const err = new InvalidConsentTokenError();
    expect(err.code).toBe('INVALID_CONSENT_TOKEN');
    expect(err.message).toContain('invalid');
  });

  it('ExpiredConsentTokenError has correct code, name, and expiredAt', () => {
    const date = new Date('2026-03-28T12:00:00Z');
    const err = new ExpiredConsentTokenError(date);
    expect(err.code).toBe('EXPIRED_CONSENT_TOKEN');
    expect(err.name).toBe('ExpiredConsentTokenError');
    expect(err.expiredAt).toEqual(date);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toContain('2026-03-28');
  });

  it('ScopeViolationError has correct code, name, and scope info', () => {
    const err = new ScopeViolationError('delete_data', ['read_data', 'write_data']);
    expect(err.code).toBe('SCOPE_VIOLATION');
    expect(err.name).toBe('ScopeViolationError');
    expect(err.requiredScope).toBe('delete_data');
    expect(err.grantedScopes).toEqual(['read_data', 'write_data']);
    expect(err).toBeInstanceOf(Error);
  });

  it('ScopeViolationError accepts array of required scopes', () => {
    const err = new ScopeViolationError(['a', 'b'], ['read_data']);
    expect(err.requiredScope).toEqual(['a', 'b']);
    expect(err.message).toContain('a, b');
  });

  it('all errors are catchable as Error', () => {
    const errors = [
      new MissingParafeExtensionError(['field']),
      new InvalidConsentTokenError(),
      new ExpiredConsentTokenError(new Date()),
      new ScopeViolationError('x', []),
    ];

    for (const err of errors) {
      expect(err).toBeInstanceOf(Error);
    }
  });
});
