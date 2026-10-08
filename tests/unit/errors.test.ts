import { describe, it, expect } from 'vitest';
import {
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
  MalformedParafeDataError,
  WrongAudienceError,
  isParafeError,
} from '../../src/index.js';

describe('error classes', () => {
  it('MissingParafeExtensionError has correct code and name (array form)', () => {
    const err = new MissingParafeExtensionError(['agent-id']);
    expect(err.code).toBe('MISSING_PARAFE_EXTENSION');
    expect(err.name).toBe('MissingParafeExtensionError');
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toContain('agent-id');
  });

  it('MissingParafeExtensionError works with string detail', () => {
    const err = new MissingParafeExtensionError('No consent token DataPart found');
    expect(err.code).toBe('MISSING_PARAFE_EXTENSION');
    expect(err.message).toContain('No consent token');
  });

  it('InvalidConsentTokenError has correct code and name', () => {
    const err = new InvalidConsentTokenError('bad signature');
    expect(err.code).toBe('INVALID_CONSENT_TOKEN');
    expect(err.name).toBe('InvalidConsentTokenError');
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toContain('bad signature');
  });

  it('InvalidConsentTokenError advises checking the token by default; other advice, or none, when given', () => {
    expect(new InvalidConsentTokenError('bad signature').message).toMatch(/bad signature.*tampered with\.$/);
    expect(new InvalidConsentTokenError('its session is over.', 'Start a new handshake.').message)
      .toBe('Parafe consent token is invalid: its session is over. Start a new handshake.');
    expect(new InvalidConsentTokenError('agent revoked.', '').message).toBe('Parafe consent token is invalid: agent revoked.');
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

  it('ScopeViolationError uses a custom message when given', () => {
    const err = new ScopeViolationError('order', ['read'], 'Scope "order" requires "attested".');
    expect(err.message).toBe('Scope "order" requires "attested".');
    expect(err.code).toBe('SCOPE_VIOLATION');
  });

  it('MalformedParafeDataError has correct code, name, and member', () => {
    const err = new MalformedParafeDataError('handshake_challenge', 'missing fields: challenge');
    expect(err.code).toBe('MALFORMED_PARAFE_DATA');
    expect(err.name).toBe('MalformedParafeDataError');
    expect(err.member).toBe('handshake_challenge');
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toContain('missing fields');
  });

  it('MalformedParafeDataError works without detail', () => {
    const err = new MalformedParafeDataError('consent');
    expect(err.message).toContain('consent');
  });

  it('WrongAudienceError names both agents', () => {
    const err = new WrongAudienceError('prf_agent_me', 'prf_agent_other');
    expect(err.code).toBe('WRONG_AUDIENCE');
    expect(err.name).toBe('WrongAudienceError');
    expect(err.expectedAgentId).toBe('prf_agent_me');
    expect(err.tokenAgentId).toBe('prf_agent_other');
    expect(err.message).toContain('prf_agent_other');
  });

  it('isParafeError recognizes only this package\'s errors', () => {
    expect(isParafeError(new WrongAudienceError('a', null))).toBe(true);
    expect(isParafeError(new InvalidConsentTokenError())).toBe(true);
    expect(isParafeError(new Error('other'))).toBe(false);
    expect(isParafeError('nope')).toBe(false);
  });

  it('all errors are catchable as Error', () => {
    const errors = [
      new MissingParafeExtensionError(['field']),
      new InvalidConsentTokenError(),
      new ExpiredConsentTokenError(new Date()),
      new ScopeViolationError('x', []),
      new MalformedParafeDataError('consent'),
      new WrongAudienceError('a', 'b'),
    ];

    for (const err of errors) {
      expect(err).toBeInstanceOf(Error);
    }
  });
});
