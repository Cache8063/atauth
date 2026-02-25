import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HttpError, httpError, sanitizeError, internalError } from './errors.js';
import type { ErrorResponse } from './errors.js';

describe('HttpError', () => {
  it('should store statusCode, code, and message', () => {
    const err = new HttpError(400, 'bad_request', 'Invalid input');
    expect(err.statusCode).toBe(400);
    expect(err.code).toBe('bad_request');
    expect(err.message).toBe('Invalid input');
    expect(err.name).toBe('HttpError');
  });

  it('should be an instance of Error', () => {
    const err = new HttpError(500, 'server_error', 'Boom');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(HttpError);
  });
});

describe('httpError factories', () => {
  it('badRequest should create 400', () => {
    const err = httpError.badRequest('missing_field', 'Field X is required');
    expect(err.statusCode).toBe(400);
    expect(err.code).toBe('missing_field');
    expect(err.message).toBe('Field X is required');
  });

  it('unauthorized should create 401', () => {
    const err = httpError.unauthorized('invalid_token', 'Token expired');
    expect(err.statusCode).toBe(401);
    expect(err.code).toBe('invalid_token');
  });

  it('forbidden should create 403', () => {
    const err = httpError.forbidden('access_denied', 'Not allowed');
    expect(err.statusCode).toBe(403);
    expect(err.code).toBe('access_denied');
  });

  it('notFound should create 404', () => {
    const err = httpError.notFound('not_found', 'Resource missing');
    expect(err.statusCode).toBe(404);
    expect(err.code).toBe('not_found');
  });

  it('conflict should create 409', () => {
    const err = httpError.conflict('duplicate', 'Already exists');
    expect(err.statusCode).toBe(409);
    expect(err.code).toBe('duplicate');
  });

  it('internalServerError should create 500', () => {
    const err = httpError.internalServerError('server_error', 'Something broke');
    expect(err.statusCode).toBe(500);
    expect(err.code).toBe('server_error');
  });
});

describe('sanitizeError', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    vi.unstubAllEnvs();
  });

  it('should log the error with context', () => {
    const err = new Error('test error');
    sanitizeError(err, 'Token verify');
    expect(consoleSpy).toHaveBeenCalledWith('Token verify error:', err);
  });

  it('should return generic message in production', () => {
    vi.stubEnv('NODE_ENV', 'production');
    const result = sanitizeError(new Error('secret details'), 'ctx');
    expect(result).toBe('An internal error occurred. Please try again later.');
  });

  it('should return generic message in test mode', () => {
    // NODE_ENV is 'test' by default in vitest
    const result = sanitizeError(new Error('details'), 'ctx');
    expect(result).toBe('An internal error occurred. Please try again later.');
  });

  it('should strip file paths in development mode', () => {
    vi.stubEnv('NODE_ENV', 'development');
    const result = sanitizeError(new Error('Failed at /home/user/app/src/index.ts:42'), 'ctx');
    expect(result).not.toContain('/home/user');
    expect(result).toContain('[path]');
  });

  it('should return generic message for non-Error objects', () => {
    vi.stubEnv('NODE_ENV', 'development');
    const result = sanitizeError('string error', 'ctx');
    expect(result).toBe('An internal error occurred. Please try again later.');
  });
});

describe('internalError', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it('should return ErrorResponse with error code and sanitized message', () => {
    const result: ErrorResponse = internalError('db_error', new Error('connection lost'), 'DB query');
    expect(result.error).toBe('db_error');
    expect(result.message).toBeTypeOf('string');
    expect(result.message).not.toContain('connection lost');
  });
});
