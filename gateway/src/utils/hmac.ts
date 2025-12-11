/**
 * HMAC Token Utilities
 *
 * Creates and verifies HMAC-SHA256 signed tokens for application authentication.
 * Token format: base64url(payload).base64url(hmac_sha256(payload, secret))
 */

import crypto from 'crypto';
import type { GatewayTokenPayload } from '../types/index.js';

const ALGORITHM = 'sha256';

/**
 * Create an HMAC-signed gateway token
 */
export function createGatewayToken(
  payload: Omit<GatewayTokenPayload, 'iat' | 'exp' | 'nonce'>,
  secret: string,
  ttlSeconds: number = 3600
): string {
  const now = Math.floor(Date.now() / 1000);

  const fullPayload: GatewayTokenPayload = {
    ...payload,
    iat: now,
    exp: now + ttlSeconds,
    nonce: crypto.randomBytes(16).toString('hex'),
  };

  const payloadJson = JSON.stringify(fullPayload);
  const payloadBase64 = Buffer.from(payloadJson).toString('base64url');

  const signature = crypto
    .createHmac(ALGORITHM, secret)
    .update(payloadBase64)
    .digest('base64url');

  return `${payloadBase64}.${signature}`;
}

/**
 * Verify an HMAC-signed gateway token
 * Returns the payload if valid, null if invalid or expired
 */
export function verifyGatewayToken(
  token: string,
  secret: string
): GatewayTokenPayload | null {
  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }

  const [payloadBase64, providedSignature] = parts;

  // Verify signature
  const expectedSignature = crypto
    .createHmac(ALGORITHM, secret)
    .update(payloadBase64)
    .digest('base64url');

  // Constant-time comparison with length check to prevent DoS
  // timingSafeEqual throws if buffer lengths differ, so we check first
  const providedBuf = Buffer.from(providedSignature);
  const expectedBuf = Buffer.from(expectedSignature);

  if (providedBuf.length !== expectedBuf.length) {
    return null;
  }

  if (!crypto.timingSafeEqual(providedBuf, expectedBuf)) {
    return null;
  }

  // Decode payload
  try {
    const payloadJson = Buffer.from(payloadBase64, 'base64url').toString('utf8');
    const payload = JSON.parse(payloadJson) as GatewayTokenPayload;

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/**
 * Generate a cryptographically secure HMAC secret
 */
export function generateHmacSecret(): string {
  return crypto.randomBytes(32).toString('hex');
}
