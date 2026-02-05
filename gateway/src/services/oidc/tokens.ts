/**
 * OIDC Token Service
 *
 * Handles creation and verification of OIDC JWTs (ID tokens, access tokens)
 */

import crypto from 'crypto';
import type { KeyManager } from './keys.js';
import type { IDTokenClaims, AccessTokenClaims, TokenResponse } from '../../types/index.js';

export class TokenService {
  constructor(
    private keyManager: KeyManager,
    private issuer: string
  ) {}

  /**
   * Create an ID Token
   */
  createIdToken(claims: {
    sub: string;
    aud: string;
    nonce?: string;
    did: string;
    handle: string;
    accessToken?: string;
    expiresIn?: number;
  }): string {
    const signingKey = this.keyManager.getSigningKey();
    if (!signingKey) {
      throw new Error('No signing key available');
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = claims.expiresIn || 3600;

    const payload: IDTokenClaims = {
      iss: this.issuer,
      sub: claims.sub,
      aud: claims.aud,
      exp: now + expiresIn,
      iat: now,
      nonce: claims.nonce,
      handle: claims.handle,
      did: claims.did,
    };

    // Add at_hash if access token is provided
    if (claims.accessToken) {
      payload.at_hash = this.computeAtHash(claims.accessToken, signingKey.algorithm);
    }

    return this.signJwt(payload as unknown as Record<string, unknown>, signingKey);
  }

  /**
   * Create an Access Token
   */
  createAccessToken(claims: {
    sub: string;
    clientId: string;
    scope: string;
    expiresIn?: number;
  }): string {
    const signingKey = this.keyManager.getSigningKey();
    if (!signingKey) {
      throw new Error('No signing key available');
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = claims.expiresIn || 3600;

    const payload: AccessTokenClaims = {
      iss: this.issuer,
      sub: claims.sub,
      aud: this.issuer,
      exp: now + expiresIn,
      iat: now,
      jti: crypto.randomUUID(),
      client_id: claims.clientId,
      scope: claims.scope,
    };

    return this.signJwt(payload as unknown as Record<string, unknown>, signingKey);
  }

  /**
   * Create a token response for the token endpoint
   */
  createTokenResponse(params: {
    sub: string;
    clientId: string;
    scope: string;
    did: string;
    handle: string;
    nonce?: string;
    accessTokenTtl?: number;
    idTokenTtl?: number;
    includeRefreshToken?: boolean;
    refreshToken?: string;
  }): TokenResponse {
    const accessTokenTtl = params.accessTokenTtl || 3600;
    const idTokenTtl = params.idTokenTtl || 3600;

    const accessToken = this.createAccessToken({
      sub: params.sub,
      clientId: params.clientId,
      scope: params.scope,
      expiresIn: accessTokenTtl,
    });

    const response: TokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: accessTokenTtl,
      scope: params.scope,
    };

    // Include ID token if openid scope is requested
    if (params.scope.includes('openid')) {
      response.id_token = this.createIdToken({
        sub: params.sub,
        aud: params.clientId,
        nonce: params.nonce,
        did: params.did,
        handle: params.handle,
        accessToken,
        expiresIn: idTokenTtl,
      });
    }

    // Include refresh token if requested
    if (params.includeRefreshToken && params.refreshToken) {
      response.refresh_token = params.refreshToken;
    }

    return response;
  }

  /**
   * Verify an access token
   */
  verifyAccessToken(token: string): AccessTokenClaims | null {
    try {
      const payload = this.verifyJwt(token);
      if (!payload) return null;

      // Check required claims
      if (!payload.iss || !payload.sub || !payload.exp || !payload.client_id) {
        return null;
      }

      // Check issuer
      if (payload.iss !== this.issuer) {
        return null;
      }

      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (typeof payload.exp !== 'number' || payload.exp < now) {
        return null;
      }

      return payload as unknown as AccessTokenClaims;
    } catch {
      return null;
    }
  }

  /**
   * Verify an ID token
   */
  verifyIdToken(token: string, expectedAudience?: string, expectedNonce?: string): IDTokenClaims | null {
    try {
      const payload = this.verifyJwt(token);
      if (!payload) return null;

      // Check required claims
      if (!payload.iss || !payload.sub || !payload.aud || !payload.exp) {
        return null;
      }

      // Check issuer
      if (payload.iss !== this.issuer) {
        return null;
      }

      // Check audience if provided
      if (expectedAudience && payload.aud !== expectedAudience) {
        return null;
      }

      // Check nonce if provided
      if (expectedNonce && payload.nonce !== expectedNonce) {
        return null;
      }

      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (typeof payload.exp !== 'number' || payload.exp < now) {
        return null;
      }

      return payload as unknown as IDTokenClaims;
    } catch {
      return null;
    }
  }

  /**
   * Sign a JWT
   */
  private signJwt(
    payload: Record<string, unknown>,
    signingKey: { kid: string; privateKey: crypto.KeyObject; algorithm: 'ES256' | 'RS256' }
  ): string {
    const header = {
      alg: signingKey.algorithm,
      typ: 'JWT',
      kid: signingKey.kid,
    };

    const headerB64 = this.base64urlEncode(JSON.stringify(header));
    const payloadB64 = this.base64urlEncode(JSON.stringify(payload));
    const signingInput = `${headerB64}.${payloadB64}`;

    let signature: Buffer;
    if (signingKey.algorithm === 'ES256') {
      const sign = crypto.createSign('SHA256');
      sign.update(signingInput);
      const derSignature = sign.sign(signingKey.privateKey);
      // Convert DER signature to raw r||s format for JWT
      signature = this.derToRaw(derSignature);
    } else {
      const sign = crypto.createSign('SHA256');
      sign.update(signingInput);
      signature = sign.sign(signingKey.privateKey);
    }

    const signatureB64 = this.base64urlEncode(signature);
    return `${signingInput}.${signatureB64}`;
  }

  /**
   * Verify a JWT signature and return payload
   */
  private verifyJwt(token: string): Record<string, unknown> | null {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;

    try {
      const header = JSON.parse(this.base64urlDecode(headerB64).toString()) as {
        alg: string;
        kid?: string;
      };

      // Get the key
      let key: { privateKey: crypto.KeyObject; algorithm: 'ES256' | 'RS256' } | null = null;
      if (header.kid) {
        key = this.keyManager.getKeyByKid(header.kid);
      }
      if (!key) {
        const signingKey = this.keyManager.getSigningKey();
        if (signingKey) {
          key = { privateKey: signingKey.privateKey, algorithm: signingKey.algorithm };
        }
      }
      if (!key) return null;

      // Get public key from private key
      const publicKey = crypto.createPublicKey(key.privateKey);

      const signingInput = `${headerB64}.${payloadB64}`;
      const signature = this.base64urlDecode(signatureB64);

      let isValid: boolean;
      if (header.alg === 'ES256') {
        // Convert raw r||s signature back to DER for verification
        const derSignature = this.rawToDer(signature);
        const verify = crypto.createVerify('SHA256');
        verify.update(signingInput);
        isValid = verify.verify(publicKey, derSignature);
      } else {
        const verify = crypto.createVerify('SHA256');
        verify.update(signingInput);
        isValid = verify.verify(publicKey, signature);
      }

      if (!isValid) return null;

      return JSON.parse(this.base64urlDecode(payloadB64).toString()) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  /**
   * Compute at_hash for ID token
   */
  private computeAtHash(accessToken: string, algorithm: 'ES256' | 'RS256'): string {
    const hashAlg = algorithm === 'ES256' ? 'sha256' : 'sha256';
    const hash = crypto.createHash(hashAlg).update(accessToken).digest();
    // Take the left half of the hash
    const leftHalf = hash.subarray(0, hash.length / 2);
    return this.base64urlEncode(leftHalf);
  }

  /**
   * Convert DER-encoded ECDSA signature to raw r||s format
   */
  private derToRaw(derSignature: Buffer): Buffer {
    // DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
    let offset = 2; // Skip 0x30 and total length

    // Read r
    if (derSignature[offset] !== 0x02) throw new Error('Invalid DER signature');
    offset++;
    const rLength = derSignature[offset];
    offset++;
    let r = derSignature.subarray(offset, offset + rLength);
    offset += rLength;

    // Read s
    if (derSignature[offset] !== 0x02) throw new Error('Invalid DER signature');
    offset++;
    const sLength = derSignature[offset];
    offset++;
    let s = derSignature.subarray(offset, offset + sLength);

    // Remove leading zeros and pad to 32 bytes
    if (r.length > 32) r = r.subarray(r.length - 32);
    if (s.length > 32) s = s.subarray(s.length - 32);

    const raw = Buffer.alloc(64);
    r.copy(raw, 32 - r.length);
    s.copy(raw, 64 - s.length);

    return raw;
  }

  /**
   * Convert raw r||s format to DER-encoded ECDSA signature
   */
  private rawToDer(rawSignature: Buffer): Buffer {
    if (rawSignature.length !== 64) throw new Error('Invalid raw signature length');

    let r = rawSignature.subarray(0, 32);
    let s = rawSignature.subarray(32, 64);

    // Remove leading zeros
    while (r.length > 1 && r[0] === 0 && (r[1] & 0x80) === 0) {
      r = r.subarray(1);
    }
    while (s.length > 1 && s[0] === 0 && (s[1] & 0x80) === 0) {
      s = s.subarray(1);
    }

    // Add leading zero if high bit is set (to ensure positive integer)
    if (r[0] & 0x80) {
      r = Buffer.concat([Buffer.from([0]), r]);
    }
    if (s[0] & 0x80) {
      s = Buffer.concat([Buffer.from([0]), s]);
    }

    const rLen = r.length;
    const sLen = s.length;
    const totalLen = 2 + rLen + 2 + sLen;

    const der = Buffer.alloc(2 + totalLen);
    let offset = 0;

    der[offset++] = 0x30; // SEQUENCE
    der[offset++] = totalLen;
    der[offset++] = 0x02; // INTEGER
    der[offset++] = rLen;
    r.copy(der, offset);
    offset += rLen;
    der[offset++] = 0x02; // INTEGER
    der[offset++] = sLen;
    s.copy(der, offset);

    return der;
  }

  /**
   * Base64url encode
   */
  private base64urlEncode(data: string | Buffer): string {
    const buffer = typeof data === 'string' ? Buffer.from(data) : data;
    return buffer.toString('base64url');
  }

  /**
   * Base64url decode
   */
  private base64urlDecode(str: string): Buffer {
    return Buffer.from(str, 'base64url');
  }
}
