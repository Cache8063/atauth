/**
 * OIDC Key Management Service
 *
 * Handles generation, storage, and retrieval of signing keys for OIDC JWTs
 */

import crypto from 'crypto';
import type { DatabaseService } from '../database.js';
import type { OIDCKey, JWK, JWKS } from '../../types/index.js';

export class KeyManager {
  private encryptionKey: Buffer;

  constructor(
    private db: DatabaseService,
    encryptionSecret: string
  ) {
    // Derive a 32-byte key from the secret using SHA-256
    this.encryptionKey = crypto.createHash('sha256').update(encryptionSecret).digest();
  }

  /**
   * Generate a new signing key pair
   */
  async generateKey(algorithm: 'ES256' | 'RS256' = 'ES256'): Promise<string> {
    const kid = `key-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    if (algorithm === 'ES256') {
      return this.generateES256Key(kid);
    } else {
      return this.generateRS256Key(kid);
    }
  }

  private generateES256Key(kid: string): string {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });

    // Export private key as PEM and encrypt it
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const encryptedPrivateKey = this.encryptPrivateKey(privatePem);

    // Export public key as JWK
    const publicJwk = publicKey.export({ format: 'jwk' }) as {
      kty: string;
      crv: string;
      x: string;
      y: string;
    };

    const jwk: JWK = {
      kty: publicJwk.kty,
      crv: publicJwk.crv,
      x: publicJwk.x,
      y: publicJwk.y,
      use: 'sig',
      alg: 'ES256',
      kid,
    };

    // Mark current signing key as not for signing
    const currentKey = this.db.getCurrentSigningKey();
    if (currentKey) {
      this.db.markKeyAsNotSigning(currentKey.kid);
    }

    // Save the new key
    this.db.saveOIDCKey({
      kid,
      algorithm: 'ES256',
      private_key_encrypted: encryptedPrivateKey,
      public_key_jwk: JSON.stringify(jwk),
      is_active: true,
      use_for_signing: true,
    });

    return kid;
  }

  private generateRS256Key(kid: string): string {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });

    // Export private key as PEM and encrypt it
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const encryptedPrivateKey = this.encryptPrivateKey(privatePem);

    // Export public key as JWK
    const publicJwk = publicKey.export({ format: 'jwk' }) as {
      kty: string;
      n: string;
      e: string;
    };

    const jwk: JWK = {
      kty: publicJwk.kty,
      n: publicJwk.n,
      e: publicJwk.e,
      use: 'sig',
      alg: 'RS256',
      kid,
    };

    // Mark current signing key as not for signing
    const currentKey = this.db.getCurrentSigningKey();
    if (currentKey) {
      this.db.markKeyAsNotSigning(currentKey.kid);
    }

    // Save the new key
    this.db.saveOIDCKey({
      kid,
      algorithm: 'RS256',
      private_key_encrypted: encryptedPrivateKey,
      public_key_jwk: JSON.stringify(jwk),
      is_active: true,
      use_for_signing: true,
    });

    return kid;
  }

  /**
   * Get the JWKS (JSON Web Key Set) containing all active public keys
   */
  getJWKS(): JWKS {
    const activeKeys = this.db.getActiveOIDCKeys();
    return {
      keys: activeKeys.map((key) => JSON.parse(key.public_key_jwk) as JWK),
    };
  }

  /**
   * Get the current signing key
   */
  getSigningKey(): { kid: string; privateKey: crypto.KeyObject; algorithm: 'ES256' | 'RS256' } | null {
    const key = this.db.getCurrentSigningKey();
    if (!key) return null;

    const decryptedPem = this.decryptPrivateKey(key.private_key_encrypted);
    const privateKey = crypto.createPrivateKey(decryptedPem);

    return {
      kid: key.kid,
      privateKey,
      algorithm: key.algorithm,
    };
  }

  /**
   * Get a specific key by kid
   */
  getKeyByKid(kid: string): { privateKey: crypto.KeyObject; algorithm: 'ES256' | 'RS256' } | null {
    const key = this.db.getOIDCKey(kid);
    if (!key || !key.is_active) return null;

    const decryptedPem = this.decryptPrivateKey(key.private_key_encrypted);
    const privateKey = crypto.createPrivateKey(decryptedPem);

    return {
      privateKey,
      algorithm: key.algorithm,
    };
  }

  /**
   * Rotate keys - generate a new key and mark the old one as not for signing
   * Old keys remain active for verification of existing tokens
   */
  async rotateKeys(algorithm: 'ES256' | 'RS256' = 'ES256'): Promise<string> {
    return this.generateKey(algorithm);
  }

  /**
   * Deactivate a key (removes from JWKS, can't verify tokens signed with it)
   */
  deactivateKey(kid: string): void {
    this.db.deactivateKey(kid);
  }

  /**
   * Delete a key permanently
   */
  deleteKey(kid: string): void {
    this.db.deleteOIDCKey(kid);
  }

  /**
   * List all keys (for admin interface)
   */
  listKeys(): OIDCKey[] {
    return this.db.getActiveOIDCKeys();
  }

  /**
   * Ensure at least one signing key exists
   */
  async ensureSigningKey(algorithm: 'ES256' | 'RS256' = 'ES256'): Promise<string> {
    const currentKey = this.db.getCurrentSigningKey();
    if (currentKey) {
      return currentKey.kid;
    }
    return this.generateKey(algorithm);
  }

  /**
   * Encrypt a private key using AES-256-GCM
   */
  private encryptPrivateKey(pem: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);

    const encrypted = Buffer.concat([
      cipher.update(pem, 'utf8'),
      cipher.final(),
    ]);

    const authTag = cipher.getAuthTag();

    // Format: iv (16 bytes) + authTag (16 bytes) + encrypted data
    const combined = Buffer.concat([iv, authTag, encrypted]);
    return combined.toString('base64');
  }

  /**
   * Decrypt a private key using AES-256-GCM
   */
  private decryptPrivateKey(encryptedBase64: string): string {
    const data = Buffer.from(encryptedBase64, 'base64');

    const iv = data.subarray(0, 16);
    const authTag = data.subarray(16, 32);
    const encrypted = data.subarray(32);

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  }
}
