/**
 * MFA Service
 *
 * Handles TOTP (Time-based One-Time Password) setup, verification,
 * and backup code management
 */

import { TOTP, Secret } from 'otpauth';
import crypto from 'crypto';
import * as QRCode from 'qrcode';
import type { DatabaseService } from './database.js';
import type { TOTPSetupResponse, MFAStatus } from '../types/mfa.js';

export interface MFAConfig {
  issuer: string;
  encryptionKey: string; // 32-byte hex string for AES-256-GCM
  backupCodesCount?: number;
}

export class MFAService {
  private issuer: string;
  private encryptionKey: Buffer;
  private backupCodesCount: number;

  constructor(
    private db: DatabaseService,
    config: MFAConfig
  ) {
    this.issuer = config.issuer;
    this.encryptionKey = Buffer.from(config.encryptionKey, 'hex');
    this.backupCodesCount = config.backupCodesCount || 10;

    if (this.encryptionKey.length !== 32) {
      throw new Error('MFA encryption key must be 32 bytes (64 hex characters)');
    }
  }

  /**
   * Start TOTP setup for a user
   * Returns the secret and QR code for authenticator app
   */
  async setupTOTP(did: string, handle: string): Promise<TOTPSetupResponse> {
    // Generate a new secret
    const secret = new Secret({ size: 20 }); // 160-bit secret

    // Create TOTP instance
    const totp = new TOTP({
      issuer: this.issuer,
      label: handle || did,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret,
    });

    // Generate provisioning URI
    const uri = totp.toString();

    // Generate QR code
    const qrCode = await QRCode.toDataURL(uri);

    // Encrypt and store the secret (not yet enabled)
    const encryptedSecret = this.encryptSecret(secret.base32);
    this.db.saveMFATOTP({
      did,
      secret_encrypted: encryptedSecret,
      enabled: false,
    });

    return {
      secret: secret.base32,
      qr_code: qrCode,
      manual_entry_key: secret.base32,
      issuer: this.issuer,
      account_name: handle || did,
    };
  }

  /**
   * Verify TOTP code during setup and enable TOTP
   */
  verifyAndEnableTOTP(did: string, code: string): boolean {
    const config = this.db.getMFATOTP(did);
    if (!config) {
      return false;
    }

    // Decrypt the secret
    const secretBase32 = this.decryptSecret(config.secret_encrypted);

    // Verify the code
    const totp = new TOTP({
      issuer: this.issuer,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: Secret.fromBase32(secretBase32),
    });

    const delta = totp.validate({ token: code, window: 1 });

    if (delta !== null) {
      // Enable TOTP
      this.db.enableMFATOTP(did);
      return true;
    }

    return false;
  }

  /**
   * Verify TOTP code during login
   */
  verifyTOTP(did: string, code: string): boolean {
    const config = this.db.getMFATOTP(did);
    if (!config || !config.enabled) {
      return false;
    }

    // Decrypt the secret
    const secretBase32 = this.decryptSecret(config.secret_encrypted);

    // Verify the code
    const totp = new TOTP({
      issuer: this.issuer,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: Secret.fromBase32(secretBase32),
    });

    const delta = totp.validate({ token: code, window: 1 });
    if (delta === null) return false;

    // Replay protection: compute absolute TOTP period and reject if already used
    const currentPeriod = Math.floor(Date.now() / 30000);
    const absolutePeriod = currentPeriod + delta;
    const lastUsed = this.db.getTOTPLastUsedPeriod(did);
    if (lastUsed !== null && absolutePeriod <= lastUsed) {
      return false;
    }
    this.db.updateTOTPLastUsedPeriod(did, absolutePeriod);

    return true;
  }

  /**
   * Disable TOTP for a user
   */
  disableTOTP(did: string): void {
    this.db.disableMFATOTP(did);
  }

  /**
   * Check if user has TOTP enabled
   */
  isTOTPEnabled(did: string): boolean {
    const config = this.db.getMFATOTP(did);
    return config?.enabled ?? false;
  }

  /**
   * Generate backup codes for a user
   */
  generateBackupCodes(did: string): string[] {
    const codes: string[] = [];
    const codeHashes: string[] = [];

    for (let i = 0; i < this.backupCodesCount; i++) {
      // Generate 8-character alphanumeric code (split into 4-4 for readability)
      const part1 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const part2 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const code = `${part1}-${part2}`;
      codes.push(code);

      // Hash the code for storage
      const hash = crypto.createHash('sha256').update(code).digest('hex');
      codeHashes.push(hash);
    }

    // Store hashed codes
    this.db.saveBackupCodes(did, codeHashes);

    return codes;
  }

  /**
   * Verify a backup code
   */
  verifyBackupCode(did: string, code: string): boolean {
    // Hash the provided code
    const codeHash = crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');

    // Look up unused backup code
    const backupCode = this.db.getUnusedBackupCode(did, codeHash);
    if (!backupCode) {
      return false;
    }

    // Mark as used
    this.db.markBackupCodeUsed(backupCode.id);
    return true;
  }

  /**
   * Get MFA status for a user
   */
  getMFAStatus(did: string, passkeyCount: number): MFAStatus {
    const totpConfig = this.db.getMFATOTP(did);
    const unusedBackupCodes = this.db.countUnusedBackupCodes(did);

    return {
      totp_enabled: totpConfig?.enabled ?? false,
      totp_verified_at: totpConfig?.verified_at?.toISOString(),
      passkey_count: passkeyCount,
      backup_codes_remaining: unusedBackupCodes,
    };
  }

  /**
   * Verify MFA (TOTP or backup code)
   */
  verifyMFA(did: string, code: string, type: 'totp' | 'backup_code'): boolean {
    if (type === 'totp') {
      return this.verifyTOTP(did, code);
    } else if (type === 'backup_code') {
      return this.verifyBackupCode(did, code);
    }
    return false;
  }

  /**
   * Encrypt a TOTP secret using AES-256-GCM
   */
  private encryptSecret(secret: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);

    let encrypted = cipher.update(secret, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    // Return iv:authTag:encrypted
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  /**
   * Decrypt a TOTP secret
   */
  private decryptSecret(encryptedData: string): string {
    const [ivHex, authTagHex, encrypted] = encryptedData.split(':');

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}
