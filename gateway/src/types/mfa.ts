/**
 * MFA/TOTP Types
 *
 * Types for multi-factor authentication
 */

/** TOTP configuration stored in database */
export interface MFATOTPConfig {
  did: string;
  secret_encrypted: string;
  enabled: boolean;
  verified_at: Date | null;
  created_at: Date;
}

/** Backup code stored in database */
export interface MFABackupCode {
  id: number;
  did: string;
  code_hash: string;
  used: boolean;
  used_at: Date | null;
  created_at: Date;
}

/** TOTP setup response */
export interface TOTPSetupResponse {
  secret: string;
  qr_code: string;
  manual_entry_key: string;
  issuer: string;
  account_name: string;
}

/** TOTP verify setup request */
export interface TOTPVerifySetupRequest {
  code: string;
}

/** TOTP verify request (during login) */
export interface TOTPVerifyRequest {
  did: string;
  code: string;
}

/** Backup codes response */
export interface BackupCodesResponse {
  codes: string[];
  generated_at: string;
}

/** MFA status for a user */
export interface MFAStatus {
  totp_enabled: boolean;
  totp_verified_at?: string;
  passkey_count: number;
  backup_codes_remaining: number;
}

/** MFA verification result */
export interface MFAVerificationResult {
  success: boolean;
  method?: 'totp' | 'backup_code' | 'passkey';
  error?: string;
}
