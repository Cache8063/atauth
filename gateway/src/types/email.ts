/**
 * Email Verification Types
 *
 * Types for email verification and account recovery
 */

/** User email stored in database */
export interface UserEmail {
  id: number;
  did: string;
  email: string;
  verified: boolean;
  verified_at: Date | null;
  is_primary: boolean;
  created_at: Date;
}

/** Email verification code stored in database */
export interface EmailVerificationCode {
  id: number;
  email: string;
  code_hash: string;
  purpose: 'verify' | 'recovery';
  expires_at: Date;
  used: boolean;
  created_at: Date;
}

/** Add email request */
export interface AddEmailRequest {
  email: string;
}

/** Verify email request */
export interface VerifyEmailRequest {
  email: string;
  code: string;
}

/** Account recovery request */
export interface RecoveryRequest {
  email: string;
}

/** Account recovery verify request */
export interface RecoveryVerifyRequest {
  email: string;
  code: string;
}

/** Email status response */
export interface EmailStatusResponse {
  emails: Array<{
    email: string;
    verified: boolean;
    is_primary: boolean;
    verified_at?: string;
    created_at: string;
  }>;
}

/** Email verification result */
export interface EmailVerificationResult {
  success: boolean;
  email?: string;
  error?: string;
}

/** Email provider configuration */
export interface EmailProviderConfig {
  provider: 'smtp' | 'resend' | 'sendgrid' | 'mailgun';
  smtp?: {
    host: string;
    port: number;
    user: string;
    pass: string;
    from: string;
  };
  api_key?: string;
  from_address?: string;
}
