/**
 * Email Service
 *
 * Handles email verification, notifications, and account recovery
 * Supports SMTP and external providers (Resend, SendGrid, etc.)
 */

import crypto from 'crypto';
import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import type { DatabaseService } from './database.js';
import type { UserEmail } from '../types/email.js';

export interface EmailServiceConfig {
  provider: 'smtp' | 'resend' | 'sendgrid' | 'mailgun' | 'mock';
  smtp?: {
    host: string;
    port: number;
    secure?: boolean;
    user?: string;
    pass?: string;
  };
  apiKey?: string;
  from: string;
  codeExpiry?: number; // in seconds, default 15 minutes
}

export class EmailService {
  private transporter: Transporter | null = null;
  private config: EmailServiceConfig;
  private codeExpiry: number;

  constructor(
    private db: DatabaseService,
    config: EmailServiceConfig
  ) {
    this.config = config;
    this.codeExpiry = config.codeExpiry || 15 * 60; // 15 minutes default

    if (config.provider === 'smtp' && config.smtp) {
      this.transporter = nodemailer.createTransport({
        host: config.smtp.host,
        port: config.smtp.port,
        secure: config.smtp.secure ?? config.smtp.port === 465,
        auth: config.smtp.user ? {
          user: config.smtp.user,
          pass: config.smtp.pass,
        } : undefined,
      });
    } else if (config.provider === 'mock') {
      // Mock transport for testing
      this.transporter = nodemailer.createTransport({
        host: 'localhost',
        port: 1025,
        ignoreTLS: true,
      });
    }
  }

  /**
   * Add an email to a user's account
   */
  async addEmail(did: string, email: string): Promise<{ success: boolean; error?: string }> {
    // Check if email is already registered to another user
    const existing = this.db.getUserByEmail(email);
    if (existing && existing.did !== did) {
      return { success: false, error: 'Email already registered to another account' };
    }

    // Save email (unverified)
    const emails = this.db.getUserEmails(did);
    const isPrimary = emails.length === 0;

    this.db.saveUserEmail({
      did,
      email,
      verified: false,
      is_primary: isPrimary,
    });

    // Generate and send verification code
    const result = await this.sendVerificationCode(email, 'verify');
    if (!result.success) {
      return result;
    }

    return { success: true };
  }

  /**
   * Send verification code to email
   */
  async sendVerificationCode(
    email: string,
    purpose: 'verify' | 'recovery'
  ): Promise<{ success: boolean; error?: string }> {
    // Generate 6-digit code
    const code = this.generateCode();
    const codeHash = this.hashCode(code);

    // Store code
    this.db.saveEmailVerificationCode({
      email,
      code_hash: codeHash,
      purpose,
      expires_at: new Date(Date.now() + this.codeExpiry * 1000),
      used: false,
    });

    // Send email
    const subject = purpose === 'verify'
      ? 'Verify your email address'
      : 'Account recovery code';

    const text = purpose === 'verify'
      ? `Your verification code is: ${code}\n\nThis code expires in ${Math.floor(this.codeExpiry / 60)} minutes.`
      : `Your recovery code is: ${code}\n\nThis code expires in ${Math.floor(this.codeExpiry / 60)} minutes.\n\nIf you did not request this, please ignore this email.`;

    try {
      await this.sendEmail(email, subject, text);
      return { success: true };
    } catch (error) {
      console.error('[Email] Failed to send email:', error);
      return { success: false, error: 'Failed to send email' };
    }
  }

  /**
   * Verify email code
   */
  verifyEmail(
    did: string,
    email: string,
    code: string
  ): { success: boolean; error?: string } {
    const codeHash = this.hashCode(code);
    const verificationCode = this.db.getValidEmailVerificationCode(email, codeHash, 'verify');

    if (!verificationCode) {
      return { success: false, error: 'Invalid or expired verification code' };
    }

    // Mark code as used
    this.db.markEmailVerificationCodeUsed(verificationCode.id);

    // Mark email as verified
    this.db.verifyUserEmail(did, email);

    return { success: true };
  }

  /**
   * Request account recovery
   */
  async requestRecovery(email: string): Promise<{ success: boolean; error?: string }> {
    // Check if email is verified
    const user = this.db.getUserByEmail(email);
    if (!user) {
      // Don't reveal if email exists or not
      return { success: true };
    }

    // Send recovery code
    return this.sendVerificationCode(email, 'recovery');
  }

  /**
   * Verify recovery code
   */
  verifyRecovery(
    email: string,
    code: string
  ): { success: boolean; did?: string; error?: string } {
    const codeHash = this.hashCode(code);
    const verificationCode = this.db.getValidEmailVerificationCode(email, codeHash, 'recovery');

    if (!verificationCode) {
      return { success: false, error: 'Invalid or expired recovery code' };
    }

    // Get user DID
    const user = this.db.getUserByEmail(email);
    if (!user) {
      return { success: false, error: 'No account found for this email' };
    }

    // Mark code as used
    this.db.markEmailVerificationCodeUsed(verificationCode.id);

    return { success: true, did: user.did };
  }

  /**
   * Get user's emails
   */
  getUserEmails(did: string): UserEmail[] {
    return this.db.getUserEmails(did);
  }

  /**
   * Remove an email from user's account
   */
  removeEmail(did: string, email: string): { success: boolean; error?: string } {
    const emails = this.db.getUserEmails(did);
    const emailToRemove = emails.find(e => e.email === email);

    if (!emailToRemove) {
      return { success: false, error: 'Email not found' };
    }

    // Don't allow removing the primary email if there are other emails
    if (emailToRemove.is_primary && emails.length > 1) {
      return { success: false, error: 'Cannot remove primary email. Set another email as primary first.' };
    }

    this.db.deleteUserEmail(did, email);
    return { success: true };
  }

  /**
   * Set an email as primary
   */
  setPrimaryEmail(did: string, email: string): { success: boolean; error?: string } {
    const emails = this.db.getUserEmails(did);
    const emailToSetPrimary = emails.find(e => e.email === email);

    if (!emailToSetPrimary) {
      return { success: false, error: 'Email not found' };
    }

    if (!emailToSetPrimary.verified) {
      return { success: false, error: 'Only verified emails can be set as primary' };
    }

    this.db.setPrimaryEmail(did, email);
    return { success: true };
  }

  /**
   * Resend verification code
   */
  async resendVerificationCode(email: string): Promise<{ success: boolean; error?: string }> {
    return this.sendVerificationCode(email, 'verify');
  }

  /**
   * Generate a 6-digit verification code
   */
  private generateCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }

  /**
   * Hash a verification code for storage
   */
  private hashCode(code: string): string {
    return crypto.createHash('sha256').update(code).digest('hex');
  }

  /**
   * Send an email
   */
  private async sendEmail(to: string, subject: string, text: string): Promise<void> {
    if (this.config.provider === 'mock') {
      console.log(`[Email] Mock send to ${to}: ${subject}`);
      console.log(`[Email] ${text}`);
      return;
    }

    if (!this.transporter) {
      throw new Error('Email transporter not configured');
    }

    await this.transporter.sendMail({
      from: this.config.from,
      to,
      subject,
      text,
    });
  }

  /**
   * Verify email transporter is working
   */
  async verify(): Promise<boolean> {
    if (!this.transporter) {
      return false;
    }

    try {
      await this.transporter.verify();
      return true;
    } catch {
      return false;
    }
  }
}
