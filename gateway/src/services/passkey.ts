/**
 * Passkey Service
 *
 * Handles WebAuthn/FIDO2 passkey registration and authentication
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';
import type { DatabaseService } from './database.js';
import type { PasskeyListItem } from '../types/passkey.js';

export interface PasskeyConfig {
  rpName: string;
  rpID: string;
  origin: string;
}

// In-memory challenge storage (in production, use Redis or database)
const pendingChallenges = new Map<string, { challenge: string; expires: number }>();

export class PasskeyService {
  private rpName: string;
  private rpID: string;
  private origin: string;

  constructor(
    private db: DatabaseService,
    config: PasskeyConfig
  ) {
    this.rpName = config.rpName;
    this.rpID = config.rpID;
    this.origin = config.origin;
  }

  /**
   * Generate registration options for a new passkey
   */
  async generateRegistrationOptions(
    did: string,
    handle: string
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    // Get existing credentials for this user
    const existingCredentials = this.db.getPasskeyCredentialsByDid(did);

    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpID,
      userID: new TextEncoder().encode(did),
      userName: handle || did,
      userDisplayName: handle || did.split(':').pop() || did,
      attestationType: 'none', // We don't need attestation
      excludeCredentials: existingCredentials.map((cred) => ({
        id: cred.id,
        transports: cred.transports as AuthenticatorTransportFuture[] | undefined,
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: undefined, // Allow both platform and cross-platform
      },
      supportedAlgorithmIDs: [-7, -257], // ES256, RS256
    });

    // Store challenge for verification
    const challengeKey = `reg:${did}`;
    pendingChallenges.set(challengeKey, {
      challenge: options.challenge,
      expires: Date.now() + 5 * 60 * 1000, // 5 minutes
    });

    return options;
  }

  /**
   * Verify registration response and store credential
   */
  async verifyRegistration(
    did: string,
    handle: string,
    response: RegistrationResponseJSON,
    name?: string
  ): Promise<{ success: boolean; credentialId?: string; error?: string }> {
    // Get stored challenge
    const challengeKey = `reg:${did}`;
    const storedChallenge = pendingChallenges.get(challengeKey);

    if (!storedChallenge) {
      return { success: false, error: 'No registration challenge found' };
    }

    if (Date.now() > storedChallenge.expires) {
      pendingChallenges.delete(challengeKey);
      return { success: false, error: 'Registration challenge expired' };
    }

    try {
      const verification: VerifiedRegistrationResponse = await verifyRegistrationResponse({
        response,
        expectedChallenge: storedChallenge.challenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpID,
        requireUserVerification: false,
      });

      if (!verification.verified || !verification.registrationInfo) {
        return { success: false, error: 'Verification failed' };
      }

      const { credentialID, credentialPublicKey, counter, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

      // Store the credential
      this.db.savePasskeyCredential({
        id: credentialID,
        did,
        handle,
        public_key: Buffer.from(credentialPublicKey).toString('base64'),
        counter,
        device_type: credentialDeviceType === 'singleDevice' ? 'platform' : 'cross-platform',
        backed_up: credentialBackedUp,
        transports: response.response.transports as string[] | undefined ?? null,
        name: name || null,
      });

      // Clean up challenge
      pendingChallenges.delete(challengeKey);

      return { success: true, credentialId: credentialID };
    } catch (error) {
      console.error('[Passkey] Registration verification error:', error);
      return { success: false, error: error instanceof Error ? error.message : 'Verification failed' };
    }
  }

  /**
   * Generate authentication options
   */
  async generateAuthenticationOptions(did?: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
    // Get user's credentials if DID provided
    let allowCredentials: { id: string; transports?: AuthenticatorTransportFuture[] }[] = [];
    if (did) {
      const credentials = this.db.getPasskeyCredentialsByDid(did);
      allowCredentials = credentials.map((cred) => ({
        id: cred.id,
        transports: cred.transports as AuthenticatorTransportFuture[] | undefined,
      }));
    }

    const options = await generateAuthenticationOptions({
      rpID: this.rpID,
      allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
      userVerification: 'preferred',
    });

    // Store challenge for verification
    // Use a unique key since we might not know the DID yet
    const challengeKey = `auth:${options.challenge}`;
    pendingChallenges.set(challengeKey, {
      challenge: options.challenge,
      expires: Date.now() + 5 * 60 * 1000, // 5 minutes
    });

    return options;
  }

  /**
   * Verify authentication response
   */
  async verifyAuthentication(
    response: AuthenticationResponseJSON,
    expectedChallenge: string
  ): Promise<{ success: boolean; did?: string; handle?: string; error?: string }> {
    // Get stored challenge
    const challengeKey = `auth:${expectedChallenge}`;
    const storedChallenge = pendingChallenges.get(challengeKey);

    if (!storedChallenge) {
      return { success: false, error: 'No authentication challenge found' };
    }

    if (Date.now() > storedChallenge.expires) {
      pendingChallenges.delete(challengeKey);
      return { success: false, error: 'Authentication challenge expired' };
    }

    // Look up credential
    const credentialId = response.id;
    const credential = this.db.getPasskeyCredential(credentialId);

    if (!credential) {
      return { success: false, error: 'Unknown credential' };
    }

    try {
      const verification: VerifiedAuthenticationResponse = await verifyAuthenticationResponse({
        response,
        expectedChallenge: storedChallenge.challenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpID,
        authenticator: {
          credentialID: credential.id,
          credentialPublicKey: Buffer.from(credential.public_key, 'base64'),
          counter: credential.counter,
          transports: credential.transports as AuthenticatorTransportFuture[] | undefined,
        },
        requireUserVerification: false,
      });

      if (!verification.verified) {
        return { success: false, error: 'Verification failed' };
      }

      // Update counter
      this.db.updatePasskeyCounter(credential.id, verification.authenticationInfo.newCounter);

      // Clean up challenge
      pendingChallenges.delete(challengeKey);

      return {
        success: true,
        did: credential.did,
        handle: credential.handle,
      };
    } catch (error) {
      console.error('[Passkey] Authentication verification error:', error);
      return { success: false, error: error instanceof Error ? error.message : 'Verification failed' };
    }
  }

  /**
   * List passkeys for a user
   */
  listPasskeys(did: string): PasskeyListItem[] {
    const credentials = this.db.getPasskeyCredentialsByDid(did);
    return credentials.map((cred) => ({
      id: cred.id,
      name: cred.name,
      device_type: cred.device_type,
      backed_up: cred.backed_up,
      last_used_at: cred.last_used_at?.toISOString() ?? null,
      created_at: cred.created_at.toISOString(),
    }));
  }

  /**
   * Rename a passkey
   */
  renamePasskey(did: string, credentialId: string, name: string): boolean {
    const credential = this.db.getPasskeyCredential(credentialId);
    if (!credential || credential.did !== did) {
      return false;
    }
    this.db.renamePasskey(credentialId, name);
    return true;
  }

  /**
   * Delete a passkey
   */
  deletePasskey(did: string, credentialId: string): boolean {
    const credential = this.db.getPasskeyCredential(credentialId);
    if (!credential || credential.did !== did) {
      return false;
    }
    this.db.deletePasskeyCredential(credentialId);
    return true;
  }

  /**
   * Get passkey count for a user
   */
  getPasskeyCount(did: string): number {
    return this.db.countPasskeysByDid(did);
  }

  /**
   * Check if user has any passkeys
   */
  hasPasskeys(did: string): boolean {
    return this.getPasskeyCount(did) > 0;
  }
}

// Cleanup expired challenges periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of pendingChallenges.entries()) {
    if (now > value.expires) {
      pendingChallenges.delete(key);
    }
  }
}, 60 * 1000); // Every minute
