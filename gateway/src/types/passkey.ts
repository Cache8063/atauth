/**
 * Passkey/WebAuthn Types
 *
 * Types for WebAuthn/FIDO2 passkey authentication
 */

/** Passkey credential stored in database */
export interface PasskeyCredential {
  id: string;
  did: string;
  handle: string;
  public_key: string;
  counter: number;
  device_type: 'platform' | 'cross-platform' | null;
  backed_up: boolean;
  transports: string[] | null;
  name: string | null;
  created_at: Date;
  last_used_at: Date | null;
}

/** Passkey list item (for API response) */
export interface PasskeyListItem {
  id: string;
  name: string | null;
  device_type: string | null;
  backed_up: boolean;
  last_used_at: string | null;
  created_at: string;
}

/** Registration options request */
export interface PasskeyRegistrationOptionsRequest {
  /** User's DID */
  did: string;
  /** User's handle */
  handle: string;
}

/** Registration verification request */
export interface PasskeyRegistrationVerifyRequest {
  credential: {
    id: string;
    rawId: string;
    response: {
      clientDataJSON: string;
      attestationObject: string;
      transports?: string[];
    };
    type: 'public-key';
    clientExtensionResults?: Record<string, unknown>;
    authenticatorAttachment?: string;
  };
  name?: string;
}

/** Authentication options request */
export interface PasskeyAuthenticationOptionsRequest {
  /** Optional: User's DID for conditional UI */
  did?: string;
}

/** Authentication verification request */
export interface PasskeyAuthenticationVerifyRequest {
  credential: {
    id: string;
    rawId: string;
    response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
      userHandle?: string;
    };
    type: 'public-key';
    clientExtensionResults?: Record<string, unknown>;
    authenticatorAttachment?: string;
  };
}

/** Registration result */
export interface PasskeyRegistrationResult {
  success: boolean;
  passkey_id?: string;
  error?: string;
}

/** Authentication result */
export interface PasskeyAuthenticationResult {
  success: boolean;
  did?: string;
  handle?: string;
  error?: string;
}
