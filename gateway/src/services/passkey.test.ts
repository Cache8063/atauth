import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PasskeyService } from './passkey.js';
import { DatabaseService } from './database.js';

// Mock @simplewebauthn/server
vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: vi.fn().mockResolvedValue({
    challenge: 'mock-challenge-registration',
    rp: { name: 'Test', id: 'localhost' },
    user: { id: 'dGVzdA', name: 'test', displayName: 'test' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
  }),
  verifyRegistrationResponse: vi.fn().mockResolvedValue({
    verified: true,
    registrationInfo: {
      credentialID: 'cred-id-123',
      credentialPublicKey: Buffer.from('public-key-bytes'),
      counter: 0,
      credentialDeviceType: 'singleDevice',
      credentialBackedUp: false,
    },
  }),
  generateAuthenticationOptions: vi.fn().mockResolvedValue({
    challenge: 'mock-challenge-authentication',
    rpId: 'localhost',
    allowCredentials: [],
    userVerification: 'preferred',
  }),
  verifyAuthenticationResponse: vi.fn().mockResolvedValue({
    verified: true,
    authenticationInfo: {
      newCounter: 1,
      credentialID: 'cred-id-123',
    },
  }),
}));

const PASSKEY_CONFIG = {
  rpName: 'Test RP',
  rpID: 'localhost',
  origin: 'http://localhost:3000',
};

describe('PasskeyService', () => {
  let db: DatabaseService;
  let service: PasskeyService;

  beforeEach(() => {
    db = new DatabaseService(':memory:');
    service = new PasskeyService(db, PASSKEY_CONFIG);
  });

  afterEach(() => {
    db.close();
    vi.clearAllMocks();
  });

  describe('generateRegistrationOptions', () => {
    it('should return registration options', async () => {
      const options = await service.generateRegistrationOptions('did:plc:test', 'test.bsky.social');
      expect(options).toBeDefined();
      expect(options.challenge).toBe('mock-challenge-registration');
    });

    it('should exclude existing credentials', async () => {
      // Save an existing credential
      db.savePasskeyCredential({
        id: 'existing-cred',
        did: 'did:plc:test',
        handle: 'test.bsky.social',
        public_key: Buffer.from('key').toString('base64'),
        counter: 0,
        device_type: 'platform',
        backed_up: false,
        transports: null,
        name: null,
      });

      await service.generateRegistrationOptions('did:plc:test', 'test.bsky.social');

      const { generateRegistrationOptions } = await import('@simplewebauthn/server');
      expect(generateRegistrationOptions).toHaveBeenCalledWith(
        expect.objectContaining({
          excludeCredentials: expect.arrayContaining([
            expect.objectContaining({ id: 'existing-cred' }),
          ]),
        })
      );
    });
  });

  describe('verifyRegistration', () => {
    it('should verify and store a credential', async () => {
      // First generate options to store challenge
      await service.generateRegistrationOptions('did:plc:test', 'test.bsky.social');

      const result = await service.verifyRegistration(
        'did:plc:test',
        'test.bsky.social',
        { id: 'cred-1', rawId: 'raw', response: { clientDataJSON: 'x', attestationObject: 'y', transports: ['internal'] }, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' },
        'My Passkey',
      );

      expect(result.success).toBe(true);
      expect(result.credentialId).toBe('cred-id-123');

      // Credential should be stored in DB
      const stored = db.getPasskeyCredential('cred-id-123');
      expect(stored).not.toBeNull();
      expect(stored!.did).toBe('did:plc:test');
    });

    it('should return error when no challenge exists', async () => {
      const result = await service.verifyRegistration(
        'did:plc:unknown',
        'unknown',
        { id: 'x', rawId: 'x', response: { clientDataJSON: 'x', attestationObject: 'y' }, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('No registration challenge');
    });

    it('should return error when challenge is expired', async () => {
      vi.useFakeTimers();
      const now = Date.now();
      vi.setSystemTime(now);

      await service.generateRegistrationOptions('did:plc:test', 'test.bsky.social');

      // Advance past 5 minute expiry
      vi.setSystemTime(now + 6 * 60 * 1000);

      const result = await service.verifyRegistration(
        'did:plc:test',
        'test.bsky.social',
        { id: 'x', rawId: 'x', response: { clientDataJSON: 'x', attestationObject: 'y' }, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' } as any,
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('expired');

      vi.useRealTimers();
    });
  });

  describe('generateAuthenticationOptions', () => {
    it('should generate options without DID (discoverable)', async () => {
      const options = await service.generateAuthenticationOptions();
      expect(options).toBeDefined();
      expect(options.challenge).toBe('mock-challenge-authentication');
    });

    it('should include credentials when DID provided', async () => {
      db.savePasskeyCredential({
        id: 'user-cred',
        did: 'did:plc:test',
        handle: 'test.bsky.social',
        public_key: Buffer.from('key').toString('base64'),
        counter: 0,
        device_type: 'platform',
        backed_up: false,
        transports: ['internal'],
        name: null,
      });

      await service.generateAuthenticationOptions('did:plc:test');

      const { generateAuthenticationOptions } = await import('@simplewebauthn/server');
      expect(generateAuthenticationOptions).toHaveBeenCalledWith(
        expect.objectContaining({
          allowCredentials: expect.arrayContaining([
            expect.objectContaining({ id: 'user-cred' }),
          ]),
        })
      );
    });
  });

  describe('verifyAuthentication', () => {
    it('should verify and return user info', async () => {
      // Store credential
      db.savePasskeyCredential({
        id: 'cred-id-123',
        did: 'did:plc:test',
        handle: 'test.bsky.social',
        public_key: Buffer.from('key').toString('base64'),
        counter: 0,
        device_type: 'platform',
        backed_up: false,
        transports: null,
        name: null,
      });

      // Generate options to store challenge
      await service.generateAuthenticationOptions();

      const result = await service.verifyAuthentication(
        { id: 'cred-id-123', rawId: 'raw', response: { clientDataJSON: 'x', authenticatorData: 'y', signature: 'z' }, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' },
        'mock-challenge-authentication',
      );

      expect(result.success).toBe(true);
      expect(result.did).toBe('did:plc:test');
      expect(result.handle).toBe('test.bsky.social');
    });

    it('should return error for unknown credential', async () => {
      await service.generateAuthenticationOptions();

      const result = await service.verifyAuthentication(
        { id: 'unknown-cred', rawId: 'raw', response: { clientDataJSON: 'x', authenticatorData: 'y', signature: 'z' }, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' },
        'mock-challenge-authentication',
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Unknown credential');
    });

    it('should return error when no challenge exists', async () => {
      const result = await service.verifyAuthentication(
        { id: 'x', rawId: 'raw', response: { clientDataJSON: 'x', authenticatorData: 'y', signature: 'z' }, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform' },
        'nonexistent-challenge',
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('No authentication challenge');
    });
  });

  describe('listPasskeys', () => {
    it('should list passkeys for a user', () => {
      db.savePasskeyCredential({
        id: 'cred-1',
        did: 'did:plc:test',
        handle: 'test.bsky.social',
        public_key: Buffer.from('key1').toString('base64'),
        counter: 0,
        device_type: 'platform',
        backed_up: true,
        transports: ['internal'],
        name: 'My Macbook',
      });

      db.savePasskeyCredential({
        id: 'cred-2',
        did: 'did:plc:test',
        handle: 'test.bsky.social',
        public_key: Buffer.from('key2').toString('base64'),
        counter: 0,
        device_type: 'cross-platform',
        backed_up: false,
        transports: ['usb'],
        name: 'YubiKey',
      });

      const passkeys = service.listPasskeys('did:plc:test');
      expect(passkeys).toHaveLength(2);
      expect(passkeys[0].name).toBe('My Macbook');
      expect(passkeys[1].name).toBe('YubiKey');
    });

    it('should return empty array for user with no passkeys', () => {
      const passkeys = service.listPasskeys('did:plc:nobody');
      expect(passkeys).toEqual([]);
    });
  });

  describe('renamePasskey', () => {
    it('should rename an existing passkey', () => {
      db.savePasskeyCredential({
        id: 'cred-1',
        did: 'did:plc:test',
        handle: 'test.bsky.social',
        public_key: Buffer.from('key').toString('base64'),
        counter: 0,
        device_type: 'platform',
        backed_up: false,
        transports: null,
        name: 'Old Name',
      });

      const result = service.renamePasskey('did:plc:test', 'cred-1', 'New Name');
      expect(result).toBe(true);
    });

    it('should return false for wrong DID', () => {
      db.savePasskeyCredential({
        id: 'cred-1',
        did: 'did:plc:other',
        handle: 'other.bsky.social',
        public_key: Buffer.from('key').toString('base64'),
        counter: 0,
        device_type: 'platform',
        backed_up: false,
        transports: null,
        name: null,
      });

      const result = service.renamePasskey('did:plc:test', 'cred-1', 'New Name');
      expect(result).toBe(false);
    });

    it('should return false for nonexistent credential', () => {
      const result = service.renamePasskey('did:plc:test', 'nonexistent', 'Name');
      expect(result).toBe(false);
    });
  });

  describe('deletePasskey', () => {
    it('should delete an existing passkey', () => {
      db.savePasskeyCredential({
        id: 'cred-1',
        did: 'did:plc:test',
        handle: 'test.bsky.social',
        public_key: Buffer.from('key').toString('base64'),
        counter: 0,
        device_type: 'platform',
        backed_up: false,
        transports: null,
        name: null,
      });

      const result = service.deletePasskey('did:plc:test', 'cred-1');
      expect(result).toBe(true);
      expect(db.getPasskeyCredential('cred-1')).toBeNull();
    });

    it('should return false for wrong DID', () => {
      db.savePasskeyCredential({
        id: 'cred-1',
        did: 'did:plc:other',
        handle: 'other',
        public_key: Buffer.from('key').toString('base64'),
        counter: 0,
        device_type: 'platform',
        backed_up: false,
        transports: null,
        name: null,
      });

      const result = service.deletePasskey('did:plc:test', 'cred-1');
      expect(result).toBe(false);
    });
  });

  describe('hasPasskeys / getPasskeyCount', () => {
    it('should return false and 0 for user with no passkeys', () => {
      expect(service.hasPasskeys('did:plc:nobody')).toBe(false);
      expect(service.getPasskeyCount('did:plc:nobody')).toBe(0);
    });

    it('should return true and correct count', () => {
      db.savePasskeyCredential({
        id: 'cred-1',
        did: 'did:plc:test',
        handle: 'test',
        public_key: Buffer.from('key').toString('base64'),
        counter: 0,
        device_type: 'platform',
        backed_up: false,
        transports: null,
        name: null,
      });

      expect(service.hasPasskeys('did:plc:test')).toBe(true);
      expect(service.getPasskeyCount('did:plc:test')).toBe(1);
    });
  });
});
