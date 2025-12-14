//! Token verification and payload types.
//!
//! This module provides secure token verification using HMAC-SHA256 with
//! constant-time comparison to prevent timing attacks.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{AuthError, AuthResult};
use crate::validation::{validate_did, validate_handle};
use crate::{MAX_TOKEN_LENGTH, MIN_SECRET_LENGTH};

type HmacSha256 = Hmac<Sha256>;

/// Payload contained within an AT Protocol authentication token.
///
/// This struct represents the decoded and verified contents of a token
/// issued by an AT Protocol auth gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPayload {
    /// Decentralized Identifier (e.g., "did:plc:abc123")
    pub did: String,

    /// AT Protocol handle (e.g., "user.bsky.social")
    pub handle: String,

    /// Application-specific user ID (optional, -1 or None if not linked)
    #[serde(default)]
    pub user_id: Option<i64>,

    /// Application/game identifier
    #[serde(default)]
    pub app_id: Option<String>,

    /// Token issued-at timestamp (Unix seconds)
    pub iat: i64,

    /// Token expiration timestamp (Unix seconds)
    pub exp: i64,

    /// Unique nonce for this token
    pub nonce: String,

    /// Additional custom claims (application-specific)
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

impl TokenPayload {
    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        now >= self.exp
    }

    /// Get the remaining validity time in seconds
    pub fn remaining_seconds(&self) -> i64 {
        let now = chrono::Utc::now().timestamp();
        (self.exp - now).max(0)
    }

    /// Get the token age in seconds since issuance
    pub fn age_seconds(&self) -> i64 {
        let now = chrono::Utc::now().timestamp();
        (now - self.iat).max(0)
    }
}

/// Token verifier for AT Protocol authentication tokens.
///
/// Uses HMAC-SHA256 with constant-time comparison for secure verification.
///
/// # Example
///
/// ```rust
/// use atauth::TokenVerifier;
///
/// let verifier = TokenVerifier::new(b"your-shared-secret");
///
/// match verifier.verify("payload.signature") {
///     Ok(payload) => println!("Valid token for: {}", payload.handle),
///     Err(e) => eprintln!("Invalid token: {}", e),
/// }
/// ```
#[derive(Clone)]
pub struct TokenVerifier {
    secret: Vec<u8>,
    /// Whether to validate DID and handle formats (default: true)
    pub validate_formats: bool,
    /// Clock skew tolerance in seconds (default: 30)
    pub clock_skew_seconds: i64,
}

impl TokenVerifier {
    /// Create a new token verifier with the given HMAC secret.
    ///
    /// The secret must be at least 32 bytes (256 bits) for security.
    /// Use a cryptographically random value shared between your
    /// application and the auth gateway.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret is shorter than 32 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use atauth::TokenVerifier;
    ///
    /// // Good: 32+ byte secret
    /// let verifier = TokenVerifier::new(b"a]j2k#9xLmN!pQ4rS7tU0vW3yZ6bC8dE").unwrap();
    ///
    /// // Bad: Too short (will error)
    /// assert!(TokenVerifier::new(b"short").is_err());
    /// ```
    pub fn new(secret: &[u8]) -> AuthResult<Self> {
        if secret.len() < MIN_SECRET_LENGTH {
            return Err(AuthError::InvalidFormat(format!(
                "Secret key must be at least {} bytes ({} bits) for security. Got {} bytes.",
                MIN_SECRET_LENGTH,
                MIN_SECRET_LENGTH * 8,
                secret.len()
            )));
        }
        Ok(Self {
            secret: secret.to_vec(),
            validate_formats: true,
            clock_skew_seconds: 30,
        })
    }

    /// Create a token verifier without checking secret length.
    ///
    /// **Warning**: This bypasses the minimum key length check. Only use this
    /// for testing or when you have validated the key length yourself.
    ///
    /// For production code, prefer `new()` which enforces security requirements.
    pub fn new_unchecked(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            validate_formats: true,
            clock_skew_seconds: 30,
        }
    }

    /// Create a verifier from a hex-encoded secret string.
    ///
    /// The decoded secret must be at least 32 bytes.
    pub fn from_hex(hex_secret: &str) -> AuthResult<Self> {
        let secret = hex::decode(hex_secret)
            .map_err(|e| AuthError::InvalidFormat(format!("Invalid hex secret: {}", e)))?;
        Self::new(&secret)
    }

    /// Create a verifier from a base64-encoded secret string.
    ///
    /// The decoded secret must be at least 32 bytes.
    pub fn from_base64(b64_secret: &str) -> AuthResult<Self> {
        let secret = URL_SAFE_NO_PAD
            .decode(b64_secret)
            .map_err(|e| AuthError::InvalidFormat(format!("Invalid base64 secret: {}", e)))?;
        Self::new(&secret)
    }

    /// Set whether to validate DID and handle formats.
    pub fn with_format_validation(mut self, validate: bool) -> Self {
        self.validate_formats = validate;
        self
    }

    /// Set clock skew tolerance in seconds.
    pub fn with_clock_skew(mut self, seconds: i64) -> Self {
        self.clock_skew_seconds = seconds;
        self
    }

    /// Verify a token and return the decoded payload.
    ///
    /// Token format: `base64url(JSON_payload).base64url(HMAC_SHA256)`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Token format is invalid
    /// - Signature verification fails
    /// - Token has expired
    /// - Payload validation fails
    pub fn verify(&self, token: &str) -> AuthResult<TokenPayload> {
        // Length check to prevent DoS
        if token.len() > MAX_TOKEN_LENGTH {
            return Err(AuthError::InvalidFormat(format!(
                "Token exceeds maximum length of {} bytes",
                MAX_TOKEN_LENGTH
            )));
        }

        // Split token into payload and signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidFormat(
                "Token must have format: payload.signature".to_string(),
            ));
        }

        let payload_b64 = parts[0];
        let signature_b64 = parts[1];

        // Verify signature using constant-time comparison
        self.verify_signature(payload_b64, signature_b64)?;

        // Decode and parse payload
        let payload = self.decode_payload(payload_b64)?;

        // Validate expiration with clock skew tolerance
        let now = chrono::Utc::now().timestamp();
        if now > payload.exp + self.clock_skew_seconds {
            return Err(AuthError::Expired);
        }

        // Validate DID and handle formats if enabled
        if self.validate_formats {
            validate_did(&payload.did)?;
            validate_handle(&payload.handle)?;
        }

        Ok(payload)
    }

    /// Verify only the signature without checking expiration.
    ///
    /// Useful for inspecting expired tokens or debugging.
    pub fn verify_signature_only(&self, token: &str) -> AuthResult<TokenPayload> {
        if token.len() > MAX_TOKEN_LENGTH {
            return Err(AuthError::InvalidFormat(
                "Token exceeds maximum length".to_string(),
            ));
        }

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidFormat(
                "Token must have format: payload.signature".to_string(),
            ));
        }

        self.verify_signature(parts[0], parts[1])?;
        self.decode_payload(parts[0])
    }

    /// Compute HMAC-SHA256 signature for a payload.
    fn compute_signature(&self, payload_b64: &str) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC can take key of any size");
        mac.update(payload_b64.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify signature using constant-time comparison.
    fn verify_signature(&self, payload_b64: &str, signature_b64: &str) -> AuthResult<()> {
        // Decode provided signature
        let provided_sig = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| AuthError::InvalidFormat("Invalid signature encoding".to_string()))?;

        // Compute expected signature
        let expected_sig = self.compute_signature(payload_b64);

        // Constant-time comparison to prevent timing attacks
        if provided_sig.ct_eq(&expected_sig).into() {
            Ok(())
        } else {
            Err(AuthError::InvalidSignature)
        }
    }

    /// Decode and parse the payload JSON.
    fn decode_payload(&self, payload_b64: &str) -> AuthResult<TokenPayload> {
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| AuthError::InvalidFormat("Invalid payload encoding".to_string()))?;

        let payload_str = String::from_utf8(payload_bytes)
            .map_err(|_| AuthError::InvalidFormat("Payload is not valid UTF-8".to_string()))?;

        serde_json::from_str(&payload_str)
            .map_err(|e| AuthError::InvalidPayload(format!("JSON parse error: {}", e)))
    }

    /// Create a signed token from a payload (for testing or gateway use).
    ///
    /// **Note**: This should typically only be used by the auth gateway,
    /// not by client applications.
    pub fn sign(&self, payload: &TokenPayload) -> AuthResult<String> {
        let payload_json = serde_json::to_string(payload)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize payload: {}", e)))?;

        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signature = self.compute_signature(&payload_b64);
        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", payload_b64, signature_b64))
    }
}

// Add hex dependency for from_hex
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("Invalid hex string length".to_string());
        }

        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("Invalid hex: {}", e))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_payload() -> TokenPayload {
        let now = chrono::Utc::now().timestamp();
        TokenPayload {
            did: "did:plc:testuser123".to_string(),
            handle: "test.bsky.social".to_string(),
            user_id: Some(42),
            app_id: Some("myapp".to_string()),
            iat: now,
            exp: now + 3600, // 1 hour from now
            nonce: "random-nonce-123".to_string(),
            extra: HashMap::new(),
        }
    }

    // Test secret that meets the 32-byte minimum requirement
    const TEST_SECRET: &[u8; 32] = b"test-secret-key-32bytes-long!!!!";
    const TEST_SECRET_2: &[u8; 32] = b"another-secret-32-bytes-long!!!!";

    #[test]
    fn test_sign_and_verify() {
        let verifier = TokenVerifier::new(TEST_SECRET).unwrap();
        let payload = create_test_payload();

        let token = verifier.sign(&payload).unwrap();
        let verified = verifier.verify(&token).unwrap();

        assert_eq!(verified.did, payload.did);
        assert_eq!(verified.handle, payload.handle);
        assert_eq!(verified.user_id, payload.user_id);
    }

    #[test]
    fn test_invalid_signature() {
        let verifier = TokenVerifier::new(TEST_SECRET).unwrap();
        let other_verifier = TokenVerifier::new(TEST_SECRET_2).unwrap();

        let payload = create_test_payload();
        let token = verifier.sign(&payload).unwrap();

        // Verify with wrong secret should fail
        assert!(matches!(
            other_verifier.verify(&token),
            Err(AuthError::InvalidSignature)
        ));
    }

    #[test]
    fn test_secret_too_short() {
        // Secrets shorter than 32 bytes should be rejected
        assert!(TokenVerifier::new(b"short").is_err());
        assert!(TokenVerifier::new(b"").is_err());
        assert!(TokenVerifier::new(b"31-bytes-secret-not-long-enuff").is_err());

        // Exactly 32 bytes should work
        assert!(TokenVerifier::new(b"exactly-32-bytes-secret-here!!!").is_ok());
    }

    #[test]
    fn test_expired_token() {
        let verifier = TokenVerifier::new(TEST_SECRET).unwrap();
        let now = chrono::Utc::now().timestamp();

        let payload = TokenPayload {
            did: "did:plc:test".to_string(),
            handle: "test.bsky.social".to_string(),
            user_id: None,
            app_id: None,
            iat: now - 7200, // 2 hours ago
            exp: now - 3600, // 1 hour ago (expired)
            nonce: "nonce".to_string(),
            extra: HashMap::new(),
        };

        let token = verifier.sign(&payload).unwrap();
        assert!(matches!(verifier.verify(&token), Err(AuthError::Expired)));
    }

    #[test]
    fn test_clock_skew_tolerance() {
        let verifier = TokenVerifier::new(TEST_SECRET).unwrap().with_clock_skew(60);
        let now = chrono::Utc::now().timestamp();

        // Token expired 30 seconds ago (within 60s tolerance)
        let payload = TokenPayload {
            did: "did:plc:test".to_string(),
            handle: "test.bsky.social".to_string(),
            user_id: None,
            app_id: None,
            iat: now - 3600,
            exp: now - 30, // 30 seconds ago
            nonce: "nonce".to_string(),
            extra: HashMap::new(),
        };

        let token = verifier.sign(&payload).unwrap();
        assert!(verifier.verify(&token).is_ok());
    }

    #[test]
    fn test_invalid_format() {
        let verifier = TokenVerifier::new(TEST_SECRET).unwrap();

        // No separator
        assert!(matches!(
            verifier.verify("invalidtoken"),
            Err(AuthError::InvalidFormat(_))
        ));

        // Too many parts
        assert!(matches!(
            verifier.verify("a.b.c"),
            Err(AuthError::InvalidFormat(_))
        ));

        // Invalid base64
        assert!(matches!(
            verifier.verify("!!!.???"),
            Err(AuthError::InvalidFormat(_))
        ));
    }

    #[test]
    fn test_token_too_long() {
        let verifier = TokenVerifier::new(TEST_SECRET).unwrap();
        let long_token = "a".repeat(MAX_TOKEN_LENGTH + 1);

        assert!(matches!(
            verifier.verify(&long_token),
            Err(AuthError::InvalidFormat(_))
        ));
    }

    #[test]
    fn test_payload_methods() {
        let now = chrono::Utc::now().timestamp();
        let payload = TokenPayload {
            did: "did:plc:test".to_string(),
            handle: "test.bsky.social".to_string(),
            user_id: None,
            app_id: None,
            iat: now - 100,
            exp: now + 100,
            nonce: "nonce".to_string(),
            extra: HashMap::new(),
        };

        assert!(!payload.is_expired());
        assert!(payload.remaining_seconds() > 0);
        assert!(payload.age_seconds() >= 100);
    }
}
