//! Input validation utilities for AT Protocol identifiers.
//!
//! This module provides validation functions for DIDs (Decentralized Identifiers)
//! and handles according to AT Protocol specifications.

use crate::error::{AuthError, AuthResult};
use crate::{MAX_DID_LENGTH, MAX_HANDLE_LENGTH};

/// Validate a Decentralized Identifier (DID).
///
/// DIDs must:
/// - Start with "did:"
/// - Be between 1 and 512 characters
/// - Follow the DID syntax (did:method:identifier)
///
/// # Examples
///
/// ```rust
/// use atauth::validate_did;
///
/// // Valid DIDs
/// assert!(validate_did("did:plc:z72i7hdynmk6r22z27h6tvur").is_ok());
/// assert!(validate_did("did:web:example.com").is_ok());
///
/// // Invalid DIDs
/// assert!(validate_did("not-a-did").is_err());
/// assert!(validate_did("").is_err());
/// ```
pub fn validate_did(did: &str) -> AuthResult<()> {
    // Check length
    if did.is_empty() {
        return Err(AuthError::InvalidDid("DID cannot be empty".to_string()));
    }

    if did.len() > MAX_DID_LENGTH {
        return Err(AuthError::InvalidDid(format!(
            "DID exceeds maximum length of {} characters",
            MAX_DID_LENGTH
        )));
    }

    // Check prefix
    if !did.starts_with("did:") {
        return Err(AuthError::InvalidDid(
            "DID must start with 'did:'".to_string(),
        ));
    }

    // Check for method component
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 3 {
        return Err(AuthError::InvalidDid(
            "DID must have format 'did:method:identifier'".to_string(),
        ));
    }

    // Validate method (second part)
    let method = parts[1];
    if method.is_empty() {
        return Err(AuthError::InvalidDid(
            "DID method cannot be empty".to_string(),
        ));
    }

    // Method should only contain lowercase letters
    if !method.chars().all(|c| c.is_ascii_lowercase()) {
        return Err(AuthError::InvalidDid(
            "DID method must contain only lowercase letters".to_string(),
        ));
    }

    // Validate identifier (third part)
    let identifier = parts[2..].join(":");
    if identifier.is_empty() {
        return Err(AuthError::InvalidDid(
            "DID identifier cannot be empty".to_string(),
        ));
    }

    // Check for invalid characters in identifier
    // AT Protocol DIDs typically use alphanumeric characters plus some special chars
    if !identifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == ':')
    {
        return Err(AuthError::InvalidDid(
            "DID identifier contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validate an AT Protocol handle.
///
/// Handles must:
/// - Contain at least one dot (domain separator)
/// - Be between 1 and 256 characters
/// - Follow DNS name conventions
///
/// # Examples
///
/// ```rust
/// use atauth::validate_handle;
///
/// // Valid handles
/// assert!(validate_handle("alice.bsky.social").is_ok());
/// assert!(validate_handle("bob.example.com").is_ok());
///
/// // Invalid handles
/// assert!(validate_handle("nodomain").is_err());
/// assert!(validate_handle("").is_err());
/// ```
pub fn validate_handle(handle: &str) -> AuthResult<()> {
    // Check length
    if handle.is_empty() {
        return Err(AuthError::InvalidHandle(
            "Handle cannot be empty".to_string(),
        ));
    }

    if handle.len() > MAX_HANDLE_LENGTH {
        return Err(AuthError::InvalidHandle(format!(
            "Handle exceeds maximum length of {} characters",
            MAX_HANDLE_LENGTH
        )));
    }

    // Check for domain separator
    if !handle.contains('.') {
        return Err(AuthError::InvalidHandle(
            "Handle must contain a domain (at least one dot)".to_string(),
        ));
    }

    // Split into parts
    let parts: Vec<&str> = handle.split('.').collect();

    // Check each label
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err(AuthError::InvalidHandle(
                "Handle contains empty label (consecutive dots)".to_string(),
            ));
        }

        // Each label should be max 63 characters (DNS limit)
        if part.len() > 63 {
            return Err(AuthError::InvalidHandle(
                "Handle label exceeds 63 characters".to_string(),
            ));
        }

        // First and last parts shouldn't start or end with hyphen
        if part.starts_with('-') || part.ends_with('-') {
            return Err(AuthError::InvalidHandle(
                "Handle labels cannot start or end with hyphen".to_string(),
            ));
        }

        // Check valid characters (alphanumeric and hyphen)
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(AuthError::InvalidHandle(
                "Handle contains invalid characters".to_string(),
            ));
        }

        // First part (username) should start with letter or number
        if i == 0
            && !part
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
        {
            return Err(AuthError::InvalidHandle(
                "Handle must start with letter or number".to_string(),
            ));
        }
    }

    // TLD validation (last part should be at least 2 chars)
    if let Some(tld) = parts.last() {
        if tld.len() < 2 {
            return Err(AuthError::InvalidHandle(
                "Handle TLD must be at least 2 characters".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate a nonce string.
///
/// Nonces should be:
/// - Non-empty
/// - Maximum 64 characters
/// - Alphanumeric with hyphens and underscores
pub fn validate_nonce(nonce: &str) -> AuthResult<()> {
    const MAX_NONCE_LENGTH: usize = 64;

    if nonce.is_empty() {
        return Err(AuthError::InvalidPayload(
            "Nonce cannot be empty".to_string(),
        ));
    }

    if nonce.len() > MAX_NONCE_LENGTH {
        return Err(AuthError::InvalidPayload(format!(
            "Nonce exceeds maximum length of {} characters",
            MAX_NONCE_LENGTH
        )));
    }

    if !nonce
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AuthError::InvalidPayload(
            "Nonce contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // DID Tests
    #[test]
    fn test_valid_dids() {
        assert!(validate_did("did:plc:z72i7hdynmk6r22z27h6tvur").is_ok());
        assert!(validate_did("did:web:example.com").is_ok());
        assert!(validate_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_ok());
    }

    #[test]
    fn test_invalid_dids() {
        // Empty
        assert!(validate_did("").is_err());

        // No prefix
        assert!(validate_did("plc:test").is_err());

        // Wrong prefix
        assert!(validate_did("DID:plc:test").is_err());

        // No method
        assert!(validate_did("did::test").is_err());

        // No identifier
        assert!(validate_did("did:plc").is_err());

        // Too long
        let long_did = format!("did:plc:{}", "a".repeat(600));
        assert!(validate_did(&long_did).is_err());
    }

    // Handle Tests
    #[test]
    fn test_valid_handles() {
        assert!(validate_handle("alice.bsky.social").is_ok());
        assert!(validate_handle("bob.example.com").is_ok());
        assert!(validate_handle("user-123.test.org").is_ok());
        assert!(validate_handle("a.bc").is_ok());
    }

    #[test]
    fn test_invalid_handles() {
        // Empty
        assert!(validate_handle("").is_err());

        // No domain
        assert!(validate_handle("nodomain").is_err());

        // Starts with hyphen
        assert!(validate_handle("-alice.example.com").is_err());

        // Ends with hyphen
        assert!(validate_handle("alice-.example.com").is_err());

        // Invalid characters
        assert!(validate_handle("alice@example.com").is_err());

        // Empty label
        assert!(validate_handle("alice..example.com").is_err());

        // TLD too short
        assert!(validate_handle("alice.a").is_err());

        // Too long
        let long_handle = format!("{}.example.com", "a".repeat(300));
        assert!(validate_handle(&long_handle).is_err());
    }

    // Nonce Tests
    #[test]
    fn test_valid_nonces() {
        assert!(validate_nonce("abc123").is_ok());
        assert!(validate_nonce("test-nonce_123").is_ok());
        assert!(validate_nonce("a").is_ok());
    }

    #[test]
    fn test_invalid_nonces() {
        assert!(validate_nonce("").is_err());
        assert!(validate_nonce(&"a".repeat(100)).is_err());
        assert!(validate_nonce("nonce with spaces").is_err());
        assert!(validate_nonce("nonce!@#").is_err());
    }
}
