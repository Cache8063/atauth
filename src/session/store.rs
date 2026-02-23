//! Session storage trait and session types.

use crate::error::{AuthError, AuthResult};
use crate::token::TokenPayload;
use serde::{Deserialize, Serialize};

/// Represents an authenticated session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session token (typically the original auth token or a derived session ID)
    pub token: String,

    /// User's DID
    pub did: String,

    /// User's handle
    pub handle: String,

    /// Application-specific user ID
    pub user_id: Option<i64>,

    /// When the session expires (Unix timestamp)
    pub expires_at: i64,

    /// When the session was created (Unix timestamp)
    pub created_at: i64,

    /// Optional metadata
    pub metadata: Option<serde_json::Value>,
}

impl Session {
    /// Create a new session from a verified token payload.
    pub fn from_payload(payload: &TokenPayload, token: String) -> Self {
        Self {
            token,
            did: payload.did.clone(),
            handle: payload.handle.clone(),
            user_id: payload.user_id,
            expires_at: payload.exp,
            created_at: chrono::Utc::now().timestamp(),
            metadata: None,
        }
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        now >= self.expires_at
    }

    /// Get remaining session time in seconds.
    pub fn remaining_seconds(&self) -> i64 {
        let now = chrono::Utc::now().timestamp();
        (self.expires_at - now).max(0)
    }
}

/// Trait for session storage backends.
///
/// Implement this trait to use custom storage backends (Redis, DynamoDB, etc.).
///
/// # Example
///
/// ```rust,ignore
/// use atauth::session::{SessionStore, Session};
/// use atauth::error::AuthResult;
///
/// struct MySessionStore {
///     // Your storage implementation
/// }
///
/// impl SessionStore for MySessionStore {
///     fn create(&self, session: &Session) -> AuthResult<()> {
///         // Store the session
///         Ok(())
///     }
///     // ... implement other methods
/// }
/// ```
pub trait SessionStore: Send + Sync {
    /// Create or update a session.
    fn upsert(&self, session: &Session) -> AuthResult<()>;

    /// Get a session by token.
    fn get(&self, token: &str) -> AuthResult<Option<Session>>;

    /// Get a session by token, returning an error if not found or expired.
    fn get_valid(&self, token: &str) -> AuthResult<Session> {
        match self.get(token)? {
            Some(session) if session.is_expired() => Err(AuthError::SessionExpired),
            Some(session) => Ok(session),
            None => Err(AuthError::SessionNotFound),
        }
    }

    /// Delete a session by token.
    fn delete(&self, token: &str) -> AuthResult<bool>;

    /// Delete all sessions for a user (by DID).
    fn delete_by_did(&self, did: &str) -> AuthResult<u64>;

    /// Delete all sessions for a user_id.
    fn delete_by_user_id(&self, user_id: i64) -> AuthResult<u64>;

    /// Get all sessions for a user (by DID).
    fn get_by_did(&self, did: &str) -> AuthResult<Vec<Session>>;

    /// Get all sessions for a user_id.
    fn get_by_user_id(&self, user_id: i64) -> AuthResult<Vec<Session>>;

    /// Extend a session's expiration time.
    fn extend(&self, token: &str, new_expires_at: i64) -> AuthResult<bool>;

    /// Remove all expired sessions.
    fn cleanup_expired(&self) -> AuthResult<u64>;

    /// Count active (non-expired) sessions.
    fn count_active(&self) -> AuthResult<u64>;
}

/// High-level session manager wrapping a SessionStore.
///
/// Provides convenient methods for common session operations.
pub struct SessionManager<S: SessionStore> {
    store: S,
    /// Default session duration in seconds (default: 24 hours)
    pub default_duration: i64,
    /// Whether to automatically extend sessions on access
    pub auto_extend: bool,
    /// Extension duration in seconds when auto_extend is true
    pub extension_duration: i64,
}

impl<S: SessionStore> SessionManager<S> {
    /// Create a new session manager with the given store.
    pub fn new(store: S) -> Self {
        Self {
            store,
            default_duration: 86400, // 24 hours
            auto_extend: false,
            extension_duration: 3600, // 1 hour
        }
    }

    /// Set default session duration.
    pub fn with_default_duration(mut self, seconds: i64) -> Self {
        self.default_duration = seconds;
        self
    }

    /// Enable auto-extension of sessions on access.
    pub fn with_auto_extend(mut self, extend: bool, extension_seconds: i64) -> Self {
        self.auto_extend = extend;
        self.extension_duration = extension_seconds;
        self
    }

    /// Create a session from a verified token payload.
    pub fn create_session(&self, payload: &TokenPayload, token: String) -> AuthResult<Session> {
        let session = Session::from_payload(payload, token);
        self.store.upsert(&session)?;
        Ok(session)
    }

    /// Create a session with custom expiration.
    pub fn create_session_with_expiry(
        &self,
        payload: &TokenPayload,
        token: String,
        expires_at: i64,
    ) -> AuthResult<Session> {
        let mut session = Session::from_payload(payload, token);
        session.expires_at = expires_at;
        self.store.upsert(&session)?;
        Ok(session)
    }

    /// Validate and optionally extend a session.
    pub fn validate(&self, token: &str) -> AuthResult<Session> {
        let session = self.store.get_valid(token)?;

        // Auto-extend if enabled and session is valid
        if self.auto_extend {
            let now = chrono::Utc::now().timestamp();
            let new_expires = now + self.extension_duration;
            if new_expires > session.expires_at {
                self.store.extend(token, new_expires)?;
            }
        }

        Ok(session)
    }

    /// Invalidate (delete) a session.
    pub fn invalidate(&self, token: &str) -> AuthResult<bool> {
        self.store.delete(token)
    }

    /// Invalidate all sessions for a user.
    pub fn invalidate_all_for_did(&self, did: &str) -> AuthResult<u64> {
        self.store.delete_by_did(did)
    }

    /// Invalidate all sessions for a user_id.
    pub fn invalidate_all_for_user(&self, user_id: i64) -> AuthResult<u64> {
        self.store.delete_by_user_id(user_id)
    }

    /// Get all active sessions for a user.
    pub fn get_user_sessions(&self, did: &str) -> AuthResult<Vec<Session>> {
        self.store.get_by_did(did)
    }

    /// Run cleanup to remove expired sessions.
    pub fn cleanup(&self) -> AuthResult<u64> {
        self.store.cleanup_expired()
    }

    /// Get underlying store reference.
    pub fn store(&self) -> &S {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_payload() -> TokenPayload {
        let now = chrono::Utc::now().timestamp();
        TokenPayload {
            did: "did:plc:testuser".to_string(),
            handle: "test.bsky.social".to_string(),
            user_id: Some(42),
            app_id: Some("test".to_string()),
            iat: now,
            exp: now + 3600,
            nonce: "test-nonce".to_string(),
            extra: HashMap::new(),
        }
    }

    #[test]
    fn test_session_from_payload() {
        let payload = create_test_payload();
        let session = Session::from_payload(&payload, "test-token".to_string());

        assert_eq!(session.did, payload.did);
        assert_eq!(session.handle, payload.handle);
        assert_eq!(session.user_id, payload.user_id);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_expiry() {
        let now = chrono::Utc::now().timestamp();
        let session = Session {
            token: "test".to_string(),
            did: "did:plc:test".to_string(),
            handle: "test.example.com".to_string(),
            user_id: None,
            expires_at: now - 100, // Expired 100 seconds ago
            created_at: now - 200,
            metadata: None,
        };

        assert!(session.is_expired());
        assert_eq!(session.remaining_seconds(), 0);
    }
}
