//! Error types for the ATAuth library.

use thiserror::Error;

/// Result type alias for ATAuth operations
pub type AuthResult<T> = Result<T, AuthError>;

/// Authentication and authorization errors
#[derive(Debug, Error)]
pub enum AuthError {
    /// Token format is invalid (wrong structure, not base64, etc.)
    #[error("Invalid token format: {0}")]
    InvalidFormat(String),

    /// Token signature verification failed
    #[error("Invalid token signature")]
    InvalidSignature,

    /// Token has expired
    #[error("Token has expired")]
    Expired,

    /// Token payload is invalid (missing fields, wrong types, etc.)
    #[error("Invalid token payload: {0}")]
    InvalidPayload(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded, retry after {0} seconds")]
    RateLimited(u64),

    /// DID format is invalid
    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    /// Handle format is invalid
    #[error("Invalid handle format: {0}")]
    InvalidHandle(String),

    /// Session not found
    #[error("Session not found")]
    SessionNotFound,

    /// Session has expired
    #[error("Session has expired")]
    SessionExpired,

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AuthError {
    /// Returns true if this error indicates the token itself is invalid
    /// (as opposed to expired or rate limited)
    pub fn is_invalid_token(&self) -> bool {
        matches!(
            self,
            AuthError::InvalidFormat(_) | AuthError::InvalidSignature | AuthError::InvalidPayload(_)
        )
    }

    /// Returns true if this error is due to expiration
    pub fn is_expired(&self) -> bool {
        matches!(self, AuthError::Expired | AuthError::SessionExpired)
    }

    /// Returns true if this error is due to rate limiting
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, AuthError::RateLimited(_))
    }

    /// Returns the HTTP status code appropriate for this error
    pub fn http_status_code(&self) -> u16 {
        match self {
            AuthError::InvalidFormat(_) => 400,
            AuthError::InvalidSignature => 401,
            AuthError::Expired => 401,
            AuthError::InvalidPayload(_) => 400,
            AuthError::RateLimited(_) => 429,
            AuthError::InvalidDid(_) => 400,
            AuthError::InvalidHandle(_) => 400,
            AuthError::SessionNotFound => 401,
            AuthError::SessionExpired => 401,
            AuthError::Database(_) => 500,
            AuthError::Internal(_) => 500,
        }
    }
}

#[cfg(feature = "session-sqlite")]
impl From<rusqlite::Error> for AuthError {
    fn from(err: rusqlite::Error) -> Self {
        AuthError::Database(err.to_string())
    }
}

#[cfg(feature = "session-sqlite")]
impl From<r2d2::Error> for AuthError {
    fn from(err: r2d2::Error) -> Self {
        AuthError::Database(err.to_string())
    }
}
