//! # ATAuth - AT Protocol Authentication Library
//!
//! A generic, plug-and-play authentication library for AT Protocol (Bluesky) OAuth integration.
//!
//! ## Features
//!
//! - **Token Verification**: Secure HMAC-SHA256 token verification with constant-time comparison
//! - **Session Management**: Trait-based session storage with SQLite and PostgreSQL backends
//! - **Rate Limiting**: IP-based rate limiting with configurable thresholds
//! - **Input Validation**: DID and handle format validation
//!
//! ## Quick Start
//!
//! ```rust
//! use atauth::{TokenVerifier, TokenPayload};
//!
//! // Create a verifier with your HMAC secret
//! let verifier = TokenVerifier::new(b"your-secret-key");
//!
//! // Verify a token from the auth gateway
//! match verifier.verify("token-from-gateway") {
//!     Ok(payload) => {
//!         println!("Authenticated user: {} ({})", payload.handle, payload.did);
//!     }
//!     Err(e) => {
//!         eprintln!("Authentication failed: {}", e);
//!     }
//! }
//! ```
//!
//! ## With Session Store
//!
//! ```rust,ignore
//! use atauth::{TokenVerifier, SessionManager};
//! use atauth::session::SqliteSessionStore;
//!
//! let verifier = TokenVerifier::new(b"your-secret-key");
//! let session_store = SqliteSessionStore::new("sessions.db")?;
//! let session_manager = SessionManager::new(session_store);
//!
//! // On successful token verification
//! if let Ok(payload) = verifier.verify(token) {
//!     session_manager.create_session(&payload)?;
//! }
//! ```

pub mod error;
pub mod token;
pub mod validation;

#[cfg(any(feature = "session-sqlite", feature = "session-postgres"))]
pub mod session;

#[cfg(feature = "rate-limit")]
pub mod rate_limit;

// Re-exports for convenience
pub use error::{AuthError, AuthResult};
pub use token::{TokenPayload, TokenVerifier};
pub use validation::{validate_did, validate_handle};

#[cfg(any(feature = "session-sqlite", feature = "session-postgres"))]
pub use session::{Session, SessionManager, SessionStore};

#[cfg(feature = "rate-limit")]
pub use rate_limit::{RateLimiter, RateLimiterConfig};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum token length (prevents DoS via large tokens)
pub const MAX_TOKEN_LENGTH: usize = 2048;

/// Maximum DID length per AT Protocol spec
pub const MAX_DID_LENGTH: usize = 512;

/// Maximum handle length
pub const MAX_HANDLE_LENGTH: usize = 256;

/// Minimum secret key length (32 bytes = 256 bits for HMAC-SHA256 security)
pub const MIN_SECRET_LENGTH: usize = 32;

/// Prelude module for common imports
pub mod prelude {
    pub use crate::error::{AuthError, AuthResult};
    pub use crate::token::{TokenPayload, TokenVerifier};
    pub use crate::validation::{validate_did, validate_handle};

    #[cfg(any(feature = "session-sqlite", feature = "session-postgres"))]
    pub use crate::session::{Session, SessionManager, SessionStore};

    #[cfg(feature = "rate-limit")]
    pub use crate::rate_limit::{RateLimiter, RateLimiterConfig};
}
