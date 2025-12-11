//! PostgreSQL session store implementation (placeholder).
//!
//! This module provides a PostgreSQL-backed session store using tokio-postgres.

use super::{Session, SessionStore};
use crate::error::{AuthError, AuthResult};

/// PostgreSQL-backed session store.
///
/// # Example
///
/// ```rust,ignore
/// use atauth::session::PostgresSessionStore;
///
/// let store = PostgresSessionStore::new("postgres://user:pass@localhost/db").await?;
/// ```
pub struct PostgresSessionStore {
    // TODO: Implement with deadpool-postgres
    _placeholder: (),
}

impl PostgresSessionStore {
    /// Create a new PostgreSQL session store.
    pub async fn new(_connection_string: &str) -> AuthResult<Self> {
        // TODO: Implement PostgreSQL connection pool
        Err(AuthError::Internal(
            "PostgreSQL session store not yet implemented".to_string(),
        ))
    }
}

impl SessionStore for PostgresSessionStore {
    fn upsert(&self, _session: &Session) -> AuthResult<()> {
        Err(AuthError::Internal("Not implemented".to_string()))
    }

    fn get(&self, _token: &str) -> AuthResult<Option<Session>> {
        Err(AuthError::Internal("Not implemented".to_string()))
    }

    fn delete(&self, _token: &str) -> AuthResult<bool> {
        Err(AuthError::Internal("Not implemented".to_string()))
    }

    fn delete_by_did(&self, _did: &str) -> AuthResult<u64> {
        Err(AuthError::Internal("Not implemented".to_string()))
    }

    fn delete_by_user_id(&self, _user_id: i64) -> AuthResult<u64> {
        Err(AuthError::Internal("Not implemented".to_string()))
    }

    fn get_by_did(&self, _did: &str) -> AuthResult<Vec<Session>> {
        Err(AuthError::Internal("Not implemented".to_string()))
    }

    fn get_by_user_id(&self, _user_id: i64) -> AuthResult<Vec<Session>> {
        Err(AuthError::Internal("Not implemented".to_string()))
    }

    fn extend(&self, _token: &str, _new_expires_at: i64) -> AuthResult<bool> {
        Err(AuthError::Internal("Not implemented".to_string()))
    }

    fn cleanup_expired(&self) -> AuthResult<u64> {
        Err(AuthError::Internal("Not implemented".to_string()))
    }

    fn count_active(&self) -> AuthResult<u64> {
        Err(AuthError::Internal("Not implemented".to_string()))
    }
}
