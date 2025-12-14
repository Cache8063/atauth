//! SQLite session store implementation.

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;

use super::{Session, SessionStore};
use crate::error::{AuthError, AuthResult};

/// SQLite-backed session store.
///
/// # Example
///
/// ```rust,ignore
/// use atauth::session::SqliteSessionStore;
///
/// // In-memory database
/// let store = SqliteSessionStore::in_memory()?;
///
/// // File-based database
/// let store = SqliteSessionStore::new("sessions.db")?;
/// ```
pub struct SqliteSessionStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteSessionStore {
    /// Create a new SQLite session store with the given database path.
    pub fn new(path: &str) -> AuthResult<Self> {
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::new(manager)?;

        let store = Self { pool };
        store.init_schema()?;
        Ok(store)
    }

    /// Create an in-memory SQLite session store.
    pub fn in_memory() -> AuthResult<Self> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::new(manager)?;

        let store = Self { pool };
        store.init_schema()?;
        Ok(store)
    }

    /// Create from an existing r2d2 pool.
    pub fn from_pool(pool: Pool<SqliteConnectionManager>) -> AuthResult<Self> {
        let store = Self { pool };
        store.init_schema()?;
        Ok(store)
    }

    /// Initialize the database schema.
    fn init_schema(&self) -> AuthResult<()> {
        let conn = self.pool.get()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                handle TEXT NOT NULL,
                user_id INTEGER,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                metadata TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_did ON sessions(did);
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
            "#,
        )?;
        Ok(())
    }

    /// Get a connection from the pool.
    fn conn(&self) -> AuthResult<r2d2::PooledConnection<SqliteConnectionManager>> {
        self.pool
            .get()
            .map_err(|e| AuthError::Database(e.to_string()))
    }
}

impl SessionStore for SqliteSessionStore {
    fn upsert(&self, session: &Session) -> AuthResult<()> {
        let conn = self.conn()?;
        let metadata_json = session
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_default());

        conn.execute(
            r#"
            INSERT INTO sessions (token, did, handle, user_id, expires_at, created_at, metadata)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(token) DO UPDATE SET
                did = excluded.did,
                handle = excluded.handle,
                user_id = excluded.user_id,
                expires_at = excluded.expires_at,
                metadata = excluded.metadata
            "#,
            params![
                session.token,
                session.did,
                session.handle,
                session.user_id,
                session.expires_at,
                session.created_at,
                metadata_json,
            ],
        )?;
        Ok(())
    }

    fn get(&self, token: &str) -> AuthResult<Option<Session>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT token, did, handle, user_id, expires_at, created_at, metadata FROM sessions WHERE token = ?1",
        )?;

        let result = stmt.query_row(params![token], |row| {
            let metadata_str: Option<String> = row.get(6)?;
            let metadata = metadata_str.and_then(|s| serde_json::from_str(&s).ok());

            Ok(Session {
                token: row.get(0)?,
                did: row.get(1)?,
                handle: row.get(2)?,
                user_id: row.get(3)?,
                expires_at: row.get(4)?,
                created_at: row.get(5)?,
                metadata,
            })
        });

        match result {
            Ok(session) => Ok(Some(session)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AuthError::Database(e.to_string())),
        }
    }

    fn delete(&self, token: &str) -> AuthResult<bool> {
        let conn = self.conn()?;
        let rows = conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])?;
        Ok(rows > 0)
    }

    fn delete_by_did(&self, did: &str) -> AuthResult<u64> {
        let conn = self.conn()?;
        let rows = conn.execute("DELETE FROM sessions WHERE did = ?1", params![did])?;
        Ok(rows as u64)
    }

    fn delete_by_user_id(&self, user_id: i64) -> AuthResult<u64> {
        let conn = self.conn()?;
        let rows = conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
        Ok(rows as u64)
    }

    fn get_by_did(&self, did: &str) -> AuthResult<Vec<Session>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT token, did, handle, user_id, expires_at, created_at, metadata
             FROM sessions WHERE did = ?1 AND expires_at > ?2",
        )?;

        let now = chrono::Utc::now().timestamp();
        let sessions = stmt
            .query_map(params![did, now], |row| {
                let metadata_str: Option<String> = row.get(6)?;
                let metadata = metadata_str.and_then(|s| serde_json::from_str(&s).ok());

                Ok(Session {
                    token: row.get(0)?,
                    did: row.get(1)?,
                    handle: row.get(2)?,
                    user_id: row.get(3)?,
                    expires_at: row.get(4)?,
                    created_at: row.get(5)?,
                    metadata,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(sessions)
    }

    fn get_by_user_id(&self, user_id: i64) -> AuthResult<Vec<Session>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT token, did, handle, user_id, expires_at, created_at, metadata
             FROM sessions WHERE user_id = ?1 AND expires_at > ?2",
        )?;

        let now = chrono::Utc::now().timestamp();
        let sessions = stmt
            .query_map(params![user_id, now], |row| {
                let metadata_str: Option<String> = row.get(6)?;
                let metadata = metadata_str.and_then(|s| serde_json::from_str(&s).ok());

                Ok(Session {
                    token: row.get(0)?,
                    did: row.get(1)?,
                    handle: row.get(2)?,
                    user_id: row.get(3)?,
                    expires_at: row.get(4)?,
                    created_at: row.get(5)?,
                    metadata,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(sessions)
    }

    fn extend(&self, token: &str, new_expires_at: i64) -> AuthResult<bool> {
        let conn = self.conn()?;
        let rows = conn.execute(
            "UPDATE sessions SET expires_at = ?1 WHERE token = ?2",
            params![new_expires_at, token],
        )?;
        Ok(rows > 0)
    }

    fn cleanup_expired(&self) -> AuthResult<u64> {
        let conn = self.conn()?;
        let now = chrono::Utc::now().timestamp();
        let rows = conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now])?;
        Ok(rows as u64)
    }

    fn count_active(&self) -> AuthResult<u64> {
        let conn = self.conn()?;
        let now = chrono::Utc::now().timestamp();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE expires_at > ?1",
            params![now],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session() -> Session {
        let now = chrono::Utc::now().timestamp();
        Session {
            token: format!("test-token-{}", now),
            did: "did:plc:testuser".to_string(),
            handle: "test.bsky.social".to_string(),
            user_id: Some(42),
            expires_at: now + 3600,
            created_at: now,
            metadata: None,
        }
    }

    #[test]
    fn test_upsert_and_get() {
        let store = SqliteSessionStore::in_memory().unwrap();
        let session = create_test_session();

        store.upsert(&session).unwrap();
        let retrieved = store.get(&session.token).unwrap().unwrap();

        assert_eq!(retrieved.did, session.did);
        assert_eq!(retrieved.handle, session.handle);
        assert_eq!(retrieved.user_id, session.user_id);
    }

    #[test]
    fn test_delete() {
        let store = SqliteSessionStore::in_memory().unwrap();
        let session = create_test_session();

        store.upsert(&session).unwrap();
        assert!(store.delete(&session.token).unwrap());
        assert!(store.get(&session.token).unwrap().is_none());
    }

    #[test]
    fn test_get_by_did() {
        let store = SqliteSessionStore::in_memory().unwrap();
        let mut session1 = create_test_session();
        session1.token = "token1".to_string();

        let mut session2 = create_test_session();
        session2.token = "token2".to_string();

        store.upsert(&session1).unwrap();
        store.upsert(&session2).unwrap();

        let sessions = store.get_by_did(&session1.did).unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_cleanup_expired() {
        let store = SqliteSessionStore::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        // Create expired session
        let mut expired = create_test_session();
        expired.token = "expired".to_string();
        expired.expires_at = now - 100;
        store.upsert(&expired).unwrap();

        // Create valid session
        let mut valid = create_test_session();
        valid.token = "valid".to_string();
        valid.expires_at = now + 3600;
        store.upsert(&valid).unwrap();

        let cleaned = store.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);

        assert!(store.get("expired").unwrap().is_none());
        assert!(store.get("valid").unwrap().is_some());
    }

    #[test]
    fn test_extend() {
        let store = SqliteSessionStore::in_memory().unwrap();
        let session = create_test_session();
        store.upsert(&session).unwrap();

        let new_expiry = session.expires_at + 7200;
        store.extend(&session.token, new_expiry).unwrap();

        let updated = store.get(&session.token).unwrap().unwrap();
        assert_eq!(updated.expires_at, new_expiry);
    }
}
