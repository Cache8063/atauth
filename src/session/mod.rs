//! Session management for authenticated users.
//!
//! This module provides a trait-based session storage system that can be
//! implemented for various backends (SQLite, PostgreSQL, Redis, etc.).

mod store;

#[cfg(feature = "session-sqlite")]
mod sqlite;

#[cfg(feature = "session-postgres")]
mod postgres;

pub use store::{Session, SessionManager, SessionStore};

#[cfg(feature = "session-sqlite")]
pub use sqlite::SqliteSessionStore;

#[cfg(feature = "session-postgres")]
pub use postgres::PostgresSessionStore;
