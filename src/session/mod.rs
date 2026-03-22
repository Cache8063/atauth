//! Session management for authenticated users.
//!
//! This module provides a trait-based session storage system that can be
//! implemented for various backends (SQLite, PostgreSQL, Redis, etc.).

mod store;

#[cfg(feature = "session-sqlite")]
mod sqlite;

pub use store::{Session, SessionManager, SessionStore};

#[cfg(feature = "session-sqlite")]
pub use sqlite::SqliteSessionStore;
