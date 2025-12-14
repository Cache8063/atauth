//! Session store example
//!
//! This example demonstrates how to use the session management system
//! with SQLite backend.
//!
//! Run with: cargo run --example with_session_store --features session-sqlite

use atauth::session::{SessionManager, SqliteSessionStore};
use atauth::{TokenPayload, TokenVerifier};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let secret = b"your-super-secret-key-here";
    let verifier = TokenVerifier::new(secret);

    // Create an in-memory session store (use file path for persistence)
    let session_store = SqliteSessionStore::in_memory()?;

    // Create session manager with auto-extend enabled
    let sessions = SessionManager::new(session_store)
        .with_default_duration(86400) // 24 hours
        .with_auto_extend(true, 3600); // Extend by 1 hour on each access

    println!("=== Session Management Example ===\n");

    // Simulate user login
    println!("1. User Login");
    println!("   Verifying token...");

    let test_payload = create_test_payload();
    let token = verifier.sign(&test_payload)?;

    match verifier.verify(&token) {
        Ok(payload) => {
            println!("   [OK] Token verified for: {}", payload.handle);

            // Create session
            let session = sessions.create_session(&payload, token.clone())?;
            println!("   [OK] Session created");
            println!("      Token: {}...", &session.token[..20]);
            println!("      Expires in: {} seconds", session.remaining_seconds());
        }
        Err(e) => {
            println!("   [FAIL] Verification failed: {}", e);
            return Ok(());
        }
    }

    println!();
    println!("2. Subsequent Request");
    println!("   Validating session...");

    // Simulate subsequent request with session token
    match sessions.validate(&token) {
        Ok(session) => {
            println!("   [OK] Session valid for: {}", session.handle);
            println!("      DID: {}", session.did);
            println!("      User ID: {:?}", session.user_id);
        }
        Err(e) => {
            println!("   [FAIL] Session invalid: {}", e);
        }
    }

    println!();
    println!("3. Get All User Sessions");

    let user_sessions = sessions.get_user_sessions(&test_payload.did)?;
    println!(
        "   Found {} session(s) for {}",
        user_sessions.len(),
        test_payload.did
    );

    println!();
    println!("4. Create Another Session (same user, different device)");

    // Create another session for same user
    let second_token = verifier.sign(&test_payload)?;
    sessions.create_session(&test_payload, second_token)?;
    println!("   [OK] Second session created");

    let user_sessions = sessions.get_user_sessions(&test_payload.did)?;
    println!("   Now has {} sessions", user_sessions.len());

    println!();
    println!("5. Logout (invalidate first session)");
    sessions.invalidate(&token)?;
    println!("   [OK] First session invalidated");

    let user_sessions = sessions.get_user_sessions(&test_payload.did)?;
    println!("   Remaining sessions: {}", user_sessions.len());

    println!();
    println!("6. Logout All Devices");
    let deleted = sessions.invalidate_all_for_did(&test_payload.did)?;
    println!("   [OK] Deleted {} session(s)", deleted);

    println!();
    println!("7. Session Cleanup");
    // In production, run this periodically (e.g., every hour)
    let cleaned = sessions.cleanup()?;
    println!("   Cleaned up {} expired session(s)", cleaned);

    println!();
    println!("=== Example Complete ===");

    Ok(())
}

fn create_test_payload() -> TokenPayload {
    let now = chrono::Utc::now().timestamp();
    TokenPayload {
        did: "did:plc:testuser123".to_string(),
        handle: "testuser.bsky.social".to_string(),
        user_id: Some(1),
        app_id: Some("session-example".to_string()),
        iat: now,
        exp: now + 3600,
        nonce: format!("nonce-{}", now),
        extra: HashMap::new(),
    }
}
