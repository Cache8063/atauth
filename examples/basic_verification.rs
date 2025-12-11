//! Basic token verification example
//!
//! This example demonstrates how to verify tokens from an AT Protocol auth gateway.
//!
//! Run with: cargo run --example basic_verification

use atauth::{TokenVerifier, TokenPayload, AuthError};
use std::collections::HashMap;

fn main() {
    // Your HMAC secret (shared with the auth gateway)
    let secret = b"your-super-secret-key-here";

    // Create a verifier
    let verifier = TokenVerifier::new(secret)
        .with_clock_skew(60)      // Allow 60 seconds clock skew
        .with_format_validation(true); // Validate DID/handle formats

    // Create a test token (in real use, this comes from the client)
    let test_payload = create_test_payload();
    let token = verifier.sign(&test_payload).expect("Failed to sign");

    println!("Generated token: {}", token);
    println!();

    // Verify the token
    match verifier.verify(&token) {
        Ok(payload) => {
            println!("[OK] Token verified successfully!");
            println!();
            println!("User Information:");
            println!("  DID:    {}", payload.did);
            println!("  Handle: {}", payload.handle);
            println!("  User ID: {:?}", payload.user_id);
            println!("  App ID:  {:?}", payload.app_id);
            println!();
            println!("Token Timing:");
            println!("  Issued:     {} seconds ago", payload.age_seconds());
            println!("  Expires in: {} seconds", payload.remaining_seconds());
            println!("  Is expired: {}", payload.is_expired());
        }
        Err(e) => {
            println!("[FAIL] Token verification failed!");
            println!("  Error: {}", e);
            println!("  HTTP Status: {}", e.http_status_code());
        }
    }

    println!();
    println!("--- Testing Error Cases ---");
    println!();

    // Test invalid signature
    let wrong_verifier = TokenVerifier::new(b"wrong-secret");
    match wrong_verifier.verify(&token) {
        Ok(_) => println!("[FAIL] Should have failed!"),
        Err(AuthError::InvalidSignature) => {
            println!("[OK] Correctly rejected invalid signature");
        }
        Err(e) => println!("[WARN] Unexpected error: {}", e),
    }

    // Test invalid format
    match verifier.verify("not-a-valid-token") {
        Ok(_) => println!("[FAIL] Should have failed!"),
        Err(AuthError::InvalidFormat(_)) => {
            println!("[OK] Correctly rejected invalid format");
        }
        Err(e) => println!("[WARN] Unexpected error: {}", e),
    }

    // Test expired token
    let expired_payload = create_expired_payload();
    let expired_token = verifier.sign(&expired_payload).expect("Failed to sign");
    match verifier.verify(&expired_token) {
        Ok(_) => println!("[FAIL] Should have failed!"),
        Err(AuthError::Expired) => {
            println!("[OK] Correctly rejected expired token");
        }
        Err(e) => println!("[WARN] Unexpected error: {}", e),
    }
}

fn create_test_payload() -> TokenPayload {
    let now = chrono::Utc::now().timestamp();
    TokenPayload {
        did: "did:plc:z72i7hdynmk6r22z27h6tvur".to_string(),
        handle: "alice.bsky.social".to_string(),
        user_id: Some(42),
        app_id: Some("example-app".to_string()),
        iat: now,
        exp: now + 3600, // 1 hour from now
        nonce: "random-nonce-12345".to_string(),
        extra: HashMap::new(),
    }
}

fn create_expired_payload() -> TokenPayload {
    let now = chrono::Utc::now().timestamp();
    TokenPayload {
        did: "did:plc:expired".to_string(),
        handle: "expired.bsky.social".to_string(),
        user_id: None,
        app_id: None,
        iat: now - 7200,  // 2 hours ago
        exp: now - 3600,  // 1 hour ago (expired)
        nonce: "expired-nonce".to_string(),
        extra: HashMap::new(),
    }
}
