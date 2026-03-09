/**
 * ATAuth Gateway - AT Protocol Authentication Service
 *
 * AT Protocol OAuth gateway for application authentication.
 * Issues HMAC-signed tokens for backend servers to verify user identity.
 * Now with OpenID Connect (OIDC) provider support.
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

import { DatabaseService } from './services/database.js';
import { OAuthService } from './services/oauth.js';
import { OIDCService } from './services/oidc/index.js';
import { PasskeyService } from './services/passkey.js';
import { MFAService } from './services/mfa.js';
import { EmailService } from './services/email.js';
import { createAuthRoutes } from './routes/auth.js';
import { createTokenRoutes } from './routes/token.js';
import { createAdminRoutes } from './routes/admin.js';
import { createSessionRoutes } from './routes/session.js';
import { createOIDCRouter } from './routes/oidc/index.js';
import { createPasskeyRouter } from './routes/passkey.js';
import { createMFARouter } from './routes/mfa.js';
import { createEmailRouter } from './routes/email.js';
import { createProxyAuthRoutes } from './routes/proxy-auth.js';
import { createUserProfileRoutes } from './routes/user-profile.js';
import { authRateLimit, apiRateLimit, adminRateLimit } from './middleware/rateLimit.js';
import { HttpError } from './utils/errors.js';

// Configuration from environment
const config = {
  port: parseInt(process.env.PORT || '3100', 10),
  host: process.env.HOST || '0.0.0.0',

  // OAuth client configuration (for AT Protocol)
  clientId: process.env.OAUTH_CLIENT_ID || 'https://auth.example.com/client-metadata.json',
  redirectUri: process.env.OAUTH_REDIRECT_URI || 'https://auth.example.com/auth/callback',

  // Admin token for app registration
  adminToken: process.env.ADMIN_TOKEN,

  // Database path
  dbPath: process.env.DB_PATH || path.join(process.cwd(), 'data', 'gateway.db'),

  // CORS origins
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],

  // OIDC configuration
  oidc: {
    enabled: process.env.OIDC_ENABLED === 'true',
    issuer: process.env.OIDC_ISSUER || 'https://auth.example.com',
    keySecret: process.env.OIDC_KEY_SECRET,
    keyAlgorithm: (process.env.OIDC_KEY_ALGORITHM || 'ES256') as 'ES256' | 'RS256',
  },

  // Passkey/WebAuthn configuration
  passkey: {
    enabled: process.env.PASSKEY_ENABLED !== 'false', // Enabled by default
    rpName: process.env.WEBAUTHN_RP_NAME || 'ATAuth',
    rpID: process.env.WEBAUTHN_RP_ID || 'localhost',
    origin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3100',
  },

  // MFA/TOTP configuration
  mfa: {
    enabled: process.env.MFA_ENABLED !== 'false', // Enabled by default
    issuer: process.env.MFA_TOTP_ISSUER || 'ATAuth',
    // 32-byte hex encryption key for TOTP secrets (64 hex characters)
    encryptionKey: process.env.MFA_ENCRYPTION_KEY,
    backupCodesCount: parseInt(process.env.MFA_BACKUP_CODES_COUNT || '10', 10),
  },

  // Email configuration
  email: {
    enabled: process.env.EMAIL_ENABLED === 'true', // Disabled by default
    provider: (process.env.EMAIL_PROVIDER || 'mock') as 'smtp' | 'resend' | 'sendgrid' | 'mailgun' | 'mock',
    from: process.env.EMAIL_FROM || 'ATAuth <noreply@example.com>',
    smtp: {
      host: process.env.SMTP_HOST || 'localhost',
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    apiKey: process.env.EMAIL_API_KEY,
    codeExpiry: parseInt(process.env.EMAIL_CODE_EXPIRY || '900', 10), // 15 minutes
  },

  // Forward-auth proxy configuration
  forwardAuth: {
    enabled: process.env.FORWARD_AUTH_ENABLED === 'true',
    sessionSecret: process.env.FORWARD_AUTH_SESSION_SECRET,
    sessionTtl: parseInt(process.env.FORWARD_AUTH_SESSION_TTL || '604800', 10), // 7 days
    proxyCookieTtl: parseInt(process.env.FORWARD_AUTH_PROXY_COOKIE_TTL || '86400', 10), // 24h
  },
};

async function main(): Promise<void> {
  console.log('Starting ATAuth Gateway...');

  // Validate CORS configuration
  if (config.corsOrigins.includes('*')) {
    console.error('CORS_ORIGINS cannot include "*" — credentials mode requires explicit origins');
    process.exit(1);
  }

  // Validate required secrets when features are enabled
  const missing: string[] = [];
  if (config.oidc.enabled && !config.oidc.keySecret) {
    missing.push('OIDC_KEY_SECRET is required when OIDC_ENABLED=true');
  }
  if (config.mfa.enabled && !config.mfa.encryptionKey) {
    missing.push('MFA_ENCRYPTION_KEY is required when MFA is enabled (set MFA_ENABLED=false to disable)');
  }
  if (config.forwardAuth.enabled && !config.forwardAuth.sessionSecret) {
    missing.push('FORWARD_AUTH_SESSION_SECRET is required when FORWARD_AUTH_ENABLED=true');
  }
  if (missing.length > 0) {
    console.error('Configuration error:');
    for (const msg of missing) console.error(`  - ${msg}`);
    process.exit(1);
  }

  // Ensure data directory exists
  const dataDir = path.dirname(config.dbPath);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  // Initialize services
  const db = new DatabaseService(config.dbPath);
  const oauth = new OAuthService(db, config.clientId, config.redirectUri);

  // Collect additional redirect URIs needed by OIDC and forward-auth
  const additionalRedirectUris: string[] = [];
  if (config.oidc.enabled && config.oidc.issuer) {
    additionalRedirectUris.push(`${config.oidc.issuer}/oauth/callback`);
  }
  if (config.forwardAuth.enabled && config.oidc.issuer) {
    additionalRedirectUris.push(`${config.oidc.issuer}/auth/proxy/callback`);
  }

  try {
    await oauth.initialize(additionalRedirectUris);
    console.log('OAuth client initialized');
  } catch (error) {
    console.error('Failed to initialize OAuth client:', error);
  }

  // Initialize OIDC service if enabled
  let oidcService: OIDCService | null = null;
  if (config.oidc.enabled) {
    oidcService = new OIDCService(db, {
      issuer: config.oidc.issuer,
      keySecret: config.oidc.keySecret!,
      keyAlgorithm: config.oidc.keyAlgorithm,
    });
    try {
      await oidcService.initialize(config.oidc.keyAlgorithm);
      console.log('OIDC service initialized');
    } catch (error) {
      console.error('Failed to initialize OIDC service:', error);
    }
  }

  // Initialize Passkey service
  let passkeyService: PasskeyService | null = null;
  if (config.passkey.enabled) {
    passkeyService = new PasskeyService(db, {
      rpName: config.passkey.rpName,
      rpID: config.passkey.rpID,
      origin: config.passkey.origin,
    });
    console.log('Passkey service initialized');
  }

  // Initialize MFA service
  let mfaService: MFAService | null = null;
  if (config.mfa.enabled) {
    mfaService = new MFAService(db, {
      issuer: config.mfa.issuer,
      encryptionKey: config.mfa.encryptionKey!,
      backupCodesCount: config.mfa.backupCodesCount,
    });
    console.log('MFA service initialized');
  }

  // Initialize Email service
  let emailService: EmailService | null = null;
  if (config.email.enabled) {
    emailService = new EmailService(db, {
      provider: config.email.provider,
      smtp: config.email.smtp,
      apiKey: config.email.apiKey,
      from: config.email.from,
      codeExpiry: config.email.codeExpiry,
    });
    console.log('Email service initialized');
  }

  // Create Express app
  const app = express();

  // Trust the first proxy (k8s ingress / cloudflared) for correct client IP in rate limiting
  app.set('trust proxy', 1);

  // Middleware
  // Generate a per-request nonce for inline scripts (CSP script-src)
  app.use((_req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    next();
  });
  app.use(helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        // Chrome enforces form-action on redirect targets (not just the action URL).
        // The OIDC login form POSTs to self, but the response redirects to bsky.social
        // or other PDS hosts. Without this, Chrome blocks the redirect silently.
        'form-action': null,
        // Allow inline scripts with per-request nonce (for login page)
        'script-src': ["'self'", (_req: any, res: any) => `'nonce-${res.locals.cspNonce}'`],
      },
    },
  }));
  app.use(cors({
    origin: config.corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Session-Id'],
  }));
  app.use(express.json({ limit: '16kb' }));
  app.use(express.urlencoded({ extended: true, limit: '16kb' }));

  // Request logging
  app.use((req, _res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
    next();
  });

  // Health check
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'atauth-gateway',
      timestamp: new Date().toISOString(),
    });
  });

  // Version endpoint
  const pkgPath = path.join(process.cwd(), 'package.json');
  const pkgVersion = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')).version;
  app.get('/version', (_req, res) => {
    res.json({
      service: 'atauth-gateway',
      version: pkgVersion,
      commit: process.env.BUILD_COMMIT || 'unknown',
    });
  });

  // Forward-auth proxy routes MUST be mounted before the general /auth rate limiter.
  // /auth/verify is called by nginx auth_request on every subrequest from a single
  // pod IP, so per-IP rate limiting would block legitimate traffic.
  if (config.forwardAuth.enabled) {
    const proxyRouter = createProxyAuthRoutes(db, oauth, { ...config.forwardAuth, sessionSecret: config.forwardAuth.sessionSecret! }, config.oidc.issuer, passkeyService);
    // Mount entire proxy router at /auth -- no rate limit on /auth/verify
    app.use('/auth', proxyRouter);
    console.log('Forward-auth proxy enabled');
  }

  // Routes with rate limiting
  app.use('/auth', authRateLimit, createAuthRoutes(db, oauth));
  app.use('/token', apiRateLimit, createTokenRoutes(db));
  app.use('/admin', adminRateLimit, createAdminRoutes(db, config.adminToken, oidcService, passkeyService, mfaService, config.forwardAuth.enabled ? config.forwardAuth.sessionSecret : undefined));
  app.use('/session', apiRateLimit, createSessionRoutes(db));

  // OIDC routes (if enabled)
  if (oidcService) {
    const { wellKnownRouter, oauthRouter } = createOIDCRouter(db, oidcService, oauth, passkeyService);
    app.use('/.well-known', wellKnownRouter);
    app.use('/oauth', authRateLimit, oauthRouter);
    console.log('OIDC routes enabled');
  }

  // Passkey routes (if enabled)
  if (passkeyService) {
    const passkeySessionSecret = config.forwardAuth.enabled ? config.forwardAuth.sessionSecret : undefined;
    app.use('/auth/passkey', authRateLimit, createPasskeyRouter(db, passkeyService, oidcService, passkeySessionSecret));
    console.log('Passkey routes enabled');
  }

  // MFA routes (if enabled)
  if (mfaService) {
    app.use('/auth/mfa', authRateLimit, createMFARouter(db, mfaService, passkeyService, oidcService));
    console.log('MFA routes enabled');
  }

  // Email routes (if enabled)
  if (emailService) {
    app.use('/auth/email', authRateLimit, createEmailRouter(db, emailService, oidcService));
    console.log('Email routes enabled');
  }

  // Forward-auth proxy routes were mounted earlier (before /auth rate limiter)

  // User profile routes (forward-auth session authenticated)
  if (config.forwardAuth.enabled) {
    const profileRouter = createUserProfileRoutes(db, passkeyService, config.forwardAuth.sessionSecret!);
    app.use('/auth/profile', authRateLimit, profileRouter);
    console.log('User profile routes enabled');
  }

  // OAuth client metadata (for AT Protocol discovery)
  app.get('/client-metadata.json', (_req, res) => {
    // Build redirect URIs array - include both legacy and OIDC callback paths
    const redirectUris = [config.redirectUri];
    // Add OIDC callback if OIDC is enabled
    if (config.oidc.enabled && config.oidc.issuer) {
      redirectUris.push(`${config.oidc.issuer}/oauth/callback`);
    }
    // Add forward-auth proxy callback if enabled
    if (config.forwardAuth.enabled && config.oidc.issuer) {
      redirectUris.push(`${config.oidc.issuer}/auth/proxy/callback`);
    }

    res.json({
      client_id: config.clientId,
      client_name: 'ATAuth Gateway',
      client_uri: config.clientId.replace('/client-metadata.json', ''),
      redirect_uris: redirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'atproto transition:generic',
      application_type: 'web',
      token_endpoint_auth_method: 'none',
      dpop_bound_access_tokens: true,
    });
  });

  // Error handler - Express 5 automatically forwards async errors here
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    // Handle known HTTP errors (thrown by route handlers)
    if (err instanceof HttpError) {
      return res.status(err.statusCode).json({
        error: err.code,
        message: err.message,
      });
    }

    // Handle AT Protocol identity resolution failures (invalid/unresolvable handles)
    if (err.constructor?.name === 'OAuthResolverError') {
      const cause = (err as any).cause;
      const handleMatch = err.message.match(/identity:\s*(.+)/);
      const handle = handleMatch ? handleMatch[1] : 'unknown';
      let userMessage = `Could not resolve handle "${handle}". `;

      if (cause?.message?.includes('does not resolve to a DID')) {
        userMessage += 'This handle has no _atproto DNS TXT record. Ensure the handle is configured on a PDS with proper DNS records.';
      } else if (cause?.message?.includes('not found')) {
        userMessage += 'The handle was not found. Check that the handle is spelled correctly and the PDS is reachable.';
      } else {
        userMessage += 'The AT Protocol identity could not be verified. Check that the handle exists and the PDS is online.';
      }

      console.error(`Identity resolution failed for "${handle}":`, cause?.message || err.message);
      return res.status(400).json({
        error: 'handle_resolution_failed',
        message: userMessage,
      });
    }

    // Log unexpected errors
    console.error('Unhandled error:', err);
    res.status(500).json({
      error: 'internal_error',
      message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
    });
  });

  // Graceful shutdown
  const shutdown = () => {
    console.log('Shutting down...');
    db.close();
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  // Periodic cleanup (every hour)
  setInterval(() => {
    const statesDeleted = db.cleanupOldOAuthStates();
    const sessionsDeleted = db.cleanupExpiredSessions();
    const authCodesDeleted = db.cleanupExpiredAuthorizationCodes();
    const refreshTokensDeleted = db.cleanupExpiredRefreshTokens();
    const emailCodesDeleted = db.cleanupExpiredEmailVerificationCodes();
    const proxySessionsDeleted = db.cleanupExpiredProxySessions();
    const proxyAuthRequestsDeleted = db.cleanupExpiredProxyAuthRequests();
    const auditLogsDeleted = db.cleanupOldAuditLogs();

    const total = statesDeleted + sessionsDeleted + authCodesDeleted + refreshTokensDeleted + emailCodesDeleted + proxySessionsDeleted + proxyAuthRequestsDeleted + auditLogsDeleted;
    if (total > 0) {
      console.log(`Cleanup: ${statesDeleted} OAuth states, ${sessionsDeleted} sessions, ${authCodesDeleted} auth codes, ${refreshTokensDeleted} refresh tokens, ${emailCodesDeleted} email codes, ${proxySessionsDeleted} proxy sessions, ${proxyAuthRequestsDeleted} proxy auth requests`);
    }
  }, 60 * 60 * 1000);

  // Start server
  app.listen(config.port, config.host, () => {
    console.log(`ATAuth Gateway listening on ${config.host}:${config.port}`);
    console.log(`OAuth Client ID: ${config.clientId}`);
    console.log(`OAuth Redirect URI: ${config.redirectUri}`);
    if (config.adminToken) {
      console.log('Admin endpoints enabled');
    } else {
      console.log('Admin endpoints disabled (set ADMIN_TOKEN to enable)');
    }
    if (config.oidc.enabled) {
      console.log(`OIDC enabled - Issuer: ${config.oidc.issuer}`);
      console.log(`OIDC Discovery: ${config.oidc.issuer}/.well-known/openid-configuration`);
    } else {
      console.log('OIDC disabled (set OIDC_ENABLED=true to enable)');
    }
    if (config.passkey.enabled) {
      console.log(`Passkey enabled - RP ID: ${config.passkey.rpID}`);
    } else {
      console.log('Passkey disabled (set PASSKEY_ENABLED=true to enable)');
    }
    if (config.mfa.enabled) {
      console.log(`MFA enabled - Issuer: ${config.mfa.issuer}`);
    } else {
      console.log('MFA disabled (set MFA_ENABLED=true to enable)');
    }
    if (config.email.enabled) {
      console.log(`Email enabled - Provider: ${config.email.provider}`);
    } else {
      console.log('Email disabled (set EMAIL_ENABLED=true to enable)');
    }
    if (config.forwardAuth.enabled) {
      console.log(`Forward-auth proxy enabled - Session TTL: ${config.forwardAuth.sessionTtl}s`);
    } else {
      console.log('Forward-auth proxy disabled (set FORWARD_AUTH_ENABLED=true to enable)');
    }
  });
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

// v2.2.1
