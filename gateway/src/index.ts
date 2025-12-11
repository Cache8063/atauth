/**
 * ATAuth Gateway
 *
 * AT Protocol OAuth gateway for application authentication.
 * Issues HMAC-signed tokens for backend servers to verify user identity.
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import path from 'path';
import fs from 'fs';

import { DatabaseService } from './services/database.js';
import { OAuthService } from './services/oauth.js';
import { createAuthRoutes } from './routes/auth.js';
import { createTokenRoutes } from './routes/token.js';
import { createAdminRoutes } from './routes/admin.js';
import { createSessionRoutes } from './routes/session.js';

// Configuration from environment
const config = {
  port: parseInt(process.env.PORT || '3100', 10),
  host: process.env.HOST || '0.0.0.0',

  // OAuth client configuration
  clientId: process.env.OAUTH_CLIENT_ID || 'https://auth.example.com/client-metadata.json',
  redirectUri: process.env.OAUTH_REDIRECT_URI || 'https://auth.example.com/auth/callback',

  // Admin token for app registration
  adminToken: process.env.ADMIN_TOKEN,

  // Database path
  dbPath: process.env.DB_PATH || path.join(process.cwd(), 'data', 'gateway.db'),

  // CORS origins
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
};

async function main(): Promise<void> {
  console.log('Starting ATAuth Gateway...');

  // Ensure data directory exists
  const dataDir = path.dirname(config.dbPath);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  // Initialize services
  const db = new DatabaseService(config.dbPath);
  const oauth = new OAuthService(db, config.clientId, config.redirectUri);

  try {
    await oauth.initialize();
    console.log('OAuth client initialized');
  } catch (error) {
    console.error('Failed to initialize OAuth client:', error);
  }

  // Create Express app
  const app = express();

  // Middleware
  app.use(helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  }));
  app.use(cors({
    origin: config.corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  }));
  app.use(express.json());

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

  // Routes
  app.use('/auth', createAuthRoutes(db, oauth));
  app.use('/token', createTokenRoutes(db));
  app.use('/admin', createAdminRoutes(db, config.adminToken));
  app.use('/session', createSessionRoutes(db));

  // OAuth client metadata (for AT Protocol discovery)
  app.get('/client-metadata.json', (_req, res) => {
    res.json({
      client_id: config.clientId,
      client_name: 'ATAuth Gateway',
      client_uri: config.clientId.replace('/client-metadata.json', ''),
      redirect_uris: [config.redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'atproto transition:generic',
      application_type: 'web',
      token_endpoint_auth_method: 'none',
      dpop_bound_access_tokens: true,
    });
  });

  // Error handler
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
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
    if (statesDeleted > 0 || sessionsDeleted > 0) {
      console.log(`Cleanup: ${statesDeleted} OAuth states, ${sessionsDeleted} sessions`);
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
  });
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
