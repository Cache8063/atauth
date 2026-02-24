/**
 * User Profile Routes
 *
 * Self-service profile page for authenticated users.
 * Passkey registration/management, active session management.
 * Protected by forward-auth session cookie.
 */

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import type { DatabaseService } from '../services/database.js';
import type { PasskeyService } from '../services/passkey.js';
import type { ProxySession } from '../types/proxy.js';
import { verifySessionCookie, parseCookies, SESSION_COOKIE_NAME } from '../utils/proxy-auth.js';

export function createUserProfileRoutes(
  db: DatabaseService,
  passkeyService: PasskeyService | null,
  sessionSecret: string
): Router {
  const router = Router();
  const csrfSecret = crypto.createHmac('sha256', sessionSecret).update('profile-csrf').digest('hex');

  function esc(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function generateCsrfToken(): string {
    const now = Math.floor(Date.now() / 1000);
    const payload = `${now}`;
    const sig = crypto.createHmac('sha256', csrfSecret).update(payload).digest('base64url');
    return `${payload}.${sig}`;
  }

  function verifyCsrfToken(token: string): boolean {
    if (!token) return false;
    const parts = token.split('.');
    if (parts.length !== 2) return false;
    const [payload, sig] = parts;
    const expected = crypto.createHmac('sha256', csrfSecret).update(payload).digest('base64url');
    if (sig.length !== expected.length) return false;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
    const ts = parseInt(payload, 10);
    const now = Math.floor(Date.now() / 1000);
    return now - ts < 3600;
  }

  function getSession(req: Request): ProxySession | null {
    const cookies = parseCookies(req.headers.cookie);
    const sessionCookie = cookies[SESSION_COOKIE_NAME];
    if (!sessionCookie) return null;
    const sessionId = verifySessionCookie(sessionCookie, sessionSecret);
    if (!sessionId) return null;
    const session = db.getProxySession(sessionId);
    if (!session || session.expires_at < Math.floor(Date.now() / 1000)) return null;
    return session;
  }

  function timeAgo(epochSeconds: number): string {
    const diff = Math.floor(Date.now() / 1000) - epochSeconds;
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  function formatDate(epochSeconds: number): string {
    return new Date(epochSeconds * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  }

  function truncateDid(did: string): string {
    if (did.length <= 32) return did;
    return did.slice(0, 20) + '...' + did.slice(-8);
  }

  /**
   * GET / — Main profile page
   */
  router.get('/', (req: Request, res: Response) => {
    const session = getSession(req);
    if (!session) {
      const profileUrl = `${req.protocol}://${req.get('host')}/auth/profile`;
      return res.redirect(`/auth/proxy/login?rd=${encodeURIComponent(profileUrl)}`);
    }

    const csrf = generateCsrfToken();
    const passkeys = passkeyService ? passkeyService.listPasskeys(session.did) : [];
    const sessions = db.getAllProxySessions(session.did, 50);
    const msg = req.query.msg as string | undefined;
    const nonce = res.locals.cspNonce || crypto.randomBytes(16).toString('base64');

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderProfilePage(session, passkeys, sessions, csrf, msg, nonce));
  });

  /**
   * POST /passkey/rename
   */
  router.post('/passkey/rename', (req: Request, res: Response) => {
    const session = getSession(req);
    if (!session) return res.redirect('/auth/profile');
    if (!verifyCsrfToken(req.body._csrf)) return res.status(403).send('Invalid form submission');

    const { passkey_id, name } = req.body;
    if (passkeyService && passkey_id && name?.trim()) {
      passkeyService.renamePasskey(session.did, passkey_id, name.trim());
    }
    res.redirect('/auth/profile?msg=Passkey+renamed');
  });

  /**
   * POST /passkey/delete
   */
  router.post('/passkey/delete', (req: Request, res: Response) => {
    const session = getSession(req);
    if (!session) return res.redirect('/auth/profile');
    if (!verifyCsrfToken(req.body._csrf)) return res.status(403).send('Invalid form submission');

    const { passkey_id } = req.body;
    if (passkeyService && passkey_id) {
      passkeyService.deletePasskey(session.did, passkey_id);
    }
    res.redirect('/auth/profile?msg=Passkey+deleted');
  });

  /**
   * POST /session/revoke
   */
  router.post('/session/revoke', (req: Request, res: Response) => {
    const session = getSession(req);
    if (!session) return res.redirect('/auth/profile');
    if (!verifyCsrfToken(req.body._csrf)) return res.status(403).send('Invalid form submission');

    const { session_id } = req.body;
    if (session_id === session.id) {
      return res.redirect('/auth/profile?msg=Cannot+revoke+current+session');
    }

    const target = db.getProxySession(session_id);
    if (target && target.did === session.did) {
      db.deleteProxySession(session_id);
    }
    res.redirect('/auth/profile?msg=Session+revoked');
  });

  function renderProfilePage(
    session: ProxySession,
    passkeys: Array<{ id: string; name: string | null; device_type: string | null; backed_up: boolean; last_used_at: string | null; created_at: string }>,
    sessions: ProxySession[],
    csrf: string,
    msg: string | undefined,
    nonce: string
  ): string {
    const flashHtml = msg ? `<div class="flash">${esc(msg)}</div>` : '';

    const passkeyRows = passkeys.length > 0 ? passkeys.map(pk => `
      <tr>
        <td>
          <form method="POST" action="/auth/profile/passkey/rename" class="inline-rename">
            <input type="hidden" name="_csrf" value="${csrf}">
            <input type="hidden" name="passkey_id" value="${esc(pk.id)}">
            <input type="text" name="name" value="${esc(pk.name || 'Unnamed')}" class="rename-input">
            <button type="submit" class="btn-icon" title="Rename">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
            </button>
          </form>
        </td>
        <td>${esc(pk.device_type || '--')}</td>
        <td>${pk.backed_up ? 'Yes' : 'No'}</td>
        <td>${pk.last_used_at ? timeAgo(Math.floor(new Date(pk.last_used_at).getTime() / 1000)) : 'Never'}</td>
        <td>
          <form method="POST" action="/auth/profile/passkey/delete" style="display:inline">
            <input type="hidden" name="_csrf" value="${csrf}">
            <input type="hidden" name="passkey_id" value="${esc(pk.id)}">
            <button type="submit" class="btn-danger-sm" onclick="return confirm('Delete this passkey?')">Delete</button>
          </form>
        </td>
      </tr>`).join('') : '<tr><td colspan="5" class="empty">No passkeys registered</td></tr>';

    const sessionRows = sessions.map(s => {
      const isCurrent = s.id === session.id;
      return `
      <tr${isCurrent ? ' class="current-session"' : ''}>
        <td>${esc(parseUserAgent(s.user_agent))}${isCurrent ? ' <span class="badge">current</span>' : ''}</td>
        <td>${esc(s.ip_address || '--')}</td>
        <td>${timeAgo(s.last_activity)}</td>
        <td>${formatDate(s.created_at)}</td>
        <td>${isCurrent ? '--' : `
          <form method="POST" action="/auth/profile/session/revoke" style="display:inline">
            <input type="hidden" name="_csrf" value="${csrf}">
            <input type="hidden" name="session_id" value="${esc(s.id)}">
            <button type="submit" class="btn-danger-sm">Revoke</button>
          </form>`}
        </td>
      </tr>`;
    }).join('');

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Profile - ATAuth</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
      padding: 24px 16px;
    }
    .page {
      max-width: 720px;
      margin: 0 auto;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 32px;
      padding-bottom: 16px;
      border-bottom: 1px solid #1e293b;
    }
    .header-left {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-name {
      font-size: 18px;
      font-weight: 700;
      letter-spacing: -0.5px;
      background: linear-gradient(135deg, #3b82f6, #8b5cf6);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .header-handle {
      color: #94a3b8;
      font-size: 14px;
    }
    .sign-out {
      color: #94a3b8;
      text-decoration: none;
      font-size: 13px;
      padding: 6px 12px;
      border: 1px solid #334155;
      border-radius: 6px;
      transition: color 0.15s, border-color 0.15s;
    }
    .sign-out:hover { color: #e2e8f0; border-color: #475569; }
    .flash {
      background: rgba(59, 130, 246, 0.12);
      border: 1px solid rgba(59, 130, 246, 0.25);
      color: #93c5fd;
      padding: 10px 14px;
      border-radius: 8px;
      margin-bottom: 20px;
      font-size: 14px;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 20px;
    }
    .card h2 {
      font-size: 16px;
      font-weight: 600;
      color: #e2e8f0;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .card h2 svg { width: 18px; height: 18px; color: #3b82f6; }
    .info-grid {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 8px 16px;
      font-size: 14px;
    }
    .info-grid dt { color: #64748b; font-weight: 500; }
    .info-grid dd { color: #e2e8f0; }
    .info-grid dd code {
      font-size: 12px;
      background: rgba(15, 23, 42, 0.6);
      padding: 2px 6px;
      border-radius: 4px;
      color: #94a3b8;
      word-break: break-all;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th {
      text-align: left;
      color: #64748b;
      font-weight: 500;
      padding: 8px 10px;
      border-bottom: 1px solid #334155;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    td {
      padding: 10px;
      border-bottom: 1px solid rgba(51, 65, 85, 0.5);
      color: #cbd5e1;
      vertical-align: middle;
    }
    .current-session td { background: rgba(59, 130, 246, 0.05); }
    .badge {
      display: inline-block;
      font-size: 11px;
      font-weight: 600;
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      padding: 2px 8px;
      border-radius: 10px;
      margin-left: 4px;
    }
    .empty {
      text-align: center;
      color: #64748b;
      padding: 24px !important;
    }
    .inline-rename {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .rename-input {
      background: transparent;
      border: 1px solid transparent;
      color: #e2e8f0;
      font-size: 13px;
      padding: 4px 6px;
      border-radius: 4px;
      width: 140px;
      transition: border-color 0.15s, background 0.15s;
    }
    .rename-input:focus {
      outline: none;
      border-color: #334155;
      background: #0f172a;
    }
    .btn-icon {
      background: none;
      border: none;
      color: #64748b;
      cursor: pointer;
      padding: 4px;
      border-radius: 4px;
      width: auto;
      margin: 0;
      transition: color 0.15s;
    }
    .btn-icon:hover { color: #3b82f6; transform: none; box-shadow: none; }
    .btn-icon svg { width: 14px; height: 14px; display: block; }
    .btn-danger-sm {
      background: rgba(127, 29, 29, 0.3);
      border: 1px solid rgba(252, 165, 165, 0.2);
      color: #fca5a5;
      font-size: 12px;
      padding: 4px 10px;
      border-radius: 4px;
      cursor: pointer;
      width: auto;
      margin: 0;
      font-weight: 500;
      transition: background 0.15s;
    }
    .btn-danger-sm:hover { background: rgba(127, 29, 29, 0.5); transform: none; box-shadow: none; }
    .register-section {
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid #334155;
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .register-name {
      background: #0f172a;
      border: 1px solid #334155;
      color: #e2e8f0;
      font-size: 14px;
      padding: 10px 14px;
      border-radius: 8px;
      flex: 1;
      min-width: 160px;
    }
    .register-name::placeholder { color: #475569; }
    .register-name:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15); }
    .btn-primary {
      background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      padding: 10px 20px;
      cursor: pointer;
      width: auto;
      margin: 0;
      transition: transform 0.15s, box-shadow 0.15s;
    }
    .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
    .register-status {
      width: 100%;
      font-size: 14px;
    }
    .register-status.success {
      background: rgba(34, 197, 94, 0.12);
      border: 1px solid rgba(34, 197, 94, 0.25);
      color: #4ade80;
      padding: 10px 14px;
      border-radius: 8px;
    }
    .register-status.error {
      background: rgba(127, 29, 29, 0.4);
      border: 1px solid rgba(252, 165, 165, 0.2);
      color: #fca5a5;
      padding: 10px 14px;
      border-radius: 8px;
    }
    @media (max-width: 640px) {
      table { font-size: 12px; }
      td, th { padding: 8px 6px; }
      .rename-input { width: 100px; }
    }
  </style>
</head>
<body>
  <div class="page">
    <div class="header">
      <div class="header-left">
        <span class="brand-name">ATAuth</span>
        <span class="header-handle">${esc(session.handle)}</span>
      </div>
      <a href="/auth/proxy/logout" class="sign-out">Sign out</a>
    </div>

    ${flashHtml}

    <div class="card">
      <h2>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        Account
      </h2>
      <dl class="info-grid">
        <dt>Handle</dt>
        <dd>${esc(session.handle)}</dd>
        <dt>DID</dt>
        <dd><code title="${esc(session.did)}">${esc(truncateDid(session.did))}</code></dd>
        <dt>Session started</dt>
        <dd>${formatDate(session.created_at)}</dd>
      </dl>
    </div>

    ${passkeyService ? `
    <div class="card">
      <h2>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 7a4 4 0 1 0-4 4"/><path d="M11 11l-1.5 1.5"/><path d="M9.5 12.5L6 16H4v2h2v-2h2v-2l1.5-1.5"/></svg>
        Passkeys
      </h2>
      <table>
        <thead>
          <tr><th>Name</th><th>Type</th><th>Backed up</th><th>Last used</th><th></th></tr>
        </thead>
        <tbody>${passkeyRows}</tbody>
      </table>
      <div class="register-section">
        <input type="text" id="passkeyName" class="register-name" placeholder="Passkey name (optional)">
        <button type="button" id="registerPasskeyBtn" class="btn-primary" style="display:none">Register passkey</button>
        <div id="registerStatus" class="register-status"></div>
      </div>
    </div>` : ''}

    <div class="card">
      <h2>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="5" rx="2"/><path d="M2 10h20"/></svg>
        Active Sessions
      </h2>
      <table>
        <thead>
          <tr><th>Device</th><th>IP</th><th>Last active</th><th>Created</th><th></th></tr>
        </thead>
        <tbody>${sessionRows}</tbody>
      </table>
    </div>
  </div>

  <script${nonce ? ` nonce="${nonce}"` : ''}>
    ${passkeyService ? `
    function b64urlToBuffer(s) {
      var b = s.replace(/-/g, '+').replace(/_/g, '/');
      var pad = b.length % 4 === 0 ? '' : '='.repeat(4 - (b.length % 4));
      var bin = atob(b + pad);
      var arr = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return arr.buffer;
    }
    function bufferToB64url(buf) {
      var bytes = new Uint8Array(buf);
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
    }
    var registerBtn = document.getElementById('registerPasskeyBtn');
    var nameInput = document.getElementById('passkeyName');
    var statusDiv = document.getElementById('registerStatus');
    if (registerBtn && window.PublicKeyCredential) {
      registerBtn.style.display = 'inline-block';
      registerBtn.addEventListener('click', function() {
        registerBtn.disabled = true;
        registerBtn.textContent = 'Waiting for authenticator...';
        statusDiv.textContent = '';
        statusDiv.className = 'register-status';
        fetch('/auth/passkey/register/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({})
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (!data.success) throw new Error(data.message || 'Failed to get options');
          var opts = data.options;
          var pubKeyOpts = {
            challenge: b64urlToBuffer(opts.challenge),
            rp: opts.rp,
            user: {
              id: b64urlToBuffer(opts.user.id),
              name: opts.user.name,
              displayName: opts.user.displayName
            },
            pubKeyCredParams: opts.pubKeyCredParams,
            timeout: opts.timeout,
            attestation: opts.attestation,
            authenticatorSelection: opts.authenticatorSelection
          };
          if (opts.excludeCredentials) {
            pubKeyOpts.excludeCredentials = opts.excludeCredentials.map(function(c) {
              return { id: b64urlToBuffer(c.id), type: c.type, transports: c.transports };
            });
          }
          return navigator.credentials.create({ publicKey: pubKeyOpts });
        })
        .then(function(cred) {
          var credential = {
            id: cred.id,
            rawId: bufferToB64url(cred.rawId),
            response: {
              clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
              attestationObject: bufferToB64url(cred.response.attestationObject),
              transports: cred.response.getTransports ? cred.response.getTransports() : undefined
            },
            type: cred.type,
            clientExtensionResults: cred.getClientExtensionResults(),
            authenticatorAttachment: cred.authenticatorAttachment
          };
          var name = nameInput ? nameInput.value.trim() : '';
          return fetch('/auth/passkey/register/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ credential: credential, name: name || undefined })
          });
        })
        .then(function(r) { return r.json(); })
        .then(function(result) {
          if (result.success) {
            statusDiv.textContent = 'Passkey registered successfully';
            statusDiv.className = 'register-status success';
            setTimeout(function() { window.location.reload(); }, 1000);
          } else {
            statusDiv.textContent = result.message || 'Registration failed';
            statusDiv.className = 'register-status error';
            registerBtn.disabled = false;
            registerBtn.textContent = 'Register passkey';
          }
        })
        .catch(function(err) {
          if (err.name !== 'NotAllowedError') {
            statusDiv.textContent = 'Registration failed: ' + err.message;
            statusDiv.className = 'register-status error';
          }
          registerBtn.disabled = false;
          registerBtn.textContent = 'Register passkey';
        });
      });
    }` : ''}
  </script>
</body>
</html>`;
  }

  return router;
}

function parseUserAgent(ua?: string): string {
  if (!ua) return 'Unknown';
  if (ua.includes('Firefox')) return 'Firefox';
  if (ua.includes('Edg/')) return 'Edge';
  if (ua.includes('Chrome')) return 'Chrome';
  if (ua.includes('Safari')) return 'Safari';
  if (ua.includes('curl')) return 'curl';
  return ua.slice(0, 30);
}
