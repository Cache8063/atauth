/**
 * Admin Dashboard Routes
 *
 * Server-rendered HTML dashboard for managing ATAuth forward-auth proxy.
 * All routes are protected by requireAdmin middleware (cookie or bearer).
 * Uses POST-redirect-GET pattern for all form submissions.
 */

import crypto from 'crypto';
import { Router, Request, Response } from 'express';
import { DatabaseService } from '../services/database.js';
import { checkAccess } from '../utils/access-check.js';
import { generateHmacSecret } from '../utils/hmac.js';
import { OIDC_APP_PRESETS, getPresetByKey } from '../data/oidc-presets.js';

/** Strip protocol scheme (e.g. https://) from user input to prevent double-protocol in URI templates. */
function stripScheme(input: string): string {
  return input.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').trim();
}

export function createAdminDashboardRoutes(
  db: DatabaseService,
  csrfSecret: string,
): Router {
  const router = Router();

  // ===== CSRF Protection =====

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
    return now - ts < 3600; // 1 hour validity
  }

  function requireCsrf(req: Request, res: Response): boolean {
    const token = req.body._csrf;
    if (!verifyCsrfToken(token)) {
      res.status(403).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(layout('Error', '<div class="card"><h2>Invalid or expired form submission</h2><p><a href="/admin/dashboard">Back to dashboard</a></p></div>'));
      return false;
    }
    return true;
  }

  // ===== Dashboard Overview =====

  router.get('/', (_req: Request, res: Response) => {
    const origins = db.listProxyAllowedOrigins();
    const rules = db.listProxyAccessRules();
    const sessions = db.getAllProxySessions(undefined, 1000);
    const oidcClients = db.getAllOIDCClients();

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Dashboard', `
      <h2>Overview</h2>
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">${oidcClients.length}</div>
          <div class="stat-label">OIDC Clients</div>
          <a href="/admin/dashboard/clients" class="stat-link">Manage</a>
        </div>
        <div class="stat-card">
          <div class="stat-value">${origins.length}</div>
          <div class="stat-label">Protected Origins</div>
          <a href="/admin/dashboard/origins" class="stat-link">Manage</a>
        </div>
        <div class="stat-card">
          <div class="stat-value">${rules.length}</div>
          <div class="stat-label">Access Rules</div>
          <a href="/admin/dashboard/access" class="stat-link">Manage</a>
        </div>
        <div class="stat-card">
          <div class="stat-value">${sessions.length}</div>
          <div class="stat-label">Active Sessions</div>
          <a href="/admin/dashboard/sessions" class="stat-link">Manage</a>
        </div>
      </div>
      <div class="card" style="margin-top: 1.5rem;">
        <h3>Quick Actions</h3>
        <div style="display: flex; gap: 0.75rem; margin-top: 1rem; flex-wrap: wrap;">
          <a href="/admin/dashboard/clients/new" class="btn btn-primary">Add OIDC Client</a>
          <a href="/admin/dashboard/clients/wizard" class="btn btn-primary">Setup Wizard</a>
          <a href="/admin/dashboard/proxy-wizard" class="btn btn-secondary">Proxy Setup</a>
          <a href="/admin/dashboard/check" class="btn btn-secondary">Test Access Check</a>
        </div>
      </div>
    `));
  });

  // ===== Origins Management =====

  router.get('/origins', (req: Request, res: Response) => {
    const origins = db.listProxyAllowedOrigins();
    const csrf = generateCsrfToken();
    const msg = req.query.msg as string | undefined;

    const ruleCountMap = new Map<number, number>();
    const allRules = db.listProxyAccessRules();
    for (const rule of allRules) {
      if (rule.origin_id !== null) {
        ruleCountMap.set(rule.origin_id, (ruleCountMap.get(rule.origin_id) || 0) + 1);
      }
    }

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Origins', `
      ${msg ? `<div class="flash flash-success">${esc(msg)}</div>` : ''}
      <h2>Protected Origins</h2>
      <div class="card" style="margin-bottom: 1.5rem;">
        <h3>Add Origin</h3>
        <form method="POST" action="/admin/dashboard/origins" class="form-inline">
          <input type="hidden" name="_csrf" value="${csrf}">
          <div class="form-group">
            <label for="origin">Origin URL</label>
            <input type="url" id="origin" name="origin" placeholder="https://search.arcnode.xyz" required>
          </div>
          <div class="form-group">
            <label for="name">Display Name</label>
            <input type="text" id="name" name="name" placeholder="SearXNG" required>
          </div>
          <button type="submit" class="btn btn-primary">Add Origin</button>
        </form>
      </div>
      ${origins.length === 0 ? '<p class="muted">No origins configured. Add one above.</p>' : `
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Origin</th>
            <th>Rules</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${origins.map(o => `
          <tr>
            <td><strong>${esc(o.name)}</strong></td>
            <td><code>${esc(o.origin)}</code></td>
            <td>${ruleCountMap.get(o.id) || 0}</td>
            <td>${formatDate(o.created_at)}</td>
            <td>
              <form method="POST" action="/admin/dashboard/origins/${o.id}/delete" style="display:inline;">
                <input type="hidden" name="_csrf" value="${csrf}">
                <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete origin ${esc(o.name)}? This also deletes all its access rules.')">Delete</button>
              </form>
            </td>
          </tr>
          `).join('')}
        </tbody>
      </table>`}
    `));
  });

  router.post('/origins', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    const { origin, name } = req.body;
    if (!origin || !name) {
      return res.redirect('/admin/dashboard/origins?msg=Origin+and+name+are+required');
    }
    try {
      const parsed = new URL(origin);
      if (parsed.origin !== origin) {
        return res.redirect('/admin/dashboard/origins?msg=Invalid+origin+format');
      }
    } catch {
      return res.redirect('/admin/dashboard/origins?msg=Invalid+URL');
    }
    try {
      db.addProxyAllowedOrigin(origin, name);
      res.redirect('/admin/dashboard/origins?msg=Origin+added');
    } catch (e) {
      const msg = e instanceof Error && e.message.includes('UNIQUE') ? 'Origin+already+exists' : 'Failed+to+add+origin';
      res.redirect(`/admin/dashboard/origins?msg=${msg}`);
    }
  });

  router.post('/origins/:id/delete', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    db.removeProxyAllowedOrigin(parseInt(req.params.id, 10));
    res.redirect('/admin/dashboard/origins?msg=Origin+deleted');
  });

  // ===== Access Rules Management =====

  router.get('/access', (req: Request, res: Response) => {
    const filterOriginId = req.query.origin_id !== undefined ? parseInt(req.query.origin_id as string, 10) : undefined;
    const origins = db.listProxyAllowedOrigins();
    const rules = filterOriginId !== undefined ? db.listProxyAccessRules(filterOriginId) : db.listProxyAccessRules();
    const csrf = generateCsrfToken();
    const msg = req.query.msg as string | undefined;

    const originMap = new Map(origins.map(o => [o.id, o]));

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Access Rules', `
      ${msg ? `<div class="flash flash-success">${esc(msg)}</div>` : ''}
      <h2>Access Rules</h2>
      <div class="card" style="margin-bottom: 1.5rem;">
        <h3>Add Rule</h3>
        <form method="POST" action="/admin/dashboard/access" class="form-grid">
          <input type="hidden" name="_csrf" value="${csrf}">
          <div class="form-group">
            <label for="origin_id">Scope</label>
            <select id="origin_id" name="origin_id">
              <option value="">Global (all origins)</option>
              ${origins.map(o => `<option value="${o.id}">${esc(o.name)} (${esc(o.origin)})</option>`).join('')}
            </select>
          </div>
          <div class="form-group">
            <label for="rule_type">Type</label>
            <select id="rule_type" name="rule_type" required>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </select>
          </div>
          <div class="form-group">
            <label for="subject_type">Subject</label>
            <select id="subject_type" name="subject_type" required>
              <option value="handle_pattern">Handle Pattern</option>
              <option value="did">DID</option>
            </select>
          </div>
          <div class="form-group">
            <label for="subject_value">Value</label>
            <input type="text" id="subject_value" name="subject_value" placeholder="*.arcnode.xyz or did:plc:..." required>
          </div>
          <div class="form-group">
            <label for="description">Description (optional)</label>
            <input type="text" id="description" name="description" placeholder="PDS users">
          </div>
          <button type="submit" class="btn btn-primary">Add Rule</button>
        </form>
      </div>

      <div style="margin-bottom: 1rem;">
        <strong>Filter by origin:</strong>
        <a href="/admin/dashboard/access" class="${filterOriginId === undefined ? 'active-filter' : ''}">All</a>
        ${origins.map(o => `
          <a href="/admin/dashboard/access?origin_id=${o.id}" class="${filterOriginId === o.id ? 'active-filter' : ''}">${esc(o.name)}</a>
        `).join(' ')}
      </div>

      ${rules.length === 0 ? '<p class="muted">No access rules configured. All authenticated users have access (open mode).</p>' : `
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Subject</th>
            <th>Value</th>
            <th>Scope</th>
            <th>Description</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${rules.map(r => `
          <tr>
            <td><span class="badge ${r.rule_type === 'allow' ? 'badge-allow' : 'badge-deny'}">${r.rule_type}</span></td>
            <td>${r.subject_type === 'did' ? 'DID' : 'Handle'}</td>
            <td><code>${esc(r.subject_value)}</code></td>
            <td>${r.origin_id === null ? '<em>Global</em>' : esc(originMap.get(r.origin_id)?.name || `#${r.origin_id}`)}</td>
            <td>${r.description ? esc(r.description) : '<span class="muted">--</span>'}</td>
            <td>
              <form method="POST" action="/admin/dashboard/access/${r.id}/delete" style="display:inline;">
                <input type="hidden" name="_csrf" value="${csrf}">
                <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete this rule?')">Delete</button>
              </form>
            </td>
          </tr>
          `).join('')}
        </tbody>
      </table>`}
    `));
  });

  router.post('/access', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    const { origin_id, rule_type, subject_type, subject_value, description } = req.body;

    if (!rule_type || !subject_type || !subject_value) {
      return res.redirect('/admin/dashboard/access?msg=Missing+required+fields');
    }
    if (!['allow', 'deny'].includes(rule_type)) {
      return res.redirect('/admin/dashboard/access?msg=Invalid+rule+type');
    }
    if (!['did', 'handle_pattern'].includes(subject_type)) {
      return res.redirect('/admin/dashboard/access?msg=Invalid+subject+type');
    }
    if (subject_type === 'did' && !subject_value.startsWith('did:')) {
      return res.redirect('/admin/dashboard/access?msg=DID+must+start+with+did:');
    }
    if (subject_type === 'handle_pattern' && subject_value !== '*' && !subject_value.match(/^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/)) {
      return res.redirect('/admin/dashboard/access?msg=Invalid+handle+pattern');
    }

    const parsedOriginId = origin_id ? parseInt(origin_id, 10) : null;

    try {
      db.createProxyAccessRule({
        origin_id: parsedOriginId,
        rule_type,
        subject_type,
        subject_value,
        description: description || null,
      });
      res.redirect('/admin/dashboard/access?msg=Rule+added');
    } catch (_e) {
      res.redirect('/admin/dashboard/access?msg=Failed+to+add+rule');
    }
  });

  router.post('/access/:id/delete', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    db.deleteProxyAccessRule(parseInt(req.params.id, 10));
    res.redirect('/admin/dashboard/access?msg=Rule+deleted');
  });

  // ===== Sessions Management =====

  router.get('/sessions', (req: Request, res: Response) => {
    const filterDid = req.query.did as string | undefined;
    const sessions = db.getAllProxySessions(filterDid, 200);
    const csrf = generateCsrfToken();
    const msg = req.query.msg as string | undefined;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Sessions', `
      ${msg ? `<div class="flash flash-success">${esc(msg)}</div>` : ''}
      <h2>Proxy Sessions</h2>
      <div class="card" style="margin-bottom: 1.5rem;">
        <form method="GET" action="/admin/dashboard/sessions" class="form-inline">
          <div class="form-group">
            <label for="did">Filter by DID</label>
            <input type="text" id="did" name="did" placeholder="did:plc:..." value="${filterDid ? esc(filterDid) : ''}">
          </div>
          <button type="submit" class="btn btn-secondary">Filter</button>
          ${filterDid ? '<a href="/admin/dashboard/sessions" class="btn btn-secondary">Clear</a>' : ''}
        </form>
      </div>
      ${sessions.length === 0 ? '<p class="muted">No active proxy sessions.</p>' : `
      <table>
        <thead>
          <tr>
            <th>Handle</th>
            <th>DID</th>
            <th>Created</th>
            <th>Last Activity</th>
            <th>IP</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${sessions.map(s => `
          <tr>
            <td><strong>${esc(s.handle)}</strong></td>
            <td><code title="${esc(s.did)}">${truncateDid(s.did)}</code></td>
            <td>${formatDate(s.created_at)}</td>
            <td>${formatDate(s.last_activity)}</td>
            <td>${s.ip_address ? esc(s.ip_address) : '<span class="muted">--</span>'}</td>
            <td>
              <form method="POST" action="/admin/dashboard/sessions/${esc(s.id)}/delete" style="display:inline;">
                <input type="hidden" name="_csrf" value="${csrf}">
                <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Revoke session for ${esc(s.handle)}?')">Revoke</button>
              </form>
            </td>
          </tr>
          `).join('')}
        </tbody>
      </table>`}
    `));
  });

  router.post('/sessions/:id/delete', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    db.deleteProxySession(req.params.id);
    res.redirect('/admin/dashboard/sessions?msg=Session+revoked');
  });

  // ===== Access Check Tool =====

  router.get('/check', (_req: Request, res: Response) => {
    const origins = db.listProxyAllowedOrigins();
    const csrf = generateCsrfToken();

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Access Check', `
      <h2>Access Check Tool</h2>
      <div class="card">
        <p class="muted" style="margin-bottom: 1rem;">Test whether a DID/handle combination would be granted access to an origin.</p>
        <form method="POST" action="/admin/dashboard/check" class="form-grid">
          <input type="hidden" name="_csrf" value="${csrf}">
          <div class="form-group">
            <label for="did">DID</label>
            <input type="text" id="did" name="did" placeholder="did:plc:..." required>
          </div>
          <div class="form-group">
            <label for="handle">Handle</label>
            <input type="text" id="handle" name="handle" placeholder="user.bsky.social" required>
          </div>
          <div class="form-group">
            <label for="origin_id">Origin</label>
            <select id="origin_id" name="origin_id" required>
              ${origins.map(o => `<option value="${o.id}">${esc(o.name)} (${esc(o.origin)})</option>`).join('')}
            </select>
          </div>
          <button type="submit" class="btn btn-primary">Check Access</button>
        </form>
      </div>
    `));
  });

  router.post('/check', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    const { did, handle, origin_id } = req.body;
    const origins = db.listProxyAllowedOrigins();
    const csrf = generateCsrfToken();

    if (!did || !handle || origin_id === undefined) {
      return res.redirect('/admin/dashboard/check');
    }

    const parsedOriginId = parseInt(origin_id, 10);
    const rules = db.getProxyAccessRulesForCheck(parsedOriginId);
    const totalRules = rules.denyRules.length + rules.originAllowRules.length + rules.globalAllowRules.length;

    let result;
    if (totalRules === 0) {
      result = { allowed: true, matched_rule_id: null as number | null, reason: 'No access rules configured (open access)' };
    } else {
      result = checkAccess(did, handle, rules);
    }

    const origin = origins.find(o => o.id === parsedOriginId);

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Access Check', `
      <h2>Access Check Tool</h2>
      <div class="card" style="margin-bottom: 1.5rem;">
        <form method="POST" action="/admin/dashboard/check" class="form-grid">
          <input type="hidden" name="_csrf" value="${csrf}">
          <div class="form-group">
            <label for="did">DID</label>
            <input type="text" id="did" name="did" placeholder="did:plc:..." required value="${esc(did)}">
          </div>
          <div class="form-group">
            <label for="handle">Handle</label>
            <input type="text" id="handle" name="handle" placeholder="user.bsky.social" required value="${esc(handle)}">
          </div>
          <div class="form-group">
            <label for="origin_id">Origin</label>
            <select id="origin_id" name="origin_id" required>
              ${origins.map(o => `<option value="${o.id}" ${o.id === parsedOriginId ? 'selected' : ''}>${esc(o.name)} (${esc(o.origin)})</option>`).join('')}
            </select>
          </div>
          <button type="submit" class="btn btn-primary">Check Access</button>
        </form>
      </div>
      <div class="card result-card ${result.allowed ? 'result-allowed' : 'result-denied'}">
        <h3>${result.allowed ? 'ACCESS ALLOWED' : 'ACCESS DENIED'}</h3>
        <dl>
          <dt>DID</dt><dd><code>${esc(did)}</code></dd>
          <dt>Handle</dt><dd><code>${esc(handle)}</code></dd>
          <dt>Origin</dt><dd>${origin ? esc(origin.name) : `#${parsedOriginId}`}</dd>
          <dt>Reason</dt><dd>${esc(result.reason)}</dd>
          ${result.matched_rule_id !== null ? `<dt>Matched Rule</dt><dd>#${result.matched_rule_id}</dd>` : ''}
        </dl>
      </div>
    `));
  });

  // ===== OIDC Client Management =====

  router.get('/clients', (req: Request, res: Response) => {
    const clients = db.getAllOIDCClients();
    const msg = req.query.msg as string | undefined;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Clients', `
      ${msg ? `<div class="flash flash-success">${esc(msg)}</div>` : ''}
      <h2>OIDC Clients</h2>
      <div style="display: flex; gap: 0.75rem; margin-bottom: 1.25rem; flex-wrap: wrap;">
        <a href="/admin/dashboard/clients/new" class="btn btn-primary">New Client</a>
        <a href="/admin/dashboard/clients/wizard" class="btn btn-secondary">Setup Wizard</a>
      </div>
      ${clients.length === 0 ? '<p class="muted">No OIDC clients configured. Create one above or use the setup wizard.</p>' : `
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Client ID</th>
            <th>Redirect URIs</th>
            <th>Scopes</th>
            <th>PKCE</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${clients.map(c => `
          <tr>
            <td><strong>${esc(c.name)}</strong></td>
            <td><code>${esc(c.id)}</code></td>
            <td>${c.redirect_uris.map(u => `<code style="font-size:0.75rem">${esc(truncateUri(u))}</code>`).join('<br>')}</td>
            <td>${c.allowed_scopes.map(s => `<span class="badge badge-allow">${esc(s)}</span>`).join(' ')}</td>
            <td>${c.require_pkce ? 'Yes' : 'No'}</td>
            <td>${formatDateObj(c.created_at)}</td>
            <td style="white-space: nowrap;">
              <a href="/admin/dashboard/clients/${encodeURIComponent(c.id)}/edit" class="btn btn-secondary btn-sm">Edit</a>
              <form method="POST" action="/admin/dashboard/clients/${encodeURIComponent(c.id)}/delete" style="display:inline;">
                <input type="hidden" name="_csrf" value="${generateCsrfToken()}">
                <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete client ${esc(c.id)}? This removes all associated sessions and tokens.')">Delete</button>
              </form>
            </td>
          </tr>
          `).join('')}
        </tbody>
      </table>`}
    `));
  });

  // --- Create Client ---

  router.get('/clients/new', (req: Request, res: Response) => {
    const csrf = generateCsrfToken();
    const preset = req.query.preset as string | undefined;
    const domain = req.query.domain as string | undefined;
    const error = req.query.error as string | undefined;
    const presetData = preset ? getPresetByKey(preset) : undefined;

    const defaults = presetData && domain ? {
      id: presetData.suggested_client_id,
      name: presetData.name,
      redirect_uris: presetData.redirect_uri_template.replace(/\{\{DOMAIN\}\}/g, stripScheme(domain)),
      grant_types: presetData.grant_types,
      scopes: presetData.scopes,
      auth_method: presetData.token_endpoint_auth_method,
      require_pkce: presetData.require_pkce,
      id_token_ttl: presetData.id_token_ttl_seconds,
      access_token_ttl: presetData.access_token_ttl_seconds,
      refresh_token_ttl: presetData.refresh_token_ttl_seconds,
    } : {
      id: '', name: '', redirect_uris: '',
      grant_types: ['authorization_code'],
      scopes: ['openid'],
      auth_method: 'client_secret_basic',
      require_pkce: true,
      id_token_ttl: 3600, access_token_ttl: 3600, refresh_token_ttl: 604800,
    };

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('New Client', renderClientForm(csrf, defaults, error, preset)));
  });

  router.post('/clients/new', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    const { id, name, redirect_uris_text, auth_method, id_token_ttl, access_token_ttl, refresh_token_ttl, preset } = req.body;
    const grant_types = normalizeCheckboxArray(req.body.grant_types);
    const scopes = normalizeCheckboxArray(req.body.scopes);
    const require_pkce = req.body.require_pkce === 'on';

    // Validation
    if (!id || !name) {
      return renderClientFormWithError(res, req.body, 'Client ID and name are required');
    }
    if (!/^[a-z0-9][a-z0-9_-]*$/.test(id) || id.length > 64) {
      return renderClientFormWithError(res, req.body, 'Client ID must be lowercase alphanumeric with hyphens/underscores, max 64 chars');
    }
    const redirect_uris = parseTextareaLines(redirect_uris_text);
    if (redirect_uris.length === 0) {
      return renderClientFormWithError(res, req.body, 'At least one redirect URI is required');
    }
    for (const uri of redirect_uris) {
      if (!isValidRedirectUri(uri)) {
        return renderClientFormWithError(res, req.body, `Invalid redirect URI: ${uri}`);
      }
    }
    if (!grant_types.includes('authorization_code')) {
      return renderClientFormWithError(res, req.body, 'authorization_code grant type is required');
    }
    if (!scopes.includes('openid')) {
      return renderClientFormWithError(res, req.body, 'openid scope is required');
    }

    const existing = db.getOIDCClient(id);
    if (existing) {
      return renderClientFormWithError(res, req.body, `Client ID "${id}" already exists`);
    }

    // Create
    const clientSecret = crypto.randomBytes(32).toString('hex');
    const clientSecretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');

    db.upsertApp({
      id, name,
      hmac_secret: generateHmacSecret(),
      token_ttl_seconds: parseInt(access_token_ttl, 10) || 3600,
      callback_url: redirect_uris[0],
    });

    db.updateOIDCClient(id, {
      client_type: 'oidc',
      client_secret: clientSecretHash,
      redirect_uris,
      grant_types,
      allowed_scopes: scopes,
      require_pkce,
      token_endpoint_auth_method: auth_method || 'client_secret_basic',
      id_token_ttl_seconds: parseInt(id_token_ttl, 10) || 3600,
      access_token_ttl_seconds: parseInt(access_token_ttl, 10) || 3600,
      refresh_token_ttl_seconds: parseInt(refresh_token_ttl, 10) || 604800,
    });

    const params = new URLSearchParams({ id, secret: clientSecret });
    if (preset) params.set('preset', preset);
    res.redirect(`/admin/dashboard/clients/created?${params.toString()}`);
  });

  // --- Secret Display (one-time) ---

  router.get('/clients/created', (req: Request, res: Response) => {
    const { id, secret, preset, rotated } = req.query as Record<string, string>;
    if (!id || !secret) {
      return res.redirect('/admin/dashboard/clients');
    }

    const presetData = preset ? getPresetByKey(preset) : undefined;
    const heading = rotated ? 'Secret Rotated' : 'Client Created';

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout(heading, `
      <h2>${heading}</h2>
      <div class="card">
        <dl>
          <dt>Client ID</dt>
          <dd><code>${esc(id)}</code></dd>
        </dl>
        <div style="margin-top: 1rem;">
          <label style="display:block; font-size:0.8rem; font-weight:500; color:#94a3b8; margin-bottom:0.25rem;">Client Secret</label>
          <div class="secret-box">
            <span id="secret-value">${esc(secret)}</span>
            <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('secret-value').textContent).then(function(){this.textContent='Copied'}.bind(this))">Copy</button>
          </div>
        </div>
        <div class="callout-warning">This secret will not be shown again. Copy it now and store it securely.</div>
        ${presetData ? `
        <div style="margin-top: 1.25rem;">
          <h3>Setup Instructions: ${esc(presetData.name)}</h3>
          <div class="callout-info">${esc(presetData.setup_notes)}</div>
        </div>
        ` : ''}
        <div style="margin-top: 1.25rem;">
          <h3>Discovery URL</h3>
          <div class="code-block">${esc(getDiscoveryUrl())}</div>
        </div>
        <div style="margin-top: 1.25rem;">
          <a href="/admin/dashboard/clients" class="btn btn-secondary">Back to Clients</a>
        </div>
      </div>
    `));
  });

  // --- Edit Client ---

  router.get('/clients/:id/edit', (req: Request, res: Response) => {
    const client = db.getOIDCClient(req.params.id);
    if (!client) {
      return res.redirect('/admin/dashboard/clients?msg=Client+not+found');
    }

    const csrf = generateCsrfToken();
    const msg = req.query.msg as string | undefined;

    const values = {
      id: client.id,
      name: client.name,
      redirect_uris: client.redirect_uris.join('\n'),
      grant_types: client.grant_types,
      scopes: client.allowed_scopes,
      auth_method: client.token_endpoint_auth_method,
      require_pkce: client.require_pkce,
      id_token_ttl: client.id_token_ttl_seconds,
      access_token_ttl: client.access_token_ttl_seconds,
      refresh_token_ttl: client.refresh_token_ttl_seconds,
    };

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Edit Client', `
      ${msg ? `<div class="flash flash-success">${esc(msg)}</div>` : ''}
      <h2>Edit Client: ${esc(client.id)}</h2>
      <div class="card">
        <form method="POST" action="/admin/dashboard/clients/${encodeURIComponent(client.id)}/edit">
          <input type="hidden" name="_csrf" value="${csrf}">
          <div class="form-group">
            <label for="id">Client ID</label>
            <input type="text" id="id" name="id" value="${esc(client.id)}" readonly>
          </div>
          <div class="form-group">
            <label for="name">Display Name</label>
            <input type="text" id="name" name="name" value="${esc(values.name)}" required>
          </div>
          <div class="form-group">
            <label for="redirect_uris_text">Redirect URIs (one per line)</label>
            <textarea id="redirect_uris_text" name="redirect_uris_text" required>${esc(values.redirect_uris)}</textarea>
          </div>
          <div class="form-group">
            <label>Grant Types</label>
            <div class="checkbox-group">
              <label><input type="checkbox" name="grant_types" value="authorization_code" ${values.grant_types.includes('authorization_code') ? 'checked' : ''}> authorization_code</label>
              <label><input type="checkbox" name="grant_types" value="refresh_token" ${values.grant_types.includes('refresh_token') ? 'checked' : ''}> refresh_token</label>
            </div>
          </div>
          <div class="form-group">
            <label>Scopes</label>
            <div class="checkbox-group">
              <label><input type="checkbox" name="scopes" value="openid" ${values.scopes.includes('openid') ? 'checked' : ''}> openid</label>
              <label><input type="checkbox" name="scopes" value="profile" ${values.scopes.includes('profile') ? 'checked' : ''}> profile</label>
              <label><input type="checkbox" name="scopes" value="email" ${values.scopes.includes('email') ? 'checked' : ''}> email</label>
            </div>
          </div>
          <div class="form-group">
            <label for="auth_method">Token Endpoint Auth Method</label>
            <select id="auth_method" name="auth_method">
              <option value="client_secret_basic" ${values.auth_method === 'client_secret_basic' ? 'selected' : ''}>client_secret_basic</option>
              <option value="client_secret_post" ${values.auth_method === 'client_secret_post' ? 'selected' : ''}>client_secret_post</option>
              <option value="none" ${values.auth_method === 'none' ? 'selected' : ''}>none (public client)</option>
            </select>
          </div>
          <div class="form-group">
            <div class="checkbox-group">
              <label><input type="checkbox" name="require_pkce" ${values.require_pkce ? 'checked' : ''}> Require PKCE</label>
            </div>
          </div>
          <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem;">
            <div class="form-group">
              <label for="id_token_ttl">ID Token TTL (s)</label>
              <input type="number" id="id_token_ttl" name="id_token_ttl" value="${values.id_token_ttl}" min="60">
            </div>
            <div class="form-group">
              <label for="access_token_ttl">Access Token TTL (s)</label>
              <input type="number" id="access_token_ttl" name="access_token_ttl" value="${values.access_token_ttl}" min="60">
            </div>
            <div class="form-group">
              <label for="refresh_token_ttl">Refresh Token TTL (s)</label>
              <input type="number" id="refresh_token_ttl" name="refresh_token_ttl" value="${values.refresh_token_ttl}" min="60">
            </div>
          </div>
          <button type="submit" class="btn btn-primary">Save Changes</button>
        </form>
      </div>
      <div class="card" style="margin-top: 1.5rem;">
        <h3>Rotate Client Secret</h3>
        <p class="muted" style="margin-bottom: 0.75rem;">Generate a new client secret. The old secret will stop working immediately.</p>
        <form method="POST" action="/admin/dashboard/clients/${encodeURIComponent(client.id)}/rotate-secret">
          <input type="hidden" name="_csrf" value="${csrf}">
          <button type="submit" class="btn btn-danger" onclick="return confirm('Rotate secret for ${esc(client.id)}? The old secret will immediately stop working.')">Rotate Secret</button>
        </form>
      </div>
    `));
  });

  router.post('/clients/:id/edit', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    const clientId = req.params.id;
    const existing = db.getOIDCClient(clientId);
    if (!existing) {
      return res.redirect('/admin/dashboard/clients?msg=Client+not+found');
    }

    const { name, redirect_uris_text, auth_method, id_token_ttl, access_token_ttl, refresh_token_ttl } = req.body;
    const grant_types = normalizeCheckboxArray(req.body.grant_types);
    const scopes = normalizeCheckboxArray(req.body.scopes);
    const require_pkce = req.body.require_pkce === 'on';
    const redirect_uris = parseTextareaLines(redirect_uris_text);

    if (!name || redirect_uris.length === 0) {
      return res.redirect(`/admin/dashboard/clients/${encodeURIComponent(clientId)}/edit?msg=Name+and+redirect+URIs+required`);
    }

    // Update name if changed
    const app = db.getApp(clientId);
    if (app && name !== app.name) {
      db.upsertApp({ ...app, name });
    }

    db.updateOIDCClient(clientId, {
      redirect_uris,
      grant_types,
      allowed_scopes: scopes,
      require_pkce,
      token_endpoint_auth_method: auth_method || existing.token_endpoint_auth_method,
      id_token_ttl_seconds: parseInt(id_token_ttl, 10) || existing.id_token_ttl_seconds,
      access_token_ttl_seconds: parseInt(access_token_ttl, 10) || existing.access_token_ttl_seconds,
      refresh_token_ttl_seconds: parseInt(refresh_token_ttl, 10) || existing.refresh_token_ttl_seconds,
    });

    res.redirect('/admin/dashboard/clients?msg=Client+updated');
  });

  // --- Rotate Secret ---

  router.post('/clients/:id/rotate-secret', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    const clientId = req.params.id;
    const existing = db.getOIDCClient(clientId);
    if (!existing) {
      return res.redirect('/admin/dashboard/clients?msg=Client+not+found');
    }

    const clientSecret = crypto.randomBytes(32).toString('hex');
    const clientSecretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');
    db.updateOIDCClientSecret(clientId, clientSecretHash);

    const params = new URLSearchParams({ id: clientId, secret: clientSecret, rotated: '1' });
    res.redirect(`/admin/dashboard/clients/created?${params.toString()}`);
  });

  // --- Delete Client ---

  router.post('/clients/:id/delete', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    db.deleteApp(req.params.id);
    res.redirect('/admin/dashboard/clients?msg=Client+deleted');
  });

  // ===== Setup Wizard =====

  router.get('/clients/wizard', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Setup Wizard', `
      <h2>Setup Wizard</h2>
      <p class="muted" style="margin-bottom: 1.25rem;">Select an application to auto-configure OIDC settings.</p>
      <div class="wizard-grid">
        ${OIDC_APP_PRESETS.map(p => `
        <div class="wizard-card">
          <h4>${esc(p.name)}</h4>
          <p>${esc(p.description)}</p>
          <a href="/admin/dashboard/clients/wizard/${esc(p.key)}" class="btn btn-primary btn-sm">Set Up</a>
        </div>
        `).join('')}
        <div class="wizard-card">
          <h4>Custom</h4>
          <p>Configure manually with full control over all settings</p>
          <a href="/admin/dashboard/clients/new" class="btn btn-secondary btn-sm">Create Custom</a>
        </div>
      </div>
    `));
  });

  router.get('/clients/wizard/:preset', (req: Request, res: Response) => {
    const presetData = getPresetByKey(req.params.preset);
    if (!presetData) {
      return res.status(404).setHeader('Content-Type', 'text/html; charset=utf-8').send(
        layout('Not Found', '<div class="card"><h2>Preset not found</h2><p><a href="/admin/dashboard/clients/wizard">Back to wizard</a></p></div>')
      );
    }

    const csrf = generateCsrfToken();

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout(`Setup ${presetData.name}`, `
      <h2>Setup ${esc(presetData.name)}</h2>
      <p class="muted" style="margin-bottom: 1.25rem;">${esc(presetData.description)}</p>
      <div class="card">
        <form method="POST" action="/admin/dashboard/clients/wizard/${esc(presetData.key)}">
          <input type="hidden" name="_csrf" value="${csrf}">
          <input type="hidden" name="preset" value="${esc(presetData.key)}">
          <div class="form-group">
            <label for="domain">Your Domain (e.g., app.example.com)</label>
            <input type="text" id="domain" name="domain" placeholder="app.example.com" required autofocus>
          </div>
          <div class="form-group">
            <label for="id">Client ID</label>
            <input type="text" id="id" name="id" value="${esc(presetData.suggested_client_id)}" required pattern="[a-z0-9][a-z0-9_-]*">
          </div>
          <div class="form-group">
            <label for="name">Display Name</label>
            <input type="text" id="name" name="name" value="${esc(presetData.name)}" required>
          </div>
          <div class="callout-info" style="margin-top: 0.5rem;">
            <strong>Redirect URI pattern:</strong> ${esc(presetData.redirect_uri_template)}
          </div>
          <details style="margin-top: 1rem;">
            <summary style="cursor: pointer; color: #94a3b8; font-size: 0.875rem;">Advanced Settings</summary>
            <div style="margin-top: 0.75rem;">
              <div class="form-group">
                <label>Grant Types</label>
                <div class="checkbox-group">
                  <label><input type="checkbox" name="grant_types" value="authorization_code" ${presetData.grant_types.includes('authorization_code') ? 'checked' : ''}> authorization_code</label>
                  <label><input type="checkbox" name="grant_types" value="refresh_token" ${presetData.grant_types.includes('refresh_token') ? 'checked' : ''}> refresh_token</label>
                </div>
              </div>
              <div class="form-group">
                <label>Scopes</label>
                <div class="checkbox-group">
                  <label><input type="checkbox" name="scopes" value="openid" ${presetData.scopes.includes('openid') ? 'checked' : ''}> openid</label>
                  <label><input type="checkbox" name="scopes" value="profile" ${presetData.scopes.includes('profile') ? 'checked' : ''}> profile</label>
                  <label><input type="checkbox" name="scopes" value="email" ${presetData.scopes.includes('email') ? 'checked' : ''}> email</label>
                </div>
              </div>
              <div class="form-group">
                <label for="auth_method">Auth Method</label>
                <select id="auth_method" name="auth_method">
                  <option value="client_secret_basic" ${presetData.token_endpoint_auth_method === 'client_secret_basic' ? 'selected' : ''}>client_secret_basic</option>
                  <option value="client_secret_post" ${presetData.token_endpoint_auth_method === 'client_secret_post' ? 'selected' : ''}>client_secret_post</option>
                  <option value="none" ${presetData.token_endpoint_auth_method === 'none' ? 'selected' : ''}>none (public)</option>
                </select>
              </div>
              <div class="form-group">
                <div class="checkbox-group">
                  <label><input type="checkbox" name="require_pkce" ${presetData.require_pkce ? 'checked' : ''}> Require PKCE</label>
                </div>
              </div>
              <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem;">
                <div class="form-group">
                  <label for="id_token_ttl">ID Token TTL (s)</label>
                  <input type="number" id="id_token_ttl" name="id_token_ttl" value="${presetData.id_token_ttl_seconds}" min="60">
                </div>
                <div class="form-group">
                  <label for="access_token_ttl">Access Token TTL (s)</label>
                  <input type="number" id="access_token_ttl" name="access_token_ttl" value="${presetData.access_token_ttl_seconds}" min="60">
                </div>
                <div class="form-group">
                  <label for="refresh_token_ttl">Refresh Token TTL (s)</label>
                  <input type="number" id="refresh_token_ttl" name="refresh_token_ttl" value="${presetData.refresh_token_ttl_seconds}" min="60">
                </div>
              </div>
            </div>
          </details>
          <div style="margin-top: 1rem;">
            <button type="submit" class="btn btn-primary">Create Client</button>
            <a href="/admin/dashboard/clients/wizard" class="btn btn-secondary" style="margin-left: 0.5rem;">Back</a>
          </div>
        </form>
      </div>
      <div class="callout-info" style="margin-top: 1rem;">
        <strong>After setup:</strong>\n${esc(presetData.setup_notes)}
      </div>
    `));
  });

  router.post('/clients/wizard/:preset', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    const presetData = getPresetByKey(req.params.preset);
    if (!presetData) {
      return res.redirect('/admin/dashboard/clients/wizard');
    }

    const { id, name, domain, auth_method, id_token_ttl, access_token_ttl, refresh_token_ttl, preset } = req.body;
    const grant_types = normalizeCheckboxArray(req.body.grant_types);
    const scopes = normalizeCheckboxArray(req.body.scopes);
    const require_pkce = req.body.require_pkce === 'on';

    if (!id || !name || !domain) {
      return res.redirect(`/admin/dashboard/clients/wizard/${encodeURIComponent(req.params.preset)}`);
    }
    if (!/^[a-z0-9][a-z0-9_-]*$/.test(id) || id.length > 64) {
      return res.redirect(`/admin/dashboard/clients/wizard/${encodeURIComponent(req.params.preset)}`);
    }

    const existing = db.getOIDCClient(id);
    if (existing) {
      return res.redirect(`/admin/dashboard/clients/wizard/${encodeURIComponent(req.params.preset)}`);
    }

    // Build redirect URIs from template
    const redirect_uris = presetData.redirect_uri_template
      .replace(/\{\{DOMAIN\}\}/g, stripScheme(domain))
      .split('\n')
      .map(u => u.trim())
      .filter(u => u.length > 0);

    const clientSecret = crypto.randomBytes(32).toString('hex');
    const clientSecretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');

    db.upsertApp({
      id, name,
      hmac_secret: generateHmacSecret(),
      token_ttl_seconds: parseInt(access_token_ttl, 10) || 3600,
      callback_url: redirect_uris[0],
    });

    db.updateOIDCClient(id, {
      client_type: 'oidc',
      client_secret: clientSecretHash,
      redirect_uris,
      grant_types: grant_types.length > 0 ? grant_types : presetData.grant_types,
      allowed_scopes: scopes.length > 0 ? scopes : presetData.scopes,
      require_pkce,
      token_endpoint_auth_method: auth_method || presetData.token_endpoint_auth_method,
      id_token_ttl_seconds: parseInt(id_token_ttl, 10) || presetData.id_token_ttl_seconds,
      access_token_ttl_seconds: parseInt(access_token_ttl, 10) || presetData.access_token_ttl_seconds,
      refresh_token_ttl_seconds: parseInt(refresh_token_ttl, 10) || presetData.refresh_token_ttl_seconds,
    });

    const params = new URLSearchParams({ id, secret: clientSecret, preset: preset || req.params.preset });
    res.redirect(`/admin/dashboard/clients/created?${params.toString()}`);
  });

  // ===== Forward-Auth Proxy Quick Setup =====

  router.get('/proxy-wizard', (_req: Request, res: Response) => {
    const csrf = generateCsrfToken();
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Proxy Setup', `
      <h2>Forward-Auth Proxy Setup</h2>
      <p class="muted" style="margin-bottom: 1.25rem;">Add a service to protect with AT Protocol authentication via nginx forward-auth.</p>
      <div class="card">
        <form method="POST" action="/admin/dashboard/proxy-wizard">
          <input type="hidden" name="_csrf" value="${csrf}">
          <div class="form-group">
            <label for="name">Service Name</label>
            <input type="text" id="name" name="name" placeholder="SearXNG" required>
          </div>
          <div class="form-group">
            <label for="origin">Origin URL</label>
            <input type="url" id="origin" name="origin" placeholder="https://search.arcnode.xyz" required>
          </div>
          <button type="submit" class="btn btn-primary">Add Service</button>
        </form>
      </div>
    `));
  });

  router.post('/proxy-wizard', (req: Request, res: Response) => {
    if (!requireCsrf(req, res)) return;
    const { origin, name } = req.body;
    if (!origin || !name) {
      return res.redirect('/admin/dashboard/proxy-wizard');
    }
    try {
      const parsed = new URL(origin);
      if (parsed.origin !== origin) {
        return res.redirect('/admin/dashboard/proxy-wizard');
      }
    } catch {
      return res.redirect('/admin/dashboard/proxy-wizard');
    }

    let originId: number;
    try {
      const created = db.addProxyAllowedOrigin(origin, name);
      originId = created.id;
    } catch {
      return res.redirect('/admin/dashboard/origins?msg=Origin+already+exists');
    }

    const params = new URLSearchParams({ origin_id: String(originId), origin, name });
    res.redirect(`/admin/dashboard/proxy-wizard/result?${params.toString()}`);
  });

  router.get('/proxy-wizard/result', (req: Request, res: Response) => {
    const { origin, name, origin_id } = req.query as Record<string, string>;
    if (!origin) return res.redirect('/admin/dashboard/proxy-wizard');

    const authUrl = getAuthBaseUrl();

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Proxy Setup Complete', `
      <h2>Proxy Setup: ${esc(name || origin)}</h2>
      <div class="flash flash-success">Origin added successfully.</div>

      <div class="card" style="margin-bottom: 1.5rem;">
        <h3>nginx Configuration</h3>
        <p class="muted" style="margin-bottom: 0.75rem;">Add this to your nginx server block:</p>
        <div class="code-block">location / {
    auth_request /auth/verify;
    auth_request_set $auth_did $upstream_http_x_auth_did;
    auth_request_set $auth_handle $upstream_http_x_auth_handle;
    proxy_set_header X-Auth-DID $auth_did;
    proxy_set_header X-Auth-Handle $auth_handle;

    proxy_pass http://your-backend:8080;
}

location = /auth/verify {
    internal;
    proxy_pass ${esc(authUrl)}/auth/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /auth/ {
    proxy_pass ${esc(authUrl)}/auth/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
}</div>
      </div>

      <div class="card" style="margin-bottom: 1.5rem;">
        <h3>Kubernetes Ingress Annotations</h3>
        <p class="muted" style="margin-bottom: 0.75rem;">For nginx-ingress controller:</p>
        <div class="code-block">nginx.ingress.kubernetes.io/auth-url: "${esc(authUrl)}/auth/verify"
nginx.ingress.kubernetes.io/auth-signin: "${esc(authUrl)}/auth/login?redirect_uri=$scheme://$http_host$request_uri"
nginx.ingress.kubernetes.io/auth-response-headers: "X-Auth-DID,X-Auth-Handle"</div>
      </div>

      <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
        ${origin_id ? `<a href="/admin/dashboard/access?origin_id=${esc(origin_id)}" class="btn btn-primary">Add Access Rules</a>` : ''}
        <a href="/admin/dashboard/origins" class="btn btn-secondary">View All Origins</a>
      </div>
    `));
  });

  return router;
}

// ===== Helper Functions =====

function normalizeCheckboxArray(val: unknown): string[] {
  if (Array.isArray(val)) return val;
  if (typeof val === 'string' && val) return [val];
  return [];
}

function parseTextareaLines(text: string | undefined): string[] {
  if (!text) return [];
  return text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
}

function isValidRedirectUri(uri: string): boolean {
  // Allow mobile deep links (e.g., app.immich:/)
  if (/^[a-z][a-z0-9+.-]*:/.test(uri) && !uri.startsWith('http')) {
    return true;
  }
  try {
    new URL(uri);
    return true;
  } catch {
    return false;
  }
}

function truncateUri(uri: string): string {
  if (uri.length <= 40) return uri;
  return uri.substring(0, 37) + '...';
}

function formatDateObj(d: Date): string {
  return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

function getDiscoveryUrl(): string {
  // Use the configured issuer or a sensible default
  return process.env.OIDC_ISSUER
    ? `${process.env.OIDC_ISSUER}/.well-known/openid-configuration`
    : '/.well-known/openid-configuration';
}

function getAuthBaseUrl(): string {
  return process.env.OIDC_ISSUER || 'https://your-atauth-domain';
}

function renderClientForm(
  csrf: string,
  values: { id: string; name: string; redirect_uris: string; grant_types: string[]; scopes: string[]; auth_method: string; require_pkce: boolean; id_token_ttl: number; access_token_ttl: number; refresh_token_ttl: number },
  error?: string,
  preset?: string,
): string {
  return `
    ${error ? `<div class="flash" style="background:#451a22;border:1px solid #7f1d2f;color:#fca5a5;">${esc(error)}</div>` : ''}
    <h2>New OIDC Client</h2>
    <div class="card">
      <form method="POST" action="/admin/dashboard/clients/new">
        <input type="hidden" name="_csrf" value="${csrf}">
        ${preset ? `<input type="hidden" name="preset" value="${esc(preset)}">` : ''}
        <div class="form-group">
          <label for="id">Client ID</label>
          <input type="text" id="id" name="id" value="${esc(values.id)}" required pattern="[a-z0-9][a-z0-9_-]*" placeholder="my-app">
        </div>
        <div class="form-group">
          <label for="name">Display Name</label>
          <input type="text" id="name" name="name" value="${esc(values.name)}" required placeholder="My Application">
        </div>
        <div class="form-group">
          <label for="redirect_uris_text">Redirect URIs (one per line)</label>
          <textarea id="redirect_uris_text" name="redirect_uris_text" required placeholder="https://app.example.com/callback">${esc(values.redirect_uris)}</textarea>
        </div>
        <div class="form-group">
          <label>Grant Types</label>
          <div class="checkbox-group">
            <label><input type="checkbox" name="grant_types" value="authorization_code" ${values.grant_types.includes('authorization_code') ? 'checked' : ''}> authorization_code</label>
            <label><input type="checkbox" name="grant_types" value="refresh_token" ${values.grant_types.includes('refresh_token') ? 'checked' : ''}> refresh_token</label>
          </div>
        </div>
        <div class="form-group">
          <label>Scopes</label>
          <div class="checkbox-group">
            <label><input type="checkbox" name="scopes" value="openid" ${values.scopes.includes('openid') ? 'checked' : ''}> openid</label>
            <label><input type="checkbox" name="scopes" value="profile" ${values.scopes.includes('profile') ? 'checked' : ''}> profile</label>
            <label><input type="checkbox" name="scopes" value="email" ${values.scopes.includes('email') ? 'checked' : ''}> email</label>
          </div>
        </div>
        <div class="form-group">
          <label for="auth_method">Token Endpoint Auth Method</label>
          <select id="auth_method" name="auth_method">
            <option value="client_secret_basic" ${values.auth_method === 'client_secret_basic' ? 'selected' : ''}>client_secret_basic</option>
            <option value="client_secret_post" ${values.auth_method === 'client_secret_post' ? 'selected' : ''}>client_secret_post</option>
            <option value="none" ${values.auth_method === 'none' ? 'selected' : ''}>none (public client)</option>
          </select>
        </div>
        <div class="form-group">
          <div class="checkbox-group">
            <label><input type="checkbox" name="require_pkce" ${values.require_pkce ? 'checked' : ''}> Require PKCE</label>
          </div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem;">
          <div class="form-group">
            <label for="id_token_ttl">ID Token TTL (s)</label>
            <input type="number" id="id_token_ttl" name="id_token_ttl" value="${values.id_token_ttl}" min="60">
          </div>
          <div class="form-group">
            <label for="access_token_ttl">Access Token TTL (s)</label>
            <input type="number" id="access_token_ttl" name="access_token_ttl" value="${values.access_token_ttl}" min="60">
          </div>
          <div class="form-group">
            <label for="refresh_token_ttl">Refresh Token TTL (s)</label>
            <input type="number" id="refresh_token_ttl" name="refresh_token_ttl" value="${values.refresh_token_ttl}" min="60">
          </div>
        </div>
        <button type="submit" class="btn btn-primary">Create Client</button>
        <a href="/admin/dashboard/clients" class="btn btn-secondary" style="margin-left: 0.5rem;">Cancel</a>
      </form>
    </div>
  `;
}

function renderClientFormWithError(res: Response, _body: Record<string, unknown>, error: string): void {
  const msg = encodeURIComponent(error);
  res.redirect(`/admin/dashboard/clients/new?error=${msg}`);
}

// ===== Template Helpers =====

function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

function truncateDid(did: string): string {
  if (did.length <= 24) return did;
  return did.substring(0, 20) + '...';
}

// ===== Layout Template =====

function layout(title: string, content: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${esc(title)} - ATAuth Admin</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
    }
    .shell {
      display: flex;
      min-height: 100vh;
    }
    nav {
      width: 220px;
      background: #1e293b;
      border-right: 1px solid #334155;
      padding: 1.5rem 0;
      flex-shrink: 0;
    }
    nav .brand {
      padding: 0 1.25rem;
      font-size: 1.1rem;
      font-weight: 700;
      color: #f1f5f9;
      margin-bottom: 1.5rem;
    }
    nav a {
      display: block;
      padding: 0.5rem 1.25rem;
      color: #94a3b8;
      text-decoration: none;
      font-size: 0.875rem;
      transition: background 0.15s, color 0.15s;
    }
    nav a:hover, nav a.active {
      background: #334155;
      color: #f1f5f9;
    }
    nav .divider {
      margin: 0.75rem 0;
      border-top: 1px solid #334155;
    }
    main {
      flex: 1;
      padding: 2rem;
      max-width: 960px;
    }
    h2 {
      font-size: 1.5rem;
      font-weight: 600;
      color: #f1f5f9;
      margin-bottom: 1.25rem;
    }
    h3 {
      font-size: 1rem;
      font-weight: 600;
      color: #f1f5f9;
      margin-bottom: 0.75rem;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 1.25rem;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
    }
    .stat-card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 1.25rem;
      text-align: center;
    }
    .stat-value {
      font-size: 2rem;
      font-weight: 700;
      color: #3b82f6;
    }
    .stat-label {
      color: #94a3b8;
      font-size: 0.875rem;
      margin-top: 0.25rem;
    }
    .stat-link {
      display: inline-block;
      margin-top: 0.5rem;
      color: #60a5fa;
      font-size: 0.8rem;
      text-decoration: none;
    }
    .stat-link:hover { text-decoration: underline; }
    table {
      width: 100%;
      border-collapse: collapse;
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      overflow: hidden;
    }
    th, td {
      padding: 0.625rem 0.875rem;
      text-align: left;
      border-bottom: 1px solid #334155;
      font-size: 0.875rem;
    }
    th {
      background: #334155;
      color: #94a3b8;
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    code {
      background: #0f172a;
      padding: 0.15rem 0.4rem;
      border-radius: 4px;
      font-size: 0.8rem;
      color: #7dd3fc;
    }
    .badge {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-allow { background: #14532d; color: #4ade80; }
    .badge-deny { background: #7f1d1d; color: #fca5a5; }
    .btn {
      display: inline-block;
      padding: 0.5rem 1rem;
      border: none;
      border-radius: 8px;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      text-decoration: none;
      transition: background 0.15s;
      color: #fff;
    }
    .btn-primary { background: #3b82f6; }
    .btn-primary:hover { background: #2563eb; }
    .btn-secondary { background: #475569; }
    .btn-secondary:hover { background: #64748b; }
    .btn-danger { background: #991b1b; }
    .btn-danger:hover { background: #b91c1c; }
    .btn-sm { padding: 0.25rem 0.625rem; font-size: 0.8rem; }
    .form-group {
      margin-bottom: 0.75rem;
    }
    .form-group label {
      display: block;
      font-size: 0.8rem;
      font-weight: 500;
      color: #94a3b8;
      margin-bottom: 0.25rem;
    }
    .form-group input,
    .form-group select {
      width: 100%;
      padding: 0.5rem 0.625rem;
      background: #0f172a;
      border: 1px solid #475569;
      border-radius: 6px;
      color: #e2e8f0;
      font-size: 0.875rem;
      outline: none;
      transition: border-color 0.15s;
    }
    .form-group input:focus,
    .form-group select:focus { border-color: #3b82f6; }
    .form-inline {
      display: flex;
      gap: 0.75rem;
      align-items: flex-end;
      flex-wrap: wrap;
    }
    .form-inline .form-group { flex: 1; min-width: 140px; margin-bottom: 0; }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 0.75rem;
      align-items: end;
    }
    .flash {
      padding: 0.75rem 1rem;
      border-radius: 8px;
      margin-bottom: 1rem;
      font-size: 0.875rem;
    }
    .flash-success {
      background: #14532d;
      border: 1px solid #166534;
      color: #4ade80;
    }
    .muted { color: #64748b; }
    .active-filter {
      color: #3b82f6;
      font-weight: 600;
    }
    a { color: #60a5fa; }
    a:hover { text-decoration: underline; }
    .result-card {
      margin-top: 1rem;
      border-width: 2px;
    }
    .result-allowed {
      border-color: #166534;
      background: #0a2618;
    }
    .result-allowed h3 { color: #4ade80; }
    .result-denied {
      border-color: #7f1d1d;
      background: #1f0a0a;
    }
    .result-denied h3 { color: #fca5a5; }
    nav .nav-section {
      padding: 0.25rem 1.25rem;
      font-size: 0.65rem;
      font-weight: 600;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-top: 0.5rem;
    }
    .secret-box {
      background: #0f172a;
      border: 2px solid #f59e0b;
      border-radius: 8px;
      padding: 1rem;
      font-family: monospace;
      font-size: 0.9rem;
      word-break: break-all;
      color: #fbbf24;
      position: relative;
    }
    .secret-box .copy-btn {
      position: absolute;
      top: 0.5rem;
      right: 0.5rem;
      background: #475569;
      border: none;
      color: #e2e8f0;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.75rem;
    }
    .secret-box .copy-btn:hover { background: #64748b; }
    .callout-warning {
      background: #451a03;
      border: 1px solid #92400e;
      border-radius: 8px;
      padding: 0.75rem 1rem;
      color: #fbbf24;
      font-size: 0.875rem;
      margin: 0.75rem 0;
    }
    .callout-info {
      background: #0c1a2e;
      border: 1px solid #1e40af;
      border-radius: 8px;
      padding: 0.75rem 1rem;
      color: #93c5fd;
      font-size: 0.875rem;
      margin: 0.75rem 0;
      white-space: pre-wrap;
    }
    .wizard-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 1rem;
    }
    .wizard-card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 1.25rem;
      transition: border-color 0.15s;
    }
    .wizard-card:hover { border-color: #3b82f6; }
    .wizard-card h4 { color: #f1f5f9; margin-bottom: 0.25rem; }
    .wizard-card p { color: #94a3b8; font-size: 0.8rem; margin-bottom: 0.75rem; }
    .code-block {
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 1rem;
      font-family: monospace;
      font-size: 0.8rem;
      color: #7dd3fc;
      overflow-x: auto;
      white-space: pre;
      line-height: 1.4;
      position: relative;
    }
    .form-group textarea {
      width: 100%;
      padding: 0.5rem 0.625rem;
      background: #0f172a;
      border: 1px solid #475569;
      border-radius: 6px;
      color: #e2e8f0;
      font-size: 0.875rem;
      font-family: monospace;
      outline: none;
      transition: border-color 0.15s;
      resize: vertical;
      min-height: 80px;
    }
    .form-group textarea:focus { border-color: #3b82f6; }
    .checkbox-group {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
    }
    .checkbox-group label {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      font-size: 0.875rem;
      color: #e2e8f0;
      cursor: pointer;
    }
    .checkbox-group input[type="checkbox"] { width: auto; accent-color: #3b82f6; }
    .form-group input[readonly] { opacity: 0.7; cursor: not-allowed; }
    dl { margin-top: 0.75rem; }
    dt {
      font-size: 0.75rem;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-top: 0.5rem;
    }
    dd { margin-top: 0.15rem; }
    @media (max-width: 768px) {
      .shell { flex-direction: column; }
      nav { width: 100%; border-right: none; border-bottom: 1px solid #334155; padding: 1rem 0; }
      nav a { display: inline-block; }
      main { padding: 1rem; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <nav>
      <div class="brand">ATAuth Admin</div>
      <a href="/admin/dashboard">Overview</a>
      <div class="nav-section">OIDC</div>
      <a href="/admin/dashboard/clients">Clients</a>
      <a href="/admin/dashboard/clients/wizard">Setup Wizard</a>
      <div class="nav-section">Forward-Auth</div>
      <a href="/admin/dashboard/origins">Origins</a>
      <a href="/admin/dashboard/access">Access Rules</a>
      <a href="/admin/dashboard/sessions">Sessions</a>
      <a href="/admin/dashboard/proxy-wizard">Proxy Setup</a>
      <div class="nav-section">Tools</div>
      <a href="/admin/dashboard/check">Access Check</a>
      <div class="divider"></div>
      <a href="/admin/logout">Sign Out</a>
    </nav>
    <main>
      ${content}
    </main>
  </div>
</body>
</html>`;
}
