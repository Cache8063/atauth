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

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(layout('Dashboard', `
      <h2>Overview</h2>
      <div class="stats-grid">
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
          <a href="/admin/dashboard/check" class="btn btn-secondary">Test Access Check</a>
          <a href="/admin/dashboard/origins" class="btn btn-secondary">Add Origin</a>
          <a href="/admin/dashboard/access" class="btn btn-secondary">Add Rule</a>
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
    } catch (e) {
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

  return router;
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
      <a href="/admin/dashboard/origins">Origins</a>
      <a href="/admin/dashboard/access">Access Rules</a>
      <a href="/admin/dashboard/sessions">Sessions</a>
      <div class="divider"></div>
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
