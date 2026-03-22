/**
 * Login Webhook Notifications
 *
 * Sends login events to a Matrix room via the Client-Server API.
 * Fire-and-forget — errors are logged but never block the auth flow.
 */

export interface WebhookConfig {
  enabled: boolean;
  /** Matrix homeserver URL (e.g., http://synapse.matrix.svc.cluster.local:8008) */
  matrixHomeserverUrl: string;
  /** Matrix bot access token */
  matrixAccessToken: string;
  /** Matrix room ID to post to */
  matrixRoomId: string;
  /** Client IDs to send login notifications for */
  loginNotifyClients: string[];
}

export interface LoginEvent {
  client_id: string;
  client_name: string;
  did: string;
  handle: string;
}

let txnCounter = 0;

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export async function notifyLogin(config: WebhookConfig, event: LoginEvent): Promise<void> {
  const text = `Login: ${event.handle} authenticated to ${event.client_name}`;
  const html = `<b>Login</b>: <code>${escapeHtml(event.handle)}</code> (<code>${escapeHtml(event.did)}</code>) → <b>${escapeHtml(event.client_name)}</b>`;
  const txnId = `atauth-${Date.now()}-${++txnCounter}`;
  const roomId = encodeURIComponent(config.matrixRoomId);

  const url = `${config.matrixHomeserverUrl}/_matrix/client/v3/rooms/${roomId}/send/m.room.message/${txnId}`;

  const resp = await fetch(url, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.matrixAccessToken}`,
    },
    body: JSON.stringify({
      msgtype: 'm.text',
      body: text,
      format: 'org.matrix.custom.html',
      formatted_body: html,
    }),
    signal: AbortSignal.timeout(5000),
  });

  if (!resp.ok) {
    throw new Error(`Matrix API returned ${resp.status}: ${await resp.text()}`);
  }
}
