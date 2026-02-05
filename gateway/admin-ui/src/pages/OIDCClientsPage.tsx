import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Header } from '../components/Layout';
import { api } from '../api/client';

export function OIDCClientsPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editingClient, setEditingClient] = useState<string | null>(null);
  const [newSecret, setNewSecret] = useState<{ clientId: string; secret: string } | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['oidc-clients'],
    queryFn: () => api.getOIDCClients(),
  });

  const deleteMutation = useMutation({
    mutationFn: (clientId: string) => api.deleteOIDCClient(clientId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oidc-clients'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const rotateMutation = useMutation({
    mutationFn: (clientId: string) => api.rotateOIDCClientSecret(clientId),
    onSuccess: (data, clientId) => {
      setNewSecret({ clientId, secret: data.client_secret });
    },
  });

  const handleDelete = (clientId: string, clientName: string) => {
    if (confirm(`Delete OIDC client "${clientName}"? All associated tokens will be invalidated.`)) {
      deleteMutation.mutate(clientId);
    }
  };

  const handleRotate = (clientId: string, clientName: string) => {
    if (confirm(`Rotate secret for "${clientName}"? The old secret will stop working.`)) {
      rotateMutation.mutate(clientId);
    }
  };

  return (
    <div>
      <Header title="OIDC Clients" />

      <div className="p-6">
        <div className="flex justify-between items-center mb-6">
          <p className="text-gray-600 dark:text-gray-400">
            Manage OpenID Connect clients for OAuth 2.0 authentication
          </p>
          <button
            onClick={() => setShowCreate(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
          >
            Create OIDC Client
          </button>
        </div>

        {showCreate && (
          <CreateOIDCClientModal
            onClose={() => setShowCreate(false)}
            onCreated={(secret) => {
              setShowCreate(false);
              setNewSecret(secret);
              queryClient.invalidateQueries({ queryKey: ['oidc-clients'] });
              queryClient.invalidateQueries({ queryKey: ['stats'] });
            }}
          />
        )}

        {editingClient && (
          <EditOIDCClientModal
            clientId={editingClient}
            client={data?.clients.find((c) => c.id === editingClient)}
            onClose={() => setEditingClient(null)}
            onSaved={() => {
              setEditingClient(null);
              queryClient.invalidateQueries({ queryKey: ['oidc-clients'] });
            }}
          />
        )}

        {newSecret && (
          <SecretModal
            clientId={newSecret.clientId}
            secret={newSecret.secret}
            onClose={() => setNewSecret(null)}
          />
        )}

        {isLoading ? (
          <div className="text-gray-500">Loading OIDC clients...</div>
        ) : error ? (
          <div className="p-4 bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-md">
            Failed to load OIDC clients
          </div>
        ) : data?.clients.length === 0 ? (
          <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg">
            <p className="text-gray-500 dark:text-gray-400">No OIDC clients registered</p>
            <p className="text-sm text-gray-400 mt-2">
              Create an OIDC client to enable OAuth 2.0 / OpenID Connect authentication
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {data?.clients.map((client) => (
              <div
                key={client.id}
                className="bg-white dark:bg-gray-800 rounded-lg shadow p-6"
              >
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                      {client.name}
                    </h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400 font-mono mt-1">
                      Client ID: {client.id}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setEditingClient(client.id)}
                      className="px-3 py-1 text-sm text-blue-600 hover:text-blue-800 dark:hover:text-blue-400"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleRotate(client.id, client.name)}
                      className="px-3 py-1 text-sm text-yellow-600 hover:text-yellow-800 dark:hover:text-yellow-400"
                    >
                      Rotate Secret
                    </button>
                    <button
                      onClick={() => handleDelete(client.id, client.name)}
                      className="px-3 py-1 text-sm text-red-600 hover:text-red-800 dark:hover:text-red-400"
                    >
                      Delete
                    </button>
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-500 dark:text-gray-400">Redirect URIs:</span>
                    <ul className="mt-1 space-y-1">
                      {client.redirect_uris.map((uri, i) => (
                        <li key={i} className="text-gray-900 dark:text-white font-mono text-xs">
                          {uri}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <span className="text-gray-500 dark:text-gray-400">Scopes:</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {client.allowed_scopes.map((scope) => (
                        <span
                          key={scope}
                          className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs"
                        >
                          {scope}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-4 flex gap-6 text-xs text-gray-500 dark:text-gray-400">
                  <span>PKCE: {client.require_pkce ? 'Required' : 'Optional'}</span>
                  <span>Access Token: {formatDuration(client.access_token_ttl_seconds)}</span>
                  <span>ID Token: {formatDuration(client.id_token_ttl_seconds)}</span>
                  <span>Refresh Token: {formatDuration(client.refresh_token_ttl_seconds)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

interface CreateOIDCClientModalProps {
  onClose: () => void;
  onCreated: (secret: { clientId: string; secret: string }) => void;
}

function CreateOIDCClientModal({ onClose, onCreated }: CreateOIDCClientModalProps) {
  const [name, setName] = useState('');
  const [redirectUris, setRedirectUris] = useState('');
  const [scopes, setScopes] = useState('openid profile email');
  const [requirePkce, setRequirePkce] = useState(true);
  const [accessTtl, setAccessTtl] = useState('3600');
  const [idTtl, setIdTtl] = useState('3600');
  const [refreshTtl, setRefreshTtl] = useState('604800');

  const createMutation = useMutation({
    mutationFn: () =>
      api.createOIDCClient({
        name,
        redirect_uris: redirectUris.split('\n').map((u) => u.trim()).filter(Boolean),
        allowed_scopes: scopes.split(' ').filter(Boolean),
        require_pkce: requirePkce,
        access_token_ttl_seconds: parseInt(accessTtl, 10),
        id_token_ttl_seconds: parseInt(idTtl, 10),
        refresh_token_ttl_seconds: parseInt(refreshTtl, 10),
      }),
    onSuccess: (data) => {
      onCreated({ clientId: data.id, secret: data.client_secret });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 overflow-auto py-8">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg p-6 m-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Create OIDC Client
        </h3>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Client Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Redirect URIs (one per line)
            </label>
            <textarea
              value={redirectUris}
              onChange={(e) => setRedirectUris(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
              rows={3}
              placeholder="https://myapp.com/callback&#10;https://myapp.com/auth/callback"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Allowed Scopes (space-separated)
            </label>
            <input
              type="text"
              value={scopes}
              onChange={(e) => setScopes(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
            />
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="requirePkce"
              checked={requirePkce}
              onChange={(e) => setRequirePkce(e.target.checked)}
              className="h-4 w-4 text-blue-600 rounded"
            />
            <label htmlFor="requirePkce" className="text-sm text-gray-700 dark:text-gray-300">
              Require PKCE (recommended)
            </label>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Access Token TTL
              </label>
              <input
                type="number"
                value={accessTtl}
                onChange={(e) => setAccessTtl(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                min="60"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                ID Token TTL
              </label>
              <input
                type="number"
                value={idTtl}
                onChange={(e) => setIdTtl(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                min="60"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Refresh Token TTL
              </label>
              <input
                type="number"
                value={refreshTtl}
                onChange={(e) => setRefreshTtl(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                min="60"
              />
            </div>
          </div>

          {createMutation.error && (
            <div className="p-3 bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-md text-sm">
              {createMutation.error instanceof Error
                ? createMutation.error.message
                : 'Failed to create client'}
            </div>
          )}

          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white rounded-md"
            >
              {createMutation.isPending ? 'Creating...' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

interface EditOIDCClientModalProps {
  clientId: string;
  client?: {
    name: string;
    redirect_uris: string[];
    allowed_scopes: string[];
    require_pkce: boolean;
    access_token_ttl_seconds: number;
    id_token_ttl_seconds: number;
    refresh_token_ttl_seconds: number;
  };
  onClose: () => void;
  onSaved: () => void;
}

function EditOIDCClientModal({ clientId, client, onClose, onSaved }: EditOIDCClientModalProps) {
  const [name, setName] = useState(client?.name || '');
  const [redirectUris, setRedirectUris] = useState(client?.redirect_uris.join('\n') || '');
  const [scopes, setScopes] = useState(client?.allowed_scopes.join(' ') || '');
  const [requirePkce, setRequirePkce] = useState(client?.require_pkce ?? true);
  const [accessTtl, setAccessTtl] = useState(String(client?.access_token_ttl_seconds || 3600));
  const [idTtl, setIdTtl] = useState(String(client?.id_token_ttl_seconds || 3600));
  const [refreshTtl, setRefreshTtl] = useState(String(client?.refresh_token_ttl_seconds || 604800));

  const updateMutation = useMutation({
    mutationFn: () =>
      api.updateOIDCClient(clientId, {
        name,
        redirect_uris: redirectUris.split('\n').map((u) => u.trim()).filter(Boolean),
        allowed_scopes: scopes.split(' ').filter(Boolean),
        require_pkce: requirePkce,
        access_token_ttl_seconds: parseInt(accessTtl, 10),
        id_token_ttl_seconds: parseInt(idTtl, 10),
        refresh_token_ttl_seconds: parseInt(refreshTtl, 10),
      }),
    onSuccess: onSaved,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateMutation.mutate();
  };

  if (!client) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 overflow-auto py-8">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg p-6 m-4">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Edit OIDC Client
        </h3>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Client Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Redirect URIs (one per line)
            </label>
            <textarea
              value={redirectUris}
              onChange={(e) => setRedirectUris(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
              rows={3}
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Allowed Scopes (space-separated)
            </label>
            <input
              type="text"
              value={scopes}
              onChange={(e) => setScopes(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
            />
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="editRequirePkce"
              checked={requirePkce}
              onChange={(e) => setRequirePkce(e.target.checked)}
              className="h-4 w-4 text-blue-600 rounded"
            />
            <label htmlFor="editRequirePkce" className="text-sm text-gray-700 dark:text-gray-300">
              Require PKCE
            </label>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Access Token TTL
              </label>
              <input
                type="number"
                value={accessTtl}
                onChange={(e) => setAccessTtl(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                min="60"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                ID Token TTL
              </label>
              <input
                type="number"
                value={idTtl}
                onChange={(e) => setIdTtl(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                min="60"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Refresh Token TTL
              </label>
              <input
                type="number"
                value={refreshTtl}
                onChange={(e) => setRefreshTtl(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                min="60"
              />
            </div>
          </div>

          {updateMutation.error && (
            <div className="p-3 bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-md text-sm">
              {updateMutation.error instanceof Error
                ? updateMutation.error.message
                : 'Failed to update client'}
            </div>
          )}

          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={updateMutation.isPending}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white rounded-md"
            >
              {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

interface SecretModalProps {
  clientId: string;
  secret: string;
  onClose: () => void;
}

function SecretModal({ clientId, secret, onClose }: SecretModalProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-md p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
          Client Secret
        </h3>
        <p className="text-sm text-yellow-600 dark:text-yellow-400 mb-4">
          Save this secret now! It won't be shown again.
        </p>

        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Client ID
          </label>
          <code className="block p-2 bg-gray-100 dark:bg-gray-900 rounded text-sm break-all">
            {clientId}
          </code>
        </div>

        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Client Secret
          </label>
          <div className="relative">
            <code className="block p-2 bg-gray-100 dark:bg-gray-900 rounded text-sm break-all pr-20">
              {secret}
            </code>
            <button
              onClick={handleCopy}
              className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </div>

        <button
          onClick={onClose}
          className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md"
        >
          Done
        </button>
      </div>
    </div>
  );
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}
