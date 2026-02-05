import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Header } from '../components/Layout';
import { api } from '../api/client';

export function AppsPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [newSecret, setNewSecret] = useState<{ appId: string; secret: string } | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['apps'],
    queryFn: () => api.getApps(),
  });

  const deleteMutation = useMutation({
    mutationFn: (appId: string) => api.deleteApp(appId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['apps'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const rotateMutation = useMutation({
    mutationFn: (appId: string) => api.rotateAppSecret(appId),
    onSuccess: (data, appId) => {
      setNewSecret({ appId, secret: data.hmac_secret });
    },
  });

  const handleDelete = (appId: string, appName: string) => {
    if (confirm(`Are you sure you want to delete "${appName}"? This cannot be undone.`)) {
      deleteMutation.mutate(appId);
    }
  };

  const handleRotate = (appId: string, appName: string) => {
    if (confirm(`Rotate secret for "${appName}"? The old secret will stop working immediately.`)) {
      rotateMutation.mutate(appId);
    }
  };

  return (
    <div>
      <Header title="Legacy Apps" />

      <div className="p-6">
        <div className="flex justify-between items-center mb-6">
          <p className="text-gray-600 dark:text-gray-400">
            Manage legacy apps using HMAC-signed tokens
          </p>
          <button
            onClick={() => setShowCreate(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
          >
            Create App
          </button>
        </div>

        {showCreate && (
          <CreateAppModal
            onClose={() => setShowCreate(false)}
            onCreated={(secret) => {
              setShowCreate(false);
              setNewSecret(secret);
              queryClient.invalidateQueries({ queryKey: ['apps'] });
              queryClient.invalidateQueries({ queryKey: ['stats'] });
            }}
          />
        )}

        {newSecret && (
          <SecretModal
            appId={newSecret.appId}
            secret={newSecret.secret}
            onClose={() => setNewSecret(null)}
          />
        )}

        {isLoading ? (
          <div className="text-gray-500">Loading apps...</div>
        ) : error ? (
          <div className="p-4 bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-md">
            Failed to load apps
          </div>
        ) : data?.apps.length === 0 ? (
          <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg">
            <p className="text-gray-500 dark:text-gray-400">No apps registered yet</p>
          </div>
        ) : (
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-900">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    App ID
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Token TTL
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Created
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {data?.apps.map((app) => (
                  <tr key={app.id}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900 dark:text-white">
                        {app.name}
                      </div>
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        {app.callback_url}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 font-mono">
                      {app.id.substring(0, 8)}...
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {formatDuration(app.token_ttl_seconds)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {new Date(app.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
                      <button
                        onClick={() => handleRotate(app.id, app.name)}
                        className="text-yellow-600 hover:text-yellow-900 dark:hover:text-yellow-400"
                        disabled={rotateMutation.isPending}
                      >
                        Rotate Secret
                      </button>
                      <button
                        onClick={() => handleDelete(app.id, app.name)}
                        className="text-red-600 hover:text-red-900 dark:hover:text-red-400"
                        disabled={deleteMutation.isPending}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

interface CreateAppModalProps {
  onClose: () => void;
  onCreated: (secret: { appId: string; secret: string }) => void;
}

function CreateAppModal({ onClose, onCreated }: CreateAppModalProps) {
  const [name, setName] = useState('');
  const [callbackUrl, setCallbackUrl] = useState('');
  const [ttl, setTtl] = useState('3600');

  const createMutation = useMutation({
    mutationFn: () =>
      api.createApp({
        name,
        callback_url: callbackUrl,
        token_ttl_seconds: parseInt(ttl, 10),
      }),
    onSuccess: (data) => {
      onCreated({ appId: data.id, secret: data.hmac_secret });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-md p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Create Legacy App
        </h3>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              App Name
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
              Callback URL
            </label>
            <input
              type="url"
              value={callbackUrl}
              onChange={(e) => setCallbackUrl(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              placeholder="https://myapp.com/auth/callback"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Token TTL (seconds)
            </label>
            <input
              type="number"
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              min="60"
              required
            />
          </div>

          {createMutation.error && (
            <div className="p-3 bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-md text-sm">
              {createMutation.error instanceof Error
                ? createMutation.error.message
                : 'Failed to create app'}
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

interface SecretModalProps {
  appId: string;
  secret: string;
  onClose: () => void;
}

function SecretModal({ appId, secret, onClose }: SecretModalProps) {
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
          App Secret
        </h3>
        <p className="text-sm text-yellow-600 dark:text-yellow-400 mb-4">
          Save this secret now! It won't be shown again.
        </p>

        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            App ID
          </label>
          <code className="block p-2 bg-gray-100 dark:bg-gray-900 rounded text-sm break-all">
            {appId}
          </code>
        </div>

        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            HMAC Secret
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
