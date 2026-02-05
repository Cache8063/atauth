import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Header } from '../components/Layout';
import { api } from '../api/client';

export function SessionsPage() {
  const queryClient = useQueryClient();
  const [filterDid, setFilterDid] = useState('');
  const [filterAppId, setFilterAppId] = useState('');

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['sessions', filterDid, filterAppId],
    queryFn: () =>
      api.getSessions({
        did: filterDid || undefined,
        app_id: filterAppId || undefined,
        limit: 100,
      }),
    refetchInterval: 30000,
  });

  const revokeMutation = useMutation({
    mutationFn: (sessionId: string) => api.revokeSession(sessionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const revokeAllMutation = useMutation({
    mutationFn: ({ did, appId }: { did: string; appId?: string }) =>
      api.revokeAllSessions(did, appId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const handleRevoke = (sessionId: string) => {
    if (confirm('Revoke this session?')) {
      revokeMutation.mutate(sessionId);
    }
  };

  const handleRevokeAll = () => {
    if (!filterDid) {
      alert('Enter a DID to revoke all sessions for that user');
      return;
    }
    if (confirm(`Revoke all sessions for ${filterDid}?`)) {
      revokeAllMutation.mutate({
        did: filterDid,
        appId: filterAppId || undefined,
      });
    }
  };

  return (
    <div>
      <Header title="Sessions" />

      <div className="p-6">
        <div className="mb-6">
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            View and manage active user sessions
          </p>

          <div className="flex gap-4 items-end">
            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Filter by DID
              </label>
              <input
                type="text"
                value={filterDid}
                onChange={(e) => setFilterDid(e.target.value)}
                className="block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="did:plc:..."
              />
            </div>
            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Filter by App ID
              </label>
              <input
                type="text"
                value={filterAppId}
                onChange={(e) => setFilterAppId(e.target.value)}
                className="block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                placeholder="app-id"
              />
            </div>
            <button
              onClick={() => refetch()}
              className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 rounded-md"
            >
              Refresh
            </button>
            {filterDid && (
              <button
                onClick={handleRevokeAll}
                disabled={revokeAllMutation.isPending}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-red-400 text-white rounded-md"
              >
                Revoke All
              </button>
            )}
          </div>
        </div>

        {isLoading ? (
          <div className="text-gray-500">Loading sessions...</div>
        ) : error ? (
          <div className="p-4 bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-md">
            Failed to load sessions
          </div>
        ) : data?.sessions.length === 0 ? (
          <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg">
            <p className="text-gray-500 dark:text-gray-400">No active sessions found</p>
          </div>
        ) : (
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-900">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    App
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Created
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Expires
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {data?.sessions.map((session) => (
                  <tr key={session.id}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900 dark:text-white">
                        @{session.handle}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 font-mono">
                        {session.did.substring(0, 20)}...
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 font-mono">
                      {session.app_id.substring(0, 8)}...
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <StatusBadge status={session.connection_state} />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {formatDateTime(session.created_at)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {formatDateTime(session.expires_at)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <button
                        onClick={() => handleRevoke(session.id)}
                        className="text-red-600 hover:text-red-900 dark:hover:text-red-400"
                        disabled={revokeMutation.isPending}
                      >
                        Revoke
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

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    active: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
    pending: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
    connected: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
    disconnected: 'bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-400',
  };

  return (
    <span
      className={`inline-flex px-2 py-0.5 text-xs font-medium rounded-full ${
        colors[status] || colors.pending
      }`}
    >
      {status}
    </span>
  );
}

function formatDateTime(dateStr: string): string {
  const date = new Date(dateStr);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
