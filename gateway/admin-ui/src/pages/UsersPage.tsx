import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Header } from '../components/Layout';
import { api } from '../api/client';

export function UsersPage() {
  const queryClient = useQueryClient();
  const [selectedUser, setSelectedUser] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.getUsers({ limit: 100 }),
  });

  const { data: userDetails, isLoading: detailsLoading } = useQuery({
    queryKey: ['user', selectedUser],
    queryFn: () => (selectedUser ? api.getUser(selectedUser) : null),
    enabled: !!selectedUser,
  });

  return (
    <div>
      <Header title="Users" />

      <div className="p-6">
        <p className="text-gray-600 dark:text-gray-400 mb-6">
          View and manage user accounts, passkeys, MFA, and sessions
        </p>

        {isLoading ? (
          <div className="text-gray-500">Loading users...</div>
        ) : error ? (
          <div className="p-4 bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-md">
            Failed to load users
          </div>
        ) : data?.users.length === 0 ? (
          <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg">
            <p className="text-gray-500 dark:text-gray-400">No users found</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1">
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                  <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                    Users ({data?.users.length})
                  </h3>
                </div>
                <div className="divide-y divide-gray-200 dark:divide-gray-700 max-h-[600px] overflow-auto">
                  {data?.users.map((user) => (
                    <button
                      key={user.did}
                      onClick={() => setSelectedUser(user.did)}
                      className={`w-full px-4 py-3 text-left hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors ${
                        selectedUser === user.did
                          ? 'bg-blue-50 dark:bg-blue-900/30'
                          : ''
                      }`}
                    >
                      <div className="font-medium text-gray-900 dark:text-white">
                        @{user.handle}
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 font-mono mt-0.5">
                        {user.did.substring(0, 30)}...
                      </div>
                      <div className="flex gap-3 mt-2 text-xs text-gray-500 dark:text-gray-400">
                        {user.passkeys_count > 0 && (
                          <span title="Passkeys">{user.passkeys_count} passkeys</span>
                        )}
                        {user.mfa_enabled && (
                          <span className="text-green-600 dark:text-green-400">MFA</span>
                        )}
                        {user.sessions_count > 0 && (
                          <span>{user.sessions_count} sessions</span>
                        )}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="lg:col-span-2">
              {selectedUser ? (
                detailsLoading ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <div className="text-gray-500">Loading user details...</div>
                  </div>
                ) : userDetails?.user ? (
                  <UserDetails
                    user={userDetails.user}
                    onRefresh={() =>
                      queryClient.invalidateQueries({ queryKey: ['user', selectedUser] })
                    }
                  />
                ) : null
              ) : (
                <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 text-center">
                  <p className="text-gray-500 dark:text-gray-400">
                    Select a user to view details
                  </p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

interface UserDetailsProps {
  user: {
    did: string;
    handle: string;
    passkeys: Array<{
      id: string;
      name: string | null;
      device_type: string;
      backed_up: boolean;
      last_used_at: string | null;
      created_at: string;
    }>;
    mfa_enabled: boolean;
    emails: Array<{
      email: string;
      verified: boolean;
      is_primary: boolean;
    }>;
    sessions: Array<{
      id: string;
      app_id: string;
      created_at: string;
      expires_at: string;
    }>;
  };
  onRefresh: () => void;
}

function UserDetails({ user, onRefresh }: UserDetailsProps) {
  const queryClient = useQueryClient();

  const revokeMfaMutation = useMutation({
    mutationFn: () => api.revokeUserMFA(user.did),
    onSuccess: () => {
      onRefresh();
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const deletePasskeyMutation = useMutation({
    mutationFn: (credentialId: string) => api.deleteUserPasskey(user.did, credentialId),
    onSuccess: () => {
      onRefresh();
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const handleRevokeMfa = () => {
    if (confirm('Disable MFA for this user? They will need to set it up again.')) {
      revokeMfaMutation.mutate();
    }
  };

  const handleDeletePasskey = (credentialId: string, name: string | null) => {
    if (confirm(`Delete passkey "${name || credentialId.substring(0, 8)}"?`)) {
      deletePasskeyMutation.mutate(credentialId);
    }
  };

  return (
    <div className="space-y-6">
      {/* User Info */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
          User Information
        </h3>
        <dl className="grid grid-cols-2 gap-4">
          <div>
            <dt className="text-sm text-gray-500 dark:text-gray-400">Handle</dt>
            <dd className="text-gray-900 dark:text-white">@{user.handle}</dd>
          </div>
          <div>
            <dt className="text-sm text-gray-500 dark:text-gray-400">DID</dt>
            <dd className="text-gray-900 dark:text-white font-mono text-sm break-all">
              {user.did}
            </dd>
          </div>
        </dl>
      </div>

      {/* Passkeys */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            Passkeys ({user.passkeys.length})
          </h3>
        </div>
        {user.passkeys.length === 0 ? (
          <p className="text-gray-500 dark:text-gray-400">No passkeys registered</p>
        ) : (
          <div className="space-y-3">
            {user.passkeys.map((passkey) => (
              <div
                key={passkey.id}
                className="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg"
              >
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">
                    {passkey.name || `Passkey ${passkey.id.substring(0, 8)}...`}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    {passkey.device_type} • {passkey.backed_up ? 'Backed up' : 'Not backed up'}
                    {passkey.last_used_at && (
                      <> • Last used: {new Date(passkey.last_used_at).toLocaleDateString()}</>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => handleDeletePasskey(passkey.id, passkey.name)}
                  className="text-red-600 hover:text-red-800 dark:hover:text-red-400 text-sm"
                  disabled={deletePasskeyMutation.isPending}
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* MFA */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            Two-Factor Authentication
          </h3>
          {user.mfa_enabled && (
            <button
              onClick={handleRevokeMfa}
              className="text-red-600 hover:text-red-800 dark:hover:text-red-400 text-sm"
              disabled={revokeMfaMutation.isPending}
            >
              Disable MFA
            </button>
          )}
        </div>
        <p className="text-gray-500 dark:text-gray-400">
          {user.mfa_enabled ? (
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 bg-green-500 rounded-full"></span>
              TOTP Enabled
            </span>
          ) : (
            'Not configured'
          )}
        </p>
      </div>

      {/* Emails */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
          Email Addresses ({user.emails.length})
        </h3>
        {user.emails.length === 0 ? (
          <p className="text-gray-500 dark:text-gray-400">No emails registered</p>
        ) : (
          <div className="space-y-2">
            {user.emails.map((email) => (
              <div
                key={email.email}
                className="flex items-center gap-3 p-2 bg-gray-50 dark:bg-gray-700 rounded"
              >
                <span className="text-gray-900 dark:text-white">{email.email}</span>
                {email.is_primary && (
                  <span className="px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 text-xs rounded">
                    Primary
                  </span>
                )}
                {email.verified ? (
                  <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 text-xs rounded">
                    Verified
                  </span>
                ) : (
                  <span className="px-2 py-0.5 bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 text-xs rounded">
                    Pending
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Sessions */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
          Active Sessions ({user.sessions.length})
        </h3>
        {user.sessions.length === 0 ? (
          <p className="text-gray-500 dark:text-gray-400">No active sessions</p>
        ) : (
          <div className="space-y-2">
            {user.sessions.map((session) => (
              <div
                key={session.id}
                className="flex justify-between items-center p-2 bg-gray-50 dark:bg-gray-700 rounded"
              >
                <div className="text-sm">
                  <span className="text-gray-900 dark:text-white font-mono">
                    {session.app_id.substring(0, 12)}...
                  </span>
                  <span className="text-gray-500 dark:text-gray-400 ml-2">
                    Expires: {new Date(session.expires_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
