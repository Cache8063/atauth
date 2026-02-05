import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Header } from '../components/Layout';
import { api } from '../api/client';

export function KeysPage() {
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ['keys'],
    queryFn: () => api.getKeys(),
  });

  const rotateMutation = useMutation({
    mutationFn: () => api.rotateKeys(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (kid: string) => api.deleteKey(kid),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] });
    },
  });

  const handleRotate = () => {
    if (confirm('Generate a new signing key? The current key will remain valid but not be used for new tokens.')) {
      rotateMutation.mutate();
    }
  };

  const handleDelete = (kid: string, isActive: boolean) => {
    if (isActive) {
      alert('Cannot delete the active signing key. Rotate first to create a new key.');
      return;
    }
    if (confirm(`Delete key ${kid}? Any tokens signed with this key will become invalid.`)) {
      deleteMutation.mutate(kid);
    }
  };

  return (
    <div>
      <Header title="Signing Keys" />

      <div className="p-6">
        <div className="flex justify-between items-center mb-6">
          <div>
            <p className="text-gray-600 dark:text-gray-400">
              Manage JWT signing keys for OIDC tokens
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-500 mt-1">
              Keys are used to sign ID tokens, access tokens, and other JWTs
            </p>
          </div>
          <button
            onClick={handleRotate}
            disabled={rotateMutation.isPending}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white rounded-md transition-colors"
          >
            {rotateMutation.isPending ? 'Generating...' : 'Rotate Keys'}
          </button>
        </div>

        {rotateMutation.isSuccess && (
          <div className="mb-6 p-4 bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-md">
            New signing key generated: <code className="font-mono">{rotateMutation.data.kid}</code>
          </div>
        )}

        {isLoading ? (
          <div className="text-gray-500">Loading keys...</div>
        ) : error ? (
          <div className="p-4 bg-red-50 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-md">
            Failed to load keys
          </div>
        ) : data?.keys.length === 0 ? (
          <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg">
            <p className="text-gray-500 dark:text-gray-400">No signing keys configured</p>
            <p className="text-sm text-gray-400 mt-2">
              Click "Rotate Keys" to generate an initial signing key
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {data?.keys.map((key) => (
              <div
                key={key.kid}
                className={`bg-white dark:bg-gray-800 rounded-lg shadow p-6 ${
                  key.use_for_signing ? 'ring-2 ring-blue-500' : ''
                }`}
              >
                <div className="flex justify-between items-start">
                  <div>
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-mono text-gray-900 dark:text-white">
                        {key.kid}
                      </h3>
                      {key.use_for_signing && (
                        <span className="px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 text-xs font-medium rounded">
                          Active Signing Key
                        </span>
                      )}
                      {key.is_active && !key.use_for_signing && (
                        <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 text-xs font-medium rounded">
                          Valid for Verification
                        </span>
                      )}
                      {!key.is_active && (
                        <span className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 text-xs font-medium rounded">
                          Inactive
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                      Algorithm: <span className="font-mono">{key.algorithm}</span>
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Created: {new Date(key.created_at).toLocaleString()}
                    </p>
                  </div>
                  <button
                    onClick={() => handleDelete(key.kid, key.use_for_signing)}
                    disabled={deleteMutation.isPending || key.use_for_signing}
                    className={`px-3 py-1 text-sm rounded ${
                      key.use_for_signing
                        ? 'text-gray-400 cursor-not-allowed'
                        : 'text-red-600 hover:text-red-800 dark:hover:text-red-400'
                    }`}
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="mt-8 p-4 bg-gray-50 dark:bg-gray-800/50 rounded-lg">
          <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
            Key Rotation Best Practices
          </h4>
          <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
            <li>- Rotate keys periodically (e.g., every 90 days)</li>
            <li>- Keep old keys active for verification until all existing tokens expire</li>
            <li>- Only delete old keys after their tokens have expired</li>
            <li>- The JWKS endpoint automatically publishes all active keys</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
