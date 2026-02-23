/**
 * React hooks and utilities for AT Protocol authentication
 *
 * @example
 * ```tsx
 * import { useAuthStore, AuthProvider } from 'atauth/react';
 *
 * function App() {
 *   const { isAuthenticated, user, login, logout } = useAuthStore();
 *
 *   if (!isAuthenticated) {
 *     return <button onClick={login}>Login with Bluesky</button>;
 *   }
 *
 *   return (
 *     <div>
 *       <p>Welcome, {user?.handle}!</p>
 *       <button onClick={logout}>Logout</button>
 *     </div>
 *   );
 * }
 * ```
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

import type { TokenPayload, AuthStore, AtAuthConfig } from './types';
import { decodeToken, isTokenExpired, shouldRefreshToken } from './token';
import { getStoredToken, removeStoredToken, storeToken } from './storage';
import { redirectToAuth, handleCallback, isOAuthCallback, buildLogoutUrl } from './oauth';

/**
 * Create an auth store with the given configuration.
 *
 * @param config - Auth configuration
 * @returns Zustand store hook
 */
export function createAuthStore(config: AtAuthConfig) {
  const storageKey = config.storageKey || 'atauth_token';

  return create<AuthStore>()(
    persist(
      (set, _get) => ({
        // Initial state
        isAuthenticated: false,
        isLoading: true,
        user: null,
        token: null,
        error: null,

        // Actions
        setToken: (token: string) => {
          const user = decodeToken(token);
          if (user && !isTokenExpired(user)) {
            storeToken(token, storageKey, config.persistSession ?? true);
            set({
              isAuthenticated: true,
              isLoading: false,
              user,
              token,
              error: null,
            });
          } else {
            set({
              isAuthenticated: false,
              isLoading: false,
              user: null,
              token: null,
              error: user ? 'Token expired' : 'Invalid token',
            });
          }
        },

        clearAuth: () => {
          removeStoredToken(storageKey, config.persistSession ?? true);
          set({
            isAuthenticated: false,
            isLoading: false,
            user: null,
            token: null,
            error: null,
          });
        },

        setLoading: (loading: boolean) => {
          set({ isLoading: loading });
        },

        setError: (error: string | null) => {
          set({ error });
        },

        refreshFromStorage: () => {
          const token = getStoredToken(storageKey, config.persistSession ?? true);
          if (token) {
            const user = decodeToken(token);
            if (user && !isTokenExpired(user)) {
              set({
                isAuthenticated: true,
                isLoading: false,
                user,
                token,
                error: null,
              });
              return;
            }
          }
          set({
            isAuthenticated: false,
            isLoading: false,
            user: null,
            token: null,
            error: null,
          });
        },
      }),
      {
        name: storageKey,
        partialize: (state) => ({
          token: state.token,
        }),
      }
    )
  );
}

/**
 * Default auth store instance.
 *
 * Initialize with your config before using:
 * ```ts
 * initAuthStore({ gatewayUrl: 'https://auth.example.com' });
 * ```
 */
let defaultStore: ReturnType<typeof createAuthStore> | null = null;
let defaultConfig: AtAuthConfig | null = null;

/**
 * Initialize the default auth store.
 *
 * @param config - Auth configuration
 */
export function initAuthStore(config: AtAuthConfig): void {
  defaultConfig = config;
  defaultStore = createAuthStore(config);

  // Auto-handle callback if on callback page
  if (isOAuthCallback()) {
    const result = handleCallback(config);
    if (result.success && result.token) {
      defaultStore.getState().setToken(result.token);
    } else if (result.error) {
      defaultStore.getState().setError(result.error);
    }
  } else {
    // Load from storage
    defaultStore.getState().refreshFromStorage();
  }
}

/**
 * Get the auth store hook.
 *
 * Must call `initAuthStore` first.
 */
export function useAuthStore(): AuthStore & {
  login: (returnTo?: string) => void;
  logout: () => void;
} {
  if (!defaultStore || !defaultConfig) {
    throw new Error(
      'Auth store not initialized. Call initAuthStore(config) first.'
    );
  }

  const state = defaultStore();

  return {
    ...state,
    login: (returnTo?: string) => {
      redirectToAuth(defaultConfig!, { returnTo });
    },
    logout: () => {
      state.clearAuth();
      // Optionally redirect to gateway logout
      if (defaultConfig?.gatewayUrl) {
        // Build logout URL - app can redirect if needed
        void buildLogoutUrl(defaultConfig, window.location.origin);
      }
    },
  };
}

/**
 * Check if user needs to re-authenticate (token expiring soon).
 *
 * @param thresholdSeconds - Seconds before expiry to trigger refresh
 * @returns True if token should be refreshed
 */
export function useNeedsRefresh(thresholdSeconds = 300): boolean {
  if (!defaultStore) return false;

  const { user } = defaultStore();
  if (!user) return false;

  return shouldRefreshToken(user, thresholdSeconds);
}

/**
 * Hook to get just the current user.
 */
export function useUser(): TokenPayload | null {
  if (!defaultStore) return null;
  return defaultStore().user;
}

/**
 * Hook to check authentication status.
 */
export function useIsAuthenticated(): boolean {
  if (!defaultStore) return false;
  return defaultStore().isAuthenticated;
}

// Re-export types for convenience
export type { TokenPayload, AuthState, AuthStore, AtAuthConfig } from './types';
