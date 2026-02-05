import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { api } from '../api/client';

interface AuthState {
  token: string | null;
  isAuthenticated: boolean;
  setToken: (token: string) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      isAuthenticated: false,

      setToken: (token: string) => {
        api.setToken(token);
        set({ token, isAuthenticated: true });
      },

      logout: () => {
        api.setToken(null);
        set({ token: null, isAuthenticated: false });
      },
    }),
    {
      name: 'atauth-admin-auth',
      onRehydrateStorage: () => (state) => {
        // Restore token to API client on rehydration
        if (state?.token) {
          api.setToken(state.token);
        }
      },
    }
  )
);
