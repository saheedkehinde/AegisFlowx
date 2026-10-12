'use client';

import { useSyncExternalStore, useCallback } from 'react';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/client';
import type { User } from '@supabase/supabase-js';

export interface UserProfile {
  id: string;
  display_name: string | null;
  created_at: string;
}

export type AuthState = 'loading' | 'authenticated' | 'unauthenticated' | 'error';

interface SharedAuthState {
  user: User | null;
  profile: UserProfile | null;
  authState: AuthState;
  loading: boolean;
  isConfigured: boolean;
  authError: string | null;
}

// Global module-level singleton state so every component shares identical, synchronized state
let globalAuthState: SharedAuthState = {
  user: null,
  profile: null,
  authState: isSupabaseConfigured() ? 'loading' : 'unauthenticated',
  loading: isSupabaseConfigured(),
  isConfigured: isSupabaseConfigured(),
  authError: null,
};

const listeners = new Set<() => void>();

function notifyListeners() {
  listeners.forEach((listener) => {
    try {
      listener();
    } catch (err) {
      console.warn('Auth state listener error:', err);
    }
  });
}

function updateGlobalState(updates: Partial<SharedAuthState>) {
  globalAuthState = { ...globalAuthState, ...updates };
  notifyListeners();
}

let authInitialized = false;

async function fetchProfileForUser(supabase: any, user: User): Promise<UserProfile | null> {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .single();

    if (!error && data) {
      return data as UserProfile;
    }
    // Fallback if row does not exist yet
    return {
      id: user.id,
      display_name:
        user.user_metadata?.display_name ||
        user.email?.split('@')[0] ||
        'Analyst',
      created_at: new Date().toISOString(),
    };
  } catch (err) {
    console.warn('Error fetching profile:', err);
    return {
      id: user.id,
      display_name:
        user.user_metadata?.display_name ||
        user.email?.split('@')[0] ||
        'Analyst',
      created_at: new Date().toISOString(),
    };
  }
}

function initializeAuth() {
  if (authInitialized || typeof window === 'undefined') return;
  authInitialized = true;

  const configured = isSupabaseConfigured();
  if (!configured) {
    updateGlobalState({
      user: null,
      profile: null,
      authState: 'unauthenticated',
      loading: false,
      isConfigured: false,
      authError: null,
    });
    return;
  }

  const supabase = createClient();

  // Initial user session verification
  supabase.auth
    .getUser()
    .then(async ({ data: { user }, error }) => {
      if (user && !error) {
        const profile = await fetchProfileForUser(supabase, user);
        updateGlobalState({
          user,
          profile,
          authState: 'authenticated',
          loading: false,
          authError: null,
        });
      } else {
        updateGlobalState({
          user: null,
          profile: null,
          authState: 'unauthenticated',
          loading: false,
          authError: error ? error.message : null,
        });
      }
    })
    .catch((err) => {
      console.warn('Auth initialization exception:', err);
      updateGlobalState({
        user: null,
        profile: null,
        authState: 'unauthenticated',
        loading: false,
        authError: err?.message || 'Authentication error',
      });
    });

  // Reactive listener for auth state changes
  supabase.auth.onAuthStateChange(async (_event, session) => {
    const currentUser = session?.user ?? null;
    if (currentUser) {
      const profile = await fetchProfileForUser(supabase, currentUser);
      updateGlobalState({
        user: currentUser,
        profile,
        authState: 'authenticated',
        loading: false,
        authError: null,
      });
    } else {
      updateGlobalState({
        user: null,
        profile: null,
        authState: 'unauthenticated',
        loading: false,
        authError: null,
      });
    }
  });
}

function subscribe(callback: () => void) {
  initializeAuth();
  listeners.add(callback);
  return () => {
    listeners.delete(callback);
  };
}

function getSnapshot(): SharedAuthState {
  return globalAuthState;
}

function getServerSnapshot(): SharedAuthState {
  return globalAuthState;
}

export function useAuth() {
  const state = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  const signOut = useCallback(async () => {
    if (!state.isConfigured) return;
    try {
      const supabase = createClient();
      await supabase.auth.signOut();
      updateGlobalState({
        user: null,
        profile: null,
        authState: 'unauthenticated',
        loading: false,
        authError: null,
      });
    } catch (err) {
      console.error('Sign out error:', err);
    }
  }, [state.isConfigured]);

  const updateDisplayName = useCallback(
    async (newDisplayName: string) => {
      if (!state.isConfigured || !state.user) return { error: 'Not authenticated' };
      try {
        const supabase = createClient();
        const trimmed = newDisplayName.trim();
        await supabase.auth.updateUser({
          data: { display_name: trimmed },
        });

        const { error } = await supabase
          .from('profiles')
          .upsert({
            id: state.user.id,
            display_name: trimmed,
            updated_at: new Date().toISOString(),
          });

        if (error) throw error;

        const updatedProfile = state.profile
          ? { ...state.profile, display_name: trimmed }
          : {
              id: state.user.id,
              display_name: trimmed,
              created_at: new Date().toISOString(),
            };

        updateGlobalState({
          profile: updatedProfile,
        });

        return { success: true };
      } catch (err: any) {
        return { error: err.message || 'Failed to update profile' };
      }
    },
    [state.isConfigured, state.user, state.profile]
  );

  return {
    user: state.user,
    profile: state.profile,
    loading: state.loading,
    authState: state.authState,
    authError: state.authError,
    isConfigured: state.isConfigured,
    signOut,
    updateDisplayName,
  };
}
