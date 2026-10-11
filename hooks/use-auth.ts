'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { createClient, isSupabaseConfigured } from '@/lib/supabase/client';
import type { User } from '@supabase/supabase-js';

export interface UserProfile {
  id: string;
  display_name: string | null;
  created_at: string;
}

export function useAuth() {
  const isConfigured = isSupabaseConfigured();
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState<boolean>(() => isConfigured);

  const supabase = useMemo(() => createClient(), []);

  const fetchProfile = useCallback(
    async (userId: string) => {
      if (!isConfigured) return;
      try {
        const { data, error } = await supabase
          .from('profiles')
          .select('*')
          .eq('id', userId)
          .single();

        if (!error && data) {
          setProfile(data as UserProfile);
        } else if (error && error.code === 'PGRST116') {
          // Profile does not exist yet; provide fallback
          setProfile({
            id: userId,
            display_name: user?.user_metadata?.display_name || user?.email?.split('@')[0] || null,
            created_at: new Date().toISOString(),
          });
        }
      } catch (err) {
        console.warn('Error fetching profile:', err);
      }
    },
    [isConfigured, supabase, user]
  );

  useEffect(() => {
    if (!isConfigured) {
      return;
    }

    let isMounted = true;

    // Check current verified user
    supabase.auth
      .getUser()
      .then(({ data: { user } }) => {
        if (!isMounted) return;
        setUser(user);
        if (user) {
          fetchProfile(user.id);
        }
      })
      .catch((err) => {
        console.warn('Error fetching user:', err);
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    // Listen to reactive auth changes
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      if (!isMounted) return;
      const currentUser = session?.user ?? null;
      setUser(currentUser);
      if (currentUser) {
        fetchProfile(currentUser.id);
      } else {
        setProfile(null);
      }
      setLoading(false);
    });

    return () => {
      isMounted = false;
      subscription.unsubscribe();
    };
  }, [fetchProfile, isConfigured, supabase]);

  const signOut = useCallback(async () => {
    if (!isConfigured) return;
    try {
      await supabase.auth.signOut();
      setUser(null);
      setProfile(null);
    } catch (err) {
      console.error('Sign out error:', err);
    }
  }, [isConfigured, supabase]);

  const updateDisplayName = useCallback(
    async (newDisplayName: string) => {
      if (!isConfigured || !user) return { error: 'Not authenticated' };

      try {
        const trimmed = newDisplayName.trim();
        // 1. Update user metadata
        await supabase.auth.updateUser({
          data: { display_name: trimmed },
        });

        // 2. Update profile table
        const { error } = await supabase
          .from('profiles')
          .upsert({
            id: user.id,
            display_name: trimmed,
            updated_at: new Date().toISOString(),
          });

        if (error) throw error;

        setProfile((prev) =>
          prev ? { ...prev, display_name: trimmed } : null
        );
        return { success: true };
      } catch (err: any) {
        return { error: err.message || 'Failed to update profile' };
      }
    },
    [isConfigured, supabase, user]
  );

  return {
    user,
    profile,
    loading,
    isConfigured,
    signOut,
    updateDisplayName,
  };
}
