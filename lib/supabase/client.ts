import { createBrowserClient } from '@supabase/ssr';
import type { SupabaseClient } from '@supabase/supabase-js';

export function isSupabaseConfigured(): boolean {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key =
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  return Boolean(
    url &&
      key &&
      url !== 'YOUR_SUPABASE_URL' &&
      key !== 'YOUR_SUPABASE_PUBLISHABLE_KEY'
  );
}

let browserClientInstance: SupabaseClient | null = null;

export function createClient(): SupabaseClient {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
  const key =
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    '';

  if (!url || !key) {
    if (!browserClientInstance) {
      browserClientInstance = createBrowserClient(
        'https://placeholder.supabase.co',
        'placeholder-key'
      );
    }
    return browserClientInstance;
  }

  if (!browserClientInstance) {
    browserClientInstance = createBrowserClient(url, key);
  }
  return browserClientInstance;
}
