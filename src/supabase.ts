/// <reference types="vite/client" />
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'https://tkdbonrhwhimcdrsfpnz.supabase.co';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || 'sb_publishable_5vV044_nCzJddglTX5X1Sw_H8Cp7ff6';

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export const getRedirectUrl = () => {
  let url = import.meta.env.VITE_APP_URL || window.location.origin;
  // Make sure to include `https://` when not localhost.
  url = url.includes('http') ? url : `https://${url}`;
  // Make sure to include a trailing slash.
  url = url.charAt(url.length - 1) === '/' ? url : `${url}/`;
  return url;
};
