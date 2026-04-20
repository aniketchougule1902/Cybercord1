/// <reference types="vite/client" />
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'https://valskfspcyfrnllojahy.supabase.co';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZhbHNrZnNwY3lmcm5sbG9qYWh5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY1ODA1ODIsImV4cCI6MjA5MjE1NjU4Mn0.dFD9Srkao8drf4VgIOP1VuD67KhaOEUvYO_d_7aBOuM';

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export const getRedirectUrl = () => {
  let url = import.meta.env.VITE_APP_URL || window.location.origin;
  // Make sure to include `https://` when not localhost.
  url = url.includes('http') ? url : `https://${url}`;
  // Make sure to include a trailing slash.
  url = url.charAt(url.length - 1) === '/' ? url : `${url}/`;
  return url;
};
