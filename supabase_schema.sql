-- =============================================================================
-- CyberCord Supabase Schema
-- Run this SQL in your Supabase SQL Editor (Settings > SQL Editor)
-- =============================================================================


-- ---------------------------------------------------------------------------
-- Helper: automatically update an `updated_at` column on every row change
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


-- =============================================================================
-- TABLE: public.users
-- Extends auth.users with application-specific profile data.
--
-- settings JSONB shape:
-- {
--   "apiKeys": {
--     "numverify": "<key>",
--     "shodan":    "<key>",
--     "censys":    "<key>"
--   },
--   "appearance": {
--     "theme": "dark" | "light" | "system"
--   },
--   "notifications": {
--     "securityAlerts":      true,
--     "scanCompletions":     true,
--     "intelligenceReports": false,
--     "systemUpdates":       false
--   }
-- }
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.users (
  id           UUID        REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  email        TEXT,
  full_name    TEXT,
  avatar_url   TEXT,
  phone        TEXT,
  organization TEXT,
  role         TEXT        NOT NULL DEFAULT 'user'
                           CHECK (role IN ('user', 'admin')),
  plan         TEXT        NOT NULL DEFAULT 'free'
                           CHECK (plan IN ('free', 'starter', 'pro', 'enterprise')),
  settings     JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER users_set_updated_at
  BEFORE UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- Auto-create a profile row whenever a new auth user signs up.
-- SECURITY DEFINER is required so the trigger can bypass RLS and insert into
-- public.users before the new user's own policies are in effect.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  INSERT INTO public.users (id, email, full_name, avatar_url, organization)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name'),
    NEW.raw_user_meta_data->>'avatar_url',
    NEW.raw_user_meta_data->>'organization'
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();


-- =============================================================================
-- TABLE: public.system_configs
-- Stores admin-managed global settings such as shared API keys.
--
-- Row with id = 'api_keys' holds keys used by the backend when a user has
-- not supplied their own key.
--
-- keys JSONB shape (each service entry):
-- {
--   "<service_name>": {
--     "value":       "<api_key>",
--     "status":      "active" | "expired" | "inactive",
--     "expiryDate":  "YYYY-MM-DD",
--     "lastUpdated": "<ISO8601>"
--   }
-- }
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.system_configs (
  id         TEXT        PRIMARY KEY,
  keys       JSONB       NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER system_configs_set_updated_at
  BEFORE UPDATE ON public.system_configs
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


-- =============================================================================
-- TABLE: public.investigations
-- Records every OSINT investigation run by a user.
--
-- type    – EntityType enum value: USER | DOMAIN | IP | EMAIL | PHONE |
--           USERNAME | ORGANIZATION | BREACH
-- status  – lifecycle: pending | running | completed | failed
--
-- entities JSONB array shape:
-- [{ "id": "<uuid>", "type": "<EntityType>", "label": "<str>", "data": {} }]
--
-- relationships JSONB array shape:
-- [{ "id": "<uuid>", "source": "<entityId>", "target": "<entityId>", "label": "<str>" }]
--
-- timeline JSONB array shape:
-- [{ "id": "<uuid>", "timestamp": "<ISO8601>", "title": "<str>",
--    "description": "<str>", "type": "info" | "warning" | "danger" | "success" }]
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.investigations (
  id            UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id       UUID        REFERENCES auth.users(id) ON DELETE CASCADE,
  query         TEXT        NOT NULL,
  type          TEXT        NOT NULL
                            CHECK (type IN ('USER','DOMAIN','IP','EMAIL','PHONE','USERNAME','ORGANIZATION','BREACH')),
  status        TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  risk_score    INT         CHECK (risk_score >= 0 AND risk_score <= 100),
                            -- NULL until the investigation completes; set by the backend after analysis
  summary       TEXT,
  entities      JSONB       NOT NULL DEFAULT '[]'::jsonb,
  relationships JSONB       NOT NULL DEFAULT '[]'::jsonb,
  timeline      JSONB       NOT NULL DEFAULT '[]'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER investigations_set_updated_at
  BEFORE UPDATE ON public.investigations
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS investigations_user_id_idx
  ON public.investigations (user_id);

CREATE INDEX IF NOT EXISTS investigations_user_created_idx
  ON public.investigations (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS investigations_status_idx
  ON public.investigations (status);


-- =============================================================================
-- ROW LEVEL SECURITY
-- =============================================================================
ALTER TABLE public.users           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_configs  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investigations  ENABLE ROW LEVEL SECURITY;

-- Convenience function: returns true if the signed-in user is an admin.
-- SECURITY DEFINER is intentional: this function is called from within RLS
-- policies on public.users itself. Without SECURITY DEFINER the recursive
-- policy check would cause an infinite loop. The function is marked STABLE and
-- only ever reads the caller's own row via auth.uid().
--
-- NOTE: The hardcoded email below is a bootstrap mechanism for the initial
-- admin account. Once the admin user exists in the database with role='admin',
-- the email check can be removed by updating this function.
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.users
    WHERE id = auth.uid()
      AND (role = 'admin' OR email = 'aniketvipulchougule@gmail.com')
  );
$$;


-- ---------------------------------------------------------------------------
-- Policies: users
-- ---------------------------------------------------------------------------
CREATE POLICY "Users can view own profile"
  ON public.users FOR SELECT
  USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile"
  ON public.users FOR INSERT
  WITH CHECK (auth.uid() = id);

CREATE POLICY "Users can update own profile"
  ON public.users FOR UPDATE
  USING (auth.uid() = id);

CREATE POLICY "Users can delete own profile"
  ON public.users FOR DELETE
  USING (auth.uid() = id);

CREATE POLICY "Admins can view all profiles"
  ON public.users FOR SELECT
  USING (public.is_admin());


-- ---------------------------------------------------------------------------
-- Policies: system_configs
-- ---------------------------------------------------------------------------
CREATE POLICY "Admins can view system configs"
  ON public.system_configs FOR SELECT
  USING (public.is_admin());

CREATE POLICY "Admins can manage system configs"
  ON public.system_configs FOR ALL
  USING (public.is_admin());


-- ---------------------------------------------------------------------------
-- Policies: investigations
-- ---------------------------------------------------------------------------
CREATE POLICY "Users can view own investigations"
  ON public.investigations FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own investigations"
  ON public.investigations FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own investigations"
  ON public.investigations FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own investigations"
  ON public.investigations FOR DELETE
  USING (auth.uid() = user_id);

CREATE POLICY "Admins can view all investigations"
  ON public.investigations FOR SELECT
  USING (public.is_admin());

CREATE POLICY "Admins can delete any investigation"
  ON public.investigations FOR DELETE
  USING (public.is_admin());
