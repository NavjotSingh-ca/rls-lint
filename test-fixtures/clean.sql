-- Clean migration: all rules should pass
-- This table has RLS enabled and properly scoped policies

CREATE TABLE public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "org_select_own"
    ON public.organizations
    FOR SELECT
    USING (org_id = auth.uid());

CREATE POLICY "org_update_own"
    ON public.organizations
    FOR UPDATE
    USING (org_id = auth.uid())
    WITH CHECK (org_id = auth.uid());

-- Second table: users
CREATE TABLE public.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    org_id UUID REFERENCES public.organizations(id),
    role TEXT NOT NULL DEFAULT 'member'
);

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_select_own_org"
    ON public.users
    FOR SELECT
    USING (org_id IN (
        SELECT org_id FROM public.organizations
        WHERE org_id = auth.uid()
    ));

CREATE POLICY "users_update_own"
    ON public.users
    FOR UPDATE
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());
