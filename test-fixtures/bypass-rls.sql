-- Violates RLS-004: GRANT BYPASS RLS detected

-- This grants a role the ability to bypass all RLS policies entirely
GRANT BYPASS RLS TO postgres;

-- Granting to multiple roles
GRANT BYPASS RLS TO admin_role, service_role;

CREATE TABLE public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action TEXT NOT NULL,
    performed_by UUID NOT NULL,
    performed_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "audit_logs_select"
    ON public.audit_logs
    FOR SELECT
    USING (tenant_id = auth.uid());
