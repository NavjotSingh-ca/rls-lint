-- Violates RLS-001: table created without ENABLE ROW LEVEL SECURITY

CREATE TABLE public.customer_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL,
    note TEXT NOT NULL,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Note: No ALTER TABLE ... ENABLE ROW LEVEL SECURITY for this table
-- This means all rows are publicly readable/writable

-- There IS a policy on this table, but RLS is not enabled, so the policy does nothing
CREATE POLICY "customer_notes_access"
    ON public.customer_notes
    FOR ALL
    USING (tenant_id = auth.uid());
