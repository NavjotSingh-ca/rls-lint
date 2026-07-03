-- Violates RLS-005: policy uses FOR ALL instead of specific command

CREATE TABLE public.documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    content TEXT,
    org_id UUID NOT NULL,
    created_by UUID NOT NULL
);

ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;

-- This policy applies to ALL operations (SELECT, INSERT, UPDATE, DELETE)
-- Should be split into separate policies per operation
CREATE POLICY "documents_all_access"
    ON public.documents
    FOR ALL
    USING (org_id = auth.uid());

-- This policy doesn't specify a FOR clause, which defaults to ALL
CREATE POLICY "documents_default_all"
    ON public.documents
    USING (org_id = auth.uid());

-- This one is fine — specific command
CREATE POLICY "documents_select_own"
    ON public.documents
    FOR SELECT
    USING (org_id = auth.uid());
