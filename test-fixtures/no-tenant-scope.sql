-- Violates RLS-003: policy has no tenant-scoping column
-- The USING clause filters by status, not by tenant

CREATE TABLE public.articles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    author_id UUID NOT NULL
);

ALTER TABLE public.articles ENABLE ROW LEVEL SECURITY;

-- This policy scopes by status, not by tenant/user
-- It allows access to all published articles across ALL tenants
CREATE POLICY "articles_published_read"
    ON public.articles
    FOR SELECT
    USING (status = 'published');

-- This one properly scopes to the author
CREATE POLICY "articles_author_access"
    ON public.articles
    FOR ALL
    USING (author_id = auth.uid());
