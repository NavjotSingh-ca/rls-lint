-- Violates RLS-002: policy open to everyone (USING(true))

CREATE TABLE public.products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    price NUMERIC NOT NULL,
    tenant_id UUID NOT NULL
);

ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;

-- This policy is open to everyone — no tenant scoping at all
-- Anyone who can reach the database can read ALL products
CREATE POLICY "products_public_read"
    ON public.products
    FOR SELECT
    USING (true);

-- This one has a real check, but the first one is already a problem
CREATE POLICY "products_admin_write"
    ON public.products
    FOR INSERT
    WITH CHECK (tenant_id = auth.uid());
