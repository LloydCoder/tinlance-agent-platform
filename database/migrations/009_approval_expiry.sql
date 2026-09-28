alter table platform.approvals add column if not exists expires_at timestamptz;
create index if not exists idx_approvals_expiry
    on platform.approvals(tenant_id, expires_at) where status = 'pending';
