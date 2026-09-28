alter table platform.events add constraint uq_events_tenant_event unique (tenant_id, event_id);
alter table platform.approvals add column if not exists expires_at timestamptz;
create index if not exists idx_approvals_expiry on platform.approvals(tenant_id, expires_at) where status = 'pending';
