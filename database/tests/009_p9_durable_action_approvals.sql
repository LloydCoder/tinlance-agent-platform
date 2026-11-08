begin;

create role p9_approval_app nologin;
grant usage on schema platform to p9_approval_app;
grant select, insert, update on platform.action_approvals to p9_approval_app;
grant select, insert on platform.action_approval_events to p9_approval_app;

insert into platform.tenants (tenant_id, name) values
('00000000-0000-0000-0000-000000000091', 'p9-approval-tenant-a'),
('00000000-0000-0000-0000-000000000092', 'p9-approval-tenant-b')
on conflict (tenant_id) do nothing;

insert into platform.action_approvals (
    approval_id, tenant_id, run_id, action, resource, reason,
    requested_by, status, intent_fingerprint, approved_by, decided_at
) values (
    '50000000-0000-0000-0000-000000000091',
    '00000000-0000-0000-0000-000000000091',
    '40000000-0000-0000-0000-000000000091',
    'replay', 'extensions://outbox/dead-letters/{event_id}',
    'Replay a dead-letter event', 'requester-a', 'approved',
    repeat('a', 64), 'approver-b', now()
);

insert into platform.action_approvals (
    approval_id, tenant_id, run_id, action, resource, reason,
    requested_by, status, intent_fingerprint, approved_by, decided_at, expires_at
) values (
    '50000000-0000-0000-0000-000000000092',
    '00000000-0000-0000-0000-000000000091',
    '40000000-0000-0000-0000-000000000092',
    'replay', 'extensions://outbox/dead-letters/{event_id}',
    'Expired approved action', 'requester-a', 'approved',
    repeat('c', 64), 'approver-b', now(), now() - interval '1 second'
);

insert into platform.action_approval_events (
    event_id, tenant_id, approval_id, event_type, actor_subject_id, intent_fingerprint
) values (
    '60000000-0000-0000-0000-000000000091',
    '00000000-0000-0000-0000-000000000091',
    '50000000-0000-0000-0000-000000000091',
    'approved', 'approver-b', repeat('a', 64)
);

set role p9_approval_app;
select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000091', true);

do $$
declare changed integer;
begin
    if (select count(*) from platform.action_approvals) <> 2 then
        raise exception 'approval tenant RLS failed';
    end if;

    update platform.action_approvals
       set status = 'consumed', consumed_at = now()
     where approval_id = '50000000-0000-0000-0000-000000000091'
       and tenant_id = '00000000-0000-0000-0000-000000000091'
       and run_id = '40000000-0000-0000-0000-000000000091'
       and action = 'replay'
       and resource = 'extensions://outbox/dead-letters/{event_id}'
       and intent_fingerprint = repeat('a', 64)
       and status = 'approved';
    get diagnostics changed = row_count;
    if changed <> 1 then
        raise exception 'approved action was not consumed exactly once';
    end if;

    update platform.action_approvals
       set status = 'consumed', consumed_at = now()
     where approval_id = '50000000-0000-0000-0000-000000000091'
       and tenant_id = '00000000-0000-0000-0000-000000000091'
       and status = 'approved';
    get diagnostics changed = row_count;
    if changed <> 0 then
        raise exception 'consumed approval was reusable';
    end if;

    update platform.action_approvals
       set status = 'expired', decided_at = now()
     where approval_id = '50000000-0000-0000-0000-000000000092'
       and tenant_id = '00000000-0000-0000-0000-000000000091'
       and status = 'approved'
       and expires_at <= now();
    if not exists (
        select 1 from platform.action_approvals
        where approval_id = '50000000-0000-0000-0000-000000000092'
          and status = 'expired' and approved_by = 'approver-b'
    ) then
        raise exception 'expired approval did not retain its approver audit identity';
    end if;

    perform set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000092', true);
    if exists (
        select 1 from platform.action_approvals
        where approval_id = '50000000-0000-0000-0000-000000000091'
    ) then
        raise exception 'cross-tenant approval visibility detected';
    end if;
    update platform.action_approvals
       set status = 'consumed', consumed_at = now()
     where approval_id = '50000000-0000-0000-0000-000000000091';
    get diagnostics changed = row_count;
    if changed <> 0 then
        raise exception 'cross-tenant approval mutation succeeded';
    end if;
end
$$;

rollback;
