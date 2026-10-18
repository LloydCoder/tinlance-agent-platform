begin;
create role p3_outbox_app nologin;
grant usage on schema platform to p3_outbox_app;
grant select, insert, update on platform.events, platform.outbox, platform.inbox to p3_outbox_app;
grant execute on function platform.claim_outbox_batch(integer, integer) to p3_outbox_app;
grant execute on function platform.ack_outbox(uuid, uuid) to p3_outbox_app;
grant execute on function platform.release_outbox(uuid, uuid, text, integer) to p3_outbox_app;
grant execute on function platform.record_inbox_once(text, text, text, text) to p3_outbox_app;

insert into platform.tenants (tenant_id, name)
values ('00000000-0000-0000-0000-000000000041', 'p3-outbox-tenant');

insert into platform.agents (
    agent_id, tenant_id, agent_type, version, owner_subject_id,
    policy_profile, trust_level, environment
) values (
    '10000000-0000-0000-0000-000000000041',
    '00000000-0000-0000-0000-000000000041',
    'research', '1.0.0', 'p3-owner', 'default', 'standard', 'test'
);
insert into platform.tasks (
    task_id, tenant_id, agent_id, agent_version, requester_subject_id, status, objective
) values (
    '30000000-0000-0000-0000-000000000041',
    '00000000-0000-0000-0000-000000000041',
    '10000000-0000-0000-0000-000000000041', '1.0.0', 'p3-owner', 'queued', 'P3 outbox function test'
);
insert into platform.runs (run_id, tenant_id, task_id, status)
values (
    '40000000-0000-0000-0000-000000000041',
    '00000000-0000-0000-0000-000000000041',
    '30000000-0000-0000-0000-000000000041', 'created'
);

insert into platform.events (
    event_id, tenant_id, run_id, event_type, payload, sequence, source, correlation_id, trace_id
) values
(
    '50000000-0000-0000-0000-000000000041',
    '00000000-0000-0000-0000-000000000041',
    '40000000-0000-0000-0000-000000000041',
    'execution.completed', '{"state":"succeeded"}', 1,
    'https://tinlance.com/platform/runs', 'p3-correlation-1', '4bf92f3577b34da6a3ce929d0e0e4736'
),
(
    '50000000-0000-0000-0000-000000000042',
    '00000000-0000-0000-0000-000000000041',
    '40000000-0000-0000-0000-000000000041',
    'execution.failed', '{"state":"failed"}', 2,
    'https://tinlance.com/platform/runs', 'p3-correlation-2', '4bf92f3577b34da6a3ce929d0e0e4736'
),
(
    '50000000-0000-0000-0000-000000000043',
    '00000000-0000-0000-0000-000000000041',
    '40000000-0000-0000-0000-000000000041',
    'execution.retry', '{"state":"retry"}', 3,
    'https://tinlance.com/platform/runs', 'p3-correlation-3', '4bf92f3577b34da6a3ce929d0e0e4736'
);
insert into platform.outbox (outbox_id, tenant_id, event_id, max_attempts)
values
(
    '60000000-0000-0000-0000-000000000041',
    '00000000-0000-0000-0000-000000000041',
    '50000000-0000-0000-0000-000000000041', 10
),
(
    '60000000-0000-0000-0000-000000000042',
    '00000000-0000-0000-0000-000000000041',
    '50000000-0000-0000-0000-000000000042', 2
),
(
    '60000000-0000-0000-0000-000000000043',
    '00000000-0000-0000-0000-000000000041',
    '50000000-0000-0000-0000-000000000043', 10
);
update platform.outbox
   set available_at = clock_timestamp() + interval '1 hour'
 where outbox_id = '60000000-0000-0000-0000-000000000043';

set role p3_outbox_app;
select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000041', true);
do $$
declare
    claimed_id uuid;
    lease uuid;
    dead_id uuid;
    dead_lease uuid;
    stale_id uuid;
    stale_lease uuid;
    reclaimed_lease uuid;
    conflict_rejected boolean := false;
begin
    select outbox_id, lease_token into claimed_id, lease
      from platform.claim_outbox_batch(1, 30);
    if claimed_id is null or lease is null then
        raise exception 'expected one outbox record to be claimed';
    end if;
    if platform.ack_outbox(claimed_id, gen_random_uuid()) then
        raise exception 'wrong lease token unexpectedly acknowledged outbox';
    end if;
    if not platform.ack_outbox(claimed_id, lease) then
        raise exception 'valid lease token failed to acknowledge outbox';
    end if;

    select outbox_id, lease_token into dead_id, dead_lease
      from platform.claim_outbox_batch(1, 30);
    if dead_id is null or dead_lease is null then
        raise exception 'expected second outbox record to be claimed';
    end if;
    if not platform.release_outbox(dead_id, dead_lease, 'provider_timeout', 0) then
        raise exception 'valid lease failed to release outbox record';
    end if;
    select outbox_id, lease_token into dead_id, dead_lease
      from platform.claim_outbox_batch(1, 30);
    if dead_id is null or dead_lease is null then
        raise exception 'released outbox record should be claimable again';
    end if;
    if not platform.release_outbox(dead_id, dead_lease, 'provider_timeout', 0) then
        raise exception 'second release should succeed and dead-letter at max attempts';
    end if;
    if exists (
        select 1 from platform.outbox
        where outbox_id = '60000000-0000-0000-0000-000000000042'
          and dead_lettered_at is null
    ) then
        raise exception 'outbox record at max attempts must be dead-lettered';
    end if;
    if platform.record_inbox_once(
        'https://tinlance.com/platform/runs', 'event-p3-001', 'consumer-a', repeat('a',64)
    ) is not true then
        raise exception 'first inbox receipt must be recorded';
    end if;
    if platform.record_inbox_once(
        'https://tinlance.com/platform/runs', 'event-p3-001', 'consumer-a', repeat('a',64)
    ) is not false then
        raise exception 'duplicate inbox receipt must be ignored';
    end if;
    begin
        perform platform.record_inbox_once(
            'https://tinlance.com/platform/runs', 'event-p3-001', 'consumer-a', repeat('b',64)
        );
    exception when raise_exception then
        if sqlerrm = 'event identity reused with a different payload digest' then
            conflict_rejected := true;
        else
            raise;
        end if;
    end;
    if not conflict_rejected then
        raise exception 'conflicting inbox payload digest was unexpectedly accepted';
    end if;

    update platform.outbox
       set available_at = clock_timestamp()
     where outbox_id = '60000000-0000-0000-0000-000000000043';
    select outbox_id, lease_token into stale_id, stale_lease
      from platform.claim_outbox_batch(1, 1);
    if stale_id is null or stale_lease is null then
        raise exception 'expected third outbox record to be claimed';
    end if;
    perform pg_sleep(1.1);
    if platform.ack_outbox(stale_id, stale_lease) then
        raise exception 'expired outbox lease unexpectedly acknowledged';
    end if;
    select lease_token into reclaimed_lease
      from platform.claim_outbox_batch(1, 30)
     where outbox_id = stale_id;
    if reclaimed_lease is null or reclaimed_lease = stale_lease then
        raise exception 'expired outbox lease must be reissued with a new token';
    end if;
    if not platform.ack_outbox(stale_id, reclaimed_lease) then
        raise exception 'reclaimed outbox lease should acknowledge successfully';
    end if;
end
$$;
reset role;
rollback;
