begin;
create role p3_app nologin;
grant usage on schema platform to p3_app;
grant select, insert on platform.inbox to p3_app;

insert into platform.tenants (tenant_id, name) values
('00000000-0000-0000-0000-000000000031', 'p3-tenant-a'),
('00000000-0000-0000-0000-000000000032', 'p3-tenant-b');

insert into platform.inbox (
    tenant_id, event_source, event_id, consumer_id, payload_digest
) values (
    '00000000-0000-0000-0000-000000000031',
    'https://tinlance.com/platform/runs',
    'event-p3-001',
    'consumer-a',
    repeat('a', 64)
);

set role p3_app;
select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000031', true);
do $$
begin
    if (select count(*) from platform.inbox) <> 1 then
        raise exception 'tenant A must see its own inbox receipt';
    end if;
    begin
        insert into platform.inbox (
            tenant_id, event_source, event_id, consumer_id, payload_digest
        ) values (
            '00000000-0000-0000-0000-000000000031',
            'https://tinlance.com/platform/runs',
            'event-p3-001',
            'consumer-a',
            repeat('a', 64)
        );
        raise exception 'duplicate inbox receipt unexpectedly accepted';
    exception when unique_violation then
        null;
    end;
    begin
        insert into platform.inbox (
            tenant_id, event_source, event_id, consumer_id, payload_digest
        ) values (
            '00000000-0000-0000-0000-000000000031',
            'https://tinlance.com/platform/runs',
            'event-p3-002',
            'consumer-a',
            'not-a-digest'
        );
        raise exception 'invalid payload digest unexpectedly accepted';
    exception when check_violation then
        null;
    end;
    perform set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000032', true);
    if exists (select 1 from platform.inbox) then
        raise exception 'cross-tenant inbox visibility detected';
    end if;
end
$$;
reset role;
rollback;
