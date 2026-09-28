do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'platform_app') then
        create role platform_app nologin;
    end if;
end
$$;

grant usage on schema platform to platform_app;
grant select, insert, update, delete on all tables in schema platform to platform_app;

insert into platform.tenants (tenant_id, name) values
    ('00000000-0000-0000-0000-000000000001', 'tenant-a'),
    ('00000000-0000-0000-0000-000000000002', 'tenant-b')
on conflict (tenant_id) do nothing;

begin;
set role platform_app;
select set_config(
    'platform.tenant_id',
    '00000000-0000-0000-0000-000000000001',
    true
);

insert into platform.agents (
    agent_id, tenant_id, agent_type, version, owner_subject_id,
    policy_profile, trust_level, environment
) values (
    '10000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'research', '1.0.0', 'owner-a', 'default', 'standard', 'test'
);

do $$
begin
    if (select count(*) from platform.tenants) <> 1 then
        raise exception 'tenant RLS failed';
    end if;
    if (select count(*) from platform.agents) <> 1 then
        raise exception 'agent RLS failed';
    end if;
end
$$;

select set_config(
    'platform.tenant_id',
    '00000000-0000-0000-0000-000000000002',
    true
);

insert into platform.agents (
    agent_id, tenant_id, agent_type, version, owner_subject_id,
    policy_profile, trust_level, environment
) values (
    '20000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000002',
    'research', '1.0.0', 'owner-b', 'default', 'standard', 'test'
);

do $$
begin
    if (select count(*) from platform.agents) <> 1 then
        raise exception 'tenant switch or agent RLS failed';
    end if;
    if exists (
        select 1 from platform.agents
        where tenant_id = '00000000-0000-0000-0000-000000000001'
    ) then
        raise exception 'cross-tenant visibility detected';
    end if;
end
$$;

rollback;
