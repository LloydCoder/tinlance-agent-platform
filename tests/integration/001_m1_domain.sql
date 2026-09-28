begin;
set role platform_app;
select set_config(
    'platform.tenant_id',
    '00000000-0000-0000-0000-000000000001',
    true
);

insert into platform.customers (
    customer_id, tenant_id, name
) values (
    '30000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'alpha'
);

insert into platform.projects (
    project_id, tenant_id, customer_id, name
) values (
    '40000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    '30000000-0000-0000-0000-000000000001',
    'project-a'
);

insert into platform.repositories (
    repository_id, tenant_id, project_id, provider, external_id, name
) values (
    '50000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    '40000000-0000-0000-0000-000000000001',
    'github',
    'alpha/repo',
    'repo'
);

insert into platform.assessments (
    assessment_id, tenant_id, repository_id, idempotency_key, kind
) values (
    '60000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    '50000000-0000-0000-0000-000000000001',
    'idem-1',
    'security'
);

do $$
begin
    if (select count(*) from platform.assessments) <> 1 then
        raise exception 'M1 tenant visibility failed';
    end if;
end
$$;

select set_config(
    'platform.tenant_id',
    '00000000-0000-0000-0000-000000000002',
    true
);

do $$
begin
    if exists (
        select 1 from platform.assessments
        where assessment_id = '60000000-0000-0000-0000-000000000001'
    ) then
        raise exception 'M1 cross-tenant leakage';
    end if;
end
$$;

rollback;
