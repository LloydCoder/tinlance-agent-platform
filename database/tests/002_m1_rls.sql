begin;
create role m1_app nologin;
grant usage on schema platform to m1_app;
grant select,insert,update,delete on all tables in schema platform to m1_app;
insert into platform.tenants(tenant_id,name) values
('00000000-0000-0000-0000-000000000001','tenant-a'),
('00000000-0000-0000-0000-000000000002','tenant-b');
insert into platform.agents(agent_id,tenant_id,agent_type,version,owner_subject_id,policy_profile,trust_level,environment)
values('10000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','m1','1.0.0','owner-a','default','standard','test');
insert into platform.tasks(task_id,tenant_id,agent_id,agent_version,requester_subject_id,status,objective)
values('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','1.0.0','owner-a','queued','m1');
set role m1_app;
select set_config('platform.tenant_id','00000000-0000-0000-0000-000000000001',true);
insert into platform.runs(run_id,tenant_id,task_id,status)
values('30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','created');
do $$ begin
if(select count(*) from platform.runs)<>1 then raise exception 'run RLS failed'; end if;
end $$;
select set_config('platform.tenant_id','00000000-0000-0000-0000-000000000002',true);
do $$ begin
if exists(select 1 from platform.runs where tenant_id='00000000-0000-0000-0000-000000000001') then raise exception 'cross-tenant run visibility detected'; end if;
end $$;
rollback;
