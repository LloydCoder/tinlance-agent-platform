begin;
create role enterprise_app nologin;
grant usage on schema platform to enterprise_app;
grant select, insert, update, delete on all tables in schema platform to enterprise_app;
insert into platform.tenants(tenant_id,name) values
('00000000-0000-0000-0000-000000000001','tenant-a'),
('00000000-0000-0000-0000-000000000002','tenant-b');
insert into platform.agents(agent_id,tenant_id,agent_type,version,owner_subject_id,policy_profile,trust_level,environment) values
('10000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','a','1','u','p','t','test'),
('20000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','b','1','u','p','t','test');
insert into platform.tasks(task_id,tenant_id,agent_id,agent_version,requester_subject_id,status,objective) values
('30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','1','u','queued','a'),
('40000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','20000000-0000-0000-0000-000000000001','1','u','queued','b');
insert into platform.runs(run_id,tenant_id,task_id,status) values
('50000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','30000000-0000-0000-0000-000000000001','created');
set role enterprise_app;
select set_config('platform.tenant_id','00000000-0000-0000-0000-000000000001',true);
insert into platform.evidence(evidence_id,tenant_id,run_id,sequence,content_hash,content,classification)
values('60000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001',1,'h','evidence','internal');
do $$ begin
if (select count(*) from platform.evidence) <> 1 then raise exception 'evidence RLS failed'; end if;
end $$;
select set_config('platform.tenant_id','00000000-0000-0000-0000-000000000002',true);
do $$ begin
if exists(select 1 from platform.evidence where tenant_id='00000000-0000-0000-0000-000000000001') then raise exception 'enterprise cross-tenant evidence leak'; end if;
end $$;
rollback;
