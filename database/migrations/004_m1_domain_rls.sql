do $$
declare t text;
begin
 foreach t in array array['customers','projects','repositories','assessments','findings','evidence'] loop
  execute format('alter table platform.%I enable row level security',t);
  execute format('alter table platform.%I force row level security',t);
  execute format('create policy %I on platform.%I using (tenant_id = platform.current_tenant_id()) with check (tenant_id = platform.current_tenant_id())',t||'_tenant_isolation',t);
 end loop;
end $$;