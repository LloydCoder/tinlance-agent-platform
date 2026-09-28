create table if not exists platform.customers (
 customer_id uuid primary key, tenant_id uuid not null references platform.tenants(tenant_id), name text not null,
 status text not null default 'active' check(status in ('active','suspended','archived')), created_at timestamptz not null default now(),
 unique(tenant_id,customer_id));
create table if not exists platform.projects (
 project_id uuid primary key, tenant_id uuid not null references platform.tenants(tenant_id), customer_id uuid not null, name text not null,
 status text not null default 'active' check(status in ('active','paused','archived')), created_at timestamptz not null default now(),
 foreign key(tenant_id,customer_id) references platform.customers(tenant_id,customer_id), unique(tenant_id,project_id));
create table if not exists platform.repositories (
 repository_id uuid primary key, tenant_id uuid not null references platform.tenants(tenant_id), project_id uuid not null, provider text not null, external_id text not null, name text not null,
 status text not null default 'active' check(status in ('active','disabled','archived')), created_at timestamptz not null default now(),
 foreign key(tenant_id,project_id) references platform.projects(tenant_id,project_id), unique(tenant_id,repository_id), unique(tenant_id,provider,external_id));
create table if not exists platform.assessments (
 assessment_id uuid primary key, tenant_id uuid not null references platform.tenants(tenant_id), repository_id uuid not null, idempotency_key text not null, kind text not null,
 status text not null default 'created' check(status in ('created','queued','running','completed','failed','cancelled')), parent_assessment_id uuid,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 foreign key(tenant_id,repository_id) references platform.repositories(tenant_id,repository_id), foreign key(parent_assessment_id) references platform.assessments(assessment_id),
 unique(tenant_id,assessment_id), unique(tenant_id,idempotency_key));
create table if not exists platform.findings (
 finding_id uuid primary key, tenant_id uuid not null references platform.tenants(tenant_id), assessment_id uuid not null, fingerprint text not null, title text not null, severity text not null,
 status text not null default 'open' check(status in ('open','confirmed','remediated','false_positive','accepted_risk')), parent_finding_id uuid,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 foreign key(tenant_id,assessment_id) references platform.assessments(tenant_id,assessment_id), foreign key(parent_finding_id) references platform.findings(finding_id),
 unique(tenant_id,finding_id));
create table if not exists platform.evidence (
 evidence_id uuid primary key, tenant_id uuid not null references platform.tenants(tenant_id), assessment_id uuid not null, finding_id uuid, source text not null, content_hash text not null, provenance text not null,
 created_at timestamptz not null default now(), foreign key(tenant_id,assessment_id) references platform.assessments(tenant_id,assessment_id), foreign key(finding_id) references platform.findings(finding_id),
 unique(tenant_id,evidence_id));
create index if not exists idx_customers_tenant on platform.customers(tenant_id);
create index if not exists idx_projects_tenant on platform.projects(tenant_id);
create index if not exists idx_repositories_tenant on platform.repositories(tenant_id);
create index if not exists idx_assessments_tenant on platform.assessments(tenant_id);
create index if not exists idx_findings_tenant on platform.findings(tenant_id);
create index if not exists idx_evidence_tenant on platform.evidence(tenant_id);