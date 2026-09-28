# PostgreSQL adapter

M1 persistence uses PostgreSQL tables with tenant-scoped RLS and transaction-local tenant context.

The application role must not be a superuser or BYPASSRLS role. Every tenant transaction must establish the tenant setting with transaction-local scope before accessing tenant-owned tables.