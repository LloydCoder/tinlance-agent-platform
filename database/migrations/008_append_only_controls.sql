-- Evidence, trajectory and audit are append-only from the application role.
revoke update, delete on platform.evidence from public;
revoke update, delete on platform.trajectory_events from public;
revoke update, delete on platform.audit_records from public;
