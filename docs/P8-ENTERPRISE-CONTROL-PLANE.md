# P8 — Enterprise Control Plane Certification

P8 certifies the enterprise control-plane surfaces already implemented by Platform.

## Control domains

- organization and tenancy;
- workspace and principal context;
- policy and authorization;
- approvals and expiry;
- budgets and capacity;
- resource/tool/model governance;
- registry and compliance mappings;
- append-only control records;
- enterprise audit and SRE/compliance evidence.

## Authority boundary

Enterprise control metadata constrains and governs execution. The Platform remains the sole authority for consequential authorization and execution.

Agent OS may compose organization/workspace/task state but cannot bypass Platform controls.

## Exit criterion

P8 is complete when the control-plane schema/migrations, policy/approval/budget/compliance surfaces, security tests and authority boundary are CI-certified.
