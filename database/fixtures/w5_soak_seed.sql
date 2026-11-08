-- Disposable W5 soak fixture. Run only against the dedicated local soak database.
INSERT INTO platform.tenants (tenant_id, name)
VALUES (:'tenant_id'::uuid, 'Tinlance W5 soak tenant')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO platform.agents (
    agent_id, tenant_id, agent_type, version, owner_subject_id,
    policy_profile, trust_level, environment
) VALUES (
    :'agent_id'::uuid,
    :'tenant_id'::uuid,
    'w5-soak-agent', '1.0.0', 'w5-soak-owner', 'default', 'standard', 'test'
) ON CONFLICT (tenant_id, agent_id) DO NOTHING;

INSERT INTO platform.tasks (
    task_id, tenant_id, agent_id, agent_version, requester_subject_id, status, objective
) VALUES (
    :'task_id'::uuid,
    :'tenant_id'::uuid,
    :'agent_id'::uuid,
    '1.0.0', 'w5-soak-owner', 'queued', 'continuous persistent-computer W5 soak'
) ON CONFLICT (tenant_id, task_id) DO NOTHING;

INSERT INTO platform.runs (run_id, tenant_id, task_id, status)
VALUES (:'run_id'::uuid, :'tenant_id'::uuid, :'task_id'::uuid, 'created')
ON CONFLICT (tenant_id, run_id) DO NOTHING;

INSERT INTO platform.tenant_budget_limits (
    tenant_id, max_concurrency, max_tool_calls, max_token_units, max_cost_units
) VALUES (:'tenant_id'::uuid, 1, 1000000, 1000000, 10000)
ON CONFLICT (tenant_id) DO UPDATE SET
    max_concurrency = EXCLUDED.max_concurrency,
    max_tool_calls = EXCLUDED.max_tool_calls,
    max_token_units = EXCLUDED.max_token_units,
    max_cost_units = EXCLUDED.max_cost_units;
