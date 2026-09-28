import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
PACKAGES = {
    "contracts": "tinlance_agent_platform_contracts", "kernel": "tinlance_agent_platform_kernel",
    "identity": "tinlance_agent_platform_identity", "tenancy": "tinlance_agent_platform_tenancy",
    "authorization": "tinlance_agent_platform_authorization", "policy": "tinlance_agent_platform_policy",
    "agents": "tinlance_agent_platform_agents", "approvals": "tinlance_agent_platform_approvals",
    "budgets": "tinlance_agent_platform_budgets", "runtime": "tinlance_agent_platform_runtime",
    "models": "tinlance_agent_platform_models", "orchestration": "tinlance_agent_platform_orchestration",
    "tools": "tinlance_agent_platform_tools", "mcp": "tinlance_agent_platform_mcp",
    "sandbox": "tinlance_agent_platform_sandbox", "secrets": "tinlance_agent_platform_secrets",
    "events": "tinlance_agent_platform_events", "evidence": "tinlance_agent_platform_evidence",
    "durability": "tinlance_agent_platform_durability", "governance": "tinlance_agent_platform_governance",
    "context": "tinlance_agent_platform_context", "trajectory": "tinlance_agent_platform_trajectory",
    "observability": "tinlance_agent_platform_observability", "evaluation": "tinlance_agent_platform_evaluation",
    "api": "tinlance_agent_platform_api", "multi_agent": "tinlance_agent_platform_multi_agent",
    "operations": "tinlance_agent_platform_operations", "sdk": "tinlance_agent_platform_sdk",
}

SERVICE_DEPS = {
    "contracts": set(), "kernel": {"contracts"}, "identity": {"contracts"},
    "tenancy": {"contracts", "kernel"}, "authorization": {"contracts", "kernel"},
    "policy": {"contracts"}, "agents": {"contracts"}, "approvals": {"contracts"},
    "budgets": {"contracts"}, "runtime": {"contracts"}, "models": set(),
    "orchestration": {"contracts", "runtime"}, "tools": {"contracts", "kernel", "policy"},
    "mcp": set(), "sandbox": {"contracts"}, "secrets": set(), "events": set(),
    "evidence": set(), "durability": {"contracts"}, "governance": set(), "context": set(),
    "trajectory": set(), "observability": set(), "evaluation": set(), "api": set(),
    "multi_agent": set(), "operations": set(),
    "sdk": {
        "agents", "approvals", "budgets", "context", "governance", "mcp", "models", "observability",
        "runtime", "sandbox", "tools",
    },
}


def imports_for(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.add(node.module.split(".")[0])
    return result


def test_bounded_package_dependencies() -> None:
    names = set(PACKAGES.values())
    for package, import_name in PACKAGES.items():
        root = ROOT / "packages" / package / "src" / import_name
        for path in root.rglob("*.py"):
            external = imports_for(path) & names
            allowed_names = {PACKAGES[name] for name in SERVICE_DEPS[package]}
            assert external <= allowed_names, f"{path}: forbidden imports {external - allowed_names}"


def test_no_provider_or_framework_imports_in_core() -> None:
    forbidden = {"fastapi", "pydantic", "openai", "anthropic", "boto3", "sqlalchemy", "psycopg"}
    for package in ("contracts", "kernel"):
        root = ROOT / "packages" / package / "src"
        for path in root.rglob("*.py"):
            assert not imports_for(path) & forbidden, f"{path}: forbidden dependency"
