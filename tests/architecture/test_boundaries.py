from pathlib import Path
import ast

ROOT = Path(__file__).parents[2]
PACKAGES = {
    "contracts": "tinlance_agent_platform_contracts",
    "kernel": "tinlance_agent_platform_kernel",
    "identity": "tinlance_agent_platform_identity",
    "tenancy": "tinlance_agent_platform_tenancy",
    "authorization": "tinlance_agent_platform_authorization",
    "policy": "tinlance_agent_platform_policy",
}
ALLOWED = {
    "contracts": set(),
    "kernel": {"tinlance_agent_platform_contracts"},
    "identity": {"tinlance_agent_platform_contracts"},
    "tenancy": {"tinlance_agent_platform_contracts", "tinlance_agent_platform_kernel"},
    "authorization": {"tinlance_agent_platform_contracts", "tinlance_agent_platform_kernel"},
    "policy": {"tinlance_agent_platform_contracts"},
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
            assert external <= ALLOWED[package], f"{path}: forbidden imports"

def test_no_provider_or_framework_imports_in_core() -> None:
    forbidden = {"fastapi", "pydantic", "openai", "anthropic", "boto3", "sqlalchemy", "psycopg"}
    for package in ("contracts", "kernel"):
        root = ROOT / "packages" / package / "src"
        for path in root.rglob("*.py"):
            assert not imports_for(path) & forbidden, f"{path}: forbidden dependency"
