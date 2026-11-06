#!/bin/sh
set -eu

workspace=/workspace/project
git -c safe.directory=/opt/tinlance-fixture clone --no-hardlinks /opt/tinlance-fixture "$workspace"
test "$(git -C "$workspace" rev-parse --is-inside-work-tree)" = true
test -n "$(git -C "$workspace" rev-parse HEAD)"
echo TINLANCE_W2_GIT_CLONE_OK

python3 - "$workspace" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
source = root / "python/src/app.py"
tests = root / "python/tests/test_app.py"
source_text = source.read_text(encoding="utf-8")
test_text = tests.read_text(encoding="utf-8")
source.write_text(source_text.replace("Tinlance Agent Workspace", "Tinlance W2 Developer Workspace"), encoding="utf-8")
tests.write_text(test_text.replace("Tinlance Agent Workspace", "Tinlance W2 Developer Workspace"), encoding="utf-8")
PY
echo TINLANCE_W2_PYTHON_EDIT_OK
PYTHONPATH="$workspace/python" python3 -m unittest discover -s "$workspace/python/tests" -v
echo TINLANCE_W2_PYTHON_TESTS_OK

python3 - "$workspace" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
source = root / "node/src/app.js"
tests = root / "node/test/app.test.js"
source_text = source.read_text(encoding="utf-8")
test_text = tests.read_text(encoding="utf-8")
source.write_text(source_text.replace("Tinlance Agent Workspace", "Tinlance W2 Developer Workspace"), encoding="utf-8")
tests.write_text(test_text.replace("Tinlance Agent Workspace", "Tinlance W2 Developer Workspace"), encoding="utf-8")
PY
echo TINLANCE_W2_NODE_EDIT_OK
cd "$workspace/node"
npm test
echo TINLANCE_W2_NODE_TESTS_OK
echo TINLANCE_W2_DEVELOPER_WORKSPACE_OK
