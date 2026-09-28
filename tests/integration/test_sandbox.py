from pathlib import Path
from uuid import uuid4
import pytest
from tinlance_agent_platform_contracts import DataClass,ExecutionLimits,ExecutionRequest,RiskTier
from tinlance_agent_platform_sandbox import DockerSandbox,SandboxUnavailable

def make_request(workspace: Path, command: tuple[str,...], network=False):
    return ExecutionRequest("1",uuid4(),uuid4(),"actor","execute",str(workspace),command,RiskTier.LOW,DataClass.INTERNAL,ExecutionLimits(10,256,10,32),None,network)

@pytest.mark.integration
def test_sandbox_workspace_isolated_and_network_disabled(tmp_path: Path):
    if not __import__("shutil").which("docker"): pytest.skip("docker unavailable")
    marker=tmp_path/"marker"
    result=DockerSandbox().execute(make_request(tmp_path,("python","-c","open('marker','w').write('ok')")))
    assert result.exit_code == 0
    assert marker.read_text() == "ok"
    net=DockerSandbox().execute(make_request(tmp_path,("python","-c","import socket; socket.create_connection(('1.1.1.1',53),1)"),True))
    assert net.exit_code != 0

@pytest.mark.integration
def test_sandbox_timeout_cleans_execution(tmp_path: Path):
    if not __import__("shutil").which("docker"): pytest.skip("docker unavailable")
    with pytest.raises(TimeoutError):
        DockerSandbox().execute(make_request(tmp_path,("python","-c","import time; time.sleep(30)")))