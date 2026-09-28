from uuid import uuid4
import pytest
from tinlance_agent_platform_contracts import DataClass,ExecutionLimits,ExecutionRequest,RiskTier
def req(risk=RiskTier.LOW,approval=None,network=False,data=DataClass.INTERNAL):
 return ExecutionRequest("1",uuid4(),uuid4(),"actor","execute","/tmp/work",("python","-c","print('ok')"),risk,data,ExecutionLimits(10,256,10,32),approval,network)
def test_high_risk_requires_approval():
 with pytest.raises(PermissionError): req(RiskTier.HIGH)
def test_prohibited_is_denied():
 with pytest.raises(PermissionError): req(RiskTier.PROHIBITED)
def test_restricted_network_is_denied():
 with pytest.raises(PermissionError): req(network=True,data=DataClass.RESTRICTED)
def test_limits_are_bounded():
 with pytest.raises(ValueError): ExecutionLimits(0,256,10,32)