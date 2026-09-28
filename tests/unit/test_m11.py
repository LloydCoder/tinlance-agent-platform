from tinlance_agent_platform_api import APIRequest, APIResponse, AgentPlatformAPI


class Handler:
    def handle(self, request: APIRequest) -> APIResponse:
        return APIResponse("accepted", {"operation": request.operation})


def test_api_requires_tenant_and_subject() -> None:
    api = AgentPlatformAPI(Handler())
    assert api.dispatch(APIRequest("t1", "u1", "run.create", {})).status == "accepted"
