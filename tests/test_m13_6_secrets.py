from tinlance_agent_platform_secrets.broker import SecretBroker, SecretHandle


class Provider:
    def resolve(self, handle: SecretHandle) -> str:
        return "secret"


def test_legacy_secret_broker_fails_closed() -> None:
    broker = SecretBroker(Provider())
    try:
        broker.resolve_for_execution(SecretHandle("key", "1"))
    except PermissionError as exc:
        assert "ScopedSecretBroker" in str(exc)
    else:
        raise AssertionError("unscoped secret resolution bypassed governance")
