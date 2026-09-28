from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Config:
    environment: str
    database_url: str
    secret_provider: str

    def validate(self) -> None:
        if self.environment not in {"development", "test", "staging", "production"}:
            raise ValueError("invalid environment")
        if not self.database_url or "password=" in self.database_url.lower():
            raise ValueError("database credentials must not be embedded in configuration")
        if not self.secret_provider:
            raise ValueError("secret provider is required")


@dataclass(frozen=True, slots=True)
class HealthStatus:
    ready: bool
    components: dict[str, bool]


class OperationsService:
    def readiness(self, components: dict[str, bool]) -> HealthStatus:
        return HealthStatus(all(components.values()), dict(components))
