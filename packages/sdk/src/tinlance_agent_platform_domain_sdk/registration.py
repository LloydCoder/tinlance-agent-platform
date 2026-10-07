from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True, slots=True)
class DomainRegistration:
    domain: str
    name: str
    version: str
    definition: str

    @property
    def definition_hash(self) -> str:
        return sha256(self.definition.encode("utf-8")).hexdigest()

    def validate(self) -> None:
        if not all((self.domain, self.name, self.version, self.definition)):
            raise ValueError("domain registration fields are required")
