from dataclasses import dataclass, field
from .types import StealerNameType
from .system import System
from .credential import Credential
from .cookie import Cookie

@dataclass
class SystemData:
    """Class defining a system's leaked data."""
    system: System | None = None
    credentials: list[Credential] = field(default_factory=list)
    cookies: list[Cookie] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "system": self.system.to_dict() if self.system else None,
            "credentials": [
                credential.to_dict() 
                for credential in self.credentials
            ],
            "cookies": [
                cookie.__dict__ 
                for cookie in self.cookies
            ]
        } 