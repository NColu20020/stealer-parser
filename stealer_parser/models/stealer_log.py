from dataclasses import dataclass
from .types import StealerNameType
from .system_data import SystemData

@dataclass
class StealerLog:
    """Class defining a single stealer log entry."""
    stealer_type: StealerNameType
    directory: str
    system_data: SystemData

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "stealer_type": self.stealer_type.value if self.stealer_type else None,
            "directory": self.directory,
            "system_data": self.system_data.to_dict() if self.system_data else None
        }
