"""Data model to define a leak's content.

- Metadata: contextual information (origin, date, size, ...)
- Compromised systems found in the leak
- Credentials found in the leak, sorted by system.
"""
#Purpose: Structures the parsed data of a leak, organizing metadata, compromised systems, and credentials.
#Classes:
#SystemData: Represents data associated with a single compromised system, with methods like add_stealer_name to label credentials with the infostealer name.
#Leak: Represents the overall structure of a leak, storing the archive’s filename and a list of SystemData objects for all compromised systems found in the archive.
#This module organizes parsed data, grouping credentials by system and enabling easier aggregation and export.

from dataclasses import dataclass, field
from .stealer_log import StealerLog

@dataclass
class Leak:
    """Class defining a leak's content."""
    filename: str
    stealer_logs: list[StealerLog] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "filename": self.filename,
            "stealer_logs": [
                stealer_log.to_dict()
                for stealer_log in self.stealer_logs
            ]
        }
