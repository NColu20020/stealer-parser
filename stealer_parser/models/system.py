"""Data model to define compromised systems found in leaks."""

#Purpose: Defines the data model for a compromised system found in logs.
# Class: System
# Attributes: Includes fields for storing system information like machine_id, computer_name, hardware_id, machine_user, ip_address, country, and log_date.
# This class helps represent each compromised system, capturing metadata for tracking and organizing information about affected machines.
from dataclasses import dataclass, field
@dataclass
class System:
    """Class defining a compromised system information.

    Attributes
    ----------
    machine_id : str, optional
        The device ID (UID or machine ID).
    computer_name : str, optional
        The machine's name.
    hardware_id : str, optional
        The hardware ID (HWID).
    machine_user : str, optional
        The machine user's name.
    ip_address : str, optional
        The machine IP address.
    country : str, optional
        The machine's country code.
    log_date : str, optional
        The compromission date.

    """

    machine_id: str | None = None
    computer_name: str | None = None
    hardware_id: str | None = None
    machine_user: str | None = None
    ip_address: str | None = None
    country: str | None = None
    log_date: str | None = None

    def to_dict(self) -> dict:
        """Convert System object to dictionary."""
        return {
            "machine_id": self.machine_id,
            "computer_name": self.computer_name,
            "hardware_id": self.hardware_id,
            "machine_user": self.machine_user,
            "ip_address": self.ip_address,
            "country": self.country,
            "log_date": self.log_date
        }

# @dataclass
# class SystemData:
#     """System data container."""
#     system: System | None = None
#     stealer_type: StealerNameType = StealerNameType.UNKNOWN
#     credentials: list[Credential] = field(default_factory=list)
#     cookies: list[Cookie] = field(default_factory=list)
