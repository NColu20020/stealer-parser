"""Data model to define compromised systems found in leaks."""

#Purpose: Defines the data model for a compromised system found in logs.
# Class: System
# Attributes: Includes fields for storing system information like machine_id, computer_name, hardware_id, machine_user, ip_address, country, and log_date.
# This class helps represent each compromised system, capturing metadata for tracking and organizing information about affected machines.
from dataclasses import dataclass
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
