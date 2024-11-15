"""Type hints to support development process."""
from datetime import datetime
from typing import Literal, TypeAlias
from enum import Enum

__all__ = [
    "JSONValueType",
    "JSONArrayType",
    "JSONObjectType",
    "JSONType",
    "StealerNameType",
]

JSONValueType: TypeAlias = (
    str
    | bytes
    | int
    | float
    | bool
    | datetime
    | None
    | list["JSONValueType"]
    | dict[str, "JSONValueType"]
)
JSONArrayType: TypeAlias = list[JSONValueType]
JSONObjectType: TypeAlias = dict[str, JSONValueType]
JSONType: TypeAlias = JSONObjectType | JSONArrayType

# NOTE: To be extended if more infostealers are handled.
class StealerNameType(Enum):
    """Stealer types."""
    UNKNOWN = "unknown"
    RACCOON = "raccoon"
    REDLINE = "redline"
