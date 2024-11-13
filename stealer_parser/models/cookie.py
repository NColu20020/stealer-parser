"""Data model to define cookies found in stealer logs."""

from dataclasses import dataclass

@dataclass
class Cookie:
    """Class defining a browser cookie information.

    Attributes
    ----------
    domain : str
        The domain or subdomain the cookie is associated with.
    flag : str
        Indicates if the cookie is accessible through HTTP only (`TRUE` or `FALSE`).
    path : str
        The URL path for which the cookie is valid.
    secure : str
        Indicates if the cookie requires a secure connection (`TRUE` or `FALSE`).
    expiration_timestamp : int
        Unix timestamp for when the cookie expires.
    name : str
        The name identifier of the cookie.
    value : str
        The actual value stored in the cookie.
    """

    domain: str
    flag: str
    path: str
    secure: str
    expiration_timestamp: int
    name: str
    value: str
