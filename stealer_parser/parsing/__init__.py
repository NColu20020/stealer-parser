"""Module that contains classes and functions related to logs parsing.

The lexer requires PLY (Python Lex-Yacc).
"""

#Purpose: Initializes the parsing module and imports main parsing functions.
#Content: Imports functions from lexer_passwords, lexer_system, parser, parsing_passwords, and parsing_system.
# Acts as the entry point for accessing all parsing-related functionalities, centralizing imports for easier use across the project.
from .lexer_passwords import PasswordToken, tokenize_passwords
from .lexer_system import SystemToken, tokenize_system
from .parser import LogsParser
from .parsing_passwords import get_browser_name, parse_passwords
from .parsing_system import parse_system, retrieve_ip_only
from .parsing_cookies import parse_cookie_file
