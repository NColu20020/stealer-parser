"""Infostealer logs parser."""

#Purpose: Manages the main processing and parsing logic for the archive’s content.
#Key Functions:
    #generate_file_list: Scans the archive to generate a list of files matching patterns for credentials, system information, IP addresses, and credits.
    #process_archive: Iterates through each system directory within an archive and processes the relevant files.
    #parse_file: Extracts specific information from each file, such as credentials, system details, or IP addresses.
#Classes:
    #LogFileType: Enum to categorize log files (e.g., PASSWORDS, SYSTEM).
    #LogFile: Dataclass that defines the structure for log files within the archive, with attributes such as file type and directory.
#Regex Pattern (FILENAMES_PATTERN): Used to match files based on specific keywords (like password, system, ip, credits) in their names, making it easier to locate and parse relevant data.

from dataclasses import dataclass
from enum import Enum
from re import Match, Pattern, compile

from py7zr.exceptions import CrcError
from rarfile import BadRarFile
from verboselogs import VerboseLogger
from stealer_parser.parsing.parsing_cookies import parse_cookie_file

from stealer_parser.models import (
    ArchiveWrapper,
    Leak,
    StealerNameType,
    System,
    SystemData,
    Cookie,  # Add Cookie to this import group
    StealerLog
)

from stealer_parser.parsing import (
    parse_passwords,
    parse_system,
    retrieve_ip_only,
)
from stealer_parser.ply.src.ply.lex import LexError
from stealer_parser.search_stealer_credits import search_stealer_name
from stealer_parser.search_stealer_credits import (
    RACCOON_HEADER,
    REDLINE_HEADER,
    REDLINE_HEADER_MALFORMED
)

# Files containing useful information such as credentials and credits.
#FILENAMES_REGEX: str = r"(?i).*((password(?!cracker))|(system|information|userinfo)|(\bip)|(credits|copyright|read)).*\.txt"  # noqa: E501
#FILENAMES_REGEX: str = r"(?i).*((password(?!cracker))|(system|information|userinfo)|(\bip)|(credits|copyright|read)|(cookies)).*\.txt"
#FILENAMES_REGEX: str = r"(?i)((cookies[/\\][^/\\]+\.txt$)|((password(?!cracker)\.txt$)|(password(?!cracker)[^/\\]*\.txt$)|(system|information|userinfo)\.txt$|(\bip\.txt$)|(credits|copyright|read)\.txt$))"
#FILENAMES_REGEX: str = r"(?i)((cookies[/\\][^/\\]+\.txt$)|(.*((password(?!cracker))|(system|information|userinfo)|(\bip)|(credits|copyright|read)).*\.txt$))"
##------
FILENAMES_REGEX: str = r"(?i).*(password\.txt$|(password(?!cracker))|(system|information|userinfo)|(\bip)|(credits|copyright|read)|(cookies[/\\][^/\\]+)).*\.txt$"
#FILENAMES_REGEX: str = r"(?i).*((password(?!cracker))|(system|information|userinfo)|(\bip)|(credits|copyright|read)|(cookies[/\\][^/\\]+)).*\.txt$"
# Let's break down this regex:
#
# (?i)       Case insensitive
# (password)|(\bcc(\b|.))|([^#](system|information|userinfo)) ...
#            Match substring.
#            Group 2: password not followed by cracker -> credentials
#            Group 3: system|information -> compromised machine information
#            Group 4: ip.txt -> IP address of the compromised machine.
#            Group 5: credits|copyright|read -> stealer name
# .*\.txt    Match any character except line terminators folled by a .txt
#            extension.
FILENAMES_PATTERN: Pattern[str] = compile(FILENAMES_REGEX)


class LogFileType(Enum):
    """Log files types."""

    PASSWORDS = 2
    SYSTEM = 3
    IP = 4
    COPYRIGHT = 5
    COOKIES = 6  # New type for cookies


@dataclass
class LogFile:
    """Class defining a log file to be parsed."""
    type: LogFileType
    filename: str
    system_dir: str
    full_path: str = ""  # Make full_path optional with default empty string


def get_system_dir(filepath: str) -> str:
    """Retrieve name of the compromised system directory."""
    parts = filepath.replace('\\', '/').split('/')
    
    # Look for the most specific stealer directory in the path
    for part in reversed(parts):  # Start from the end of the path
        # Look for stealer log directory patterns
        for pattern in [
            r'^[A-Z0-9]{20,}_\d{4}_\d{2}_\d{2}T',  # Standard format
            r'^[A-Z0-9]{20,}$',                     # Just ID
        ]:
            if compile(pattern).match(part):
                return part
    
    # If no stealer pattern found, look for functional directories
    for i, part in enumerate(parts):
        if part.lower() in {'cookies', 'passwords', 'browser'}:
            # Get the parent directory if it exists and isn't a system directory
            if i > 0 and not parts[i-1].startswith('__MACOSX'):
                return parts[i-1]
    
    return filepath


def generate_file_list(root: ArchiveWrapper) -> list[LogFile]:
    """Generate interesting file list.

    This is a work around since archive.iterdir() is too slow and we need to
    keep the directory structure.

    Parameters
    ----------
    root : stealer_parser.models.archive_wrapper.ArchiveWrapper
        The root of the archive to be searched.

    Returns
    -------
    list of SystemDir
        Log files grouped by related compromised system.

    """
    files: list[LogFile] = []

    for name in sorted(root.namelist()):
        matched: Match[str] | None = FILENAMES_PATTERN.search(name)

        if matched:
            log_type: LogFileType | None = None

            # First check for password files (highest priority)
            if ("password.txt" in name.lower() or 
                (matched.group(2) and "password" in name.lower() and "cracker" not in name.lower())):
                log_type = LogFileType.PASSWORDS
            # Then check for cookies directory
            elif "/cookies/" in name.lower() or "\\cookies\\" in name.lower():
                log_type = LogFileType.COOKIES
            # Then check other types
            elif matched.group(3) and "#" not in name:
                log_type = LogFileType.SYSTEM
            elif matched.group(4):
                log_type = LogFileType.IP
            elif matched.group(5):
                log_type = LogFileType.COPYRIGHT

            if log_type is not None:
                files.append(LogFile(log_type, name, get_system_dir(name)))
                
    return files


# def parse_file(
#     logger: VerboseLogger,
#     filename: str,
#     system_data: SystemData,
#     file: LogFile,
#     text: str,
# ) -> None:
#     """Parse a file containing credential, system information and so forth.

#     Parameters
#     ----------
#     logger : verboselogs.VerboseLogger
#         The program's logger.
#     filename : str
#         The complete filepath.
#     system_data : stealer_parser.models.leak.SystemCredentials
#         The collected system's data.
#     file : LogFile
#         The file to parsed.
#     text : str
#         The file's content.

#     """
#     try:
#         match file.type:
#             case LogFileType.PASSWORDS:
#                 system_data.credentials += parse_passwords(
#                     logger, filename, text
#                 )

#             case LogFileType.SYSTEM:
#                 system: System | None = parse_system(logger, filename, text)

#                 if system:
#                     if system_data.system and system_data.system.ip_address:
#                         system.ip_address = system_data.system.ip_address
#                     system_data.system = system

#             case LogFileType.IP:
#                 retrieve_ip_only(text, system_data)

#     except (LexError, SyntaxError) as err:
#         logger.error(f"Failed parsing file '{filename}': {err}")

from stealer_parser.parsing.parsing_cookies import parse_cookie_file
from stealer_parser.models.cookie import Cookie

def parse_file(
    logger: VerboseLogger,
    filename: str,
    system_data: SystemData,
    file: LogFile,
    text: str,
) -> None:
    """Parse a file containing credential, system information, cookies, etc.

    Parameters
    ----------
    logger : verboselogs.VerboseLogger
        The program's logger.
    filename : str
        The complete filepath.
    system_data : stealer_parser.models.leak.SystemData
        The collected system's data.
    file : LogFile
        The file to be parsed.
    text : str
        The file's content.
    """
    try:
        match file.type:
            case LogFileType.PASSWORDS:
                system_data.credentials += parse_passwords(
                    logger, filename, text
                )

            case LogFileType.SYSTEM:
                system: System | None = parse_system(logger, filename, text)
                if system:
                    if system_data.system and system_data.system.ip_address:
                        system.ip_address = system_data.system.ip_address
                    system_data.system = system

            case LogFileType.IP:
                retrieve_ip_only(text, system_data)

            case LogFileType.COOKIES:
                try:
                    cookies = parse_cookie_file(filename, text)
                    if cookies:
                        system_data.cookies.extend(cookies)
                        logger.info(f"Successfully added {len(cookies)} cookies from {filename}")
                    else:
                        logger.warning(f"No cookies found in file: {filename}")
                except Exception as e:
                    logger.error(f"Failed to parse cookies from {filename}: {e}")

    except (LexError, SyntaxError) as err:
        logger.error(f"Failed parsing file '{filename}': {err}")



def process_system_dir(
    logger: VerboseLogger,
    archive: ArchiveWrapper,
    files: list[LogFile],
) -> SystemData:
    """Process files from a single system directory."""
    system_data = SystemData()
    system_data.stealer_directory = files[0].system_dir if files else ""
    
    # Group files by type
    files_by_type: dict[LogFileType, list[LogFile]] = {}
    for file in files:
        if "/cookies/" in file.filename.lower() or "\\cookies\\" in file.filename.lower():
            file_type = LogFileType.COOKIES
        else:
            file_type = file.type
            
        if file_type not in files_by_type:
            files_by_type[file_type] = []
        files_by_type[file_type].append(file)
    
    # Process each type
    for file_type, type_files in files_by_type.items():
        for file in type_files:
            try:
                content = archive.read_file(file.filename)
                
                match file_type:
                    case LogFileType.COOKIES:
                        cookies = parse_cookie_file(file.filename, content)
                        if cookies:
                            system_data.cookies.extend(cookies)
                            logger.info(f"Added {len(cookies)} cookies from {file.filename}")
                    
                    case LogFileType.SYSTEM:
                        system = parse_system(logger, file.filename, content)
                        if system:
                            system_data.system = system
                    
                    case LogFileType.PASSWORDS:
                        credentials = parse_passwords(logger, file.filename, content)
                        if credentials:
                            system_data.credentials.extend(credentials)
                    
                    case LogFileType.IP:
                        ip = retrieve_ip_only(content)
                        if ip and system_data.system:
                            system_data.system.ip_address = ip
                
            except Exception as e:
                logger.error(f"Failed to process file {file.filename}: {e}")
                continue
    
    return system_data


def process_archive(logger: VerboseLogger, archive: ArchiveWrapper) -> Leak:
    """Process archive content."""
    leak = Leak(filename=archive.filename)
    logger.info(f"Processing: {archive.filename} ...")
    
    # Group files by stealer directory
    system_files: dict[str, list[LogFile]] = {}
    
    for file in generate_file_list(archive):
        system_dir = get_system_dir(file.filename)
        if is_valid_system_dir(system_dir):
            if system_dir not in system_files:
                system_files[system_dir] = []
            system_files[system_dir].append(file)
    
    # Process each stealer directory separately
    for system_dir, files in system_files.items():
        try:
            logger.debug(f"Processing system directory: {system_dir}")
            system_data = process_system_dir(logger, archive, files)
            
            if system_data.system or system_data.credentials or system_data.cookies:
                stealer_type = detect_stealer_type(files, archive, logger)
                
                stealer_log = StealerLog(
                    stealer_type=stealer_type,
                    directory=system_dir,
                    system_data=system_data
                )
                
                logger.info(f"Adding stealer log for directory: {system_dir}")
                leak.stealer_logs.append(stealer_log)
                
        except Exception as e:
            logger.warning(f"Failed to process system directory {system_dir}: {e}")
            continue
    
    return leak

def get_file_type(filename: str) -> LogFileType:
    """Determine file type based on its name.
    
    Parameters
    ----------
    filename : str
        The file name to analyze.
        
    Returns
    -------
    LogFileType
        The detected file type.
    """
    filename_lower = filename.lower()
    
    # Add cookie detection before existing conditions
    if "cookie" in filename_lower:
        return LogFileType.COOKIES
        
    # Existing conditions
    if "password" in filename_lower and "cracker" not in filename_lower:
        return LogFileType.PASSWORDS
    if any(
        keyword in filename_lower
        for keyword in ("system", "information", "userinfo")
    ):
        return LogFileType.SYSTEM
    if "ip" in filename_lower:
        return LogFileType.IP
        
    return LogFileType.COPYRIGHT

def detect_stealer_type(
    files: list[LogFile], 
    archive: ArchiveWrapper,
    logger: VerboseLogger
) -> StealerNameType:
    """Detect the type of stealer from log files."""
    for file in files:
        try:
            content = archive.read_file(file.filename)
            if file.type == LogFileType.COPYRIGHT:
                stealer_name = search_stealer_name(content)
                if stealer_name:
                    return stealer_name
            
            # Look for stealer-specific patterns
            if RACCOON_HEADER in content:
                return StealerNameType.RACCOON
            elif REDLINE_HEADER in content or REDLINE_HEADER_MALFORMED in content:
                return StealerNameType.REDLINE
        except Exception as e:
            logger.error(f"Failed to read file {file.filename}: {e}")
            continue
    
    return StealerNameType.UNKNOWN

def is_valid_system_dir(directory: str) -> bool:
    """Check if a directory is a valid stealer log directory."""
    if directory.startswith('__MACOSX'):
        return False
    
    # Check for typical stealer directory patterns
    stealer_patterns = [
        r'^[A-Z0-9]{20,}_\d{4}_\d{2}_\d{2}T',
        r'^[A-Z0-9]{20,}$',
    ]
    
    return any(compile(pattern).match(directory) for pattern in stealer_patterns)
