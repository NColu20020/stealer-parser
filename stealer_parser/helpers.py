"""Helper functions."""
from argparse import ArgumentParser, Namespace
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from json import JSONEncoder, dumps
from pathlib import Path
from typing import Any

import coloredlogs
from verboselogs import VerboseLogger


class EnhancedJSONEncoder(JSONEncoder):
    """Enhanced JSON encoder for specific classes."""

    def default(self: Any, obj: Any) -> Any:
        """Handle custom types JSON serialization."""
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)


def dump_to_file(
    logger: VerboseLogger, filename: str, content: str | Any
) -> None:
    """Save data to local file."""
    filepath = Path(filename)

    try:
        if not filepath.parent.exists():
            filepath.parent.mkdir(parents=True)

        if not isinstance(content, str):
            content_json = dumps(
                content,
                ensure_ascii=False,
                cls=EnhancedJSONEncoder,
                indent=4,
            )
            filepath.write_text(content_json)
        else:
            filepath.write_text(content)

    except (FileNotFoundError, OSError, PermissionError, ValueError) as err:
        logger.error(f"Failed to write file to '{str(filepath)}': {err}")

    else:
        logger.info(f"Successfully wrote '{str(filepath)}'.")


def parse_options(description: str = "Parse infostealer logs archives.") -> Namespace:
    """Parse command-line arguments.

    Parameters
    ----------
    description : str
        The program's description.

    Returns
    -------
    argparse.Namespace
        Parsed command-line arguments as an object.

    """
    parser = ArgumentParser(description=description)

    parser.add_argument(
        "filename",
        type=str,
        help="the archive to process (handled extensions: .rar, .zip, .7z)",
    )
    parser.add_argument(
        "-p",
        "--password",
        metavar="ARCHIVE_PASSWORD",
        type=str,
        default=None,
        help="the archive's password if required",
    )
    parser.add_argument(
        "-o",
        "--outfile",
        metavar="FILENAME.json",
        type=str,
        default=None,
        help="the output file name (expects a .json)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase logs output verbosity (default: info, -v: verbose, "
        "-vv: debug, -vvv: spam)",
    )

    args: Namespace = parser.parse_args()

    if not args.outfile:
        args.outfile = Path(args.filename).with_suffix(".json").name

    return args


def init_logger(
    verbosity_level: int = 0,
    name: str = "StealerParser",
    formatting: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
) -> VerboseLogger:
    """Initialize the program's logger."""
    levels = ["INFO", "VERBOSE", "DEBUG", "SPAM"]
    logger = VerboseLogger(name)
    
    coloredlogs.install(
        logger=logger,
        level=levels[min(verbosity_level, len(levels) - 1)],
        fmt=formatting,
        isatty=True,
    )
    
    return logger
