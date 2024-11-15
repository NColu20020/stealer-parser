"""Infostealer logs parser."""

#Purpose: The core file for executing the main logic of the parser.
#Key Functions:
    #read_archive: Opens and processes different archive formats (.rar, .zip, .7z), returning an ArchiveWrapper object to interact with the archive’s contents.
    #main: The main function to handle argument parsing, logger setup, archive reading, processing, and output. It reads the archive, processes it, and then saves the parsed data.
#Usage: This file controls the program flow from reading an archive to outputting parsed data.

from argparse import Namespace
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from py7zr import SevenZipFile
from rarfile import RarFile
from verboselogs import VerboseLogger

from stealer_parser.helpers import dump_to_file, init_logger, parse_options
from stealer_parser.models import ArchiveWrapper, Leak
from stealer_parser.processing import process_archive


def read_archive(
    buffer: BytesIO, filename: str, password: str | None
) -> ArchiveWrapper:
    """Open logs archive and returns a reader object.

    Parameters
    ----------
    buffer : io.BytesIO
        The opened archive stream.
    filename : str
        The archive filename.
    password : str
        If applicable, the password required to open the archive.

    Returns
    -------
    stealer_parser.models.archive_wrapper.ArchiveWrapper or None

    Raises
    ------
    NotImplementedError
        If the ZIP compression method or the file extension is not handled.
    rarfile.Error
        If either unrar, unar or bdstar binary is not found.
    py7zr.exceptions.Bad7zFile
        If the file is not a 7-Zip file.
    FileNotFoundError, OSError, PermissionError
        If the archive file is not found or can't be read.

    """
    archive: RarFile | ZipFile | SevenZipFile

    match Path(filename).suffix:
        case ".rar":
            archive = RarFile(buffer)

        case ".zip":
            archive = ZipFile(buffer)

        case ".7z":
            archive = SevenZipFile(buffer, password=password)

        case other_ext:
            raise NotImplementedError(f"{other_ext} not handled.")

    return ArchiveWrapper(archive, filename=filename, password=password)


def main() -> None:
    """Main function."""
    args: Namespace = parse_options()
    logger = init_logger(args.verbose)

    try:
        with open(args.filename, "rb") as buffer:
            archive = read_archive(buffer, args.filename, args.password)
            leak = process_archive(logger, archive)
            dump_to_file(
                logger,
                args.outfile or f"{Path(args.filename).stem}.json",
                leak.to_dict()
            )

    except Exception as err:
        logger.critical(f"{err.__class__.__name__}: {err}")
        raise


if __name__ == "__main__":
    main()
