import functools
import logging
import mmap
import os
import shutil
import tempfile
from dataclasses import dataclass#, field
from pathlib import Path
from typing import IO, Iterator, Optional, Tuple

from sflock.abstracts import File as SFLockFile  # type: ignore
from sflock.abstracts import Unpacker
from sflock.unpack.zip7 import ZipFile as SFLockZipFile  # type: ignore

try:
    import pefile  # type: ignore
    from debloat.processor import process_pe  # type: ignore

    HAS_DEBLOAT = True
except ImportError:
    HAS_DEBLOAT = False

COMMON_PASSWORDS = [
    "infected",
    "malware",
    "password",
]

logger = logging.getLogger("karton.archive-extractor")

# Monkey-patching for sflock.unpack.zip7.ZipFile.handles
#
# Originally it contains additional line that looks for
# b"Registry.dat", b"AppxManifest.xml" in contents to avoid
# MSIX files unpacking , but that loads the whole content into
# memory. We want to avoid that.

@dataclass(slots=True)
class ArchiveInfo:
    """Information about the archive and how to process it"""
    # Input: archive identification
    name: str
    password: str | None = None

    # Input: analyst-provided filepath to execute
    filepath_to_exe: Path | None = None

    # Output: decision and results (populated during processing)
    is_package: bool = False
    matched_child_name: str | None = None



@functools.wraps(SFLockZipFile.handles)
def zip_handles(self: SFLockZipFile) -> bool:
    if (
        hasattr(self.f, "filename")
        and self.f.filename
        and self.f.filename.endswith(self.exts)
    ):
        return True
    if super(SFLockZipFile, self).handles():
        return True
    if self.f.stream.read(2) == b"PK":
        return True
    return False


SFLockZipFile.handles = zip_handles


def sflock_unpack(filepath: bytes, filename: bytes, password: str | None) -> SFLockFile:
    # We don't use sflock.unpack because the final step is "identify"
    # which is unnecessary in our case and loads whole file into memory
    sflock_file = SFLockFile.from_path(
        filepath=filepath,
        filename=filename,
    )
    Unpacker.single(sflock_file, password=password, duplicates=[])
    return sflock_file


def debloat_pe(
    filename: str, child: SFLockFile, max_size: int
) -> Optional[Tuple[str, IO[bytes]]]:
    def log_message_wrapped(message: str, *args, **kwargs) -> None:
        logger.info(message)

    if HAS_DEBLOAT is False:
        logger.info("Child looks like bloated PE file, but debloat is not installed.")
        return None

    mapped_child = mmap.mmap(child.stream.fileno(), 0, access=mmap.ACCESS_READ)
    pe = None
    try:
        try:
            pe = pefile.PE(data=mapped_child, fast_load=True)
        except Exception:
            logger.warning("Failed to load as PE file.")
            return None

        # we need to use a temporary directory because debloat can implicitly unpack
        # NSIS archives to parent directory of the passed file
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_file = Path(tmp_dir) / filename

            try:
                process_pe(
                    pe,
                    cert_preservation=False,
                    out_path=temp_file.as_posix(),
                    last_ditch_processing=False,
                    log_message=log_message_wrapped,
                )
            except Exception:
                logger.exception("Debloat failed with exception.")
            else:
                # debloat can sometimes unpack NSIS installer archives
                # but we're interested only in the installer script
                for unpacked_file in Path(tmp_dir).rglob("*"):
                    if unpacked_file.is_dir():
                        continue

                    if (
                        unpacked_file.name == filename
                        or unpacked_file.name.lower() == "setup.nsis"
                    ):
                        return unpacked_file.name, unpacked_file.open(mode="rb")
    finally:
        if pe:
            pe.close()
        mapped_child.close()

    logger.warning("Output file is empty - failed to debloat file")
    return None


def try_unpack(
    file: IO[bytes],
    filename: str,
    password: str | None,
    archive_info: ArchiveInfo,
) -> Optional[SFLockFile]:
    try:
        if password is not None:
            passwords: list[str | None] = [password]
        else:
            passwords = [None] + COMMON_PASSWORDS

        unpacked = None
        for password in passwords:
            if password is not None:
                logger.info("Trying to unpack archive using password '%s'", password)

            unpacked = sflock_unpack(
                filepath=file.name.encode("utf-8"),
                filename=filename.encode("utf-8"),
                password=password,
            )

            if not unpacked.children:
                logger.info("Failed to unpack this archive: %s", unpacked.error)
                # Try another password
                unpacked = None
                continue

            has_contents = False

            children: list[SFLockFile] = unpacked.children

            for child in children:
                if not child.stream.read(1):
                    logger.info(
                        "Child %s has no contents or "
                        "is protected using different password",
                        child.filename,
                    )
                else:
                    has_contents = True

                child.stream.seek(0)

                if has_contents:
                    # If any child is non-empty: we're done
                    archive_info.password = password
                    return unpacked

            # Otherwise, we don't know how to unpack this archive
            unpacked = None
    except Exception as e:
        # we can't really do anything about corrupted archives :(
        logger.warning("Error while unpacking archive: %s", e)
        return None

    return unpacked


def find_executable_in_children(
    unpacked: SFLockFile,
    filepath: Path,
) -> Optional[str]:
    """
    Find a child file matching the given filepath.

    Args:
        unpacked: The unpacked archive
        filepath: Relative path to file (e.g., "setup.exe" or "folder/file.exe")

    Returns:
        The matching child filename or None
    """
    target_path = str(filepath).strip()
    logger.info(f"Looking for executable: {target_path}")

    for child in unpacked.children:
        child_name = (child.filename and child.filename.decode("utf8")) or child.sha256

        # Try exact match first
        if child_name == target_path:
            logger.info(f"Found exact match: {child_name}")
            return child_name

        # Try case-insensitive match
        if child_name.lower() == target_path.lower():
            logger.info(f"Found case-insensitive match: {child_name}")
            return child_name

    logger.warning(f"File not found in archive: {target_path}")
    return None


def should_treat_as_package(
    unpacked: SFLockFile,
    archive_info: ArchiveInfo,
) -> None:
    """
    Determine if archive should be treated as a single package.
    Updates archive_info in-place with the decision.

    Args:
        unpacked: The unpacked archive
        archive_info: ArchiveInfo object to update with decision
    """
    logger.info("Checking if archive should be processed as a package")

    # If analyst provided a filepath, treat as package
    if archive_info.filepath_to_exe is not None:
        matched_child = find_executable_in_children(unpacked, archive_info.filepath_to_exe)
        archive_info.is_package = True
        archive_info.matched_child_name = matched_child

        if matched_child:
            logger.info(f"Treating as package with selected executable: {matched_child}")
        else:
            logger.warning(
                f"Analyst provided filepath '{archive_info.filepath_to_exe}' "
                f"but file not found in archive. Falling back to extracting all children."
            )
            archive_info.is_package = False
        return

    # TODO: Add automatic heuristics here
    # Examples:
    # - Single .exe with many supporting files?
    # - Presence of installer metadata?
    # - Known installer formats (NSIS, InnoSetup, etc.)?
    #
    # For now, default to extracting all children
    archive_info.is_package = False


def unpack(
    file: IO[bytes],
    filename: str,
    password: str | None,
    max_children: int,
    max_size: int,
    archive_info: ArchiveInfo,
) -> Iterator[Tuple[str, IO[bytes]]]:
    """
    Unpack archive and yield all children.

    Package detection information is stored in archive_info but doesn't
    affect child extraction - all children are always yielded.
    """
    unpacked = try_unpack(file, filename, password, archive_info=archive_info)

    if not unpacked:
        logger.warning("We're unable to unpack this archive")
        return

    # Determine if this should be treated as a package
    # This populates archive_info fields but doesn't change extraction behavior
    should_treat_as_package(unpacked, archive_info)

    try:
        if len(unpacked.children) > max_children:
            logger.warning(
                f"Too many children ({len(unpacked.children)}) for further processing "
                f"(max: {max_children})"
            )
            return

        for child in unpacked.children:
            fname = (child.filename and child.filename.decode("utf8")) or child.sha256

            logger.info("Unpacking child %s", fname)

            magic = child.stream.read(2)

            if not magic:
                logger.warning(
                    "Child has no contents or is protected by unknown password"
                )
                continue

            stream = child.stream

            if child.filesize > max_size:
                if magic == b"MZ":
                    debloated = debloat_pe(fname, child, max_size=max_size)
                    if debloated is not None:
                        fname, stream = debloated

            # Is it still too big?
            stream.seek(0, os.SEEK_END)
            stream_size = stream.tell()
            stream.seek(0, os.SEEK_SET)

            if stream_size > max_size:
                logger.warning(
                    "Child is too big for further processing (%d > %d)",
                    stream_size,
                    max_size,
                )
                continue

            yield fname, stream
            stream.close()
    except Exception:
        unpacked.close()
        raise


def is_safe_path(path: str) -> bool:
    try:
        root_dir = Path(os.getcwd())
        root_dir.joinpath(path).resolve().relative_to(root_dir.resolve())
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    import argparse
    import logging

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(
        description="Process a file with optional size and children limits."
    )
    parser.add_argument("file", help="Path to the file")
    parser.add_argument(
        "--max-size",
        type=int,
        default=25 * 1024 * 1024,
        help="Maximum child size in bytes",
    )
    parser.add_argument(
        "--max-children", type=int, default=1000, help="Maximum number of children"
    )
    parser.add_argument(
        "--password",
        type=str,
        default=None,
        help="Non-standard password to use when unpacking file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Run without writing output files (default: False)",
    )
    parser.add_argument(
        "--filepath-to-execute",
        type=str,
        default=None,
        help="Path to file within archive to execute (for package mode)",
    )
    args = parser.parse_args()

    archive_info = ArchiveInfo(
        name=args.file,
        password=None,
        filepath_to_exe=Path(args.filepath_to_execute) if args.filepath_to_execute else None,
    )

    with open(args.file, "rb") as f:
        for name, stream in unpack(
            f,
            args.file,
            password=args.password,
            max_size=args.max_size,
            max_children=args.max_children,
            archive_info=archive_info,
        ):
            logger.info("Unpacked file: %s", name)
            if not args.dry_run:
                if not is_safe_path(name):
                    logger.warning(
                        "File was not written, target path is out of current directory"
                    )
                with open(name, "wb") as outf:
                    shutil.copyfileobj(stream, outf)

    # Print package detection result
    if archive_info.is_package:
        logger.info(f"Archive detected as package")
        if archive_info.matched_child_name:
            logger.info(f"Executable to run: {archive_info.matched_child_name}")
        else:
            logger.warning(f"Package mode requested but executable not found")
