import logging
import mmap
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Iterator, Optional, Tuple, cast

from .backends import ChildFile, ExtractedArchive, UnpackBackend, resolve_backend
from .package_heuristics import determine_if_package

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


@dataclass(slots=True)
class ArchiveInfo:
    """Information about the archive and how to process it"""

    # Input: archive identification
    name: str
    password: str | None = None

    # Entry path to execute within the archive
    # Set from analyst input or auto-detected during processing
    entry_path: str | None = None

    # Output: decision and results (populated during processing)
    is_package: bool = False

    # Manifest of every file in the archive: [{"path": ..., "size": ...}, ...]
    files: list[dict[str, str | int]] = field(default_factory=list)


def debloat_pe(
    filename: str, child: ChildFile, max_size: int
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

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_file = Path(tmp_dir) / filename

            try:
                process_pe(
                    pe,
                    cert_preservation=False,
                    out_path=tmp_file.as_posix(),
                    last_ditch_processing=False,
                    log_message=log_message_wrapped,
                    extract=False,  # don't extract NSIS and other installers
                )
            except Exception:
                logger.exception("Debloat failed with exception.")
            else:
                for unpacked_file in Path(tmp_dir).rglob("*"):
                    if unpacked_file.is_dir():
                        continue

                    if unpacked_file.name == filename:
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
    backend: UnpackBackend,
) -> Optional[ExtractedArchive]:
    try:
        passwords: list[str | None]
        if password is not None:
            passwords = [password]
        else:
            passwords = cast(list[str | None], [None]) + cast(
                list[str | None], COMMON_PASSWORDS
            )

        unpacked = None
        for password in passwords:
            if password is not None:
                logger.info("Trying to unpack archive using password '%s'", password)

            unpacked = backend.unpack(
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

            unpacked_children: list[ChildFile] = unpacked.children

            for child in unpacked_children:
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


def _child_path(child: ChildFile) -> str:
    """
    Return the path of a child within the archive.
    Use relapath to preserve directory structure within archive
    relapath contains the full relative path (e.g., "dir1/dir2/file.exe")
    """
    return (
        (child.relapath and child.relapath.decode("utf8", "replace"))
        or (child.filename and child.filename.decode("utf8", "replace"))
        or child.sha256
    )


def unpack(
    file: IO[bytes],
    filename: str,
    password: str | None,
    max_children: int,
    max_size: int,
    archive_info: ArchiveInfo,
    backend: UnpackBackend,
) -> Iterator[Tuple[str, IO[bytes]]]:
    """
    Unpack archive and yield all children.

    Package detection information is stored in archive_info but doesn't
    affect child extraction - all children are always yielded.
    """
    unpacked = try_unpack(
        file, filename, password, archive_info=archive_info, backend=backend
    )

    if not unpacked:
        logger.warning("We're unable to unpack this archive")
        if archive_info.entry_path:
            archive_info.is_package = True
            logger.warning(
                f"Entry path '{archive_info.entry_path}' provided, but "
                "we couldn't verify it."
            )
        return

    # Determine if this should be treated as a package
    # This populates archive_info fields but doesn't change extraction behavior
    determine_if_package(unpacked, archive_info)

    try:
        if len(unpacked.children) > max_children:
            logger.warning(
                f"Too many children ({len(unpacked.children)}) for further processing "
                f"(max: {max_children})"
            )
            for child in unpacked.children:
                archive_info.files.append(
                    {
                        "path": _child_path(child),
                        "size": child.filesize,
                        "error": "Extraction skipped: too many files in archive",
                    }
                )
            return

        for child in unpacked.children:
            size = child.filesize
            child.stream.seek(0)
            # Use relapath to preserve directory structure within archive
            # relapath contains the full relative path (e.g., "dir1/dir2/file.exe")
            child_filename = _child_path(child)

            logger.info("Unpacking child %s", child_filename)

            magic = child.stream.read(2)

            if not magic:
                logger.warning(
                    "Child has no contents or is protected by unknown password"
                )
                archive_info.files.append(
                    {
                        "path": child_filename,
                        "size": size,
                        "error": "File is empty or protected by an unknown password",
                    }
                )
                continue

            child_stream = child.stream

            if size > max_size:
                if magic == b"MZ":
                    debloat_result = debloat_pe(
                        child_filename, child, max_size=max_size
                    )
                    if debloat_result is not None:
                        child_filename, child_stream = debloat_result

            # Is it still too big?
            child_stream.seek(0, os.SEEK_END)
            stream_size = child_stream.tell()
            child_stream.seek(0, os.SEEK_SET)

            if stream_size > max_size:
                logger.warning(
                    "Child is too big for further processing (%d > %d)",
                    stream_size,
                    max_size,
                )
                archive_info.files.append(
                    {
                        "path": child_filename,
                        "size": size,
                        "error": (
                            f"File is too big to extract "
                            f"({size} bytes, limit is {max_size} bytes)"
                        ),
                    }
                )
                continue

            archive_info.files.append({"path": child_filename, "size": size})
            yield child_filename, child_stream
            child_stream.close()
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
        "--archive-entry-path",
        type=str,
        default=None,
        help="Path to file within archive to execute (for package mode)",
    )
    parser.add_argument(
        "--backend",
        type=str,
        default=None,
        help="Unpacking backend: sflock (default) or 7zip",
    )
    args = parser.parse_args()

    backend = resolve_backend(args.backend)

    archive_info = ArchiveInfo(
        name=args.file,
        password=None,
        entry_path=args.archive_entry_path,
    )

    with open(args.file, "rb") as f:
        for name, stream in unpack(
            f,
            args.file,
            password=args.password,
            max_size=args.max_size,
            max_children=args.max_children,
            archive_info=archive_info,
            backend=backend,
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
        logger.info("Archive detected as package")
        if archive_info.entry_path:
            logger.info(f"Executable to run: {archive_info.entry_path}")
        else:
            logger.warning("Package mode requested but executable not found")
