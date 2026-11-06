"""
7-Zip unpacking backend.

Drives the official 7-Zip command line binary (``7zz``, or legacy ``7z``)
as a child process to safely unpack archives, mirroring the unpacking
semantics of sflock's own 7z-based unpackers (sflock.unpack.zip7):

- always passes ``-p<password>`` (empty when password is unknown) so 7-Zip
  never blocks waiting for interactive password input,
- extracts with full paths (``x``) into a fresh temporary directory,
- keeps partial extraction results: a failed run that still produced
  files on disk yields children anyway (sflock's ZipFile behavior), so
  wrong-password ZIP archives still expose their zero-byte entries,
- reports hard failures (no files extracted) via ``ExtractedArchive.error``
  without raising.

The backend works with the stock binary available on PATH. The official
7-Zip static build for Linux (with unRAR support) is recommended — e.g.
fetched at Docker build time from https://www.7-zip.org/download.html.
"""

import logging
import os
import shutil
import subprocess
import tempfile
from typing import Optional, Tuple

from .backends import ChildFile, ExtractedArchive

logger = logging.getLogger("karton.archive-extractor.sevenzip")

# Binary override, mostly for tests: set to a 7-Zip executable path.
SEVENZIP_BIN: Optional[str] = None

# Hard cap for a single unpacking attempt. Malicious archives may try to
# exhaust CPU by decompressing endlessly; the process is killed afterwards.
DEFAULT_TIMEOUT = 60.0


def find_7z_binary() -> str:
    """Locate the 7-Zip binary"""
    if SEVENZIP_BIN is not None:
        return SEVENZIP_BIN
    for candidate in ("7zz", "7z"):
        path = shutil.which(candidate)
        if path is not None:
            return path
    raise RuntimeError(
        "7-Zip binary not found: install 7-Zip (e.g. the official 7zz static build)"
    )


def _error_summary(stderr: bytes, limit: int = 200) -> str:
    """First meaningful lines of 7-Zip stderr, as a single-line string."""
    lines = [
        line.strip()
        for line in stderr.decode("utf-8", "replace").splitlines()
        if line.strip()
    ]
    summary = "; ".join(lines[:2])
    return summary[:limit]


def unpack_7z(
    filepath: bytes,
    filename: bytes,
    password: Optional[str],
    timeout: float = DEFAULT_TIMEOUT,
) -> ExtractedArchive:
    """Unpack an archive with 7-Zip, returning extracted children.

    Reports unpacking failures via ``error`` field of ExtractedArchive.
    """
    binary = find_7z_binary()
    archive_path = os.path.abspath(os.fsdecode(filepath))
    password_arg = "-p" + (password or "")

    result: ExtractedArchive
    with tempfile.TemporaryDirectory(prefix="karton-ae-7z-") as outdir:
        cmd: Tuple[str, ...] = (
            binary,
            "x",  # extract with full directory structure
            "-y",  # assume "yes" on all prompts
            "-mmt=off",  # single-threaded decompression
            password_arg,
            "-o" + outdir,
            "--",
            archive_path,
        )

        timed_out = False
        stderr = b""
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,  # never allow interactive prompts
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                _, stderr = proc.communicate(timeout=timeout)
                return_code = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                logger.warning(
                    "7z unpacking exceeded %.0fs (file %r), killing process",
                    timeout,
                    filename,
                )
                proc.kill()
                proc.communicate()
                return_code = proc.returncode
        except OSError as e:
            result = ExtractedArchive(
                filename=filename,
                error=f"Failed to execute 7-Zip: {e}",
            )
        else:
            # Whatever is on disk at this point is the extraction result.
            # Files created before a failure (e.g. zero-byte entries from
            # a wrong password attempt) are kept, matching sflock's
            # ZipFile behavior.
            if timed_out:
                error = f"7z timed out after {timeout:.0f}s"
            elif return_code in (0, 1):
                # Warnings are acceptable
                error = None
            elif os.listdir(outdir):
                # Partial extraction: keep the children, note the error
                error = (
                    f"7z exited with code {return_code} "
                    f"(partial extraction): {_error_summary(stderr or b'')}"
                )
                logger.debug(
                    "7z partial extraction for %r: %s",
                    filename,
                    _error_summary(stderr or b""),
                )
            else:
                # Hard failure with nothing extracted
                error = (
                    f"7z exited with code {return_code}: "
                    f"{_error_summary(stderr or b'')}"
                )

            children = _collect_children(outdir)
            result = ExtractedArchive(
                filename=filename,
                children=children,
                error=error,
            )

    if result.error is not None:
        logger.warning("7z unpacking error for %r: %s", filename, result.error)
    return result


def _collect_children(outdir: str) -> list[ChildFile]:
    """Walk the extraction directory and open every regular file.

    Symlinks are skipped: they cannot be represented as sample streams
    and 7-Zip refuses to create links escaping the output directory.
    Children are sorted by path for deterministic listings.
    """
    children: list[ChildFile] = []
    for root, _dirs, files in os.walk(outdir, followlinks=False):
        for name in files:
            full_path = os.path.join(root, name)
            if os.path.islink(full_path):
                logger.warning("Skipping symlink child %r", name)
                continue
            try:
                stream = open(full_path, "rb")
            except OSError as e:
                logger.error("Failed to open extracted file %r: %s", name, e)
                continue
            relapath = (os.path.relpath(full_path, outdir).replace(os.sep, "/")).encode(
                "utf-8", "surrogateescape"
            )
            children.append(
                ChildFile(
                    relapath=relapath,
                    filename=relapath.rsplit(b"/", 1)[-1],
                    filesize=os.fstat(stream.fileno()).st_size,
                    stream=stream,
                )
            )
    children.sort(key=lambda child: child.relapath)
    return children
