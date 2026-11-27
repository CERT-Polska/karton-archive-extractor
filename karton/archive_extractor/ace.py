"""
ACE archive unpacking for the ungoose backend.

Uses the vendored ``acefile`` (``thirdparty.acefile``, upstream 0.6.14)
with the optional C accelerator disabled.

Extraction semantics mirror sevenzip.py:

- every non-directory member is materialized into the temporary
  extraction directory and exposed as an fd-backed ChildFile,
- encrypted members are decrypted with the provided password (acefile
  implements ACE Blowfish decryption); a wrong or missing password is
  reported via ``ExtractedArchive.error``,
- partial results are kept: members extracted before a failure stay in
  the children list, with the error noted.
"""

import logging
import os
import tempfile
from typing import Optional

from .backends import ExtractedArchive, collect_children
from .thirdparty import acefile

logger = logging.getLogger("karton.archive-extractor.ace")


def unpack_ace(
    filepath: bytes,
    filename: bytes,
    password: Optional[str],
) -> ExtractedArchive:
    """Unpack an ACE archive with acefile, returning extracted children.

    Reports unpacking failures via ``error`` field of ExtractedArchive.
    ``password`` decrypts Blowfish-encrypted members; encrypted members
    with a wrong or missing password raise ``EncryptedArchiveError``.
    """
    archive_path = os.fsdecode(filepath)

    result: ExtractedArchive
    with tempfile.TemporaryDirectory(prefix="karton-ae-ace-") as outdir:
        error: Optional[str]
        try:
            with acefile.open(archive_path) as archive:
                _extract_members(archive, outdir, password)
            error = None
        except acefile.EncryptedArchiveError as e:
            error = f"Encrypted ACE archive: {e}"
        except acefile.CorruptedArchiveError as e:
            # Keep whatever was extracted before the corruption point
            children = collect_children(outdir)
            error = (
                f"Corrupted ACE archive (partial extraction, "
                f"{len(children)} files): {e}"
            )
            logger.warning("ACE partial extraction for %r: %s", filename, e)
            return ExtractedArchive(filename=filename, children=children, error=error)
        except acefile.AceError as e:
            error = f"ACE unpacking failed: {e}"
        except OSError as e:
            error = f"Failed to read ACE archive: {e}"

        if error is not None:
            children = []
        else:
            children = collect_children(outdir)
        result = ExtractedArchive(filename=filename, children=children, error=error)

    if result.error is not None:
        logger.warning("ACE unpacking error for %r: %s", filename, result.error)
    return result


def _extract_members(
    archive: acefile.AceArchive, outdir: str, password: Optional[str]
) -> None:
    """Write every non-directory member into ``outdir``."""
    for member in archive.getmembers():
        if member.is_dir():
            continue
        # acefile sanitizes member.filename (no absolute paths, no '..')
        archive.extract(member, path=outdir, pwd=password)
