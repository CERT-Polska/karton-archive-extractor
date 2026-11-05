"""
Common unpacking backend interface and data model.

Defines the child-archive representation consumed by the rest of the
service (unpacker, package heuristics, debloat) — intentionally mirroring
the subset of sflock.abstracts.File attributes that karton-archive-extractor
relies on, so backend implementations are drop-in replaceable:

- ``relapath``: full path relative to the archive root, "/"-separated bytes
  (e.g. b"dir1/dir2/file.exe"), preserving the archive directory structure
- ``filename``: basename of the entry
- ``filesize``: uncompressed size in bytes
- ``stream``: fd-backed binary stream (must support mmap via fileno())
- ``sha256``: lazily computed digest of the stream contents
- ``close()``: releases the underlying stream
"""

import functools
import hashlib
import logging
from dataclasses import dataclass, field
from typing import IO, Any, Protocol, cast, runtime_checkable

logger = logging.getLogger("karton.archive-extractor")


@dataclass(slots=True)
class ChildFile:
    """A single unpacked file, lazily backed by an open file descriptor."""

    relapath: bytes
    filename: bytes
    filesize: int
    stream: IO[bytes]
    _sha256: str | None = field(default=None, repr=False, compare=False)

    @property
    def sha256(self) -> str:
        """SHA256 of the stream contents, computed on first access."""
        if self._sha256 is None:
            hasher = hashlib.sha256()
            self.stream.seek(0)
            for chunk in iter(lambda: self.stream.read(0x10000), b""):
                hasher.update(chunk)
            self._sha256 = hasher.hexdigest()
        return self._sha256

    def close(self) -> None:
        self.stream.close()


@dataclass(slots=True)
class ExtractedArchive:
    """Result of unpacking an archive with a single child list."""

    # Original archive filename (basename), for logging context
    filename: bytes
    # Unpacked children (may be empty on failure)
    children: list[ChildFile] = field(default_factory=list)
    # Set when the archive could not be unpacked (e.g. wrong password,
    # unrecognized or corrupted format). Empty children + error is a
    # hard failure; non-empty children + error means partial extraction.
    error: str | None = None

    def close(self) -> None:
        for child in self.children:
            child.close()


@runtime_checkable
class UnpackBackend(Protocol):
    """Interface every unpacking backend must implement."""

    name: str

    def unpack(
        self,
        filepath: bytes,
        filename: bytes,
        password: str | None,
    ) -> ExtractedArchive:
        """Unpack a single archive located at ``filepath``.

        Must never raise for expected unpacking failures (bad/corrupted
        archives, wrong passwords) — report them via ``error`` instead.
        """
        ...


class SflockBackend:
    """Legacy backend shelling out to the sflock library."""

    name = "sflock"

    def unpack(
        self,
        filepath: bytes,
        filename: bytes,
        password: str | None,
    ) -> ExtractedArchive:
        from sflock.abstracts import File as SFLockFile  # type: ignore
        from sflock.abstracts import Unpacker
        from sflock.unpack.zip7 import ZipFile as SFLockZipFile  # type: ignore

        self._apply_msix_monkeypatch(SFLockZipFile)

        # We don't use sflock.unpack because the final step is "identify"
        # which is unnecessary in our case and loads whole file into memory
        sflock_file = SFLockFile.from_path(
            filepath=filepath,
            filename=filename,
        )
        Unpacker.single(sflock_file, password=password, duplicates=[])
        return self._convert(sflock_file)

    @staticmethod
    def _apply_msix_monkeypatch(SFLockZipFile: type) -> None:
        # Monkey-patching for sflock.unpack.zip7.ZipFile.handles
        #
        # Originally it contains additional line that looks for
        # b"Registry.dat", b"AppxManifest.xml" in contents to avoid
        # MSIX files unpacking, but that loads the whole content into
        # memory. We want to avoid that.

        # idempotence: patching a patched method would wrap endlessly
        if getattr(SFLockZipFile.handles, "__wrapped__", None) is not None:
            return

        @functools.wraps(SFLockZipFile.handles)
        def zip_handles(self: "SFLockZipFile") -> bool:
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

    @staticmethod
    def _convert(sflock_file: Any) -> ExtractedArchive:
        """Adapt sflock's File tree into the backend data model.

        sflock's File objects are attribute-compatible with ChildFile
        (relapath, filename, filesize, stream, sha256, close), so children
        are passed through as-is — no copying, streams stay on their
        original descriptors.
        """
        return ExtractedArchive(
            filename=sflock_file.filename or b"",
            children=cast(list[ChildFile], sflock_file.children),
            error=(
                sflock_file.error
                if isinstance(sflock_file.error, str)
                else str(sflock_file.error) if sflock_file.error else None
            ),
        )


class SevenzipBackend:
    """Backend driving the official 7-Zip binary (7zz)."""

    name = "7zip"

    def unpack(
        self,
        filepath: bytes,
        filename: bytes,
        password: str | None,
    ) -> ExtractedArchive:
        from .sevenzip import unpack_7z

        return unpack_7z(filepath, filename, password)


#: Available backends, in the order they should be documented
BACKENDS: dict[str, type[SflockBackend] | type[SevenzipBackend]] = {
    SflockBackend.name: SflockBackend,
    SevenzipBackend.name: SevenzipBackend,
}

#: Default backend used when the "backend" config option is not set
DEFAULT_BACKEND = SflockBackend.name


def resolve_backend(name: str | None) -> UnpackBackend:
    """Instantiate the backend identified by ``name`` (case-insensitive).

    Falls back to the default backend for unknown or missing names.
    """
    if name is None:
        name = DEFAULT_BACKEND
    backend_cls = BACKENDS.get(name.strip().lower())
    if backend_cls is None:
        logger.warning(
            "Unknown backend name %r, falling back to %r", name, DEFAULT_BACKEND
        )
        backend_cls = BACKENDS[DEFAULT_BACKEND]
    return backend_cls()
