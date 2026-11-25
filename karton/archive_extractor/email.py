"""
E-mail message unpacking for the ungoose backend.

Two message formats are handled natively in Python:

- EML (RFC 5322 / MIME): parsed with the standard library ``email``
  package. Every non-multipart part with a filename (or a non-body
  content type) is decoded into a child file.
- MSG (Outlook): parsed with ``olefile`` over the CDFv2 compound file,
  reading the MSG property stream layout (``__substg1.0_XXXXYYYY``
  streams below ``__attach_version1.0_#NNNNNNNN`` storages).
  Attached messages (attach method 5) are recursed into, and OLE
  package attachments (attach methods 6/7) are unwrapped with
  ``oletools.oleobj.OleNativeStream`` so the embedded payload file is
  emitted instead of the OLE1 wrapper.
"""

import codecs
import email.header
import email.parser
import hashlib
import itertools
import logging
import os
import tempfile
from typing import IO, Iterator, Optional

import olefile
from oletools.oleobj import OleNativeStream

from karton.archive_extractor.backends import SpecialFormat

from .backends import ChildFile, ExtractedArchive

logger = logging.getLogger("karton.archive-extractor.email")

# CDFv2 (OLE compound file) magic: MSG files start with it
CDFV2_MARKER = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# MSG stream property suffixes: 001F = UTF-16-LE string, 001E = ANSI string
_PSTG_STRING_SUFFIXES = (
    ("001F", "utf-16-le"),
    ("001E", "cp1252"),
)

# Codepage -> codec overrides for values codecs.lookup() cannot resolve,
# from refinery.lib.outlook
_CODEPAGE_OVERRIDES = {
    20127: "ascii",
    20932: "euc-jp",
    28591: "iso-8859-1",
    28592: "iso-8859-2",
    28593: "iso-8859-3",
    28594: "iso-8859-4",
    28595: "iso-8859-5",
    28596: "iso-8859-6",
    28597: "iso-8859-7",
    28598: "iso-8859-8",
    28599: "iso-8859-9",
    28603: "iso-8859-13",
    28605: "iso-8859-15",
    50220: "iso-2022-jp",
    50221: "iso-2022-jp",
    50225: "iso-2022-kr",
    51932: "euc-jp",
    51949: "euc-kr",
}

# PidTagAttachMethod values
_ATTACH_METHOD_DATA = 1
_ATTACH_METHOD_EMBEDDED_MSG = 5
_ATTACH_METHOD_OLE = 6
_ATTACH_METHOD_REFERENCE = 7

# Property IDs (PT_TSTRING/PT_BINARY suffixes appended at read time)
_PROP_ATTACH_DATA = "3701"  # PidTagAttachDataBinary
_PROP_ATTACH_FILENAME = "3707"  # PidTagAttachLongFilename
_PROP_ATTACH_SHORTNAME = "3704"  # PidTagAttachFilename
_PROP_ATTACH_METHOD = 0x3705  # PidTagAttachMethod (VT_I4)
_PROP_MESSAGE_CODEPAGE = 0x3FFD  # PidTagMessageCodepage (VT_I4)

# Storage holding an attached (embedded) message
_STORAGE_EMBEDDED_MSG = "__substg1.0_3701000D"

# EML body content types without a filename are not extracted,
# matching sflock's EmlFile whitelisted_content_type behavior
_EML_BODY_CONTENT_TYPES = ("text/plain", "text/html")


def _try_decode_mime_header(value: str) -> str:
    """Decode RFC 2047 encoded words in a header value."""
    try:
        return str(email.header.make_header(email.header.decode_header(value)))
    except Exception:
        logger.warning("Failed to decode mime header: %r", value, exc_info=True)
        return value


def _safe_relapath(filename: Optional[str], fallback: str) -> bytes:
    """Sanitize an attachment name into a flat, path-safe relapath."""
    if filename:
        filename = _try_decode_mime_header(filename)
        # relapath must be a single child name: strip NULs and separators
        filename = (
            filename.replace("\x00", "").replace("/", "_").replace("\\", "_").strip()
        )
        filename = filename.lstrip(".")[:255]  # limit filename to 255 chars
    if not filename:
        filename = fallback
    try:
        return filename.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return filename.encode("utf-8", "replace")


def _payload_bytes(payload: object) -> Optional[bytes]:
    """Normalize an email part payload into bytes, or None."""
    if isinstance(payload, str):
        return payload.encode("latin-1", "replace") or None
    if isinstance(payload, bytes):
        return payload or None
    return None


def _dedupe_children(children: list[ChildFile]) -> list[ChildFile]:
    """Resolve relapath collisions among children.

    Children extracted from nested messages can repeat a relapath. When
    the colliding contents are identical the later child is dropped (a
    duplicate); when they differ, the later child keeps its data under a
    suffixed relapath (``name(1).ext``) so distinct files never shadow
    each other. Colliding streams of dropped duplicates are closed.
    """
    by_path: dict[bytes, ChildFile] = {}
    result: list[ChildFile] = []
    for child in children:
        existing = by_path.get(child.relapath)
        if existing is not None:
            if _stream_sha256(existing) == _stream_sha256(child):
                child.close()
                continue
            relapath = child.relapath
            for counter in itertools.count(1):
                candidate = _suffixed_relapath(relapath, counter)
                if candidate not in by_path:
                    relapath = candidate
                    break
            child.relapath = relapath
            child.filename = relapath.rsplit(b"/", 1)[-1]
        by_path[child.relapath] = child
        result.append(child)
    return result


def _stream_sha256(child: ChildFile) -> str:
    """SHA256 of a child's stream contents, leaving the stream rewound."""
    hasher = hashlib.sha256()
    child.stream.seek(0)
    for chunk in iter(lambda: child.stream.read(0x10000), b""):
        hasher.update(chunk)
    child.stream.seek(0)
    return hasher.hexdigest()


def _suffixed_relapath(relapath: bytes, counter: int) -> bytes:
    """Insert ``(N)`` before the extension of a relapath."""
    stem, dot, ext = relapath.rpartition(b".")
    if not dot or not stem:
        return f"{relapath.decode('utf-8', 'surrogateescape')}({counter})".encode(
            "utf-8", "surrogateescape"
        )
    return stem + f"({counter})".encode() + dot + ext


def unpack_email(
    filepath: bytes,
    filename: bytes,
    fmt: SpecialFormat,
) -> ExtractedArchive:
    if fmt is SpecialFormat.msg:
        result = _unpack_msg(filepath, filename)
    elif fmt is SpecialFormat.eml:
        result = _unpack_eml(filepath, filename)
    else:
        raise ValueError("fmt argument must be an e-mail message format")
    if result.error is not None:
        logger.warning("E-mail unpacking error for %r: %s", filename, result.error)
    return result


# EML ----------------------------------------------------------------


def _unpack_eml(filepath: bytes, filename: bytes) -> ExtractedArchive:
    """Unpack an RFC 5322 / MIME message with the stdlib email package."""
    with open(filepath, "rb") as f:
        data = f.read()

    try:
        message = email.parser.BytesParser().parsebytes(data, headersonly=False)
    except Exception as e:
        return ExtractedArchive(filename=filename, error=f"Failed to parse EML: {e!r}")

    if message is None:
        return ExtractedArchive(
            filename=filename, error="Failed to parse EML: message is empty"
        )

    children: list[ChildFile] = []
    attachment_index = 0
    with tempfile.TemporaryDirectory(prefix="karton-ae-eml-") as outdir:
        for part in message.walk():
            if part.is_multipart():
                continue

            raw_filename = part.get_filename()
            if (
                raw_filename is None
                and part.get_content_type() in _EML_BODY_CONTENT_TYPES
            ):
                continue

            try:
                payload = _payload_bytes(part.get_payload(decode=True))
            except Exception as e:
                logger.warning("Failed to decode EML part: %r", e, exc_info=True)
                continue
            if payload is None:
                continue

            if raw_filename:
                relapath = _safe_relapath(raw_filename, "attachment")
            else:
                relapath = f"attachment_{attachment_index}".encode()
            attachment_index += 1

            child = _child_from_payload(outdir, len(children), relapath, payload)
            if child is not None:
                children.append(child)

    return ExtractedArchive(filename=filename, children=_dedupe_children(children))


# MSG ----------------------------------------------------------------


def _unpack_msg(filepath: bytes, filename: bytes) -> ExtractedArchive:
    """Unpack an Outlook MSG file with olefile."""
    try:
        ole = olefile.OleFileIO(filepath)
    except Exception as e:
        return ExtractedArchive(
            filename=filename, error=f"Failed to parse MSG as OLE file: {e!r}"
        )

    try:
        ansi_codec = _msg_ansi_codec(ole)
        with tempfile.TemporaryDirectory(prefix="karton-ae-msg-") as outdir:
            children = _msg_children(ole, (), outdir, ansi_codec, itertools.count())
    except Exception as e:
        logger.exception("MSG unpacking failed for %r", filename)
        return ExtractedArchive(filename=filename, error=f"MSG unpacking failed: {e!r}")
    finally:
        ole.close()

    return ExtractedArchive(filename=filename, children=_dedupe_children(children))


def _msg_children(
    ole: "olefile.OleFileIO",
    base: tuple[str, ...],
    outdir: str,
    ansi_codec: str,
    disk_index: Iterator[int],
) -> list[ChildFile]:
    """Collect children from the __attach storages below ``base``.

    ``base`` is empty for the top-level message and holds the storage
    path of an embedded message otherwise. ``disk_index`` is the
    unpack-wide counter backing on-disk child names; it is shared
    across nesting levels so a later sibling can never truncate a
    nested child's already-open file.
    """
    children: list[ChildFile] = []
    seen: set[str] = set()
    embedded_index = 0
    for parts in ole.listdir():
        if len(parts) <= len(base) or parts[: len(base)] != list(base):
            continue
        storage = parts[len(base)]
        if not storage.startswith("__attach") or storage in seen:
            continue
        seen.add(storage)
        attach_parts = base + (storage,)
        children.extend(
            _msg_attachment_children(
                ole, attach_parts, outdir, ansi_codec, embedded_index, disk_index
            )
        )
        embedded_index += 1
    return children


def _msg_attachment_children(
    ole: "olefile.OleFileIO",
    attach_parts: tuple[str, ...],
    outdir: str,
    ansi_codec: str,
    index: int,
    disk_index: Iterator[int],
) -> list[ChildFile]:
    filename = _msg_string(ole, attach_parts, _PROP_ATTACH_FILENAME, ansi_codec)
    if filename is None:
        filename = _msg_string(ole, attach_parts, _PROP_ATTACH_SHORTNAME, ansi_codec)
    method = _msg_attach_method(ole, attach_parts)

    if method == _ATTACH_METHOD_EMBEDDED_MSG:
        embedded_parts = attach_parts + (_STORAGE_EMBEDDED_MSG,)
        if ole.exists(embedded_parts):
            # Attached message: extract its own attachments, prefixed
            # with the attachment name
            nested = _msg_children(ole, embedded_parts, outdir, ansi_codec, disk_index)
            prefix = filename or f"msg{index}"
            for child in nested:
                child.relapath = _safe_relapath(
                    f"{prefix}/{child.relapath.decode('utf-8', 'surrogateescape')}",
                    f"msg{index}",
                )
                child.filename = child.relapath.rsplit(b"/", 1)[-1]
            return nested
        # No embedded message storage: fall through and emit the raw
        # PidTagAttachDataBinary payload, if any, instead of dropping
        # the attachment.
        logger.warning("Attached message without data storage: %r", filename)

    data = _msg_binary(ole, attach_parts, _PROP_ATTACH_DATA)
    if data is None:
        logger.warning("MSG attachment %r has no data stream", filename)
        return []

    relapath = _safe_relapath(filename, f"att{index}")

    if method in (_ATTACH_METHOD_OLE, _ATTACH_METHOD_REFERENCE):
        unwrapped = _unwrap_ole_package(data)
        if unwrapped is not None:
            payload, package_name = unwrapped
            if package_name:
                relapath = _safe_relapath(
                    os.path.basename(package_name),
                    relapath.decode("utf-8", "surrogateescape"),
                )
            data = payload

    extracted = _child_from_payload(outdir, next(disk_index), relapath, data)
    return [extracted] if extracted is not None else []


def _unwrap_ole_package(data: bytes) -> Optional[tuple[bytes, Optional[str]]]:
    """Unwrap an OLE1 native stream (OLE package attachment payload).

    Uses oletools.oleobj.OleNativeStream; returns (payload, filename)
    or None when the data does not parse as an OLE package.
    """
    try:
        native = OleNativeStream(bindata=data)
    except Exception as e:
        logger.debug("Not an OLE native stream: %r", e, exc_info=True)
        return None
    if native.is_link or not native.data:
        return None
    return native.data, native.filename


# Child construction ---------------------------------------------------


def _child_from_payload(
    outdir: str,
    index: int,
    relapath: bytes,
    payload: bytes,
) -> Optional[ChildFile]:
    """Materialize a payload as an fd-backed child file.

    Payloads live in memory while ChildFile streams must be fd-backed
    (mmap via fileno()), so each child is written into the unpack's
    temporary directory. ``index`` only shapes the on-disk name, which
    is independent from the reported relapath.
    """
    disk_path = os.path.join(outdir, f"{index:04d}")
    try:
        with open(disk_path, "wb") as f:
            f.write(payload)
        stream: IO[bytes] = open(disk_path, "rb")
    except OSError as e:
        logger.error("Failed to write extracted e-mail child: %r", e, exc_info=True)
        return None
    return ChildFile(
        relapath=relapath,
        filename=relapath.rsplit(b"/", 1)[-1],
        filesize=os.fstat(stream.fileno()).st_size,
        stream=stream,
    )


# MSG stream helpers ---------------------------------------------------


def _msg_stream(
    ole: "olefile.OleFileIO", prefix: tuple[str, ...], name: str
) -> Optional[bytes]:
    parts = list(prefix) + [name]
    try:
        if not ole.exists(parts):
            return None
        return ole.openstream(parts).read()
    except OSError:
        return None


def _msg_string(
    ole: "olefile.OleFileIO",
    prefix: tuple[str, ...],
    prop_id: str,
    ansi_codec: str,
) -> Optional[str]:
    for suffix, codec in _PSTG_STRING_SUFFIXES:
        if suffix == "001E":
            codec = ansi_codec
        data = _msg_stream(ole, prefix, f"__substg1.0_{prop_id}{suffix}")
        if data is None:
            continue
        try:
            return data.decode(codec).rstrip("\x00")
        except (UnicodeDecodeError, LookupError):
            continue
    return None


def _msg_binary(
    ole: "olefile.OleFileIO", prefix: tuple[str, ...], prop_id: str
) -> Optional[bytes]:
    return _msg_stream(ole, prefix, f"__substg1.0_{prop_id}0102")


def _msg_attach_method(ole: "olefile.OleFileIO", attach_parts: tuple[str, ...]) -> int:
    """Read PidTagAttachMethod from the attachment property stream.

    Attachment property streams have an 8-byte header followed by
    16-byte records: [2B type][2B id][4B reserved][8B value].
    """
    data = _msg_stream(ole, attach_parts, "__properties_version1.0")
    if not data or len(data) < 24:
        return _ATTACH_METHOD_DATA
    for offset in range(8, len(data) - 15, 16):
        prop_type = int.from_bytes(data[offset : offset + 2], "little")
        prop_id = int.from_bytes(data[offset + 2 : offset + 4], "little")
        if prop_id == _PROP_ATTACH_METHOD and prop_type == 0x0003:
            return int.from_bytes(data[offset + 8 : offset + 12], "little")
    return _ATTACH_METHOD_DATA


def _msg_ansi_codec(ole: "olefile.OleFileIO") -> str:
    """Codec for 8-bit string properties, from PidTagMessageCodepage."""
    data = _msg_stream(ole, (), "__properties_version1.0")
    if data and len(data) >= 48:
        # Root message property streams have a 32-byte header
        for offset in range(32, len(data) - 15, 16):
            prop_type = int.from_bytes(data[offset : offset + 2], "little")
            prop_id = int.from_bytes(data[offset + 2 : offset + 4], "little")
            if prop_id == _PROP_MESSAGE_CODEPAGE and prop_type == 0x0003:
                codepage = int.from_bytes(data[offset + 8 : offset + 12], "little")
                if codepage in _CODEPAGE_OVERRIDES:
                    return _CODEPAGE_OVERRIDES[codepage]
                try:
                    return codecs.lookup(f"cp{codepage}").name
                except LookupError:
                    break
    return "cp1252"
