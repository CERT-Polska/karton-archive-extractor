import mmap
import os
import tempfile
from pathlib import Path
from typing import IO, Optional, Tuple, cast

from karton.core import Karton, RemoteResource, Resource, Task
from karton.core.backend import KartonBackend
from karton.core.config import Config
from sflock import unpack  # type: ignore
from sflock.abstracts import File as SFLockFile  # type: ignore

from .__version__ import __version__

try:
    import pefile  # type: ignore
    from debloat.processor import process_pe  # type: ignore

    HAS_DEBLOAT = True
except ImportError:
    HAS_DEBLOAT = False


class ArchiveExtractor(Karton):
    """
    Extracts files from known archives and e-mail attachments.
    Produces "raw" artifacts for further classification.
    """

    identity = "karton.archive-extractor"
    version = __version__
    persistent = True
    filters = [
        {"type": "sample", "stage": "recognized", "kind": "archive"},
    ]

    def __init__(
        self,
        config: Optional[Config] = None,
        identity: Optional[str] = None,
        backend: Optional[KartonBackend] = None,
    ) -> None:
        super().__init__(config=config, identity=identity, backend=backend)

        # Maximum levels of nested extraction
        self.max_depth = self.config.getint(
            "archive-extractor", "max_depth", fallback=5
        )
        # Maximum unpacked child filesize, larger files are not reported
        self.max_size = self.config.getint(
            "archive-extractor", "max_size", fallback=25 * 1024 * 1024
        )
        # Maximum number of children files for further analysis
        self.max_children = self.config.getint(
            "archive-extractor", "max_children", fallback=1000
        )

    def debloat_pe(
        self, filename: str, child: SFLockFile
    ) -> Optional[Tuple[str, IO[bytes]]]:
        def log_message_wrapped(message: str, *args, **kwargs) -> None:
            self.log.info(message)

        if HAS_DEBLOAT is False:
            self.log.info(
                "Child looks like bloated PE file, but debloat is not installed."
            )
            return None

        with mmap.mmap(
            child.stream.fileno(), 0, access=mmap.ACCESS_READ
        ) as mapped_child:
            try:
                pe = pefile.PE(data=mapped_child)
            except Exception:
                self.log.warning("Failed to load as PE file.")
                return None

            # we need to use a temporary directory because debloat can implicitly unpack
            # NSIS archives to parent directory of the passed file
            with tempfile.TemporaryDirectory() as tmp_dir:
                temp_file = Path(tmp_dir) / filename

                process_pe(
                    pe,
                    cert_preservation=False,
                    out_path=temp_file.as_posix(),
                    last_ditch_processing=False,
                    log_message=log_message_wrapped,
                )

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

        self.log.warning("Output file is empty - failed to debloat file")
        return None

    def _get_password(self, task: Task) -> Optional[str]:
        task_password = task.get_payload("password", default=None)

        attributes = task.get_payload("attributes", default={})
        if not task_password and attributes.get("password"):
            self.log.info("Accepting password from attributes")
            task_password = attributes.get("password")[0]
        return task_password

    def process(self, task: Task) -> None:
        sample = cast(RemoteResource, task.get_resource("sample"))
        task_password = self._get_password(task)

        fname = "archive"
        try:
            if sample.name:
                fname = sample.name

            classifier_extension = task.headers.get("extension")
            if classifier_extension:
                classifier_extension = "." + classifier_extension
                if not fname.endswith(classifier_extension):
                    fname += classifier_extension
        except Exception as e:
            self.log.warning("Exception during extraction: %r", e)

        extraction_level = task.get_payload("extraction_level", 0)

        if extraction_level > self.max_depth:
            self.log.warning(
                "Maximum extraction depth exceeded. Can't extract this archive."
            )
            return

        with sample.download_temporary_file() as archive_file:
            archive_password = None
            if task_password is not None:
                archive_password = task_password

            try:
                unpacked = unpack(
                    filename=fname.encode("utf-8"),
                    filepath=archive_file.name.encode("utf-8"),
                    password=archive_password,
                )
            except Exception as e:
                # we can't really do anything about corrupted archives :(
                self.log.warning("Error while unpacking archive: %s", e)
                return

        try:
            fname = (
                unpacked.filename and unpacked.filename.decode("utf8")
            ) or unpacked.sha256
        except Exception as e:
            self.log.warning("Exception during extraction: %r", e)
            fname = "(unknown)"

        self.log.info("Got archive {}".format(fname))

        if not unpacked.children:
            self.log.warning("Don't know how to unpack this archive")
            return

        if len(unpacked.children) > self.max_children:
            self.log.warning("Too many children for further processing")
            return

        for child in unpacked.children:
            fname = (child.filename and child.filename.decode("utf8")) or child.sha256

            self.log.info("Unpacked child {}".format(fname))

            header = child.header

            if not header:
                self.log.warning(
                    "Child has no contents or protected by unknown password"
                )
                continue

            stream = child.stream

            if child.filesize > self.max_size:
                if header[:2] == b"MZ":
                    debloated = self.debloat_pe(fname, child)
                    if debloated is not None:
                        fname, stream = debloated

            # Is it still too big?
            stream.seek(0, os.SEEK_END)
            stream_size = stream.tell()
            stream.seek(0, os.SEEK_SET)

            if stream.size > self.max_size:
                self.log.warning(
                    "Child is too big for further processing (%d > %d)",
                    stream_size,
                    self.max_size,
                )
                continue

            resource = Resource(name=fname, fd=stream, _close_fd=True)
            task = Task(
                headers={
                    "type": "sample",
                    "kind": "raw",
                    "quality": task.headers.get("quality", "high"),
                },
                payload={
                    "sample": resource,
                    "parent": sample,
                    "extraction_level": extraction_level + 1,
                },
            )
            self.send_task(task)
