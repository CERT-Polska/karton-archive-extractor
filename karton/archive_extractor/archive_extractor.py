import tempfile
from typing import Optional

from karton.core import Karton, Resource, Task
from karton.core.backend import KartonBackend
from karton.core.config import Config
from sflock import unpack  # type: ignore

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

    def debloat_pe(self, child_contents: bytes) -> Optional[bytes]:
        def log_message_wrapped(message: str, *args, **kwargs) -> None:
            self.log.info(message)

        if HAS_DEBLOAT is False:
            self.log.info(
                "Child looks like bloated PE file, but debloat is not installed."
            )
            return None

        try:
            pe = pefile.PE(data=child_contents)
        except Exception:
            self.log.warning("Failed to load as PE file.")
            return None

        with tempfile.NamedTemporaryFile() as f:
            process_pe(
                pe,
                out_path=f.name,
                unsafe_processing=False,
                log_message=log_message_wrapped,
            )
            processed = f.read()

        if processed:
            return processed
        else:
            self.log.warning("Output file is empty - failed to debloat file")
            return None

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        task_password = task.get_payload("password", default=None)

        attributes = task.get_payload("attributes", default={})
        if not task_password and attributes.get("password"):
            self.log.info("Accepting password from attributes")
            task_password = attributes.get("password")[0]

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

        with tempfile.TemporaryDirectory() as dir_name:
            filepath = f"{dir_name}/{fname}"
            with open(filepath, "wb") as f:
                f.write(sample.content)

            archive_password = None
            if task_password is not None:
                archive_password = task_password

            try:
                unpacked = unpack(
                    filename=fname.encode("utf-8"),
                    filepath=filepath.encode("utf-8"),
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

            if not child.contents:
                self.log.warning(
                    "Child has no contents or protected by unknown password"
                )
                continue

            contents = child.contents

            if len(contents) > self.max_size:
                if contents[:2] == b"MZ":
                    debloated = self.debloat_pe(contents)
                    if debloated is not None:
                        contents = debloated

            # Is it still too big?
            if len(contents) > self.max_size:
                self.log.warning(
                    "Child is too big for further processing (%d > %d)",
                    len(contents),
                    self.max_size,
                )
                continue

            task = Task(
                headers={
                    "type": "sample",
                    "kind": "raw",
                    "quality": task.headers.get("quality", "high"),
                },
                payload={
                    "sample": Resource(fname, contents),
                    "parent": sample,
                    "extraction_level": extraction_level + 1,
                },
            )
            self.send_task(task)
