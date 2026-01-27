from pathlib import Path
from typing import Optional, cast

from karton.core import Karton, RemoteResource, Resource, Task
from karton.core.backend import KartonBackend
from karton.core.config import Config

from .__version__ import __version__
from .unpacker import unpack, ArchiveInfo


class ArchiveExtractor(Karton):
    """
    Extracts files from known archives and e-mail attachments.
    Produces "raw" artifacts for further classification.
    """

    identity = "karton.archive-extractor"
    version = __version__
    persistent = True
    filters = [
        {"type": "sample", "stage": "recognized", "kind": "archive", "package": "!True"},
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

    def _get_password(self, task: Task) -> Optional[str]:
        password = task.get_payload("password", default=None)

        attributes = task.get_payload("attributes", default={})
        if not password and attributes.get("password"):
            self.log.info("Accepting password from attributes")
            password = attributes.get("password")[0]
        return password

    def _get_filepath_to_execute(self, task: Task) -> Optional[Path]:
        karton_internal = task.get_payload("karton_internal", default={})
        value = karton_internal.get("filepath_to_execute")
        if value:
            return Path(value)
        return None

    def process(self, task: Task) -> None:
        sample = cast(RemoteResource, task.get_resource("sample"))
        archive_password = self._get_password(task)

        if sample.name:
            fname = sample.name
        else:
            # Placeholder name if sample resource doesn't come
            # with any name. We append the proper extension in
            # further step and it could be unexpected to have
            # the name part empty.
            fname = "archive"

        try:
            classifier_extension = task.headers.get("extension")
            if classifier_extension:
                classifier_extension = "." + classifier_extension
                if not fname.endswith(classifier_extension):
                    fname += classifier_extension
        except Exception as e:
            self.log.warning("Exception during extraction: %r", e)

        self.log.info("Got archive %s", fname)

        extraction_level = task.get_payload("extraction_level", 0)

        if extraction_level > self.max_depth:
            self.log.warning(
                "Maximum extraction depth exceeded. Can't extract this archive."
            )
            return

        with sample.download_temporary_file() as archive_file:
            archive_info = ArchiveInfo(fname, None, self._get_filepath_to_execute(task))

            for child_name, child_stream in unpack(
                file=archive_file,
                filename=fname,
                password=archive_password,
                max_children=self.max_children,
                max_size=self.max_size,
                archive_info=archive_info
            ):
                # TODO: tmp
                if archive_info.is_package:
                    continue
                resource = Resource(name=child_name, fd=child_stream)
                child_task = Task(
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
                self.send_task(child_task)

            # If detected as package, also emit the archive with metadata for sandbox
            if archive_info.is_package and archive_info.matched_child_name:
                self.log.info(
                    f"Archive detected as package, re-emitting with executable hint: "
                    f"{archive_info.matched_child_name}"
                )

                # Re-open the archive file for re-emission
                archive_file.seek(0)
                archive_resource = Resource(name=fname, fd=archive_file)

                # Internal Karton attributes for inter-service communication.
                # Put in 'karton_internal' key to prevent mwdb-reporter from processing them.
                karton_internal = {
                    "filepath_to_execute": str(archive_info.matched_child_name),
                }

                if archive_info.password:
                    karton_internal["archive_password"] = archive_info.password

                package_task = Task(
                    headers={
                        "type": "sample",
                        "stage": "recognized",
                        "kind": "archive",
                        "package": "True",
                        "quality": task.headers.get("quality", "high"),
                    },
                    payload={
                        "sample": archive_resource,
                        "parent": sample,
                        "extraction_level": extraction_level,
                        "karton_internal": karton_internal,
                    },
                )
                self.send_task(package_task)
                

