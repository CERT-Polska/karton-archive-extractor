import os.path
from typing import Optional, cast

from karton.core import Karton, RemoteResource, Resource, Task
from karton.core.backend import KartonBackend
from karton.core.config import Config

from .__version__ import __version__
from .unpacker import ArchiveInfo, unpack


class ArchiveExtractor(Karton):
    """
    Extracts files from known archives and e-mail attachments.
    Produces "raw" artifacts for further classification.
    """

    identity = "karton.archive-extractor"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "sample",
            "stage": "recognized",
            "kind": "archive",
            "executable_package": "!True",
        },
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

    def _get_archive_entry_path(self, task: Task) -> Optional[str]:
        archive_entry_path = task.get_payload("archive_entry_path", default=None)

        attributes = task.get_payload("attributes", default={})
        if not archive_entry_path and attributes.get("archive_entry_path"):
            self.log.info("Accepting archive_entry_path from attributes")
            archive_entry_path = attributes.get("archive_entry_path")[0]

        return archive_entry_path

    def process(self, task: Task) -> None:
        sample = cast(RemoteResource, task.get_resource("sample"))
        archive_password = self._get_password(task)
        archive_entry_path = self._get_archive_entry_path(task)
        extraction_level = task.get_payload("extraction_level", 0)
        quality = task.headers.get("quality", "high")

        # Use sample name or placeholder if not provided
        # Extension will be appended in the next step if needed
        # (it could be unexpected to have the name part empty)
        archive_filename = sample.name or "archive"

        try:
            classifier_extension = task.headers.get("extension")
            if classifier_extension:
                classifier_extension = "." + classifier_extension
                if not archive_filename.endswith(classifier_extension):
                    archive_filename += classifier_extension
        except Exception as e:
            self.log.warning("Exception during extraction: %r", e)

        self.log.info("Got archive %s", archive_filename)

        if extraction_level > self.max_depth:
            self.log.warning(
                "Maximum extraction depth exceeded. Can't extract this archive."
            )
            return

        with sample.download_temporary_file() as tmp_archive_file:
            archive_info = ArchiveInfo(
                archive_filename,
                archive_password,
                archive_entry_path,
            )

            for child_name, child_stream in unpack(
                file=tmp_archive_file,
                filename=archive_filename,
                password=archive_password,
                max_children=self.max_children,
                max_size=self.max_size,
                archive_info=archive_info,
            ):
                # Extract basename for child resource name
                # (paths in archives may include dirs)
                child_basename = os.path.basename(child_name)
                child_resource = Resource(name=child_basename, fd=child_stream)
                child_task = Task(
                    headers={
                        "type": "sample",
                        "kind": "raw",
                        "quality": quality,
                    },
                    payload={
                        "sample": child_resource,
                        "parent": sample,
                        "extraction_level": extraction_level + 1,
                    },
                )
                self.send_task(child_task)

            # If detected as package, also emit the archive with metadata for sandbox
            if archive_info.is_package and archive_info.entry_path:
                self.log.info(
                    f"Archive detected as package, re-emitting with executable hint: "
                    f"{archive_info.entry_path}"
                )

                # Reset file pointer for re-emission
                tmp_archive_file.seek(0)
                archive_resource = Resource(name=archive_filename, fd=tmp_archive_file)

                # Internal Karton metadata for inter-service communication.
                # Separate from 'attributes' to avoid MWDB attribute validation errors.
                package_payload = {
                    "sample": archive_resource,
                    "parent": sample,
                    "extraction_level": extraction_level,
                    "archive_entry_path": archive_info.entry_path,
                }

                if archive_info.password:
                    package_payload["archive_password"] = archive_info.password

                package_task = Task(
                    headers={
                        **task.headers,
                        "executable_package": "True",
                    },
                    payload=package_payload,
                )
                self.send_task(package_task)
