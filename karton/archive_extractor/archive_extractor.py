import tempfile

from karton.core import Karton, Resource, Task
from sflock import unpack

from .__version__ import __version__


class ArchiveExtractor(Karton):
    """
    Extracts files from known archives and e-mail attachments.
    Produces "raw" artifacts for further classification.
    """

    # Maximum levels of nested extraction
    max_depth = 5
    # Maximum unpacked child filesize, larger files are not reported
    max_size = 25 * 1024 * 1024
    # Maximum number of childs for further analysis
    max_children = 1000

    identity = "karton.archive-extractor"
    version = __version__
    persistent = True
    filters = [
        {"type": "sample", "stage": "recognized", "kind": "archive"},
    ]

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        task_password = task.get_payload("password", default=None)

        attributes = task.get_payload("attributes", default={})
        if not task_password and attributes.get("password"):
            self.log.info("Accepting password from attributes")
            task_password = attributes.get("password")[0]

        try:
            if sample.name:
                fname = sample.name.encode("utf8")

                classifier_extension = "." + task.headers.get("extension")
                if classifier_extension and not fname.endswith(
                    classifier_extension.encode("utf-8")
                ):
                    fname += classifier_extension.encode("utf-8")

        except Exception as e:
            self.log.warning("Exception during extraction: %r", e)
            fname = None

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

            unpacked = unpack(
                filename=fname,
                filepath=filepath.encode("utf-8"),
                password=archive_password,
            )

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

            if len(child.contents) > self.max_size:
                self.log.warning("Child is too big for further processing")
                continue

            task = Task(
                headers={
                    "type": "sample",
                    "kind": "raw",
                    "quality": task.headers.get("quality", "high"),
                },
                payload={
                    "sample": Resource(fname, child.contents),
                    "parent": sample,
                    "extraction_level": extraction_level + 1,
                },
            )
            self.send_task(task)
