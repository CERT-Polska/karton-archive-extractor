import itertools
import pathlib

import pytest
from karton.core import Resource, Task
from karton.core.test import ConfigMock, KartonTestCase

from karton.archive_extractor import ArchiveExtractor

from .testcases import TEST_CASES, ArchiveFile


class ArchiveExtractorTestCase(KartonTestCase):
    karton_class = ArchiveExtractor
    # Unpacking backend exercised by this test case ("sflock" or "7zip")
    backend_name = "sflock"
    # Fixtures (by name) that the backend is known not to cover, with the
    # reason as the value. They are skipped in test_extract_archive and
    # exercised by dedicated xfail-marked tests in the subclass instead,
    # because pytest cannot xfail individual subtests.
    known_unsupported: dict[str, str] = {}

    def setUp(self):
        self.config = ConfigMock()
        self.config._config["archive-extractor"] = {
            "emit_listing": True,
            "backend": self.backend_name,
        }
        super().setUp()

    def _run_archive_case(self, archive: ArchiveFile, test_cases: list) -> None:
        """Run a single archive fixture through the service.

        ``test_cases`` is the work queue of the calling test method:
        nested archives discovered here are inserted back into it.
        """
        if archive.content is not None:
            resource = Resource(name=archive.path.name, content=archive.content)
        else:
            resource = Resource(name=archive.path.name, path=archive.path.as_posix())

        archive_task = Task(
            headers={
                "type": "sample",
                "stage": "recognized",
                "kind": "archive",
                "extension": archive.path.suffix[1:],
            },
            payload={"sample": resource},
        )
        extracted = self.run_task(archive_task)

        listing_tasks = [t for t in extracted if t.has_payload("attributes")]
        extracted = [t for t in extracted if not t.has_payload("attributes")]

        # Filter out package re-emission task (executable_package: True)
        # which is emitted when archive contains executables
        extracted = [
            t for t in extracted if t.headers.get("executable_package") != "True"
        ]

        # The archive contents are reported as a single attribute task
        self.assertEqual(
            len(listing_tasks),
            1,
            msg="Expected a single archive file listing task",
        )
        listing = listing_tasks[0]
        self.assertEqual(listing.headers["stage"], "analyzed")
        archive_files = listing.get_payload("attributes")["archive_files"]
        self.assertIsInstance(archive_files, list)
        self.assertEqual(
            len(archive_files),
            1,
            msg="archive_files attribute should hold a single value",
        )
        files = archive_files[0]
        self.assertIsInstance(files, list)
        self.assertTrue(files, msg="Archive file listing should not be empty")
        for entry in files:
            self.assertIsInstance(entry["path"], str)
            self.assertIsInstance(entry["size"], int)

        if ... in archive.children:
            children = list(
                itertools.takewhile(lambda c: c is not ..., archive.children)
            )
            self.assertGreaterEqual(
                len(extracted),
                len(archive.children),
                msg="Incorrect number of extracted files",
            )
            extracted = extracted[: len(children)]
        else:
            children = archive.children
            self.assertEqual(
                len(extracted),
                len(archive.children),
                msg="Incorrect number of extracted files",
            )
        extracted = sorted(extracted, key=lambda c: c.get_resource("sample").name)
        children = sorted(children, key=lambda c: c.name)
        for task, expected_child in zip(extracted, children):
            child = task.get_resource("sample")
            if expected_child.name is not ...:
                self.assertEqual(
                    child.name,
                    expected_child.name,
                    msg="Incorrect extracted file name",
                )
            self.assertEqual(
                child.sha256,
                expected_child.sha256,
                msg="Incorrect extracted file sha256",
            )
            if expected_child.children:
                # Test nested archive
                content = self.backend.download_object(
                    self.backend.default_bucket_name, child.uid
                )
                nested_archive_name = pathlib.PurePath("./" + expected_child.name)
                if expected_child.real_extension:
                    nested_archive_name = nested_archive_name.with_suffix(
                        "." + expected_child.real_extension
                    )
                nested_archive = ArchiveFile(
                    path=nested_archive_name,
                    content=content,
                    children=expected_child.children,
                )
                test_cases.insert(0, nested_archive)

    def _run_single_case(self, name: str) -> None:
        """Run exactly one fixture from TEST_CASES (incl. nested cases)."""
        archive = next(c for c in TEST_CASES if c.path.name == name)
        test_cases = [archive]
        while test_cases:
            self._run_archive_case(test_cases.pop(), test_cases)

    def test_extract_archive(self) -> None:
        test_cases = [
            c for c in TEST_CASES if c.path.name not in self.known_unsupported
        ]
        while test_cases:
            archive = test_cases.pop()
            with self.subTest(archive.path.as_posix()):
                self._run_archive_case(archive, test_cases)


class SevenzipArchiveExtractorTestCase(ArchiveExtractorTestCase):
    """Same fixture matrix, driven through the 7-Zip backend.

    Fixtures covering capabilities the 7-Zip backend is known to lack are
    excluded from the main matrix and get dedicated xfail-marked tests
    below, so the gaps stay visible until they are properly decided on
    (native shims, dropping fixtures, or documented non-support).
    """

    backend_name = "7zip"

    KNOWN_UNSUPPORTED = {
        "archive.eml": (
            "7-Zip backend has no EML parser"
        ),
        "archive.msg": (
            "7-Zip backend has no MSG parser: the OLE compound file is unpacked "
            "as a plain directory tree, emitting internal property streams "
            "(e.g. __substg1.0_*) instead of the attachments, e.g. "
            "'invoice_5839.exe' is reported as '__attach_version1.0_#00000000/"
            "__substg1.0_37010102'."
        ),
        "archive.ace": ("ACE archive format is not supported by any 7-Zip version."),
        "archive.lz": (
            "lzip (.lz) archives are not extractable by the 7-Zip binary",
        ),
        "bloated.tgz": (
            "sflock unpacks nested archives internally (tgz -> tar -> exe), while the 7-Zip "
            "backend yields the intermediate .tar which is unpacked on the next "
            "service hop. This will be covered in future versions."
        ),
    }
    known_unsupported = KNOWN_UNSUPPORTED

    @pytest.mark.xfail(reason=KNOWN_UNSUPPORTED["archive.eml"], strict=False)
    def test_xfail_eml(self) -> None:
        self._run_single_case("archive.eml")

    @pytest.mark.xfail(reason=KNOWN_UNSUPPORTED["archive.msg"], strict=False)
    def test_xfail_msg(self) -> None:
        self._run_single_case("archive.msg")

    @pytest.mark.xfail(reason=KNOWN_UNSUPPORTED["archive.ace"], strict=False)
    def test_xfail_ace(self) -> None:
        self._run_single_case("archive.ace")

    @pytest.mark.xfail(reason=KNOWN_UNSUPPORTED["archive.lz"], strict=False)
    def test_xfail_lz(self) -> None:
        self._run_single_case("archive.lz")

    @pytest.mark.xfail(reason=KNOWN_UNSUPPORTED["bloated.tgz"], strict=False)
    def test_xfail_bloated_tgz(self) -> None:
        self._run_single_case("bloated.tgz")
