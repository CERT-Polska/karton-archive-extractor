import itertools
import pathlib

from karton.core import Task, Resource
from karton.core.test import KartonTestCase
from karton.archive_extractor import ArchiveExtractor

from .testcases import TEST_CASES, ArchiveFile

class ArchiveExtractorTestCase(KartonTestCase):
    karton_class = ArchiveExtractor

    def test_extract_archive(self) -> None:
        test_cases = TEST_CASES[:]
        while test_cases:
            archive = test_cases.pop()
            with self.subTest(archive.path.as_posix()):
                if archive.content is not None:
                    resource = Resource(name=archive.path.name, content=archive.content)
                else:
                    resource = Resource(
                        name=archive.path.name, path=archive.path.as_posix()
                    )

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
                if ... in archive.children:
                    children = list(itertools.takewhile(lambda c: c is not ..., archive.children))
                    self.assertGreaterEqual(
                        len(extracted),
                        len(archive.children),
                        msg="Incorrect number of extracted files",
                    )
                    extracted = extracted[:len(children)]
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
                        nested_archive_name = pathlib.PurePath(
                            "./" + expected_child.name
                        )
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
