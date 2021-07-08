#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from pathlib import Path

version_path = Path(__file__).parent / "karton/archive_extractor/__version__.py"
version_info = {}
exec(version_path.read_text(), version_info)

setup(
    name="karton-archive-extractor",
    version=version_info["__version__"],
    url="https://github.com/CERT-Polska/karton-archive-extractor/",
    description="Extractor of various archive formats for Karton framework",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    namespace_packages=["karton"],
    packages=[
        "karton.archive_extractor",
    ],
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        'console_scripts': [
            'karton-archive-extractor=karton.archive_extractor:ArchiveExtractor.main'
        ],
    },
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
