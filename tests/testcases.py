import dataclasses
from pathlib import Path, PurePath
from types import EllipsisType

@dataclasses.dataclass
class UnpackedFile:
    # If extracted name is random, ... can be specified
    name: str | EllipsisType
    sha256: str
    children: list["UnpackedFile"] = dataclasses.field(default_factory=list)
    real_extension: str | None = None


@dataclasses.dataclass
class ArchiveFile:
    path: PurePath
    content: bytes | None = None
    # You can use [...] for "any, non-zero children" semantics
    # You can also use [UnpackedFile, ...] if only first child is meaningful
    children: list[UnpackedFile | EllipsisType] = dataclasses.field(default_factory=list)


TESTFILES_DIR = Path(__file__).absolute().parent / "testfiles"
TEST_CASES = [
    ArchiveFile(
        path=TESTFILES_DIR / "archive.eml",
        children=[
            UnpackedFile(
                name="dodatkowe (03) docx.z",
                sha256="5426209597c75a96a6a77ad2fdc64f73793399e7a96d76187a91815b33f8c439",
                children=[
                    UnpackedFile(
                        name="dodatkowe (03).docx.exe",
                        sha256="6ee38c6a8235521896d04c269adc98f44795fb15fc301c2b97da15ff42f094ce",
                    )
                ],
                real_extension="rar",
            )
        ],
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.7z",
        children=[
            UnpackedFile(
                name="Final Payment Proof.exe",
                sha256="7ec49d8c7a7fb669fa66582245896e561ee56e8daf98f425bacd6d857c469c4f"
            )
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.ace",
        children=[
            UnpackedFile(
                name="BID PRICE (BPS).exe",
                sha256="2046be8050936440a6f2d2bdb9046b6fe91b64d3e255bdac0065b03476eb49b5"
            )
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.cab",
        children=[
            UnpackedFile(
                name="360se.ini",
                sha256="cf62c3a49baa328239b4eb93e1fb7806b524cf37a671739b381fa5be52e0958b"
            )
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.gz",
        children=[
            UnpackedFile(
                name="Order 002_PDF.exe",
                sha256="9bb6a76344a0906d9292209ede4ecb2b87bda68265397a1e854cf464e078ec5d"
            )
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.iso",
        children=[
            UnpackedFile(
                name="DHL Shipping Document (Please Sign)_Pdf.exe",
                sha256="65a2e108026ada4d16dc8f8f1bd77aa0f76496593eff4c2b5836082f6bcffe65"
            )
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.lz",
        children=[
            UnpackedFile(
                name=..., # output name is temporary file name
                sha256="36ef14835a9d2c8fe241286a7758b7f849bdabccc698e7e78318abfb195dc1db"
            )
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.lzh",
        children=[
            UnpackedFile(
                name="Quotation linked toContract No 2208747-NS202-007-.exe",
                sha256="04681751fc848d83f2c2609f43786d533e81e301ab5b02dbb1eca6c35f9f5dea"
            )
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.tar",
        children=[
            UnpackedFile(
                name="INV-234567SA33.vbs",
                sha256="e5a851011804b600eed79a0aaecbd6d48308321262336009ffa1ec821a1c8df2"
            )
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.udf",
        children=[
            UnpackedFile(
                name="345765r958.exe",
                sha256="6077a4c8886409d4677bcd79474063a7d01e120ba2d906d729f3950bdc58771a"
            )
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.vhd",
        children=[
            ...
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.xz",
        children=[
            UnpackedFile(
                name=..., # output name is temporary file name
                sha256="b27b22b5264ddeb59889e2df01d327ac26a290686d8dd9b9f1c010e1d2122fd5"
            )
        ]
    ),
    ArchiveFile(
        path=TESTFILES_DIR / "archive.zip",
        children=[
            UnpackedFile(
                name="scan.exe",
                sha256="3a11ba9d0fe917eca75c6038281c7bd55dea9ce1e0dc1b478d55e2592e6f846f"
            )
        ]
    ),
]
