"""Known-answer regression tests for PDF 2.0 (R5/R6) password handling.

The expected U/UE/O/OE values in ``VECTORS`` were produced by an independent
implementation of ISO 32000-2 algorithms 3.8/3.9 and 2.B, using fixed salts and
a fixed file key.  They are committed as literals: nothing here calls
``_normalize_password``, ``_password_hash``, ``_r5_password`` or
``_r6_password`` to decide what a vector should be.

A minimal PDF is assembled in memory for each vector and opened through
``PDFDocument``, so the tests exercise the real entry point (including SASLprep
import, UTF-8 truncation and the owner path binding to U) without needing an
external PDF tool.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from io import BytesIO

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pdfminer.pdfdocument import (
    PDFDocument,
    PDFEncryptionUnsupported,
    PDFPasswordIncorrect,
)
from pdfminer.pdfparser import PDFParser

# Fixed salts and file key shared by every vector.  Their bytes are also
# embedded in the U and O entries below, so the vectors are self-checking.
USER_VALIDATION_SALT = bytes.fromhex("0011223344556677")
USER_KEY_SALT = bytes.fromhex("8899aabbccddeeff")
OWNER_VALIDATION_SALT = bytes.fromhex("1021324354657687")
OWNER_KEY_SALT = bytes.fromhex("98a9babbdcddedef")
FILE_KEY = bytes(range(32))
DOC_ID = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
TITLE = b"r5r6-password-evidence"


@dataclass(frozen=True)
class Vector:
    revision: int
    user_password: str
    owner_password: str
    u: str
    ue: str
    o: str
    oe: str

    @property
    def u_bytes(self) -> bytes:
        return bytes.fromhex(self.u)

    @property
    def ue_bytes(self) -> bytes:
        return bytes.fromhex(self.ue)

    @property
    def o_bytes(self) -> bytes:
        return bytes.fromhex(self.o)

    @property
    def oe_bytes(self) -> bytes:
        return bytes.fromhex(self.oe)


VECTORS: dict[str, Vector] = {
    # r5-empty: user bytes=0 owner bytes=8
    "r5-empty": Vector(
        revision=5,
        user_password="",
        owner_password="owner-r5",
        u=(
            "d1a5f998fa6ed82da6943127533b412f2286b30c8473a819f70a8fec5913fea700112233"
            "445566778899aabbccddeeff"
        ),
        ue=("cdfdbe7d34d93d9d6cefaea34433f695cc0b7f1bdabd8aba094ad1b15c8f6e0e"),
        o=(
            "14a99ab94cdd55a8390a3810435acad7b342d4b20c5abe767de1d4bf7e06f1a910213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("1d6a0d7d4c629582a830a525ba985926df6f15bf774b1f51f81e2f58ef838fd8"),
    ),
    # r5-nfd: user bytes=13 owner bytes=10
    "r5-nfd": Vector(
        revision=5,
        user_password="évidence-r5",
        owner_password="ownér-r5",
        u=(
            "69488807e26d9a35237a5b52fd9018f2b373ebeef438803fa4e66adb3375c29100112233"
            "445566778899aabbccddeeff"
        ),
        ue=("27e9d20d45239256b246ada2a20ad30b4e4af1ced2c14c07108c8dbdaa804999"),
        o=(
            "11dd8e013338144033b4a5abab937871c1deee4e2a14ed5115ef3068f2d26fb810213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("0e709111be963bfb615ae945dd0d76f382fb207114286af0a26ed4b6e0df25a4"),
    ),
    # r5-expand: user bytes=33 owner bytes=15
    "r5-expand": Vector(
        revision=5,
        user_password="㍿㍿㍿㍿㍿㍿㍿㍿㍿㍿㍿",
        owner_password="owner-r5-expand",
        u=(
            "112570c4db2b76ee6b1fedceb6a8a68c4825f648364cce59f9286f37a21b282b00112233"
            "445566778899aabbccddeeff"
        ),
        ue=("2b52fc55f437ec5168350a9d4efff550192b28936155051f45b1e72116e99fd1"),
        o=(
            "94be636527e1c4a372a496f98df14251cd16d0f18de17062f9411c90fd3a565110213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("37835f7b0d32cc93031cd923313e421829ad7882df34a0c85770269e8567194b"),
    ),
    # r5-split: user bytes=127 owner bytes=127
    "r5-split": Vector(
        revision=5,
        user_password="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA€",
        owner_password="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB€",
        u=(
            "f751ffbedc96e44c5074b666a2ae32bfca6c068e17858c5a0a26c77b5710385700112233"
            "445566778899aabbccddeeff"
        ),
        ue=("41273846431c42c6d5a491209ab32d935c451ec50317d0b1f455482c700f7b4b"),
        o=(
            "0b48d31580f9a1bc8860b25026ad6444dfea6e899531424f042951534930557110213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("f94962c5244b617a41f07b6b9cb2416c96a30a743ab6ea42a7e40b4501db2795"),
    ),
    # r5-control: user bytes=8 owner bytes=9
    "r5-control": Vector(
        revision=5,
        user_password="pa\x07ss-r5",
        owner_password="own\x00er-r5",
        u=(
            "00f9ea9169dcdffac14064215ed2f7bc5ab1879b2a567e57935c6942bb5c6aaa00112233"
            "445566778899aabbccddeeff"
        ),
        ue=("7a7e0be0258f59b27af2f741e5914b7d3141c7d34dbf868684c1d3da18c59b8f"),
        o=(
            "f9507bb48e06408695dc45c61021db2a6ac9a2370d9e5649f644631502ffd08510213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("0b17e1a1697320445989fbfc5b2f7f914786d04615475ea47ce16f9c605739b0"),
    ),
    # r5-mapped: user bytes=2 owner bytes=3
    "r5-mapped": Vector(
        revision=5,
        user_password="\xad",
        owner_password="\u200b",
        u=(
            "4094cd713dd7ad22b0f6f51f70cbca2ba7fa7b86ca5687e0a82c4e378bcf2a5300112233"
            "445566778899aabbccddeeff"
        ),
        ue=("af8bbb22b8fc5ccedcb33aff09763fffbe9a485bf5d28776f6b1c8af7ca37d7f"),
        o=(
            "8e886038a93d2bbec06e4bcb527a63284d3d0764759bbf6bc43743d6a0f2431910213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("bb6b6fe17534dd73295342c1a9f8b979107755795ef3b49e48d94e263600000c"),
    ),
    # r5-limit: user bytes=127 owner bytes=127
    "r5-limit": Vector(
        revision=5,
        user_password="CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        owner_password="DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
        u=(
            "7ad73efa7e7ad5ea9bbb38d68749bbd14a81ada957bc08e9a2e84966df9c317100112233"
            "445566778899aabbccddeeff"
        ),
        ue=("3a97ee7cb6cce763337fde797cc2ca3395ea2db658a844c5291a9bfbb7cb46ba"),
        o=(
            "ac28b857287df0547ccafd7efc2674813c1b70be7b396b95868af6b7b777adba10213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("b23a459fc82ad3138678f8454a3190b52143c7cf71df06a3522969af876581d2"),
    ),
    # r6-empty: user bytes=0 owner bytes=8
    "r6-empty": Vector(
        revision=6,
        user_password="",
        owner_password="owner-r6",
        u=(
            "c2e2dc9383748384b0ef05fdbc769d3879a739cffd5a05a7d6bb2958d0f9ccf000112233"
            "445566778899aabbccddeeff"
        ),
        ue=("eb73d4ee7386f657108c68a024caac405d2c55f23532cc4f3d19c7eb184e5aca"),
        o=(
            "a62eb340384c3fe456b17745f2e11400ac759ac97524ec1310973866ea52b73c10213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("f7fead20e5650e95ef89d2afe35db944aa1d3183e26a65624d214e1296dc29d7"),
    ),
    # r6-nfd: user bytes=12 owner bytes=9
    "r6-nfd": Vector(
        revision=6,
        user_password="évidence-r6",
        owner_password="ownér-r6",
        u=(
            "5c4a9daba8784e28e5270a7bf076891f639ee7a7d28b04042ad1931986daf67800112233"
            "445566778899aabbccddeeff"
        ),
        ue=("ff85c181ff18e9b473202df7e4f39b17ee73d680cd6d5ecaa4d355a01081a8f3"),
        o=(
            "109320f97a34248738511b65a0fd8f61410cc12311c4b66007e066833baacbc510213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("8ac881756395304341170643b77c7f7891b7ec7e2494e67d3476db561046e474"),
    ),
    # r6-expand: user bytes=127 owner bytes=15
    "r6-expand": Vector(
        revision=6,
        user_password="㍿㍿㍿㍿㍿㍿㍿㍿㍿㍿㍿",
        owner_password="owner-r6-expand",
        u=(
            "d95a08832563dbb98512c0745c988c7e3d4bef79bf63b3b8234e79628567f5da00112233"
            "445566778899aabbccddeeff"
        ),
        ue=("6518c0978f1d03045c1bf411e4eb0a0d5969518dc57cd9c8ed56ef04a534782e"),
        o=(
            "757a8e6019dc754f27f2f939e2d84cddadf7aba2ce389ed215e3260a8dce99b110213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("9c6e928af1bc9ae6b28feac0d82441f85ee3f3f77d156556ba215d285b4c3da0"),
    ),
    # r6-split: user bytes=127 owner bytes=127
    "r6-split": Vector(
        revision=6,
        user_password="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA€",
        owner_password="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB€",
        u=(
            "c43c32064881a88a9450bc9eccfaf8d089c829d949cd403c08b2abc7f14544f800112233"
            "445566778899aabbccddeeff"
        ),
        ue=("0a27c62b4058dfcdf3e53a7df688fd72ffb38e773d71d49d320484b5567cafb6"),
        o=(
            "f6837b0dfa16c321bd62f2c526af9869f9cd5df838404d4424eced18e58b1d1810213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("5ddb6a2dcf527f9ff5e19e6d8d568898275cc7d435acaa8862ed40e0debfee1b"),
    ),
    # r6-mapped: user bytes=0 owner bytes=0
    "r6-mapped": Vector(
        revision=6,
        user_password="\xad",
        owner_password="\u200b",
        u=(
            "c2e2dc9383748384b0ef05fdbc769d3879a739cffd5a05a7d6bb2958d0f9ccf000112233"
            "445566778899aabbccddeeff"
        ),
        ue=("eb73d4ee7386f657108c68a024caac405d2c55f23532cc4f3d19c7eb184e5aca"),
        o=(
            "5046f1c357e8a2eaa3f18895b77a3fba219fc185e9df67e9a1446b058b75cebc10213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("cb1fbb53e1c2efd59c844520d0e31f08fcfc25dad84750d621cee4d87d591bcd"),
    ),
    # r6-limit: user bytes=127 owner bytes=127
    "r6-limit": Vector(
        revision=6,
        user_password="CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        owner_password="DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
        u=(
            "4946118028a0579282169bf7ac5f1ac7c7a3f881b511122e82e42d4c91fa4bdd00112233"
            "445566778899aabbccddeeff"
        ),
        ue=("5ab1dbaaad48d0d41fbc1dded2a67dbebeb4c6a5944e52c27cc3f914d48b27d4"),
        o=(
            "8475af076392a6cf62bc0bd7585c7affa2e4e10c3bbbab7656a02b2e9d75558e10213243"
            "5465768798a9babbdcddedef"
        ),
        oe=("bdd74d3d8c2848b2070527774acc354eaa53ffa583f5a2f21b42e535b81a4915"),
    ),
}

R5_VECTORS = {k: v for k, v in VECTORS.items() if v.revision == 5}
R6_VECTORS = {k: v for k, v in VECTORS.items() if v.revision == 6}


def _pdf_escape_hex(data: bytes) -> bytes:
    return b"<" + data.hex().encode("ascii") + b">"


class _PdfBuilder:
    """Build a tiny single-object PDF with an AES-256 encryption dictionary."""

    def __init__(self, revision: int, u: bytes, ue: bytes, o: bytes, oe: bytes):
        self.revision = revision
        self.u = u
        self.ue = ue
        self.o = o
        self.oe = oe
        self._out = bytearray(b"%PDF-2.0\n%\xe2\xe3\xcf\xd3\n")
        self._offsets: dict[int, int] = {}

    def _object(self, number: int, body: bytes) -> None:
        self._offsets[number] = len(self._out)
        self._out.extend(f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n")

    @staticmethod
    def _encrypt_string(data: bytes) -> bytes:
        # AESV3 strings are IV || ciphertext; derive stand-alone so the
        # fixture does not depend on the code under test.
        iv = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
        pad = 16 - len(data) % 16
        padded = data + bytes([pad]) * pad
        encryptor = Cipher(algorithms.AES(FILE_KEY), modes.CBC(iv)).encryptor()
        return iv + encryptor.update(padded) + encryptor.finalize()

    def build(self) -> bytes:
        self._object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
        self._object(2, b"<< /Type /Pages /Kids [] /Count 0 >>")
        self._object(
            3,
            b"<< /Title " + _pdf_escape_hex(self._encrypt_string(TITLE)) + b" >>",
        )
        encrypt = (
            b"<< /Filter /Standard /V 5 /R "
            + str(self.revision).encode("ascii")
            + b" /Length 256 /P -4"
            + b" /O "
            + _pdf_escape_hex(self.o)
            + b" /U "
            + _pdf_escape_hex(self.u)
            + b" /OE "
            + _pdf_escape_hex(self.oe)
            + b" /UE "
            + _pdf_escape_hex(self.ue)
            + b" /CF << /StdCF << /CFM /AESV3 /Length 32 /AuthEvent /DocOpen >> >>"
            + b" /StmF /StdCF /StrF /StdCF /EncryptMetadata true >>"
        )
        self._object(4, encrypt)
        xref = len(self._out)
        self._out.extend(b"xref\n0 5\n0000000000 65535 f \n")
        for number in range(1, 5):
            self._out.extend(f"{self._offsets[number]:010d} 00000 n \n".encode("ascii"))
        self._out.extend(
            b"trailer\n<< /Size 5 /Root 1 0 R /Info 3 0 R /Encrypt 4 0 R"
            b" /ID [" + _pdf_escape_hex(DOC_ID) + _pdf_escape_hex(DOC_ID) + b"] >>\n"
        )
        self._out.extend(f"startxref\n{xref}\n%%EOF\n".encode("ascii"))
        return bytes(self._out)


def build_pdf(vector: Vector, **overrides: bytes) -> bytes:
    """Build a PDF for ``vector``; ``overrides`` replace a named field."""
    builder = _PdfBuilder(
        vector.revision,
        overrides.get("u", vector.u_bytes),
        overrides.get("ue", vector.ue_bytes),
        overrides.get("o", vector.o_bytes),
        overrides.get("oe", vector.oe_bytes),
    )
    return builder.build()


def open_document(data: bytes, password: str = "") -> PDFDocument:
    return PDFDocument(PDFParser(BytesIO(data)), password)


def assert_opens(vector: Vector, password: str) -> None:
    document = open_document(build_pdf(vector), password)
    assert document.info == [{"Title": TITLE}]
    assert document.decipher is not None


class TestVectorIntegrity:
    @pytest.mark.parametrize("name", VECTORS)
    def test_field_lengths_match_spec(self, name: str) -> None:
        vector = VECTORS[name]
        assert len(vector.u_bytes) == 48
        assert len(vector.o_bytes) == 48
        assert len(vector.ue_bytes) == 32
        assert len(vector.oe_bytes) == 32

    @pytest.mark.parametrize("name", VECTORS)
    def test_fixed_salts_are_embedded_in_u_and_o(self, name: str) -> None:
        vector = VECTORS[name]
        assert vector.u_bytes[32:40] == USER_VALIDATION_SALT
        assert vector.u_bytes[40:48] == USER_KEY_SALT
        assert vector.o_bytes[32:40] == OWNER_VALIDATION_SALT
        assert vector.o_bytes[40:48] == OWNER_KEY_SALT

    def test_r6_characters_mapped_to_nothing_match_empty_password(self) -> None:
        assert R6_VECTORS["r6-mapped"].ue == R6_VECTORS["r6-empty"].ue
        assert R6_VECTORS["r6-mapped"].u == R6_VECTORS["r6-empty"].u

    def test_r5_preserves_characters_that_r6_deletes(self) -> None:
        assert R5_VECTORS["r5-mapped"].u != R5_VECTORS["r5-empty"].u
        assert R6_VECTORS["r6-mapped"].u == R6_VECTORS["r6-empty"].u

    def test_empty_password_uses_different_algorithms(self) -> None:
        assert R5_VECTORS["r5-empty"].u != R6_VECTORS["r6-empty"].u


class TestR5UserPath:
    @pytest.mark.parametrize("name", R5_VECTORS)
    def test_exact_user_password_opens(self, name: str) -> None:
        vector = R5_VECTORS[name]
        document = open_document(build_pdf(vector), vector.user_password)
        assert document.info == [{"Title": TITLE}]

    def test_nfd_and_nfc_are_different_under_r5(self) -> None:
        vector = R5_VECTORS["r5-nfd"]
        # NFC "é" is not what R5 hashed, so it must not open the document.
        with pytest.raises(PDFPasswordIncorrect):
            open_document(
                build_pdf(vector),
                unicodedata.normalize("NFC", vector.user_password),
            )

    def test_r5_does_not_expand_compatibility_characters(self) -> None:
        vector = R5_VECTORS["r5-expand"]
        # R5 hashes the raw compatibility ideograph bytes; the NFKC-expanded
        # form is a different byte string, not a synonym.
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "株式会社" * 11)

    def test_r5_keeps_prohibited_characters_verbatim(self) -> None:
        vector = R5_VECTORS["r5-control"]
        document = open_document(build_pdf(vector), vector.user_password)
        assert document.info == [{"Title": TITLE}]

    def test_r5_does_not_delete_mapped_characters(self) -> None:
        vector = R5_VECTORS["r5-mapped"]
        document = open_document(build_pdf(vector), vector.user_password)
        assert document.info == [{"Title": TITLE}]
        # Deleting U+00AD (what R6 does) changes the password for R5.
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "")

    def test_r5_truncation_boundary_ignores_tail(self) -> None:
        vector = R5_VECTORS["r5-split"]
        # The 127-byte prefix is 126 ASCII bytes plus the first byte of the
        # euro sign, so the bare 126 ASCII bytes are a different password.
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "A" * 126)
        # Anything after byte 127 is outside the limit and cannot be required.
        assert_opens(vector, "A" * 126 + "€" + "ignored")

    def test_r5_empty_user_password(self) -> None:
        vector = R5_VECTORS["r5-empty"]
        document = open_document(build_pdf(vector), "")
        assert document.info == [{"Title": TITLE}]
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "\x00")

    def test_r5_exact_127_bytes_has_no_tail_to_ignore(self) -> None:
        vector = R5_VECTORS["r5-limit"]
        assert_opens(vector, "C" * 127)
        assert_opens(vector, "C" * 127 + "tail")
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "C" * 126)


class TestR5OwnerPath:
    @pytest.mark.parametrize("name", R5_VECTORS)
    def test_exact_owner_password_opens(self, name: str) -> None:
        vector = R5_VECTORS[name]
        document = open_document(build_pdf(vector), vector.owner_password)
        assert document.info == [{"Title": TITLE}]

    def test_r5_owner_does_not_normalize(self) -> None:
        vector = R5_VECTORS["r5-nfd"]
        with pytest.raises(PDFPasswordIncorrect):
            open_document(
                build_pdf(vector),
                unicodedata.normalize("NFC", vector.owner_password),
            )

    def test_r5_owner_truncation_boundary(self) -> None:
        vector = R5_VECTORS["r5-split"]
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "B" * 126)
        assert_opens(vector, "B" * 126 + "€" + "ignored")

    def test_r5_owner_exact_127_bytes(self) -> None:
        vector = R5_VECTORS["r5-limit"]
        assert_opens(vector, "D" * 127)
        assert_opens(vector, "D" * 127 + "tail")
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "D" * 126)

    def test_r5_owner_does_not_equal_user_path(self) -> None:
        vector = R5_VECTORS["r5-nfd"]
        assert vector.owner_password != vector.user_password
        assert_opens(vector, vector.user_password)
        assert_opens(vector, vector.owner_password)

    def test_r5_owner_bound_to_u(self) -> None:
        vector = R5_VECTORS["r5-nfd"]
        data = build_pdf(vector, u=bytes(a ^ 0x01 for a in vector.u_bytes))
        with pytest.raises(PDFPasswordIncorrect):
            open_document(data, vector.owner_password)


class TestR6UserPath:
    @pytest.mark.parametrize("name", R6_VECTORS)
    def test_exact_user_password_opens(self, name: str) -> None:
        vector = R6_VECTORS[name]
        document = open_document(build_pdf(vector), vector.user_password)
        assert document.info == [{"Title": TITLE}]

    def test_nfd_and_nfc_are_equivalent_under_r6(self) -> None:
        vector = R6_VECTORS["r6-nfd"]
        nfc = unicodedata.normalize("NFC", vector.user_password)
        assert nfc != vector.user_password
        document = open_document(build_pdf(vector), nfc)
        assert document.info == [{"Title": TITLE}]

    def test_r6_expands_then_truncates(self) -> None:
        vector = R6_VECTORS["r6-expand"]
        # SASLprep turns each U+337F into 株式会社, producing 132 bytes; the
        # last character is cut, so the surviving prefix still matches.
        assert vector.user_password.encode("utf-8") == b"\xe3\x8d\xbf" * 11
        document = open_document(build_pdf(vector), vector.user_password)
        assert document.info == [{"Title": TITLE}]

    def test_r6_truncation_boundary_ignores_tail(self) -> None:
        vector = R6_VECTORS["r6-split"]
        # Same split point as R5: the last character is cut mid-sequence, so
        # the bare ASCII prefix is not equivalent, while bytes past 127 are.
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "A" * 126)
        assert_opens(vector, "A" * 126 + "€" + "ignored")
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "A" * 125)

    def test_r6_maps_characters_to_nothing(self) -> None:
        vector = R6_VECTORS["r6-mapped"]
        document = open_document(build_pdf(vector), vector.user_password)
        assert document.info == [{"Title": TITLE}]
        document = open_document(build_pdf(vector), "")
        assert document.info == [{"Title": TITLE}]

    def test_r6_empty_user_password(self) -> None:
        vector = R6_VECTORS["r6-empty"]
        document = open_document(build_pdf(vector), "")
        assert document.info == [{"Title": TITLE}]
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), " ")

    def test_r6_exact_127_bytes_has_no_tail_to_ignore(self) -> None:
        vector = R6_VECTORS["r6-limit"]
        assert_opens(vector, "C" * 127)
        assert_opens(vector, "C" * 127 + "tail")
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "C" * 126)

    def test_r6_prohibited_character_is_unsupported_not_auth_failure(self) -> None:
        vector = R6_VECTORS["r6-nfd"]
        with pytest.raises(PDFEncryptionUnsupported) as excinfo:
            open_document(build_pdf(vector), "pa\u0007ss")
        assert not isinstance(excinfo.value, PDFPasswordIncorrect)


class TestR6OwnerPath:
    @pytest.mark.parametrize("name", R6_VECTORS)
    def test_exact_owner_password_opens(self, name: str) -> None:
        vector = R6_VECTORS[name]
        document = open_document(build_pdf(vector), vector.owner_password)
        assert document.info == [{"Title": TITLE}]

    def test_r6_owner_normalizes(self) -> None:
        vector = R6_VECTORS["r6-nfd"]
        nfc = unicodedata.normalize("NFC", vector.owner_password)
        assert nfc != vector.owner_password
        assert_opens(vector, nfc)

    def test_r6_owner_truncation_boundary(self) -> None:
        vector = R6_VECTORS["r6-split"]
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "B" * 126)
        assert_opens(vector, "B" * 126 + "€" + "ignored")

    def test_r6_owner_exact_127_bytes(self) -> None:
        vector = R6_VECTORS["r6-limit"]
        assert_opens(vector, "D" * 127)
        assert_opens(vector, "D" * 127 + "tail")
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector), "D" * 126)

    def test_r6_owner_bound_to_u(self) -> None:
        vector = R6_VECTORS["r6-nfd"]
        data = build_pdf(vector, u=bytes(a ^ 0x01 for a in vector.u_bytes))
        with pytest.raises(PDFPasswordIncorrect):
            open_document(data, vector.owner_password)

    def test_r6_owner_prohibited_character_is_unsupported(self) -> None:
        vector = R6_VECTORS["r6-empty"]
        with pytest.raises(PDFEncryptionUnsupported) as excinfo:
            open_document(build_pdf(vector), "owner\u0007")
        assert not isinstance(excinfo.value, PDFPasswordIncorrect)


class TestUnsupportedInput:
    def test_r6_bidirectional_violation_is_unsupported(self) -> None:
        vector = R6_VECTORS["r6-empty"]
        with pytest.raises(PDFEncryptionUnsupported) as excinfo:
            open_document(build_pdf(vector), "\u05d0a")
        assert not isinstance(excinfo.value, PDFPasswordIncorrect)

    @pytest.mark.parametrize("revision", [5, 6])
    def test_unencodable_surrogate_is_unsupported(self, revision: int) -> None:
        vector = VECTORS[f"r{revision}-empty"]
        with pytest.raises(PDFEncryptionUnsupported) as excinfo:
            open_document(build_pdf(vector), "\ud800")
        assert not isinstance(excinfo.value, PDFPasswordIncorrect)

    def test_r5_accepts_control_characters(self) -> None:
        # The same string that is prohibited for R6 must remain valid for R5.
        vector = R5_VECTORS["r5-control"]
        assert_opens(vector, vector.user_password)


class TestDamagedFields:
    @pytest.mark.parametrize("revision", [5, 6])
    def test_truncated_u_is_unsupported(self, revision: int) -> None:
        vector = VECTORS[f"r{revision}-empty"]
        for damaged in (vector.u_bytes[:40], vector.u_bytes[:-1], b""):
            with pytest.raises(PDFEncryptionUnsupported):
                open_document(build_pdf(vector, u=damaged), vector.user_password)

    @pytest.mark.parametrize("revision", [5, 6])
    def test_truncated_o_is_unsupported(self, revision: int) -> None:
        vector = VECTORS[f"r{revision}-empty"]
        for damaged in (vector.o_bytes[:40], vector.o_bytes[:-1], b""):
            with pytest.raises(PDFEncryptionUnsupported):
                open_document(build_pdf(vector, o=damaged), vector.owner_password)

    @pytest.mark.parametrize("revision", [5, 6])
    def test_damaged_ue_oe_are_unsupported(self, revision: int) -> None:
        vector = VECTORS[f"r{revision}-empty"]
        for field in ("ue", "oe"):
            damaged = getattr(vector, f"{field}_bytes")[:16]
            with pytest.raises(PDFEncryptionUnsupported):
                open_document(
                    build_pdf(vector, **{field: damaged}),
                    vector.user_password,
                )

    @pytest.mark.parametrize("revision", [5, 6])
    def test_modified_hash_does_not_open(self, revision: int) -> None:
        vector = VECTORS[f"r{revision}-nfd"]
        bad_u = bytearray(vector.u_bytes)
        bad_u[0] ^= 0xFF
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector, u=bytes(bad_u)), vector.user_password)
        bad_o = bytearray(vector.o_bytes)
        bad_o[0] ^= 0xFF
        with pytest.raises(PDFPasswordIncorrect):
            open_document(build_pdf(vector, o=bytes(bad_o)), vector.owner_password)

    def test_unknown_revision_is_unsupported(self) -> None:
        vector = VECTORS["r6-empty"]
        data = build_pdf(vector).replace(b"/R 6", b"/R 7", 1)
        with pytest.raises(PDFEncryptionUnsupported):
            open_document(data, vector.user_password)

    def test_unknown_algorithm_is_unsupported(self) -> None:
        vector = VECTORS["r6-empty"]
        data = build_pdf(vector).replace(b"/V 5", b"/V 9", 1)
        with pytest.raises(PDFEncryptionUnsupported):
            open_document(data, vector.user_password)
