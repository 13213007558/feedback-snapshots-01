"""Create two small synthetic DICOM files containing *fictional* PHI only.

No real patient data is used. The files deliberately contain:

* direct identity attributes (name, ID, birth date, free-text description),
* a private (odd group) element carrying an identifier,
* a sequence item that itself contains a patient name,
* retained pixel data,

so the de-identification allow-list has something to remove and something to
keep.
"""

from __future__ import annotations

import os
from pathlib import Path

# pydicom creates ~/.pydicom on import; point HOME at a writable sandbox dir.
os.environ.setdefault("HOME", os.path.join(os.environ["TMPDIR"], "fakehome"))

import numpy as np  # noqa: E402
import pydicom  # noqa: E402
from pydicom.dataset import FileDataset, FileMetaDataset  # noqa: E402
from pydicom.uid import ExplicitVRLittleEndian, generate_uid  # noqa: E402

SOP_CLASS = "1.2.840.10008.5.1.4.1.1.7"  # Secondary Capture Image Storage


def build_sample(
    path: Path,
    *,
    patient_name: str,
    patient_id: str,
    birth_date: str,
    private_id: str,
    nested_name: str,
    institution: str,
) -> Path:
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = SOP_CLASS
    meta.MediaStorageSOPInstanceUID = generate_uid()
    meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds = FileDataset(str(path), {}, file_meta=meta, preamble=b"\0" * 128)
    ds.is_little_endian = True
    ds.is_implicit_VR = False

    # Direct identifiers (must be removed).
    ds.PatientName = patient_name
    ds.PatientID = patient_id
    ds.PatientBirthDate = birth_date
    ds.PatientSex = "M"
    ds.InstitutionName = institution
    ds.ContributionDescription = f"Case note for {patient_name}"

    # Stable study/series identifiers (UIDs must be re-mapped, not leaked).
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = SOP_CLASS

    # Non-identifying technical attributes (must survive).
    ds.Modality = "OT"
    ds.Manufacturer = "SyntheticImaging"
    ds.StudyID = "STUDY1"
    ds.SeriesNumber = 1
    ds.InstanceNumber = 1

    # Pixel data (retained verbatim).
    rows = cols = 4
    ds.Rows = rows
    ds.Columns = cols
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = (np.arange(rows * cols, dtype="<u2") * 7).tobytes()

    # Private element carrying an identifier (must be removed).
    ds.add_new(0x00090010, "LO", private_id)

    # Sequence with nested PHI (the whole sequence is blocked; nested name must
    # never survive).
    item = pydicom.Dataset()
    item.PatientName = nested_name
    item.CodeValue = "CODE-1"
    ds.add_new(0x0040A170, "SQ", pydicom.Sequence([item]))

    path.parent.mkdir(parents=True, exist_ok=True)
    ds.save_as(str(path), enforce_file_format=True)
    return path


def main(base_dir: Path) -> tuple[Path, Path]:
    sample_a = build_sample(
        base_dir / "sample_a.dcm",
        patient_name="Bogus^Alice",
        patient_id="FAKE-PID-0001",
        birth_date="19900101",
        private_id="PRIVATE-MRN-A",
        nested_name="Bogus^Nested-Alice",
        institution="Synthetic General Hospital",
    )
    sample_b = build_sample(
        base_dir / "sample_b.dcm",
        patient_name="Bogus^Bob",
        patient_id="FAKE-PID-0002",
        birth_date="19910203",
        private_id="PRIVATE-MRN-B",
        nested_name="Bogus^Nested-Bob",
        institution="Synthetic General Hospital",
    )
    return sample_a, sample_b


if __name__ == "__main__":
    target = Path(os.environ.get("SAMPLE_DIR", Path.cwd() / "demo" / "data"))
    a, b = main(target)
    print(f"wrote {a}")
    print(f"wrote {b}")
