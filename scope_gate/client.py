"""Local SCU clients and small synthetic DICOM input for the demo."""

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid
from pynetdicom import AE
from pynetdicom.sop_class import (
    PatientRootQueryRetrieveInformationModelFind,
    SecondaryCaptureImageStorage,
)


def synthetic_instance(patient_id="SYNTH001", patient_name="Synth^Demo"):
    """A minimal synthetic Secondary Capture instance (no pixel data)."""
    ds = Dataset()
    ds.SOPClassUID = SecondaryCaptureImageStorage
    ds.SOPInstanceUID = generate_uid()
    ds.PatientID = patient_id
    ds.PatientName = patient_name
    ds.Modality = "OT"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()

    ds.file_meta = FileMetaDataset()
    ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
    ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    return ds


def find_identifier(patient_id=""):
    """A small C-FIND identifier at PATIENT level."""
    ds = Dataset()
    ds.QueryRetrieveLevel = "PATIENT"
    ds.PatientID = patient_id
    ds.PatientName = ""
    return ds


def connect(ae_title, port, route, want_read=True, want_write=False):
    """Associate a local client to *route* on the shared gateway.

    Returns the established (or rejected) association; the caller inspects
    ``assoc.is_established`` / ``assoc.accepted_contexts``.
    """
    ae = AE(ae_title=ae_title)
    if want_read:
        ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)
    if want_write:
        ae.add_requested_context(SecondaryCaptureImageStorage)
    return ae.associate("127.0.0.1", port, ae_title=route)


def accepted_sops(assoc):
    """SOP class names whose presentation contexts were accepted."""
    return [cx.abstract_syntax.name for cx in assoc.accepted_contexts]
