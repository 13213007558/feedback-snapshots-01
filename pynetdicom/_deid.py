"""Support for deployment supplied de-identification of outgoing datasets."""

from collections.abc import Callable

from pydicom.dataset import Dataset

from pynetdicom._exceptions import DeidentificationError

DeidentifierType = Callable[[Dataset], Dataset | None]

# (0000,0902) *Error Comment* is limited to 64 characters by PS3.7
MAX_ERROR_COMMENT_LENGTH = 64

# The elements that must exist for a C-STORE request to be possible
_REQUIRED_KEYWORDS = ("SOPClassUID", "SOPInstanceUID")


def deidentify_dataset(
    dataset: Dataset,
    deidentifier: DeidentifierType | None,
    sop_instance_uid: str | None = None,
) -> Dataset:
    """Return the de-identified version of `dataset`.

    If `deidentifier` is ``None`` then `dataset` is returned unchanged,
    otherwise the deployment supplied operation is applied and its result
    validated. Any failure is reported as a
    :class:`~pynetdicom._exceptions.DeidentificationError` so that the caller
    can abort the C-STORE operation rather than send the original dataset.

    Parameters
    ----------
    dataset : pydicom.dataset.Dataset
        The dataset that's about to be sent.
    deidentifier : callable or None
        The deployment supplied de-identification operation.
    sop_instance_uid : str, optional
        The *SOP Instance UID* of `dataset`, if known. Used to identify the
        dataset in any raised exception.

    Returns
    -------
    pydicom.dataset.Dataset
        The dataset to send.

    Raises
    ------
    pynetdicom._exceptions.DeidentificationError
        If `deidentifier` is not ``None`` and the dataset couldn't be
        de-identified, or if the de-identifier returned an unusable dataset.
    """
    if deidentifier is None:
        return dataset

    if sop_instance_uid is None:
        sop_instance_uid = getattr(dataset, "SOPInstanceUID", None)

    try:
        result = deidentifier(dataset)
    except DeidentificationError:
        raise
    except Exception as exc:
        reason = str(exc).strip() or exc.__class__.__name__
        raise DeidentificationError(
            f"De-identification failed: {reason}", sop_instance_uid
        ) from exc

    if result is None:
        raise DeidentificationError(
            "De-identification failed: the de-identifier returned None",
            sop_instance_uid,
        )

    if not isinstance(result, Dataset):
        raise DeidentificationError(
            "De-identification failed: the de-identifier returned "
            f"{type(result).__name__} instead of a pydicom Dataset",
            sop_instance_uid,
        )

    missing = [kw for kw in _REQUIRED_KEYWORDS if kw not in result]
    if missing:
        raise DeidentificationError(
            "De-identification failed: the returned dataset is missing the "
            f"required element(s) {', '.join(missing)}",
            sop_instance_uid,
        )

    file_meta = getattr(result, "file_meta", None)
    if file_meta is None or "TransferSyntaxUID" not in file_meta:
        raise DeidentificationError(
            "De-identification failed: the returned dataset is missing the "
            "(0002,0010) 'Transfer Syntax UID' file meta information element",
            sop_instance_uid,
        )

    return result


def error_comment(reason: str) -> str:
    """Return `reason` truncated to fit in a DIMSE *Error Comment* element."""
    return reason[:MAX_ERROR_COMMENT_LENGTH]
