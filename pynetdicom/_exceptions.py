"""Exceptions used by *pynetdicom*."""


class DeidentificationError(ValueError):
    """Raised when a dataset can't be de-identified before being sent.

    A ``DeidentificationError`` is raised when a deployment supplied
    de-identifier is set on an :class:`~pynetdicom.ae.ApplicationEntity` and
    the C-STORE dataset can't be de-identified. No C-STORE request is sent
    when this exception is raised, so the original, identified dataset is
    never transmitted.

    Attributes
    ----------
    reason : str
        A description of why the dataset couldn't be de-identified.
    sop_instance_uid : str or None
        The (0008,0018) *SOP Instance UID* of the affected dataset, if known.
    """

    def __init__(self, reason: str, sop_instance_uid: str | None = None) -> None:
        """Create a new DeidentificationError.

        Parameters
        ----------
        reason : str
            A description of why the dataset couldn't be de-identified.
        sop_instance_uid : str, optional
            The (0008,0018) *SOP Instance UID* of the affected dataset, if
            known.
        """
        super().__init__(reason)
        self.reason = reason
        self.sop_instance_uid = sop_instance_uid
