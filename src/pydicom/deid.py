# Copyright 2008-2025 pydicom authors. See LICENSE file for details.
"""Convenience imports for de-identification rules."""

from pydicom.deidentification import (
    PrivateTagPolicy,
    PrivateTagRule,
    apply_private_tag_policy,
    deidentify_dataset,
    get_private_creator,
)

deidentify = deidentify_dataset
remove_private_tags = deidentify_dataset

__all__ = [
    "PrivateTagPolicy",
    "PrivateTagRule",
    "apply_private_tag_policy",
    "deidentify",
    "deidentify_dataset",
    "get_private_creator",
    "remove_private_tags",
]
