# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""bounded, metadata-driven reachability review for managed plugin entry points.

this package deliberately does not execute, load, or reflect over the assembly
under review. it only reads CIL method bodies and metadata rows.
"""

from dncil.analysis.review import (
    Finding,
    CallSite,
    Decision,
    EntryReview,
    FindingKind,
    ReviewLimits,
    ReviewReport,
    UnresolvedCall,
    UnresolvedKind,
    ReachableMethod,
    review_entry_point,
    review_entry_points,
)
from dncil.analysis.metadata import (
    MetadataView,
    MethodRecord,
    MetadataError,
    ReferenceKind,
    MethodReference,
    SyntheticMetadata,
)

__all__ = [
    "CallSite",
    "Decision",
    "EntryReview",
    "Finding",
    "FindingKind",
    "MetadataError",
    "MetadataView",
    "MethodRecord",
    "MethodReference",
    "ReferenceKind",
    "ReachableMethod",
    "ReviewLimits",
    "ReviewReport",
    "SyntheticMetadata",
    "UnresolvedCall",
    "UnresolvedKind",
    "review_entry_point",
    "review_entry_points",
]
