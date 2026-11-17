# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""Print the original and widened demonstration method and the stale-branch report.

Run with ``python -m tests.metamorphic.demo`` from the repository root.  Everything is
rendered from the independent layout record, so the output shows the intended mapping
rather than re-stating dncil's decoded offsets.
"""

from __future__ import annotations

from tests.metamorphic.cfg import compare_cfgs, expected_cfg, extract_dncil_cfg
from tests.metamorphic.layout import build, format_layout, build_with_stale_branch, branches_needing_relocation
from tests.metamorphic.methods import BRANCHES_AND_EH


def main() -> int:
    original = build(BRANCHES_AND_EH, widen_short=False)
    widened = build(BRANCHES_AND_EH, widen_short=True)

    print(format_layout(original, "original"))
    print()
    print(format_layout(widened, "widened"))
    print()

    expected = expected_cfg(widened)
    actual = extract_dncil_cfg(widened)
    print("decoded widened CFG: %d logical edges, %d clauses" % (len(actual.edges), len(actual.clauses)))
    print(compare_cfgs(expected, actual).describe())
    print()

    label = "leave_try"
    assert label in branches_needing_relocation(BRANCHES_AND_EH)
    stale = build_with_stale_branch(BRANCHES_AND_EH, label)
    report = compare_cfgs(expected_cfg(stale), extract_dncil_cfg(stale, tolerate_invalid_targets=True))
    print("deliberately stale branch %r (displacement copied from the original layout):" % label)
    print(report.describe())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
