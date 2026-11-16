"""Run the parameter matrix over the three samples and diff the reading orders.

For every sample we extract evidence under two or more LAParams settings,
then compare pairwise relations. A pair whose relative order flips when a
parameter changes is PROOF that the order is layout inference, not file
content - the report must present it as such, and must not present the
parameter-sensitive output as "the original content changed".
"""

import json
from pathlib import Path

from trace_order import extract, parse_laparams

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"

RUNS = {
    "sample1_twocol.pdf": [
        ("default", []),
        ("noflow", ["boxes_flow=None"]),
        ("flow_neg", ["boxes_flow=-0.5"]),
    ],
    "sample2_rotated.pdf": [
        ("default", []),
        ("vertical", ["detect_vertical=true"]),
    ],
    "sample3_overlap.pdf": [
        ("default", []),
        ("wide_margin", ["char_margin=3.0"]),
    ],
}


def to_laparams(overrides):
    fixed = []
    for item in overrides:
        if item.endswith("=true"):
            fixed.append(item[:-5] + "=1")
        else:
            fixed.append(item)
    params = parse_laparams(fixed)
    for item in overrides:
        if item.endswith("=true"):
            setattr(params, item[:-5], True)
    return params


def pair_key(pair):
    return tuple(pair["pair"])


def page_relations(page):
    """Pairwise relations keyed by render_index, normalized so that the
    relation is always expressed as 'lower render# before/after higher
    render# in this run's output'."""
    chars = {c["id"]: c for c in page["chars"]}
    out_pos = {}
    for pos, cid in enumerate(page["output_sequence"]):
        out_pos[chars[cid]["render_index"]] = pos
    relations = {}
    for pair in page["pairs"]:
        a, b = pair["pair"]
        ra, rb = chars[a]["render_index"], chars[b]["render_index"]
        lo, hi = min(ra, rb), max(ra, rb)
        if ra in out_pos and rb in out_pos:
            rel = "before" if out_pos[lo] < out_pos[hi] else "after"
        else:
            rel = "omitted"
        first, second = (a, b) if ra < rb else (b, a)
        relations[(lo, hi)] = {
            "relation": rel,
            "basis": pair["basis"],
            "texts": [chars[first]["text"], chars[second]["text"]],
            "bboxes": [chars[first]["bbox"], chars[second]["bbox"]],
            "stream_relation": "before",  # lo always painted before hi
        }
    return relations


def compare(run_a, run_b):
    """Return pairs whose output relation differs between two runs."""
    rel_a = page_relations(run_a["pages"][0])
    rel_b = page_relations(run_b["pages"][0])
    flips = []
    for key, pa in rel_a.items():
        pb = rel_b.get(key)
        if pb is None:
            continue
        if pa["relation"] != pb["relation"]:
            flips.append({
                "render_indices": list(key),
                "texts": pa["texts"],
                "bboxes": pa["bboxes"],
                "stream_relation": pa["stream_relation"],
                "basis_before": pa["basis"],
                "basis_after": pb["basis"],
                "relation_before": pa["relation"],
                "relation_after": pb["relation"],
            })
    return flips


def main():
    OUT.mkdir(exist_ok=True)
    report = []
    for sample, runs in RUNS.items():
        pdf = HERE / sample
        evidences = {}
        report.append(f"## {sample}\n")
        for name, overrides in runs:
            laparams = to_laparams(overrides)
            ev = extract(pdf, laparams)
            evidences[name] = ev
            out_file = OUT / f"{sample[:-4]}_{name}.json"
            out_file.write_text(
                json.dumps(ev, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            page = ev["pages"][0]
            stream_text = "".join(
                c["text"]
                for c in sorted(page["chars"], key=lambda c: c["render_index"])
            )
            report.append(
                f"- run `{name}` params={page['laparams']}\n"
                f"  - stream order (file fact): `{stream_text}`\n"
                f"  - output order (inference): `{page['output_text']}`"
            )
        names = [n for n, _ in runs]
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                a, b = names[i], names[j]
                flips = compare(evidences[a], evidences[b])
                report.append(
                    f"- compare `{a}` vs `{b}`: {len(flips)} pair(s) changed order"
                )
                for f in flips:
                    report.append(
                        f"  - render# {f['render_indices']} {f['texts']} bbox={f['bboxes']} "
                        f"stream={f['stream_relation']} "
                        f"basis: {f['basis_before']} -> {f['basis_after']} "
                        f"output: {f['relation_before']} -> {f['relation_after']}"
                    )
        report.append("")

    text = "\n".join(report)
    (OUT / "comparison.md").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
