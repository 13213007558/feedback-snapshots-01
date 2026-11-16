"""Minimal forensic prototype: trace how pdfminer.six produces reading order.

For every character on a page this records four layers of evidence:

1. stream_order  - the order characters are painted by the content stream.
                   This is a FILE FACT: it comes from operator sequence, not
                   from any geometric inference.
2. geometry      - each character's bbox / matrix / upright flag.
                   Also a FILE FACT (numbers stored in or derived directly
                   from the file's text operators).
3. grouping      - which LTTextLine / LTTextBox each character lands in.
                   This is INFERENCE, controlled by LAParams (char_margin,
                   line_margin, word_margin, boxes_flow, detect_vertical).
4. output_order  - the final text sequence pdfminer emits.
                   INFERENCE, except inside one LTTextLine, where pdfminer
                   keeps the content-stream order (so intra-line order is
                   file-derived, not inferred).

Pairwise relations are classified so a report never presents an inferred
order as an original fact, and never forces an undecidable pair into a
single timeline:

- "file_stream"      same LTTextLine: output order == content-stream order.
- "inferred_layout"  different lines/boxes: order comes from LAParams-driven
                     grouping and geometric sort keys.
- "ambiguous_overlap" bboxes overlap with positive area: geometry gives no
                     unique reading order; only the stream order is factual.

Usage:
    python trace_order.py file.pdf -o evidence.json \
        --set boxes_flow=0.5 --set char_margin=2.0
"""

import argparse
import json
import sys
from pathlib import Path

from pdfminer.high_level import PDFPageInterpreter, PDFResourceManager
from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import (
    LAParams,
    LTAnno,
    LTChar,
    LTTextBox,
    LTTextBoxHorizontal,
    LTTextBoxVertical,
    LTTextLine,
)
from pdfminer.pdfpage import PDFPage


class TracingAggregator(PDFPageAggregator):
    """PDFPageAggregator that tags every LTChar with its paint order."""

    def __init__(self, rsrcmgr, laparams=None):
        super().__init__(rsrcmgr, laparams=laparams)
        self.render_counter = 0

    def render_char(self, *args, **kwargs):
        adv = super().render_char(*args, **kwargs)
        item = self.cur_item._objs[-1]
        if isinstance(item, LTChar):
            item.render_index = self.render_counter
            self.render_counter += 1
        return adv


def parse_laparams(overrides):
    params = {}
    for item in overrides:
        key, _, raw = item.partition("=")
        if raw.lower() == "none":
            value = None
        else:
            value = float(raw)
        params[key] = value
    return LAParams(**params)


def laparams_dict(laparams):
    return {
        "line_overlap": laparams.line_overlap,
        "char_margin": laparams.char_margin,
        "line_margin": laparams.line_margin,
        "word_margin": laparams.word_margin,
        "boxes_flow": laparams.boxes_flow,
        "detect_vertical": laparams.detect_vertical,
        "all_texts": laparams.all_texts,
    }


def rect_overlap_area(a, b):
    x = min(a[2], b[2]) - max(a[0], b[0])
    y = min(a[3], b[3]) - max(a[1], b[1])
    return max(0.0, x) * max(0.0, y)


def build_evidence(layout, laparams, page_no):
    chars = {}
    lines = []
    boxes = []

    def walk_lines(container, box_rec=None):
        for child in container:
            if isinstance(child, LTTextLine):
                line_chars = []
                for elem in child:
                    if isinstance(elem, LTChar):
                        cid = len(chars)
                        chars[cid] = {
                            "id": cid,
                            "text": elem.get_text(),
                            "render_index": elem.render_index,
                            "bbox": [round(v, 2) for v in elem.bbox],
                            "upright": elem.upright,
                            "matrix": [round(v, 3) for v in elem.matrix],
                        }
                        line_chars.append(cid)
                    elif isinstance(elem, LTAnno):
                        pass  # synthetic "\n"/" " inserted by pdfminer, not in file
                line_rec = {
                    "line_id": len(lines),
                    "kind": type(child).__name__,
                    "bbox": [round(v, 2) for v in child.bbox],
                    "char_ids": line_chars,
                    "box_id": box_rec["box_id"] if box_rec else None,
                }
                lines.append(line_rec)
                if box_rec is not None:
                    box_rec["line_ids"].append(line_rec["line_id"])
            elif isinstance(child, LTTextBox):
                box_rec = {
                    "box_id": len(boxes),
                    "kind": type(child).__name__,
                    "index": child.index,
                    "bbox": [round(v, 2) for v in child.bbox],
                    "line_ids": [],
                }
                boxes.append(box_rec)
                walk_lines(child, box_rec)

    # layout iteration order == pdfminer's final output order for the page
    walk_lines(layout)

    output_sequence = []
    for box in boxes:  # boxes were recorded in page iteration (output) order
        for lid in box["line_ids"]:
            output_sequence.extend(lines[lid]["char_ids"])

    # pairwise relation evidence
    pairs = []
    ids = sorted(chars)
    line_of = {}
    for line in lines:
        for cid in line["char_ids"]:
            line_of[cid] = line["line_id"]
    out_pos = {cid: pos for pos, cid in enumerate(output_sequence)}
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            ca, cb = chars[a], chars[b]
            stream_rel = "before" if ca["render_index"] < cb["render_index"] else "after"
            if a in out_pos and b in out_pos:
                out_rel = "before" if out_pos[a] < out_pos[b] else "after"
            else:
                out_rel = "omitted"
            overlap = rect_overlap_area(ca["bbox"], cb["bbox"]) > 0
            if overlap:
                # Overlapping glyphs have no unique visual/logical order,
                # even when pdfminer happens to place them on one line.
                basis = "ambiguous_overlap"
            elif line_of.get(a) is not None and line_of.get(a) == line_of.get(b):
                basis = "file_stream"
            else:
                basis = "inferred_layout"
            pairs.append({
                "pair": [a, b],
                "texts": [ca["text"], cb["text"]],
                "stream_relation": stream_rel,
                "output_relation": out_rel,
                "basis": basis,
                "bbox_overlap": overlap,
            })

    return {
        "page": page_no,
        "laparams": laparams_dict(laparams),
        "char_count": len(chars),
        "chars": [chars[cid] for cid in ids],
        "lines": lines,
        "boxes": boxes,
        "output_sequence": output_sequence,
        "output_text": "".join(
            chars[cid]["text"] for cid in output_sequence
        ),
        "pairs": pairs,
    }


def extract(path, laparams):
    rsrcmgr = PDFResourceManager()
    device = TracingAggregator(rsrcmgr, laparams=laparams)
    interpreter = PDFPageInterpreter(rsrcmgr, device)
    pages = []
    with open(path, "rb") as fp:
        for page_no, page in enumerate(PDFPage.get_pages(fp), start=1):
            device.render_counter = 0
            interpreter.process_page(page)
            pages.append(build_evidence(device.get_result(), laparams, page_no))
    return {
        "source_file": str(path),
        "tool": "pdfminer.six tracing prototype",
        "provenance_note": (
            "stream_order and geometry are file facts; grouping and "
            "output_order are LAParams-dependent inference; pairs marked "
            "ambiguous_overlap have no uniquely determinable order."
        ),
        "pages": pages,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pdf")
    ap.add_argument("-o", "--out", help="write evidence JSON here (default stdout)")
    ap.add_argument("--set", dest="overrides", action="append", default=[],
                    metavar="KEY=VALUE",
                    help="LAParams override, e.g. boxes_flow=0.5, boxes_flow=None")
    args = ap.parse_args(argv)

    laparams = parse_laparams(args.overrides)
    evidence = extract(args.pdf, laparams)
    text = json.dumps(evidence, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print("wrote", args.out, file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
