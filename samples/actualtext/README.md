# ActualText forensic sample

`actualtext-forensic.pdf` is a generated fixture that demonstrates why the
accessible replacement text (`/ActualText`) and the glyphs that are actually
painted must be treated as two separate pieces of evidence.

## How to regenerate

```
python samples/actualtext/generate_sample.py
```

`pdfbuilder.py` is a small dependency-free PDF writer used only to build this
fixture and is not part of the pdfminer library.

## What the document contains

- **Page 1**
  - `PLAIN-START` / `PLAIN-END`: ordinary text outside any replacement scope.
  - An outer marked-content sequence `<P MCID=3>` whose `/ActualText`
    (`outer replacement text`) replaces **two** painted runs
    (`DRAWN-ONE`, `DRAWN-TWO`, `DRAWN-THREE`).
  - A nested `<Span MCID=7>` whose property dictionary is referenced **by
    name** through the page's `/Properties` resource dictionary.
  - A Form XObject `Fm1` with its **own** resource dictionary, containing an
    independent ActualText span.
- **Page 2**
  - A `<Span MCID=9>` marked-content sequence that is never closed, used to
    demonstrate the locatable unclosed-marker diagnostic.

## Reading vs drawn evidence

Run the forensic output with either entry point:

```
python tools/pdf2txt.py -t forensic samples/actualtext/actualtext-forensic.pdf
```

```python
from pdfminer.forensic import extract_actualtext_report

report = extract_actualtext_report("samples/actualtext/actualtext-forensic.pdf")
for page in report.pages:
    print(page.reading_text)  # accessible reading order (ActualText applied)
    print(page.drawn_text)    # glyphs actually painted, replacements suppressed
    print(page.mismatches())  # spans where the two channels differ
    print(page.diagnostics)   # unclosed markers and other problems
```

The reading channel announces each `/ActualText` exactly once and suppresses
the glyphs it covers; the drawn channel retains every painted glyph and never
includes the replacement text. `mismatches()` points at the specific marked
tag (with MCID) and the page / Form XObject location where the two channels
diverge.
