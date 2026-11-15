# Minimal failing samples

These are complete, self-contained pcapng files (`.pcapng.bin` so the
repository-wide `*.pcapng` ignore rule does not hide them). Each one is a
minimal witness for one structural guard in the NRB / EPB boundary suite:

| File | Guard it pins |
| --- | --- |
| `*-end-record-length-4.pcapng.bin` | end-of-records marker must have length 0 |
| `*-missing-end-record-at-body-end.pcapng.bin` | record list must not end by exhaustion |
| `*-missing-end-record-options-as-records.pcapng.bin` | option bytes must not be decoded as records |
| `*-ipv4-record-too-short.pcapng.bin` | address record must contain its address |
| `*-missing-opt-endofopt.pcapng.bin` | options must end with `opt_endofopt` |
| `*-opt-endofopt-length-4.pcapng.bin` | `opt_endofopt` must have length 0 |
| `*-bytes-after-opt-endofopt.pcapng.bin` | no residual bytes after the terminator |
| `*-unknown-record-and-option-retained.pcapng.bin` | unknown items stay intact |
| `*-epb-missing-opt-endofopt.pcapng.bin` | EPB options require the terminator |

`manifest.json` contains the expected exception/message or decoded contents
for each file. Regenerate everything with:

```sh
python -m tests.nrb_mutations.generator
```

The generator uses the fixed seed `0x5EED2026`; `corpus.json` stores the exact
bytes for every case (50, both endiannesses) so the suite never depends on an
RNG at test time.
