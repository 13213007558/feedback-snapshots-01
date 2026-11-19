M3UA audit transcripts
======================

Three short transcripts used to check `pycrate_mobile/M3UAAudit.py` and
`tools/pycrate_m3ua_audit.py`.  Every line is `SRC -> DST: HEX`, where the
hexadecimal payload is a complete M3UA message (RFC 4666), as would be taken
from SCTP payload protocol identifier 3.

The three files deliberately cover the boundary the auditor must respect:

* `normal_activation.txt` – ASP-UP / ASP-UP-ACK, then ASP-ACTIVE /
  ASP-ACTIVE-ACK for Routing Context 7, then DATA on RC 7.  The DATA is
  `OK` and the report cites #1–#4 as the evidence.
* `data_after_deactivation.txt` – the same activation, then ASP-INACTIVE /
  ASP-INACTIVE-ACK for RC 7, then DATA on RC 7.  This is a proven ordering
  violation and the report cites #5 and #6.
* `mid_capture.txt` – DATA only, in both directions.  Nothing about the
  earlier association state is visible, so both DATA messages are
  `INSUFFICIENT_EVIDENCE`; the transcript is not evidence of an attack.

Run them with:

```console
$ ./tools/pycrate_m3ua_audit.py test/res/m3ua_audit/normal_activation.txt
$ ./tools/pycrate_m3ua_audit.py -j test/res/m3ua_audit/mid_capture.txt
```

The tool exits 0 when no violation is proven and 2 when at least one DATA is
a proven violation; insufficient evidence never changes the exit status into
a failure.  These payloads are synthetic and were produced with pycrate's own
M3UA encoder, so no capture-derived subscriber or operator data is included.
