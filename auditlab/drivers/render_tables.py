import csv, json, sys
from pathlib import Path
WS = Path(sys.argv[1]).resolve()
EV = WS / "auditlab/evidence"
r = json.loads((EV / "audit-report.json").read_text(encoding="utf-8"))

cols = ["target", "state", "provenance", "logical_path", "source_basis",
        "actual_sha256", "actual_size", "source_record_hash_match",
        "in_target_record", "target_record_hash_match"]

with (EV / "itemized-evidence.csv").open("w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(cols)
    for tname, t in r["targets"].items():
        for i in t["items"]:
            w.writerow([tname] + [i[c] for c in cols[1:]])

# Markdown table
lines = ["| target | state | provenance | path | actual sha256 | size | src-REC | in-tgt-REC | tgt-REC |",
         "|---|---|---|---|---|---|---|---|---|"]
for tname, t in r["targets"].items():
    for i in t["items"]:
        lines.append("| {target} | {state} | {prov} | `{p}` | `{h}` | {sz} | {sm} | {it} | {tm} |".format(
            target=tname, state=i["state"], prov=i["provenance"], p=i["logical_path"],
            h=i["actual_sha256"].replace("sha256=", ""), sz=i["actual_size"],
            sm=i["source_record_hash_match"], it=i["in_target_record"],
            tm=i["target_record_hash_match"]))
(EV / "itemized-evidence.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("wrote itemized-evidence.csv and .md ; rows:",
      sum(len(t["items"]) for t in r["targets"].values()))
