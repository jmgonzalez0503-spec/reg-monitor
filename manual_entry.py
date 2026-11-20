#!/usr/bin/env python3
"""Turn an owner-submitted GitHub issue form into an entry in docs/data/manual.json."""
import datetime as dt
import json
import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(ROOT, "docs", "data", "manual.json")
body = os.environ.get("ISSUE_BODY", "")
today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
data = json.load(open(PATH, encoding="utf-8")) if os.path.exists(PATH) else {"checks": {}, "items": []}
valid = {s["id"] for s in json.load(open(os.path.join(ROOT, "sources.json"), encoding="utf-8"))["sources"]}

fields = {}
for m in re.finditer(r"###\s*(.+?)\s*\n+(.*?)(?=\n###|\Z)", body, re.S):
    val = m.group(2).strip()
    fields[m.group(1).strip().lower()] = "" if val == "_No response_" else val


def clean_date(v):
    m = re.search(r"\d{4}-\d{2}-\d{2}", v or "")
    return m.group(0) if m else ""


if "sources checked" in fields:
    for m in re.finditer(r"- \[[xX]\]\s*(\d+)\.", fields["sources checked"]):
        if int(m.group(1)) in valid:
            data["checks"][m.group(1)] = today
    print("Recorded checks:", data["checks"])
elif "title" in fields:
    m = re.match(r"\s*(\d+)\.", fields.get("source", ""))
    sid = int(m.group(1)) if m else 0
    title = re.sub(r"\s+", " ", fields["title"])[:300]
    url = fields.get("link", "").split()[0] if fields.get("link") else ""
    if sid in valid and title:
        data["items"].append({"source_id": sid, "title": title, "url": url if re.match(r"https?://", url) else "",
                              "date": clean_date(fields.get("date published")), "due": clean_date(fields.get("closing date")),
                              "note": re.sub(r"\s+", " ", fields.get("note", ""))[:400], "added": today})
        data["checks"][str(sid)] = today
        print("Added item for source", sid)
    else:
        raise SystemExit("The form did not include a valid source and title.")
else:
    raise SystemExit("This issue is not a monitor form.")

with open(PATH, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=1, ensure_ascii=False)
    fh.write("\n")
