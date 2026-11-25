"""재실행한 ontology_conformed 플래그를 저장된 플래그와 트리플렛 단위로 비교한다."""
import json, sys
from collections import Counter
from pathlib import Path

stored_root, new_root, extracted_root = map(Path, sys.argv[1:4])
dates = sys.argv[4:]
tot = Counter(); diffs = []
for date in dates:
    c = Counter()
    for sp in sorted((stored_root / date).glob("*.json")):
        np_, ep = new_root / date / sp.name, extracted_root / date / sp.name
        if not np_.exists():
            c["missing_new_file"] += 1; continue
        s = json.load(open(sp))["kg_extraction_triplets"]
        n = json.load(open(np_))["kg_extraction_triplets"]
        e = json.load(open(ep))["kg_extraction_triplets"] if ep.exists() else None
        c["files"] += 1
        if len(s) != len(n):
            c["length_mismatch_files"] += 1; continue
        if e is not None and any("ontology_conformed" in t for t in e):
            c["extracted_already_had_flag"] += 1
        for i, (a, b) in enumerate(zip(s, n)):
            c["triplets"] += 1
            same = bool(a["ontology_conformed"]) == bool(b["ontology_conformed"])
            c["agree" if same else "disagree"] += 1
            if not same: diffs.append((date, sp.name, i, a["ontology_conformed"], b["ontology_conformed"], a.get("source_entity_type"), a.get("relation"), a.get("target_entity_type")))
            c[f"stored_{bool(a['ontology_conformed'])}__new_{bool(b['ontology_conformed'])}"] += 1
    print(date, dict(c)); tot.update(c)
print("합계", dict(tot))
if diffs:
    print("불일치 샘플:"); [print(" ", d) for d in diffs[:10]]
