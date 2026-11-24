"""O 단계에서 제거된 트리플렛이 어떤 규칙 때문인지 분해한다."""
import glob, json, sys
from collections import Counter
sys.path.insert(0, "extraction")
import ontology_conformance_agent as a
from consts import FILTERED_RELATIONSHIP_SOURCE_TO_TARGET as ONT
ont = set(ONT)
reasons = Counter(); first = Counter(); judged = Counter()
for d in ("2026-02-01", "2026-04-24"):
    for p in sorted(glob.glob(f"../stats/output/evaluated_papers/{d}/*.json")):
        for t in json.load(open(p))["kg_extraction_triplets"]:
            if t["ontology_conformed"]: continue
            in_ont = (t["source_entity_type"], t["target_entity_type"], t["relation"]) in ont
            sem = a.semantic_boundaries_conform(t)
            key = "스키마 조합이 온톨로지에 없음" if not in_ont else "조합은 맞지만 의미 경계 규칙 위반"
            reasons[key] += 1
            judged[(key, bool(t["eval"]))] += 1
            if not in_ont: first[(t["source_entity_type"], t["relation"], t["target_entity_type"])] += 1
print("제거 사유:", dict(reasons))
print("제거된 것 중 judge가 맞다고 본 비율:")
for k in reasons: print(f"  {k}: {judged[(k,True)]:,}/{reasons[k]:,} = {100*judged[(k,True)]/reasons[k]:.1f}%")
print("가장 많이 제거된 (출발,관계,도착) 상위 8:")
for k, v in first.most_common(8): print(f"  {v:5,d}  {k}")
