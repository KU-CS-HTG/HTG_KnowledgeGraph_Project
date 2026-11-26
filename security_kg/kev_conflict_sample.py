"""KEV의 CWE 출처 충돌(기본값-C1) 검토용 표본을 만든다.

KEV 1,795건 중 232건은 KEV, CNA, ADP가 붙인 CWE가 서로 다르다(`data/kev.json`의 `cwe_conflict`).
어느 쪽이 맞는지는 이 스크립트가 판단하지 않는다. 사람이 CWE 정의를 읽고 판정할 수 있도록
충돌을 관계별로 분류하고, 사람이 볼 표본을 고정된 방식(seed)으로 뽑아 판정 칸을 비워 둔다.

관계(relation): 대표값(`cwe_display`)과 값이 다른 출처의 CWE 사이의 관계. 여러 출처가 다르면 **가장 약한 관계**를 쓴다.
  subset      한쪽 CWE 집합이 다른 쪽의 일부(예: {CWE-79}와 {CWE-79, CWE-80})
  hierarchy   상하위 관계(ChildOf로 이어짐). 같은 문제를 다른 구체성으로 말한 것일 가능성
  unrelated   위 둘이 아님. 서로 다른 문제를 말하는 것일 수 있어 사람이 봐야 함
  (대표값이 없는 경우 no_display)

사용: python kev_conflict_sample.py            # 표본 30건과 전체 분류를 backbone/export/에 쓴다
      python kev_conflict_sample.py --self-test
"""
import csv
import json
import random
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEV = HERE / "data" / "kev.json"
CWE = HERE / "data" / "cwe_catalog.json"
OUT = HERE / "backbone" / "export"
SEED = 20261126
SAMPLE = {"unrelated": 20, "hierarchy": 5, "subset": 5}  # 합 30
ORDER = {"subset": 0, "hierarchy": 1, "unrelated": 2}


def _num(c):
    return str(c).replace("CWE-", "").strip()


def ancestors(n, weak):
    seen, stack = set(), list(weak.get(n, {}).get("parents", []))
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        stack.extend(weak.get(p, {}).get("parents", []))
    return seen


def relation(a, b, weak):
    """CWE 집합 a와 b의 관계(subset, hierarchy, unrelated)."""
    A, B = {_num(x) for x in a}, {_num(x) for x in b}
    if A <= B or B <= A:
        return "subset"
    for x in A:
        for y in B:
            if y in ancestors(x, weak) or x in ancestors(y, weak):
                return "hierarchy"
    return "unrelated"


def sources(v):
    """출처별 CWE 집합. ADP는 제공자별 값을 합치고 제공자 이름을 남긴다."""
    s = v["cwe_by_source"]
    adp = s.get("adp") or {}
    adp_all = sorted({c for cs in adp.values() for c in cs})
    return {"kev": list(s.get("kev") or []), "cna": list(s.get("cna") or []), "adp": adp_all}, sorted(adp)


def classify(v, weak):
    """충돌 항목의 (관계, 어느 출처와 대표값이 다른가). 대표값이 없으면 ("no_display", "")."""
    src, _ = sources(v)
    disp = v.get("cwe_display") or []
    if not disp:
        return "no_display", ""
    worst, diff = "subset", []
    for name, vals in src.items():
        if not vals or set(map(_num, vals)) == set(map(_num, disp)):
            continue
        diff.append(name)
        r = relation(disp, vals, weak)
        if ORDER[r] > ORDER[worst]:
            worst = r
    return (worst if diff else "subset"), "+".join(diff)


def _label(ids, weak, groupings):
    out = []
    for c in ids:
        n = _num(c)
        w = weak.get(n) or groupings.get(n) or {}
        out.append(f"{c} ({w.get('name', '목록에 없음')})")
    return "; ".join(out)


def build(kev, cat, seed=SEED, sample=SAMPLE):
    weak, groupings = cat["weaknesses"], cat["groupings"]
    rows = []
    for cve, v in sorted(kev.items()):
        if not v.get("cwe_conflict"):
            continue
        rel, diff = classify(v, weak)
        src, providers = sources(v)
        rows.append({
            "cve": cve, "vendor": v["vendor"], "product": v["product"], "name": v["name"], "date_added": v["date_added"],
            "relation": rel, "differs_from_display": diff,
            "display_source": v.get("cwe_display_source", ""),
            "display": _label(v.get("cwe_display") or [], weak, groupings),
            "cwe_kev": _label(src["kev"], weak, groupings),
            "cwe_cna": _label(src["cna"], weak, groupings),
            "cwe_adp": _label(src["adp"], weak, groupings) + (f" [제공자: {', '.join(providers)}]" if providers else ""),
        })
    rng = random.Random(seed)
    chosen = []
    for rel, n in sample.items():
        pool = [r for r in rows if r["relation"] == rel]
        # 어느 출처가 다른지(differs_from_display) 유형이 고르게 들어가도록 유형별로 돌려가며 뽑는다
        groups = {}
        for r in pool:
            groups.setdefault(r["differs_from_display"], []).append(r)
        for g in groups.values():
            rng.shuffle(g)
        picked = []
        keys = sorted(groups)
        while len(picked) < min(n, len(pool)):
            for k in keys:
                if groups[k] and len(picked) < n:
                    picked.append(groups[k].pop())
        chosen += picked
    return rows, chosen


FIELDS = ["no", "cve", "vendor", "product", "name", "date_added", "relation", "differs_from_display", "display_source",
          "display", "cwe_kev", "cwe_cna", "cwe_adp", "judge_correct", "judge_note"]


def write(rows, path, numbered=True):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, FIELDS, lineterminator="\r\n", extrasaction="ignore")
        w.writeheader()
        for i, r in enumerate(rows, 1):
            w.writerow({**r, "no": i if numbered else "", "judge_correct": "", "judge_note": ""})


def self_test():
    weak = {"1": {"parents": ["2"]}, "2": {"parents": ["3"]}, "3": {"parents": []}, "9": {"parents": []}, "10": {"parents": []}}
    assert ancestors("1", weak) == {"2", "3"}
    assert relation(["CWE-1"], ["CWE-3"], weak) == "hierarchy"
    assert relation(["CWE-1"], ["CWE-1", "CWE-9"], weak) == "subset"
    assert relation(["CWE-9"], ["CWE-10"], weak) == "unrelated"

    def v(disp, kev, cna, adp):
        return {"cwe_display": disp, "cwe_by_source": {"kev": kev, "cna": cna, "adp": adp}}
    assert classify(v(["CWE-9"], ["CWE-10"], ["CWE-9"], {}), weak) == ("unrelated", "kev")
    assert classify(v(["CWE-1"], ["CWE-3"], ["CWE-1"], {"x": ["CWE-10"]}), weak) == ("unrelated", "kev+adp")  # 가장 약한 관계
    assert classify(v([], ["CWE-3"], [], {}), weak) == ("no_display", "")
    kev = {f"CVE-{i}": {"vendor": "v", "product": "p", "name": "n", "date_added": "d", "cwe_conflict": True,
                        "cwe_display": ["CWE-9"], "cwe_display_source": "cna",
                        "cwe_by_source": {"kev": ["CWE-10"], "cna": ["CWE-9"], "adp": {}}} for i in range(40)}
    cat = {"weaknesses": weak, "groupings": {}}
    a, s1 = build(kev, cat, sample={"unrelated": 5})
    _, s2 = build(kev, cat, sample={"unrelated": 5})
    assert [r["cve"] for r in s1] == [r["cve"] for r in s2] and len(s1) == 5   # 같은 seed면 같은 표본
    assert all(r["judge_correct"] == "" for r in [])  # 판정 칸은 write에서 비워 둔다
    print("자체 시험 통과")


def main():
    if "--self-test" in sys.argv:
        return self_test()
    kev = json.load(open(KEV, encoding="utf-8"))["vulnerabilities"]
    cat = json.load(open(CWE, encoding="utf-8"))
    rows, chosen = build(kev, cat)
    write(rows, OUT / "kev_conflicts_all.csv")
    write(chosen, OUT / "kev_conflict_sample.csv")
    print(f"충돌 {len(rows)}건:", dict(Counter(r["relation"] for r in rows)))
    print("어느 출처가 다른가:", dict(Counter(r["differs_from_display"] for r in rows)))
    print(f"표본 {len(chosen)}건:", dict(Counter(r["relation"] for r in chosen)))


if __name__ == "__main__":
    main()
