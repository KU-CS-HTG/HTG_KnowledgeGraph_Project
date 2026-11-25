"""위협 행위자 이름 조회: ATT&CK 그룹은 정확히 일치하면 연결하고, MISP는 후보로만 제시한다 (결정: 옵션 A).

문제: 같은 행위자를 보안 업체마다 다른 이름으로 부른다(Kimsuky, Velvet Chollima, Thallium ...). 반대로 한 별칭이 서로 다른
행위자에 쓰이는 경우도 있다(MISP에서 48개 별칭이 둘 이상의 항목에 나온다). 이름 문자열만으로 합치면 사건 해소에서
겪은 것과 같은 잘못된 합치기가 생기므로, 이 파일은 합치지 않고 판정만 한다.

규칙(정확히 일치, 대소문자와 공백만 무시):
  link   : 문서의 이름이 ATT&CK 그룹 한 곳의 이름이나 별칭과 일치 → 그 그룹으로 연결한다 (ATT&CK가 닫힌 목록이므로)
  review : ATT&CK 그룹 둘 이상에 일치(모호), 또는 ATT&CK에는 없고 MISP에만 일치 → 연결하지 않고 후보를 제시해 사람이 확인한다
  none   : 어디에도 없음 → 연결하지 않는다(새 행위자일 수 있다)
MISP 항목과 ATT&CK 그룹을 같은 행위자로 합치지 않는다. 별칭이 겹치면 `possible_attack_groups`로 알려 줄 뿐이다.

사용: python actors.py "Velvet Chollima"   # 한 이름 조회 (data/ 필요)
      python actors.py review              # 사람 확인용 CSV (backbone/export/actor_alias_candidates.csv)
      python actors.py                     # 자체 시험
"""
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"


def norm(s: str) -> str:
    """대소문자와 공백만 무시한다. 부분 일치나 비슷한 이름은 쓰지 않는다."""
    return re.sub(r"\s+", " ", str(s)).strip().casefold()


def build_index(attack: dict, misp: dict) -> dict:
    """이름·별칭 → 항목 목록. 항목: {source, id, name, via}. source는 attack 또는 misp."""
    idx = defaultdict(list)
    for gid, g in attack["groups"].items():
        for n in {g["name"], *g.get("aliases", [])}:
            idx[norm(n)].append({"source": "attack", "id": gid, "name": g["name"], "via": "name" if n == g["name"] else "alias"})
    for a in misp["actors"]:
        for n in {a["name"], *a.get("synonyms", [])}:
            idx[norm(n)].append({"source": "misp", "id": a.get("uuid"), "name": a["name"], "via": "name" if n == a["name"] else "alias"})
    return idx


def _dedupe(entries):
    seen, out = set(), []
    for e in entries:
        k = (e["source"], e["id"])
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out


def lookup_actor(name: str, idx: dict, attack: dict) -> dict:
    hits = _dedupe(idx.get(norm(name), []))
    atk = [h for h in hits if h["source"] == "attack"]
    misp = [h for h in hits if h["source"] == "misp"]
    # MISP 항목이 ATT&CK 그룹과 별칭을 공유하는지: 같은 행위자일 수 있다는 힌트일 뿐, 합치지 않는다
    possible = []
    for m in misp:
        for g in idx_groups_sharing(m, idx):
            if g not in possible:
                possible.append(g)
    out = {"query": name, "attack": atk, "misp": misp, "possible_attack_groups": [g for g in possible if g not in {a["id"] for a in atk}]}
    if len(atk) == 1:
        out.update(action="link", reason="exact_attack_match", link_to=atk[0]["id"])
    elif len(atk) > 1:
        out.update(action="review", reason="ambiguous_attack_alias", link_to=None)
    elif misp:
        out.update(action="review", reason="misp_only_candidate", link_to=None)
    else:
        out.update(action="none", reason="not_found", link_to=None)
    return out


def idx_groups_sharing(misp_hit: dict, idx: dict) -> list:
    """MISP 항목이 가진 이름·별칭 중 ATT&CK 그룹과 겹치는 것을 찾아 그 그룹 ID를 돌려준다(힌트용)."""
    out = []
    for key, entries in idx.items():
        if any(e["source"] == "misp" and e["id"] == misp_hit["id"] for e in entries):
            out.extend(e["id"] for e in entries if e["source"] == "attack")
    return sorted(set(out))


def review_rows(attack: dict, misp: dict) -> list:
    """MISP 항목마다 겹치는 ATT&CK 그룹을 모은 사람 확인용 표."""
    idx = build_index(attack, misp)
    rows = []
    for a in misp["actors"]:
        hit = {"id": a.get("uuid")}
        groups = idx_groups_sharing(hit, idx)
        names = {norm(n) for n in [a["name"], *a.get("synonyms", [])]}
        # 이 항목의 이름·별칭을 쓰는 MISP 항목이 또 있는지(모호한 별칭)
        dup = sorted({e["name"] for n in names for e in idx[n] if e["source"] == "misp" and e["id"] != a.get("uuid")})
        rows.append([a["name"], "; ".join(a.get("synonyms", [])), a.get("country") or "", a.get("state_sponsor") or "",
                     "; ".join(f"{g} {attack['groups'][g]['name']}" for g in groups),
                     "; ".join(dup), "겹치는 ATT&CK 그룹 없음" if not groups else ("둘 이상" if len(groups) > 1 else "하나")])
    return rows


# ── 자체 시험(가짜 데이터) ──────────────────────────────────────────────────
def self_test() -> None:
    attack = {"groups": {
        "G1": {"name": "Alpha", "aliases": ["Alpha", "Bluebird", "Shared"], "techniques": [], "software": []},
        "G2": {"name": "Beta", "aliases": ["Beta", "Shared"], "techniques": [], "software": []},
    }}
    misp = {"actors": [
        {"uuid": "m1", "name": "ALPHA Group", "synonyms": ["Bluebird", "Sky Crew"], "country": "XX", "state_sponsor": None},
        {"uuid": "m2", "name": "Gamma", "synonyms": ["Sky Crew"], "country": None, "state_sponsor": None},
        {"uuid": "m3", "name": "Delta", "synonyms": [], "country": None, "state_sponsor": None},
    ]}
    idx = build_index(attack, misp)
    r = lookup_actor("  alpha ", idx, attack)                         # 대소문자와 공백은 무시하고 ATT&CK 한 곳에 일치
    assert (r["action"], r["link_to"]) == ("link", "G1")
    r = lookup_actor("Bluebird", idx, attack)                        # ATT&CK 별칭으로 연결. MISP도 같은 별칭이지만 합치지는 않는다
    assert (r["action"], r["link_to"]) == ("link", "G1") and [m["id"] for m in r["misp"]] == ["m1"]
    r = lookup_actor("Shared", idx, attack)                          # 두 그룹의 별칭이면 모호 → 사람 확인
    assert (r["action"], r["reason"]) == ("review", "ambiguous_attack_alias") and len(r["attack"]) == 2
    r = lookup_actor("Sky Crew", idx, attack)                        # MISP에만 있음(두 항목) → 후보만 제시. m1은 ATT&CK 그룹과 별칭을 공유
    assert (r["action"], r["reason"]) == ("review", "misp_only_candidate") and {m["id"] for m in r["misp"]} == {"m1", "m2"}
    assert r["possible_attack_groups"] == ["G1"]                     # 힌트일 뿐 연결하지 않는다
    assert r["link_to"] is None
    r = lookup_actor("Delta", idx, attack)                           # 겹치는 ATT&CK 그룹이 없는 MISP 항목
    assert (r["action"], r["possible_attack_groups"]) == ("review", [])
    r = lookup_actor("Alph", idx, attack)                            # 부분 일치는 쓰지 않는다
    assert r["action"] == "none"
    assert lookup_actor("Unknown Crew", idx, attack)["action"] == "none"
    rows = review_rows(attack, misp)
    by = {x[0]: x for x in rows}
    assert by["ALPHA Group"][4] == "G1 Alpha" and by["ALPHA Group"][6] == "하나"
    assert by["ALPHA Group"][5] == "Gamma"                           # 'Sky Crew'를 쓰는 다른 MISP 항목
    assert by["Delta"][6] == "겹치는 ATT&CK 그룹 없음"
    print("자체 시험 통과")


if __name__ == "__main__":
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass
    a = sys.argv[1:]
    if not a:
        self_test()
    else:
        atk = json.loads((DATA / "attack_catalog.json").read_text(encoding="utf-8"))
        mp = json.loads((DATA / "misp_threat_actors.json").read_text(encoding="utf-8"))
        if a[0] == "review":
            dest = HERE / "backbone" / "export" / "actor_alias_candidates.csv"
            dest.parent.mkdir(parents=True, exist_ok=True)
            rows = review_rows(atk, mp)
            with open(dest, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(["misp_name", "synonyms", "country", "state_sponsor", "attack_groups_sharing_alias", "other_misp_actors_sharing_alias", "attack_overlap"])
                w.writerows(rows)
            from collections import Counter
            print("저장:", dest, f"({len(rows)}행)")
            print(dict(Counter(r[6] for r in rows)), "| 같은 별칭을 쓰는 다른 MISP 항목이 있는 행:", sum(1 for r in rows if r[5]))
        else:
            idx = build_index(atk, mp)
            print(json.dumps(lookup_actor(" ".join(a), idx, atk), ensure_ascii=False, indent=2))
