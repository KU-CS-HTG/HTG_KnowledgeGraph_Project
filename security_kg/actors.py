"""위협 행위자 이름 조회와 새 노드 계획: ATT&CK은 연결하고, MISP는 후보로만 제시하고, 어디에도 없으면 확인 대기 노드로 둔다.

문제: 같은 행위자를 업체마다 다른 이름으로 부른다(Kimsuky, Velvet Chollima, Thallium, 김수키 ...). 반대로 한 별칭이 서로
다른 행위자에 쓰이기도 한다(MISP에서 48개 별칭이 둘 이상의 항목에 나온다). 이름 문자열만으로 합치면 사건 해소에서 겪은
것과 같은 잘못된 합치기가 생기므로, 이 파일은 정확히 일치할 때만 연결하고 나머지는 사람이 확인하게 한다.

조회 순서(lookup_actor, 대소문자와 공백만 무시한 정확한 일치):
  1. ATT&CK 그룹 한 곳의 이름·별칭과 일치            → link   (reason: exact_attack_match)
  2. ATT&CK 그룹 둘 이상에 일치                       → review (모호. 새 노드를 만들지 않는다)
  3. 별칭 사전(consts.ACTOR_ALIAS_SEED)에 있음         → link   (reason: alias_seed. 사람이 확인한 별칭만 들어 있다)
  4. ATT&CK 소프트웨어(악성코드·도구)의 이름과 일치     → review (reason: matches_software. 행위자가 아니라 종류 오류일 수 있음)
  5. MISP에만 일치                                     → review (후보 제시. 합치지 않는다)
  6. 어디에도 없음                                     → none
plan_actor는 위 결과에 새 노드 정책(consts.ACTOR_NEW_NODE_POLICY)을 적용한다: 연결되면 새 노드 없음, 모호하거나
소프트웨어 이름이면 노드를 만들지 않고 확인, 5·6번은 `document_added`, `pending_review` 표시가 붙은 새 노드를 만든다.
AI가 영문명을 제안했으면 같은 조회를 한 결과를 `ai_suggestion`으로만 붙이고 확정으로 세지 않는다.
이름 유사도로 자동 합치지 않는다. 같은 이름(정확히 같은 철자)이 여러 문서에서 나오면 한 대기 항목으로만 묶는다.

사용: python actors.py "김수키"        # 한 이름의 계획 (data/ 필요)
      python actors.py review          # MISP↔ATT&CK 별칭 겹침 CSV (backbone/export/actor_alias_candidates.csv)
      python actors.py                 # 자체 시험
"""
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402

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


def build_seed_index(seed: dict) -> dict:
    """별칭 사전 → 정규화한 별칭 → ATT&CK 그룹 ID 목록."""
    out = defaultdict(list)
    for gid, e in (seed or {}).items():
        for n in e["aliases"]:
            out[norm(n)].append(gid)
    return out


def build_software_index(attack: dict) -> dict:
    out = defaultdict(list)
    for sid, sw in attack.get("software", {}).items():
        for n in {sw["name"], *sw.get("aliases", [])}:
            out[norm(n)].append({"id": sid, "name": sw["name"], "type": sw["type"]})
    return out


def validate_alias_seed(seed: dict, attack: dict) -> list:
    """별칭 사전의 그룹 ID가 실제 ATT&CK 목록에 있고 이름이 맞는지 점검한다. 문제 목록을 돌려준다."""
    problems = []
    for gid, e in seed.items():
        g = attack["groups"].get(gid)
        if g is None:
            problems.append(f"{gid}: ATT&CK 목록에 없음")
        elif g["name"] != e["canonical"]:
            problems.append(f"{gid}: 이름이 다름 (사전 {e['canonical']}, 목록 {g['name']})")
    return problems


def _dedupe(entries):
    seen, out = set(), []
    for e in entries:
        k = (e["source"], e["id"])
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out


def idx_groups_sharing(misp_hit: dict, idx: dict) -> list:
    """MISP 항목이 가진 이름·별칭 중 ATT&CK 그룹과 겹치는 것을 찾아 그 그룹 ID를 돌려준다(힌트용)."""
    out = []
    for entries in idx.values():
        if any(e["source"] == "misp" and e["id"] == misp_hit["id"] for e in entries):
            out.extend(e["id"] for e in entries if e["source"] == "attack")
    return sorted(set(out))


def lookup_actor(name: str, idx: dict, attack: dict, seed: dict | None = None) -> dict:
    hits = _dedupe(idx.get(norm(name), []))
    atk = [h for h in hits if h["source"] == "attack"]
    misp = [h for h in hits if h["source"] == "misp"]
    seeded = sorted(set(build_seed_index(seed).get(norm(name), [])))
    software = build_software_index(attack).get(norm(name), [])
    possible = []
    for m in misp:
        for g in idx_groups_sharing(m, idx):
            if g not in possible:
                possible.append(g)
    out = {"query": name, "attack": atk, "misp": misp, "software": software, "seed": seeded,
           "possible_attack_groups": [g for g in possible if g not in {a["id"] for a in atk}]}
    if len(atk) == 1:
        out.update(action="link", reason="exact_attack_match", link_to=atk[0]["id"])
    elif len(atk) > 1:
        out.update(action="review", reason="ambiguous_attack_alias", link_to=None)
    elif len(seeded) == 1:
        out.update(action="link", reason="alias_seed", link_to=seeded[0])
    elif len(seeded) > 1:
        out.update(action="review", reason="ambiguous_alias_seed", link_to=None)
    elif software:
        out.update(action="review", reason="matches_software", link_to=None)
    elif misp:
        out.update(action="review", reason="misp_only_candidate", link_to=None)
    else:
        out.update(action="none", reason="not_found", link_to=None)
    return out


def plan_actor(name: str, idx: dict, attack: dict, seed: dict | None = None, ai_english_name: str | None = None,
               doc_id: str | None = None) -> dict:
    """문서가 쓴 행위자 이름 하나에 대한 처리 계획. 연결할지, 새 노드를 만들지, 사람 확인을 요청할지를 정한다."""
    pol = consts.ACTOR_NEW_NODE_POLICY
    r = lookup_actor(name, idx, attack, seed)
    plan = {"name": name, "doc_id": doc_id, "action": r["action"], "reason": r["reason"], "link_to": r["link_to"],
            "create_node": False, "node": None, "candidates": {"attack": r["attack"], "misp": r["misp"],
                                                                 "software": r["software"],
                                                                 "possible_attack_groups": r["possible_attack_groups"]}}
    if r["reason"] in ("misp_only_candidate", "not_found"):
        plan["create_node"] = True
        plan["node"] = {"name": name, "type": "ThreatActor", "origin": pol["origin"], "status": pol["status"]}
    if r["reason"] == "matches_software" and not pol["skip_if_software_name"]:
        plan["create_node"] = True
        plan["node"] = {"name": name, "type": "ThreatActor", "origin": pol["origin"], "status": pol["status"]}
    if ai_english_name and plan["link_to"] is None:
        s = lookup_actor(ai_english_name, idx, attack, seed)
        plan["ai_suggestion"] = {"english_name": ai_english_name, "status": pol["ai_english_name"],
                                 "link_to": s["link_to"], "reason": s["reason"]}   # 확정이 아니다. 사람이 확인해야 한다
    return plan


def consolidate_pending(plans: list) -> list:
    """같은 철자(대소문자와 공백 무시)로 나온 확인 대기 항목만 하나로 묶는다. 비슷한 이름은 묶지 않는다."""
    groups = {}
    for p in plans:
        if p["action"] == "link":
            continue
        g = groups.setdefault(norm(p["name"]), {"name": p["name"], "reason": p["reason"], "docs": [], "create_node": p["create_node"],
                                                "candidates": p["candidates"], "ai_suggestions": []})
        if p["doc_id"] is not None and p["doc_id"] not in g["docs"]:
            g["docs"].append(p["doc_id"])
        if p.get("ai_suggestion") and p["ai_suggestion"] not in g["ai_suggestions"]:
            g["ai_suggestions"].append(p["ai_suggestion"])
    return sorted(groups.values(), key=lambda g: (-len(g["docs"]), g["name"]))


def review_rows(attack: dict, misp: dict) -> list:
    """MISP 항목마다 겹치는 ATT&CK 그룹을 모은 사람 확인용 표."""
    idx = build_index(attack, misp)
    rows = []
    for a in misp["actors"]:
        groups = idx_groups_sharing({"id": a.get("uuid")}, idx)
        names = {norm(n) for n in [a["name"], *a.get("synonyms", [])]}
        dup = sorted({e["name"] for n in names for e in idx[n] if e["source"] == "misp" and e["id"] != a.get("uuid")})
        rows.append([a["name"], "; ".join(a.get("synonyms", [])), a.get("country") or "", a.get("state_sponsor") or "",
                     "; ".join(f"{g} {attack['groups'][g]['name']}" for g in groups),
                     "; ".join(dup), "겹치는 ATT&CK 그룹 없음" if not groups else ("둘 이상" if len(groups) > 1 else "하나")])
    return rows


# ── 자체 시험(가짜 데이터) ──────────────────────────────────────────────────
def self_test() -> None:
    attack = {"groups": {
        "G0001": {"name": "Alpha", "aliases": ["Alpha", "Bluebird", "Shared"], "techniques": [], "software": []},
        "G0002": {"name": "Beta", "aliases": ["Beta", "Shared"], "techniques": [], "software": []},
    }, "software": {"S1": {"name": "FakeMal", "type": "malware", "aliases": ["FakeMal", "FM"], "techniques": []}}}
    misp = {"actors": [
        {"uuid": "m1", "name": "ALPHA Group", "synonyms": ["Bluebird", "Sky Crew"], "country": "XX", "state_sponsor": None},
        {"uuid": "m2", "name": "Gamma", "synonyms": ["Sky Crew"], "country": None, "state_sponsor": None},
        {"uuid": "m3", "name": "Delta", "synonyms": [], "country": None, "state_sponsor": None},
    ]}
    seed = {"G0001": {"canonical": "Alpha", "aliases": ["알파", "Al"]}}
    idx = build_index(attack, misp)
    L = lambda n, s=None: lookup_actor(n, idx, attack, s)   # noqa: E731

    # 조회: ATT&CK 정확 일치, 모호, MISP만, 없음
    r = L("  alpha ")
    assert (r["action"], r["link_to"], r["reason"]) == ("link", "G0001", "exact_attack_match")
    r = L("Bluebird")                                              # ATT&CK 별칭으로 연결. MISP도 같은 별칭이지만 합치지 않는다
    assert r["link_to"] == "G0001" and [m["id"] for m in r["misp"]] == ["m1"]
    r = L("Shared")
    assert (r["action"], r["reason"]) == ("review", "ambiguous_attack_alias") and len(r["attack"]) == 2
    r = L("Sky Crew")
    assert (r["action"], r["reason"]) == ("review", "misp_only_candidate") and {m["id"] for m in r["misp"]} == {"m1", "m2"}
    assert r["possible_attack_groups"] == ["G0001"] and r["link_to"] is None   # 힌트일 뿐 연결하지 않는다
    assert L("Delta")["possible_attack_groups"] == []
    assert L("Alph")["action"] == "none"                           # 부분 일치는 쓰지 않는다
    assert L("Unknown Crew")["reason"] == "not_found"

    # 별칭 사전: 사전에 있으면 연결, 없으면 그대로
    assert L("알파")["action"] == "none"                            # 사전을 주지 않으면 연결되지 않는다
    r = L("알파", seed)
    assert (r["action"], r["reason"], r["link_to"]) == ("link", "alias_seed", "G0001")
    assert L("  AL ", seed)["link_to"] == "G0001"                  # 대소문자와 공백 무시
    r = lookup_actor("알파", idx, attack, {"G0001": {"canonical": "Alpha", "aliases": ["알파"]},
                                              "G0002": {"canonical": "Beta", "aliases": ["알파"]}})
    assert (r["action"], r["reason"]) == ("review", "ambiguous_alias_seed")   # 사전이 모호하면 연결하지 않는다
    assert validate_alias_seed(seed, attack) == []
    assert "G9999" in validate_alias_seed({"G9999": {"canonical": "X", "aliases": ["x"]}}, attack)[0]
    assert "이름이 다름" in validate_alias_seed({"G0001": {"canonical": "Wrong", "aliases": ["x"]}}, attack)[0]

    # 악성코드 이름은 행위자로 새 노드를 만들지 않는다
    r = L("FakeMal")
    assert (r["action"], r["reason"]) == ("review", "matches_software")
    assert plan_actor("FakeMal", idx, attack, seed)["create_node"] is False

    # 새 노드 계획
    p = plan_actor("알파", idx, attack, seed, doc_id="d1")           # 연결되면 새 노드가 없다
    assert (p["action"], p["create_node"], p["node"]) == ("link", False, None)
    p = plan_actor("Shared", idx, attack, seed)                      # 모호하면 노드를 만들지 않고 확인
    assert (p["action"], p["create_node"]) == ("review", False)
    p = plan_actor("Unknown Crew", idx, attack, seed, doc_id="d1")   # 어디에도 없으면 확인 대기 노드
    assert p["create_node"] is True
    assert p["node"] == {"name": "Unknown Crew", "type": "ThreatActor", "origin": "document_added", "status": "pending_review"}
    p = plan_actor("Delta", idx, attack, seed)                       # MISP에만 있어도 새 노드이지만 후보를 함께 준다
    assert p["create_node"] is True and p["candidates"]["misp"][0]["id"] == "m3"

    # AI가 제안한 영문명은 후보일 뿐 연결하지 않는다
    p = plan_actor("솔트", idx, attack, seed, ai_english_name="Alpha")
    assert p["link_to"] is None and p["create_node"] is True
    assert p["ai_suggestion"] == {"english_name": "Alpha", "status": "ai_suggested", "link_to": "G0001", "reason": "exact_attack_match"}
    p = plan_actor("솔트", idx, attack, seed, ai_english_name="Nonexistent")
    assert p["ai_suggestion"]["link_to"] is None

    # 대기열: 같은 철자만 묶고 비슷한 이름은 묶지 않으며, 연결된 것은 제외한다
    plans = [plan_actor("Unknown Crew", idx, attack, seed, doc_id="d1"), plan_actor("unknown  crew", idx, attack, seed, doc_id="d2"),
             plan_actor("Unknown Crews", idx, attack, seed, doc_id="d3"), plan_actor("알파", idx, attack, seed, doc_id="d4")]
    q = consolidate_pending(plans)
    assert [(g["name"], g["docs"]) for g in q] == [("Unknown Crew", ["d1", "d2"]), ("Unknown Crews", ["d3"])]

    # MISP↔ATT&CK 확인표
    by = {x[0]: x for x in review_rows(attack, misp)}
    assert by["ALPHA Group"][4] == "G0001 Alpha" and by["ALPHA Group"][5] == "Gamma" and by["Delta"][6] == "겹치는 ATT&CK 그룹 없음"
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
                w.writerow(["misp_name", "synonyms", "country", "state_sponsor", "attack_groups_sharing_alias",
                            "other_misp_actors_sharing_alias", "attack_overlap"])
                w.writerows(rows)
            from collections import Counter
            print("저장:", dest, f"({len(rows)}행)")
            print(dict(Counter(r[6] for r in rows)), "| 같은 별칭을 쓰는 다른 MISP 항목이 있는 행:", sum(1 for r in rows if r[5]))
            bad = validate_alias_seed(consts.ACTOR_ALIAS_SEED, atk)
            print("별칭 사전 점검:", "문제 없음" if not bad else bad)
        else:
            idx = build_index(atk, mp)
            print(json.dumps(plan_actor(" ".join(a), idx, atk, consts.ACTOR_ALIAS_SEED), ensure_ascii=False, indent=2))
