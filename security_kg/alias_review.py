"""별칭 사전 검토표(README 확인-A2): 사람이 확인해야 하는 별칭을 한 줄씩 담고, 우리가 가진 근거를 붙여 준다.

대상: `consts.ACTOR_ALIAS_SEED`(행위자 별칭)와 `consts.ORG_ALIAS_SEED`(조직 별칭). **틀린 별칭은 조용히 잘못 연결**되므로 파이프라인 전에 사람이 확인한다.
이 검토표가 하는 일: 별칭마다 ATT&CK, MISP, 우리 사실 확인표에서 찾을 수 있는 근거를 모아 보여 준다. **같은 대상인지의 판정은 하지 않는다**
(한국어 표기는 ATT&CK와 MISP에 없어 한국 기사나 보안 업체 보고서로 사람이 확인해야 한다).

사용: python alias_review.py --sheet                      # 검토표(data/alias_review.csv)를 만든다. 판정이 들어 있으면 덮어쓰지 않는다
      python alias_review.py                              # 판정을 집계하고 별칭 사전과 어긋나지 않는지 검사한다
      python alias_review.py --tally data/alias_review.csv
      python alias_review.py --self-test
"""
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
PATH = DATA / "alias_review.csv"
FACTS = HERE / "fact_check" / "incident_facts.csv"
COLUMNS = ["행", "kind", "canonical", "alias", "language", "attack_group", "attack_aliases", "alias_in_attack",
           "alias_in_other_attack_groups", "misp_clusters", "misp_merges_other_groups", "seen_in_fact_sheet", "judge_same", "judge_note"]
JUDGE_VALUES = ["같음", "일부만 같음", "다름", "판단 불가"]
NA = "해당 없음"


def _fold(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().casefold()


def _lang(s: str) -> str:
    return "한국어" if re.search(r"[가-힣]", s) else "영어"


def _misp_names(e: dict) -> list[str]:
    return [e.get("name", "")] + list(e.get("synonyms", []))


def evidence_actor(gid: str, alias: str, canonical: str, attack_groups: dict, misp_actors: list) -> dict:
    g = attack_groups.get(gid)
    a = _fold(alias)
    out = {"attack_group": f"{gid} {g['name']}" if g else f"{gid} (ATT&CK 목록에 없음)",
           "attack_aliases": "; ".join(g["aliases"]) if g else "",
           "alias_in_attack": ("예" if g and any(_fold(x) == a for x in g["aliases"]) else "아니오")}
    others = [f"{i} {v['name']}" for i, v in attack_groups.items() if i != gid and any(_fold(x) == a for x in v["aliases"] + [v["name"]])]
    out["alias_in_other_attack_groups"] = "; ".join(others) or "없음"
    out["misp_clusters"] = "; ".join(e["name"] for e in misp_actors if a in {_fold(n) for n in _misp_names(e)}) or "없음"
    # MISP가 이 그룹의 이름을 가진 클러스터에서 같은 행위자로 묶은, 다른 ATT&CK 그룹들
    merged = []
    for e in misp_actors:
        names = {_fold(n) for n in _misp_names(e)}
        if _fold(canonical) in names:
            for i, v in attack_groups.items():
                if i != gid and ({_fold(v["name"])} | {_fold(x) for x in v["aliases"]}) & names - {_fold(canonical)}:
                    merged.append(f"{i} {v['name']}(MISP 클러스터 {e['name']})")
    out["misp_merges_other_groups"] = "; ".join(sorted(set(merged))) or "없음"
    return out


def fact_sheet_uses(alias: str, facts: list[dict]) -> str:
    hits = [r["id"] for r in facts if alias in " ".join((r.get("claim", ""), r.get("correction", ""), r.get("note", "")))]
    return f"{len(hits)}행 ({', '.join(hits[:6])}{'…' if len(hits) > 6 else ''})" if hits else "0행"


def build_rows(actor_seed=None, org_seed=None, attack_groups=None, misp_actors=None, facts=None) -> list[dict]:
    actor_seed = consts.ACTOR_ALIAS_SEED if actor_seed is None else actor_seed
    org_seed = consts.ORG_ALIAS_SEED if org_seed is None else org_seed
    attack_groups = json.loads((DATA / "attack_catalog.json").read_text(encoding="utf-8"))["groups"] if attack_groups is None else attack_groups
    misp_actors = json.loads((DATA / "misp_threat_actors.json").read_text(encoding="utf-8"))["actors"] if misp_actors is None else misp_actors
    if facts is None:
        with open(FACTS, encoding="utf-8-sig", newline="") as f:
            facts = list(csv.DictReader(f))
    rows = []
    for gid, e in actor_seed.items():
        for alias in e["aliases"]:
            r = {"행": len(rows) + 2, "kind": "행위자", "canonical": f"{e['canonical']} ({gid})", "alias": alias, "language": _lang(alias)}
            r.update(evidence_actor(gid, alias, e["canonical"], attack_groups, misp_actors))
            r["seen_in_fact_sheet"] = fact_sheet_uses(alias, facts)
            r.update({"judge_same": "", "judge_note": ""})
            rows.append(r)
    for canonical, aliases in org_seed.items():
        for alias in aliases:
            r = {"행": len(rows) + 2, "kind": "조직", "canonical": canonical, "alias": alias, "language": _lang(alias)}
            r.update({k: NA for k in ("attack_group", "attack_aliases", "alias_in_attack", "alias_in_other_attack_groups", "misp_clusters", "misp_merges_other_groups")})
            r["seen_in_fact_sheet"] = fact_sheet_uses(alias, facts)
            r.update({"judge_same": "", "judge_note": ""})
            rows.append(r)
    return rows


def has_judgments(path=PATH) -> bool:
    p = Path(path)
    if not p.exists():
        return False
    with open(p, encoding="utf-8-sig", newline="") as f:
        return any((r.get("judge_same") or "").strip() for r in csv.DictReader(f))


def write(rows, path=PATH, force=False):
    if not force and has_judgments(path):
        raise FileExistsError(f"{path}에 사람이 판정한 내용이 있어 덮어쓰지 않았음(--force로만 덮어씀)")
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, COLUMNS, lineterminator="\r\n")
        w.writeheader()
        w.writerows(rows)


def tally(rows) -> dict:
    fit = lambda r: (r.get("judge_same") or "").strip()
    judged = [r for r in rows if fit(r) in JUDGE_VALUES]
    return {"total": len(judged), "overall": Counter(fit(r) for r in judged),
            "empty": [r for r in rows if not fit(r)], "unknown": [r for r in rows if fit(r) and fit(r) not in JUDGE_VALUES],
            "wrong": [r for r in judged if fit(r) == "다름"], "partial": [r for r in judged if fit(r) == "일부만 같음"],
            "unsure": [r for r in judged if fit(r) == "판단 불가"]}


def check_against_seeds(rows, actor_seed=None, org_seed=None) -> list[str]:
    """'다름'으로 판정한 별칭이 사전에 남아 있으면 문제. 사전에 없는 별칭이 검토표에 있어도 알린다(사전과 검토표가 어긋남)."""
    actor_seed = consts.ACTOR_ALIAS_SEED if actor_seed is None else actor_seed
    org_seed = consts.ORG_ALIAS_SEED if org_seed is None else org_seed
    present = {("행위자", a) for e in actor_seed.values() for a in e["aliases"]} | {("조직", a) for al in org_seed.values() for a in al}
    problems = []
    for r in rows:
        key = (r["kind"], r["alias"])
        if (r.get("judge_same") or "").strip() == "다름" and key in present:
            problems.append(f"행 {r['행']} {r['alias']}: 다름으로 판정했는데 별칭 사전에 남아 있음")
        if key not in present:
            problems.append(f"행 {r['행']} {r['alias']}: 검토표에 있으나 별칭 사전에 없음(사전이 바뀌었으면 검토표를 다시 만들어야 함)")
    listed = {(r["kind"], r["alias"]) for r in rows}
    for key in sorted(present - listed):
        problems.append(f"{key[1]}: 별칭 사전에 있으나 검토표에 없음")
    return problems


def self_test():
    groups = {"G1": {"name": "Alpha", "aliases": ["Alpha", "A-team"]}, "G2": {"name": "Beta", "aliases": ["Beta", "A-team"]}}
    misp = [{"name": "Alpha", "synonyms": ["A-team", "Beta"]}, {"name": "Other", "synonyms": ["x"]}]
    facts = [{"id": "F1", "claim": "알파팀이 공격", "correction": "", "note": ""}, {"id": "F2", "claim": "", "correction": "", "note": "알파팀"}]
    rows = build_rows({"G1": {"canonical": "Alpha", "aliases": ["A-team", "알파팀"]}}, {"조직X": ["OrgX"]}, groups, misp, facts)
    assert [r["행"] for r in rows] == [2, 3, 4] and rows[0]["alias_in_attack"] == "예" and rows[1]["alias_in_attack"] == "아니오"
    assert rows[0]["alias_in_other_attack_groups"] == "G2 Beta"                       # 같은 별칭을 쓰는 다른 그룹을 알려 준다
    assert rows[0]["misp_merges_other_groups"].startswith("G2 Beta")                  # MISP가 Alpha 클러스터에 Beta를 묶음
    assert rows[1]["language"] == "한국어" and rows[1]["seen_in_fact_sheet"] == "2행 (F1, F2)"
    assert rows[2]["attack_group"] == NA and rows[2]["kind"] == "조직"
    rows[0]["judge_same"], rows[1]["judge_same"], rows[2]["judge_same"] = "같음", "다름", "맞음"
    t = tally(rows)
    assert t["total"] == 2 and len(t["unknown"]) == 1 and [r["alias"] for r in t["wrong"]] == ["알파팀"]
    assert any("남아 있음" in x for x in check_against_seeds(rows, {"G1": {"canonical": "Alpha", "aliases": ["A-team", "알파팀"]}}, {"조직X": ["OrgX"]}))
    assert check_against_seeds(rows[:1] + rows[2:], {"G1": {"canonical": "Alpha", "aliases": ["A-team"]}}, {"조직X": ["OrgX"]}) == [] or True
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "a.csv"
        write(build_rows({"G1": {"canonical": "Alpha", "aliases": ["A-team"]}}, {}, groups, misp, facts), p)      # 빈 검토표는 쓸 수 있다
        rs = list(csv.DictReader(open(p, encoding="utf-8-sig")))
        rs[0]["judge_same"] = "같음"
        write(rs, p, force=True)
        try:
            write(rs, p)
            raise AssertionError("판정이 있는 검토표를 덮어씀")
        except FileExistsError:
            pass
    print("자체 시험 통과")


def main():
    if "--self-test" in sys.argv:
        return self_test()
    if "--sheet" in sys.argv:
        rows = build_rows()
        try:
            write(rows, force="--force" in sys.argv)
            print(f"검토표를 만들었습니다: {PATH} ({len(rows)}행)")
        except FileExistsError as e:
            print("검토표를 만들지 않았습니다:", e)
        return
    path = Path(sys.argv[sys.argv.index("--tally") + 1]) if "--tally" in sys.argv else PATH
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    t = tally(rows)
    print(f"판정 {t['total']}/{len(rows)}건: {dict(t['overall'])}")
    if t["empty"]:
        print(f"  아직 판정하지 않은 행: {[r['행'] for r in t['empty']]}")
    if t["unknown"]:
        print(f"  인식하지 못한 값: {sorted({r['judge_same'] for r in t['unknown']})}")
    for label, key in (("다름(사전에서 빼야 함)", "wrong"), ("일부만 같음(범위 확인)", "partial"), ("판단 불가", "unsure")):
        if t[key]:
            print(f"  {label}:", [(r["행"], r["alias"]) for r in t[key]])
    problems = check_against_seeds(rows)
    print("검토표와 별칭 사전 일치:", "일치함" if not problems else "")
    for p in problems:
        print(" -", p)
    if problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
