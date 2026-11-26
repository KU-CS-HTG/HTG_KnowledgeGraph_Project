"""행위자 확인 대기열 처리: 시트 만들기, 사람의 결정 반영, 스냅샷 갱신 때 옮기기, AI 이름 응답 검증.

actors.py가 만든 확인 대기 항목(consolidate_pending)을 사람이 처리하는 절차다. 화면은 없고 CSV 시트로 한다.

  1) sheet   : 대기 항목 → 확인용 CSV. `decision` 칸을 사람이 채운다
                 link:G0094     이 이름은 ATT&CK 그룹 G0094의 별칭이다 (별칭 사전에 더해진다)
                 new            ATT&CK에 없는 새 행위자가 맞다 (pending_review → confirmed_new)
                 reject         행위자가 아니다 / reject:malware 처럼 종류를 적으면 그 종류로 다시 보낸다
                 (빈칸)         아직 결정하지 않음
  2) apply   : 채운 시트를 data/actor_decisions.json에 반영한다. 잘못된 칸은 반영하지 않고 이유를 알려 준다. 다시 반영해도 중복되지 않는다.
  3) migrate : ATT&CK 스냅샷을 새로 받은 뒤, 확인 대기·확정 새 행위자가 이제 ATT&CK에 정확히 일치하는지 보고서를 만든다.
                 자동으로 옮기지 않는다. 사람이 승인한 이름만 옮김 기록(migrated)에 남긴다.
  4) AI 이름 응답 검증(parse_ai_name_response): 응답 형식, 종류(악성코드는 행위자가 아님), 원문 존재를 점검한다.

결정 저장소(data/actor_decisions.json)는 actors.plan_actor가 읽는다. 결정이 있어도 ATT&CK에 정확히 일치하면 연결이 우선한다.

사용: python actor_review.py sheet <pending.json> <out.csv>
      python actor_review.py apply <sheet.csv> --by <이름>
      python actor_review.py migrate [<pending.json>]
      python actor_review.py                        # 자체 시험
"""
import csv
import datetime
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import consts  # noqa: E402
import actors  # noqa: E402

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
DECISIONS_PATH = DATA / "actor_decisions.json"
SHEET_HEADER = ["name", "docs", "reason", "create_node", "attack_candidates", "misp_candidates", "software_candidates",
                "possible_attack_groups", "ai_suggestion", "decision", "note"]


def load_decisions(path: Path | None = None) -> dict:
    path = Path(path or DECISIONS_PATH)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else actors.empty_decisions()


def save_decisions(d: dict, path: Path | None = None) -> None:
    path = Path(path or DECISIONS_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


# ── 1) 시트 만들기 ─────────────────────────────────────────────────────────
def pending_to_sheet(pending: list, path: Path) -> int:
    """확인 대기 항목(consolidate_pending의 결과)을 시트로 쓴다. decision과 note 칸은 비워 둔다."""
    def names(entries):
        return "; ".join(f"{e['id']} {e['name']}" for e in entries)
    rows = []
    for g in pending:
        c = g["candidates"]
        ai = "; ".join(f"{a['english_name']} → {a['link_to'] or '일치 없음'} ({a['status']})" for a in g.get("ai_suggestions", []))
        rows.append([g["name"], "; ".join(map(str, g["docs"])), g["reason"], "예" if g["create_node"] else "",
                     names(c["attack"]), names(c["misp"]), names(c["software"]), "; ".join(c["possible_attack_groups"]), ai, "", ""])
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(SHEET_HEADER)
        w.writerows(rows)
    return len(rows)


# ── 2) 결정 반영 ───────────────────────────────────────────────────────────
def parse_decision(cell: str) -> tuple[str, str | None] | None:
    """칸의 값을 (종류, 값)으로 읽는다. 빈칸은 None(미결정). 읽을 수 없으면 ValueError."""
    c = (cell or "").strip()
    if not c:
        return None
    m = re.match(r"^(link|reject)\s*:\s*(\S+)$", c, re.I)
    if m:
        return m.group(1).lower(), m.group(2)
    if c.lower() in ("new", "reject"):
        return c.lower(), None
    raise ValueError(f"읽을 수 없는 결정: {c!r} (link:G0094, new, reject, reject:malware 중 하나)")


def apply_sheet(rows: list, decisions: dict, attack: dict, by: str, seed: dict | None = None,
                today: str | None = None) -> tuple[dict, dict]:
    """시트 행(딕셔너리 목록)을 결정에 반영한다. 반환: (결정, 보고서{applied, skipped, undecided}). 입력 결정은 바꾸지 않는다."""
    today = today or datetime.date.today().isoformat()
    d = json.loads(json.dumps(decisions))
    for k, v in actors.empty_decisions().items():
        d.setdefault(k, v)
    report = {"applied": [], "skipped": [], "undecided": []}
    atk_index = {}
    for gid, g in attack["groups"].items():
        for n in {g["name"], *g.get("aliases", [])}:
            atk_index.setdefault(actors.norm(n), set()).add(gid)
    for r in rows:
        name = r["name"].strip()
        try:
            dec = parse_decision(r.get("decision", ""))
        except ValueError as e:
            report["skipped"].append((name, str(e)))
            continue
        if dec is None:
            report["undecided"].append(name)
            continue
        kind, val = dec
        key = actors.norm(name)
        stamp = {"confirmed_by": by, "date": today, "note": (r.get("note") or "").strip()}
        if kind == "link":
            if val not in attack["groups"]:
                report["skipped"].append((name, f"ATT&CK 목록에 없는 그룹 {val}"))
                continue
            if key in atk_index:
                report["skipped"].append((name, "이미 ATT&CK 이름·별칭과 일치(연결은 자동이므로 결정이 필요 없음)"))
                continue
            current = actors.effective_seed(seed, d)
            other = [gid for gid, e in current.items() if key in {actors.norm(a) for a in e["aliases"]} and gid != val]
            if other:
                report["skipped"].append((name, f"이미 다른 그룹 {other[0]}의 별칭임"))
                continue
            slot = d["confirmed_aliases"].setdefault(val, {"canonical": attack["groups"][val]["name"], "aliases": []})
            if key not in {actors.norm(a["alias"] if isinstance(a, dict) else a) for a in slot["aliases"]}:
                slot["aliases"].append({"alias": name, **stamp})
            report["applied"].append((name, f"link:{val}"))
        elif kind == "new":
            if key in atk_index:
                report["skipped"].append((name, "이미 ATT&CK에 있는 이름이라 새 행위자가 아님"))
                continue
            if key not in actors._decided(d, "confirmed_new"):
                d["confirmed_new"].append({"name": name, **stamp})
            report["applied"].append((name, "new"))
        else:   # reject
            if key not in actors._decided(d, "rejected"):
                d["rejected"].append({"name": name, "reroute": val, **stamp})
            report["applied"].append((name, f"reject:{val}" if val else "reject"))
    return d, report


# ── 3) 스냅샷 갱신 때 옮기기 ───────────────────────────────────────────────
def migration_report(names: list, decisions: dict, attack: dict, misp: dict, seed: dict | None = None) -> list:
    """이름(확인 대기와 확정 새 행위자)이 새 스냅샷에서 이제 ATT&CK에 정확히 일치하는지, 별칭 사전의 그룹이 아직 있는지 점검한다.
    제안만 만든다. 자동으로 옮기지 않는다."""
    idx = actors.build_index(attack, misp)
    seed_eff = actors.effective_seed(seed, decisions)
    out = []
    for name in sorted({*names, *(x["name"] for x in decisions.get("confirmed_new", []))}, key=actors.norm):
        r = actors.lookup_actor(name, idx, attack, {})   # 결정과 사전 없이 ATT&CK/MISP만 본다(스냅샷이 바뀐 것만 보려는 것)
        if r["reason"] == "exact_attack_match":
            out.append({"name": name, "proposal": "now_in_attack", "to": r["link_to"], "group": attack["groups"][r["link_to"]]["name"]})
        elif r["reason"] == "ambiguous_attack_alias":
            out.append({"name": name, "proposal": "ambiguous_now", "to": [a["id"] for a in r["attack"]]})
        else:
            out.append({"name": name, "proposal": "unchanged", "to": None})
    for gid, e in seed_eff.items():
        if gid not in attack["groups"]:
            out.append({"name": e["canonical"], "proposal": "group_missing_in_snapshot", "to": gid})
        elif attack["groups"][gid]["name"] != e["canonical"]:
            out.append({"name": e["canonical"], "proposal": "group_renamed", "to": f"{gid} → {attack['groups'][gid]['name']}"})
    return out


def apply_migration(decisions: dict, report: list, accept: list, today: str | None = None) -> dict:
    """사람이 승인한 이름만 옮김 기록에 남기고 확정 새 행위자 목록에서 뺀다. 입력은 바꾸지 않는다."""
    today = today or datetime.date.today().isoformat()
    d = json.loads(json.dumps(decisions))
    d.setdefault("migrated", {})
    ok = {actors.norm(a) for a in accept}
    for r in report:
        if r["proposal"] == "now_in_attack" and actors.norm(r["name"]) in ok:
            d["migrated"][r["name"]] = {"to": r["to"], "date": today}
            d["confirmed_new"] = [x for x in d.get("confirmed_new", []) if actors.norm(x["name"]) != actors.norm(r["name"])]
    return d


# ── 4) AI 이름 응답 검증 ───────────────────────────────────────────────────
def parse_ai_name_response(resp, document_text: str | None = None) -> list:
    """AI의 응답(JSON 문자열 또는 딕셔너리)을 검증한다. 항목마다 accepted와 issues를 붙인다.
    행위자가 아닌 종류, 원문에 없는 이름은 accepted=False. english_name은 문자열이 아니면 버린다(확정으로 세지 않음)."""
    try:
        obj = json.loads(resp) if isinstance(resp, str) else resp
        items = obj["names"]
        if not isinstance(items, list):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        raise ValueError("응답 형식이 올바르지 않음: {'names': [...]} 이어야 함")
    out = []
    for it in items:
        issues = []
        name = it.get("name_as_written") if isinstance(it, dict) else None
        if not isinstance(name, str) or not name.strip():
            out.append({"name": None, "accepted": False, "issues": ["no_name"]})
            continue
        ntype = it.get("name_type")
        if ntype not in consts.ACTOR_NAME_TYPES:
            issues.append("bad_name_type")
        elif ntype != "threat_actor":
            issues.append(f"not_actor:{ntype}")
        en = it.get("english_name")
        if en is not None and not (isinstance(en, str) and en.strip()):
            issues.append("bad_english_name")
            en = None
        if document_text is not None and actors.norm(name) not in actors.norm(document_text):
            issues.append("name_not_in_document")
        conf = it.get("confidence") if it.get("confidence") in ("high", "medium", "low") else None
        out.append({"name": name.strip(), "english_name": en.strip() if en else None, "name_type": ntype, "confidence": conf,
                    "evidence": it.get("evidence"), "accepted": not issues, "issues": issues})
    return out


# ── 자체 시험(가짜 데이터) ──────────────────────────────────────────────────
def self_test() -> None:
    import tempfile
    attack = {"groups": {"G0001": {"name": "Alpha", "aliases": ["Alpha", "Bluebird"], "techniques": [], "software": []},
                         "G0002": {"name": "Beta", "aliases": ["Beta"], "techniques": [], "software": []}},
              "software": {"S1": {"name": "FakeMal", "type": "malware", "aliases": ["FakeMal"], "techniques": []}}}
    misp = {"actors": [{"uuid": "m1", "name": "Delta", "synonyms": [], "country": None, "state_sponsor": None}]}
    idx = actors.build_index(attack, misp)
    seed = {"G0001": {"canonical": "Alpha", "aliases": ["알파"]}}

    # 대기 항목 만들기 → 시트 → 사람이 채움 → 반영
    names = [("솔트", "d1", "Alpha"), ("솔트", "d2", None), ("델타", "d3", None), ("페이크멀", "d4", None), ("신규집단", "d5", None), ("Bluebird", "d6", None)]
    plans = [actors.plan_actor(n, idx, attack, seed, ai_english_name=ai, doc_id=d) for n, d, ai in names]
    pend = actors.consolidate_pending(plans)
    assert [g["name"] for g in pend if g["name"] != "솔트"] and {g["name"] for g in pend} == {"솔트", "델타", "페이크멀", "신규집단"}   # Bluebird는 연결돼 대기열에 없음
    with tempfile.TemporaryDirectory() as td:
        sheet = Path(td) / "s.csv"
        assert pending_to_sheet(pend, sheet) == 4
        raw = sheet.read_bytes()
        assert raw.startswith(b"\xef\xbb\xbf")
        rows = list(csv.DictReader(raw.decode("utf-8-sig").splitlines()))
        by_name = {r["name"]: r for r in rows}
        assert by_name["솔트"]["docs"] == "d1; d2" and "ai_suggested" in by_name["솔트"]["ai_suggestion"]
        assert "<generator" not in raw.decode("utf-8-sig") and "None" not in raw.decode("utf-8-sig")
        by_name["솔트"]["decision"] = "link:G0001"
        by_name["델타"]["decision"] = "new"
        by_name["페이크멀"]["decision"] = "reject:malware"
        by_name["신규집단"]["decision"] = ""                       # 미결정
        dec, rep = apply_sheet(rows, actors.empty_decisions(), attack, by="tester", seed=seed, today="2099-01-01")
        assert sorted(a[1] for a in rep["applied"]) == ["link:G0001", "new", "reject:malware"] and rep["undecided"] == ["신규집단"]
        assert dec["confirmed_aliases"]["G0001"]["aliases"][0]["alias"] == "솔트"
        # 반영한 결정이 plan_actor에 영향을 준다
        assert actors.plan_actor("솔트", idx, attack, seed, decisions=dec)["link_to"] == "G0001"             # 별칭이 사전에 더해짐
        p = actors.plan_actor("델타", idx, attack, seed, decisions=dec)
        assert p["node"]["status"] == "confirmed_new" and p["create_node"] is True                             # 확정 새 행위자
        p = actors.plan_actor("페이크멀", idx, attack, seed, decisions=dec)
        assert (p["action"], p["reason"], p["create_node"], p["rejection"]["reroute"]) == ("rejected", "human_rejected", False, "malware")
        assert actors.plan_actor("신규집단", idx, attack, seed, decisions=dec)["node"]["status"] == "pending_review"   # 미결정은 그대로
        # 다시 반영해도 중복되지 않는다(멱등)
        dec2, rep2 = apply_sheet(rows, dec, attack, by="tester", seed=seed, today="2099-01-02")
        assert len(dec2["confirmed_aliases"]["G0001"]["aliases"]) == 1 and len(dec2["confirmed_new"]) == 1 and len(dec2["rejected"]) == 1
        # 입력 결정은 바뀌지 않는다
        assert actors.empty_decisions()["confirmed_aliases"] == {}
        # 파일로 저장하고 다시 읽는다
        pth = Path(td) / "d.json"
        save_decisions(dec, pth)
        assert load_decisions(pth) == dec and load_decisions(Path(td) / "none.json") == actors.empty_decisions()

    # 잘못된 결정은 반영하지 않고 이유를 알려 준다
    bad = [{"name": "A", "decision": "link:G9999"}, {"name": "Bluebird", "decision": "link:G0002"}, {"name": "B", "decision": "maybe"},
           {"name": "알파", "decision": "link:G0002"}, {"name": "Alpha", "decision": "new"}]
    d3, rep3 = apply_sheet(bad, actors.empty_decisions(), attack, by="t", seed=seed)
    assert rep3["applied"] == [] and len(rep3["skipped"]) == 5
    assert "없는 그룹" in rep3["skipped"][0][1] and "이미 ATT&CK" in rep3["skipped"][1][1] and "읽을 수 없는" in rep3["skipped"][2][1]
    assert "다른 그룹 G0001" in rep3["skipped"][3][1] and "새 행위자가 아님" in rep3["skipped"][4][1]
    assert d3 == {**actors.empty_decisions()}

    # 스냅샷 갱신: 새 스냅샷에 그룹이 생겼을 때 옮기기 제안
    new_attack = {"groups": {**attack["groups"], "G0003": {"name": "신규집단", "aliases": ["신규집단"], "techniques": [], "software": []}},
                  "software": attack["software"]}
    rep = migration_report(["신규집단", "솔트"], dec, new_attack, misp, seed)
    prop = {r["name"]: r for r in rep}
    assert prop["신규집단"]["proposal"] == "now_in_attack" and prop["신규집단"]["to"] == "G0003"
    assert prop["델타"]["proposal"] == "unchanged"
    gone = {"groups": {"G0002": attack["groups"]["G0002"]}, "software": {}}
    assert any(r["proposal"] == "group_missing_in_snapshot" and r["to"] == "G0001" for r in migration_report([], dec, gone, misp, seed))
    d4 = apply_migration(dec, rep, accept=["신규집단"], today="2099-02-01")
    assert d4["migrated"] == {"신규집단": {"to": "G0003", "date": "2099-02-01"}}
    assert apply_migration(dec, rep, accept=[])["migrated"] == {}                                   # 승인하지 않으면 옮기지 않는다
    assert d4["confirmed_new"] == dec["confirmed_new"]                                              # 이름이 확정 목록에 없었으면 그대로

    # AI 이름 응답 검증
    doc = "The group Fancy Bear and the backdoor FakeMal were involved."
    good = {"names": [{"name_as_written": "Fancy Bear", "english_name": "APT28", "name_type": "threat_actor", "confidence": "high", "evidence": "x"},
                      {"name_as_written": "FakeMal", "english_name": None, "name_type": "malware", "confidence": "low", "evidence": "x"},
                      {"name_as_written": "Ghost Crew", "english_name": 5, "name_type": "threat_actor", "evidence": "x"},
                      {"name_as_written": "Odd", "name_type": "alien"}, {"x": 1}]}
    r = parse_ai_name_response(json.dumps(good), document_text=doc)
    assert r[0]["accepted"] and r[0]["english_name"] == "APT28"
    assert not r[1]["accepted"] and "not_actor:malware" in r[1]["issues"]                          # 악성코드는 행위자가 아님
    assert "name_not_in_document" in r[2]["issues"] and "bad_english_name" in r[2]["issues"] and r[2]["english_name"] is None
    assert "bad_name_type" in r[3]["issues"] and r[4]["issues"] == ["no_name"]
    assert parse_ai_name_response({"names": []}) == []
    for badresp in ("not json", {"names": "x"}, {"other": []}):
        try:
            parse_ai_name_response(badresp)
            raise AssertionError("형식 오류를 못 잡음")
        except ValueError:
            pass
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
        if a[0] == "sheet":
            n = pending_to_sheet(json.loads(Path(a[1]).read_text(encoding="utf-8")), Path(a[2]))
            print(f"저장: {a[2]} ({n}행). decision 칸을 채운 뒤 `apply`로 반영하세요.")
        elif a[0] == "apply":
            by = a[a.index("--by") + 1] if "--by" in a else None
            if not by:
                sys.exit("--by <이름>이 필요합니다(누가 확인했는지 기록합니다).")
            with open(a[1], encoding="utf-8-sig", newline="") as f:
                rows = list(csv.DictReader(f))
            d, rep = apply_sheet(rows, load_decisions(), atk, by, consts.ACTOR_ALIAS_SEED)
            save_decisions(d)
            print(f"반영 {len(rep['applied'])}, 건너뜀 {len(rep['skipped'])}, 미결정 {len(rep['undecided'])}")
            for n, why in rep["skipped"]:
                print("  건너뜀:", n, "-", why)
        elif a[0] == "migrate":
            pend = [g["name"] for g in json.loads(Path(a[1]).read_text(encoding="utf-8"))] if len(a) > 1 else []
            for r in migration_report(pend, load_decisions(), atk, mp, consts.ACTOR_ALIAS_SEED):
                print(r)
