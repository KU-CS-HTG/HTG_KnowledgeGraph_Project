"""기법 층: 서술형 행동 → ATT&CK 매핑 → 악성코드에서 기법 유도 (결정 D5~D8).

문제: 뉴스는 "악성코드를 설치했다"처럼 평이하게 쓰고 ATT&CK는 표준 이름의 기법이다. 닫힌 목록에 맞추다 실패하면
사실이 버려지고, 억지로 맞추면 틀린 매핑이 생긴다. 그래서 세 층으로 나눈다.

  1층 서술형 행동(AttackBehavior): 문서가 말한 행동을 평이한 말로 기록한다. 맞출 수 없어도 사라지지 않는다.
  2층 ATT&CK 매핑: 별도 단계에서 후보를 붙인다. 문서가 기법 이름·ID를 직접 쓰면 그대로 받고, AI가 맞춘 것은
     사람이 확인하기 전까지 확정으로 세지 않는다. 맞는 것이 없으면 no_match로 두고 억지로 맞추지 않는다.
  3층 뼈대 유도: 이름 있는 악성코드는 ATT&CK에서 기법을 가져오되 "문서의 주장이 아니라 뼈대 유도"로 구분한다.

이 파일은 AI를 호출하지 않는다. AI가 낸 후보와 사람이 확인한 결과를 받아 검증하고 집계한다.
후보는 반드시 내려받은 ATT&CK 목록 안의 것이어야 하고, 목록에 없는 ID는 버린다(환각 방지).

카탈로그 형식: {technique_id: {"name": str, "tactics": [str], "parent": str | None}}
소프트웨어 대응: {소프트웨어 이름(소문자): [technique_id, ...]}

사용: python attack_mapping.py   # 자체 시험 실행
"""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402


# ── ATT&CK STIX 번들에서 카탈로그 만들기 ──────────────────────────────────
def load_catalog_from_stix(bundle: dict) -> dict:
    """ATT&CK STIX 2.1 번들(JSON)에서 기법 목록을 만든다.
    사용하는 필드: type=attack-pattern, external_references[source_name=mitre-attack].external_id,
    kill_chain_phases[kill_chain_name=mitre-attack].phase_name, revoked, x_mitre_deprecated.
    (STIX 필드 이름은 ATT&CK STIX 데이터 모델에 대한 일반 지식이며 실제 번들로 시험하지 않았다.)"""
    catalog = {}
    for o in bundle.get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = next((r.get("external_id") for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
        if not tid:
            continue
        tactics = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        catalog[tid] = {"name": o.get("name", ""), "tactics": tactics, "parent": tid.split(".")[0] if "." in tid else None}
    return catalog


def load_software_map(bundle: dict, catalog: dict) -> dict:
    """소프트웨어(malware, tool) → 기법 대응. relationship_type == 'uses'인 관계에서 만든다."""
    objs = {o["id"]: o for o in bundle.get("objects", []) if "id" in o}
    tech_id = {}
    for o in objs.values():
        if o.get("type") == "attack-pattern":
            for r in o.get("external_references", []):
                if r.get("source_name") == "mitre-attack" and r.get("external_id") in catalog:
                    tech_id[o["id"]] = r["external_id"]
    out = defaultdict(set)
    for o in objs.values():
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses":
            src, tgt = objs.get(o.get("source_ref")), o.get("target_ref")
            if src and src.get("type") in ("malware", "tool") and tgt in tech_id:
                out[src["name"].casefold()].add(tech_id[tgt])
    return {k: sorted(v) for k, v in out.items()}


# ── 2층: 후보 검증 ─────────────────────────────────────────────────────
def _join_notes(*notes):
    return "; ".join(n for n in notes if n) or None


def validate_candidates(candidates: list[dict], catalog: dict, specific: bool = False, replaced: dict | None = None):
    """AI가 낸 후보를 검사한다. 반환: (유효한 후보, 버려진 후보와 이유).
    - 카탈로그에 없는 ID는 버린다(환각 방지). 폐기된 기법이면 대체 ID가 있을 때 대체하고(note에 남김),
      없으면 stale_id로 버린다. 버리되 조용히 사라지지 않게 호출한 쪽이 이유를 받는다.
    - 하위 기법은 근거(specific_evidence)가 있을 때만 유지하고, 없으면 상위 기법으로 올린다(결정 D7).
      `specific=True`를 주면 근거 없이도 유지한다(호출한 쪽이 구체성을 직접 보증하는 경우).
    - evidence_strength는 AI confidence와 별개다. 허용 값이 아니면 inferred로 낮춘다."""
    replaced = replaced or {}
    valid, dropped = [], []
    for c in candidates:
        c = dict(c)
        tid = c.get("technique_id")
        if tid not in catalog:
            new = replaced.get(tid)
            if new and new in catalog:
                c["technique_id"], c["note"] = new, _join_notes(c.get("note"), f"replaced_from_{tid}")
                tid = new
            else:
                dropped.append({**c, "reason": "stale_id" if tid in replaced else "unknown_id"})
                continue
        parent = catalog[tid]["parent"]
        keep_sub = specific or bool(str(c.get("specific_evidence") or "").strip())
        if parent and not keep_sub and consts.ALLOW_SUBTECHNIQUE_ONLY_IF_SPECIFIC and parent in catalog:
            c["technique_id"], c["note"] = parent, _join_notes(c.get("note"), f"rolled_up_from_{tid}")
        if c.get("confidence") not in consts.MAPPING_CONFIDENCE_LEVELS:
            c["confidence"] = "low"
        if c.get("evidence_strength") is not None and c["evidence_strength"] not in consts.MAPPING_EVIDENCE_STRENGTH:
            c["evidence_strength"] = "inferred"
        valid.append(c)
    return valid, dropped


def effective_techniques(record: dict, catalog: dict, specific: bool = False, replaced: dict | None = None) -> list[dict]:
    """매핑 기록 하나에서 지금 답으로 보여 줄 기법을 상태 규칙에 따라 고른다.
    확정(counted)은 사람이 확인한 것(human_confirmed)과, 출처가 confirmed로 쓴 기법 이름·ID(documented)뿐이다.
    사람이 확정했거나 문서가 쓴 기법의 ID가 ATT&CK 갱신으로 사라졌으면 비우지 않고 stale 항목으로 남긴다."""
    status = record.get("status")
    if status in ("human_rejected", "no_match", None):
        return []
    valid, dropped = validate_candidates(record.get("candidates", []), catalog, specific, replaced)
    counted = status == "human_confirmed" or (status == "documented" and record.get("assertion_status") == "confirmed") or (
        status == "ai_suggested" and not consts.MAPPING_REQUIRES_HUMAN_CONFIRMATION)
    out, seen = [], set()
    for c in valid:
        if c["technique_id"] in seen:
            continue
        seen.add(c["technique_id"])
        info = catalog[c["technique_id"]]
        out.append({"id": c["technique_id"], "name": info["name"], "tactics": info["tactics"],
                    "label": status, "counted": counted, "confidence": c.get("confidence"), "note": c.get("note"),
                    "evidence_strength": c.get("evidence_strength"), "specific_evidence": c.get("specific_evidence"),
                    "evidence_quote": c.get("evidence_quote"), "reviewed_by": record.get("reviewed_by"),
                    "reviewed_at": record.get("reviewed_at"), "attack_version": record.get("attack_version")})
    if status in ("human_confirmed", "documented"):
        for d in dropped:
            out.append({"id": d.get("technique_id"), "name": None, "tactics": [], "label": status, "counted": False,
                        "stale": True, "note": d["reason"], "confidence": d.get("confidence"),
                        "reviewed_by": record.get("reviewed_by"), "reviewed_at": record.get("reviewed_at"),
                        "attack_version": record.get("attack_version")})
    return out


# ── 3층: 뼈대 유도 ─────────────────────────────────────────────────────
def software_map_from_catalog(software: dict) -> dict:
    """내려받은 ATT&CK 소프트웨어({S번호: {"name", "aliases", "techniques"}})에서 {이름 또는 별칭(소문자): [기법]}을 만든다.
    같은 악성코드를 별칭(예: JustForFun)으로 불러도 찾을 수 있게 한다."""
    out = {}
    for s in software.values():
        techs = sorted(set(s.get("techniques", [])))
        for name in [s.get("name", "")] + list(s.get("aliases", [])):
            if name:
                out.setdefault(name.casefold(), techs)
    return out


def derive_from_malware(malware_names: list[str], software_map: dict, catalog: dict) -> list[dict]:
    """이름 있는 악성코드에서 ATT&CK 기법을 가져온다. 모르는 악성코드는 추측하지 않는다(결정 D8: 표시해서 포함).
    이것은 그 악성코드가 알려진 기능이지 이 사건에서 실제로 실행된 기법이 아니므로 counted=False이고 전용 이름표를 붙인다."""
    if not consts.INCLUDE_BACKBONE_DERIVED_TECHNIQUES:
        return []
    derived = {}
    for name in malware_names:
        for tid in software_map.get(name.casefold(), []):
            if tid in catalog:
                d = derived.setdefault(tid, {"id": tid, "name": catalog[tid]["name"], "tactics": catalog[tid]["tactics"],
                                             "label": consts.BACKBONE_DERIVED_LABEL, "counted": False, "from_malware": []})
                d["from_malware"].append(name)
    return sorted(derived.values(), key=lambda d: d["id"])


# ── 집계 ──────────────────────────────────────────────────────────
def _resolve_documented(name_or_id: str, catalog: dict, replaced: dict | None = None):
    """문서가 쓴 기법 이름·ID를 카탈로그의 ID로 바꾼다. 반환: (ID 또는 None, 메모). 폐기된 ID는 대체 ID가 있으면 대체한다."""
    replaced = replaced or {}
    if name_or_id in catalog:
        return name_or_id, None
    new = replaced.get(name_or_id)
    if new and new in catalog:
        return new, f"replaced_from_{name_or_id}"
    by_name = {v["name"].casefold(): k for k, v in catalog.items()}
    return by_name.get(name_or_id.casefold()), None


def _tactic_label(tech: dict) -> str:
    """전술 집계에서 쓰는 이름표. 사람이 확정한 것은 confirmed, 문서가 쓴 것은 출처가 confirmed일 때만 documented."""
    if tech["label"] == "human_confirmed":
        return "confirmed"
    if tech["label"] == "documented":
        return "documented" if tech.get("counted") else "documented_unconfirmed"
    return tech["label"]


def summarize_attack_layer(triplets: list[dict], mapping_records: dict, software_map: dict, catalog: dict,
                           replaced: dict | None = None) -> dict:
    """사건 하나의 기법 층. mapping_records: {서술형 행동 문장: 매핑 기록}."""
    # 서술형 행동
    groups = defaultdict(lambda: {"docs": set(), "statuses": set()})
    for t in triplets:
        if t.get("relation") == "USED_BEHAVIOR":
            g = groups[t["target_entity_instance"]]
            g["docs"].add(t.get("doc_id"))
            g["statuses"].add(t.get("assertion_status", "inferred"))
    behaviors = []
    for text, g in groups.items():
        rec = mapping_records.get(text)
        techs = effective_techniques(rec, catalog, replaced=replaced) if rec else []
        behaviors.append({
            "behavior": text, "n_documents": len(g["docs"]),
            "best_status": min(g["statuses"], key=lambda s: consts.ASSERTION_RANK.get(s, 99)),
            "mapping_status": rec["status"] if rec else "unmapped", "techniques": techs,
        })
    behaviors.sort(key=lambda b: (consts.ASSERTION_RANK.get(b["best_status"], 99), -b["n_documents"], b["behavior"]))

    # 문서가 기법 이름·ID를 직접 쓴 것. 출처마다 주장(claims)을 모두 보존하고, 확정은 출처가 confirmed일 때만 센다.
    # 카탈로그에 없으면 조용히 받지 않고 따로 알린다
    documented, unrecognized = {}, []
    for t in triplets:
        if t.get("relation") == "USED_TECHNIQUE":
            tid, note = _resolve_documented(t["target_entity_instance"], catalog, replaced)
            if tid:
                d = documented.setdefault(tid, {"id": tid, "name": catalog[tid]["name"], "tactics": catalog[tid]["tactics"],
                                                "label": "documented", "claims": [], "note": None})
                d["claims"].append({"doc_id": t.get("doc_id"), "assertion_status": t.get("assertion_status", "inferred")})
                d["note"] = d["note"] or note
            else:
                unrecognized.append(t["target_entity_instance"])
    for d in documented.values():
        statuses = {c["assertion_status"] for c in d["claims"]}
        d["n_documents"] = len({c["doc_id"] for c in d["claims"]})
        d["best_status"] = min(statuses, key=lambda s: consts.ASSERTION_RANK.get(s, 99))
        d["counted"] = "confirmed" in statuses

    # 악성코드 → 뼈대 유도
    malware = sorted({t["target_entity_instance"] for t in triplets if t.get("relation") == "USED_MALWARE"})
    derived = derive_from_malware(malware, software_map, catalog)

    # 전술 단위 집계(사건 간 비교의 기준, 결정 D7). 같은 기법은 출처가 여럿이어도 가장 강한 하나만 센다.
    rank = {k: i for i, k in enumerate(consts.TECHNIQUE_LABEL_PRIORITY)}
    strongest = {}
    for tech in list(documented.values()) + [x for b in behaviors for x in b["techniques"] if not x.get("stale")] + derived:
        lab = _tactic_label(tech)
        cur = strongest.get(tech["id"])
        if cur is None or rank.get(lab, 99) < rank.get(cur["label"], 99):
            strongest[tech["id"]] = {"label": lab, "tactics": tech["tactics"], "sources": set(cur["sources"]) if cur else set()}
        strongest[tech["id"]]["sources"].add(lab)
    tactics = defaultdict(lambda: defaultdict(int))
    for info in strongest.values():
        for tac in info["tactics"]:
            tactics[tac][info["label"]] += 1
    stale = [x for b in behaviors for x in b["techniques"] if x.get("stale")]
    return {
        "behaviors": behaviors,
        "documented_techniques": sorted(documented.values(), key=lambda d: d["id"]),
        "unrecognized_techniques": sorted(set(unrecognized)),
        "stale_techniques": stale,
        "malware": malware,
        "derived_techniques": derived,
        "technique_summary": {k: {"label": v["label"], "sources": sorted(v["sources"], key=lambda x: rank.get(x, 99))}
                              for k, v in sorted(strongest.items())},
        "tactics": {k: dict(v) for k, v in sorted(tactics.items())},
    }


def render_attack_layer(layer: dict) -> str:
    lines = ["  (c) 기법 층:"]
    for b in layer["behaviors"]:
        lines.append(f"    - 행동: {b['behavior']} [{b['best_status']}, 문서 {b['n_documents']}개]")
        if b["mapping_status"] == "unmapped":
            lines.append("        ATT&CK 매핑: 아직 매핑 안 됨")
        elif b["mapping_status"] == "no_match":
            lines.append("        ATT&CK 매핑: 맞는 기법 없음 (서술형으로 유지)")
        elif not b["techniques"]:
            lines.append(f"        ATT&CK 매핑: {b['mapping_status']} (표시할 기법 없음)")
        for x in b["techniques"]:
            if x.get("stale"):
                lines.append(f"        ATT&CK: {x['id']} [{x['label']}] ※ATT&CK 갱신으로 목록에서 사라짐({x['note']}), 다시 확인 필요")
                continue
            flag = "확정" if x["counted"] else "※사람 확인 전(확정 아님)"
            lines.append(f"        ATT&CK: {x['id']} {x['name']} [{x['label']}, {flag}]")
    for x in layer["documented_techniques"]:
        flag = "확정" if x["counted"] else f"※출처의 확정 수준이 {x['best_status']}라 확정 아님"
        lines.append(f"    - 문서가 직접 쓴 기법: {x['id']} {x['name']} [documented, 문서 {x['n_documents']}개, {flag}]")
    for name in layer["unrecognized_techniques"]:
        lines.append(f"    - 문서가 쓴 기법 이름을 ATT&CK 목록에서 찾지 못함: {name}")
    for x in layer["derived_techniques"]:
        lines.append(f"    - 뼈대 유도: {x['id']} {x['name']} ({', '.join(x['from_malware'])}에서 유도, 문서의 주장이 아님)")
    if layer["tactics"]:
        lines.append("    전술별 집계(기법마다 가장 강한 하나만 셈): " + "; ".join(f"{k} {dict(v)}" for k, v in layer["tactics"].items()))
    return "\n".join(lines)


# ── 자체 시험 ─────────────────────────────────────────────────────────────
def _test_catalog() -> dict:
    """시험용 가짜 목록이다. ID, 이름, 전술은 실제 ATT&CK 값이 아니다."""
    return {
        "T9001": {"name": "Example Supply Chain Technique", "tactics": ["initial-access"], "parent": None},
        "T9002": {"name": "Example Credential Forgery", "tactics": ["credential-access"], "parent": None},
        "T9002.001": {"name": "Example Forged Token", "tactics": ["credential-access"], "parent": "T9002"},
        "T9003": {"name": "Example Signaling", "tactics": ["defense-evasion", "command-and-control"], "parent": None},
        "T9003.002": {"name": "Example Socket Filters", "tactics": ["defense-evasion", "command-and-control"], "parent": "T9003"},
    }


def _t(relation, target, status, doc):
    return {"relation": relation, "target_entity_instance": target, "assertion_status": status, "doc_id": doc}


def self_test() -> None:
    cat = _test_catalog()
    software = {"examplebackdoor": ["T9003.002"]}

    # 1) 환각 방지: 목록에 없는 ID는 버린다
    valid, dropped = validate_candidates([{"technique_id": "T9001", "confidence": "high"},
                                          {"technique_id": "T1234", "confidence": "high"}], cat)
    assert [v["technique_id"] for v in valid] == ["T9001"] and dropped[0]["reason"] == "unknown_id"

    # 2) 하위 기법: 문서가 구체적이지 않으면 상위로 올리고, 구체적이면 유지한다 (D7)
    v, _ = validate_candidates([{"technique_id": "T9002.001", "confidence": "high"}], cat, specific=False)
    assert v[0]["technique_id"] == "T9002" and v[0]["note"] == "rolled_up_from_T9002.001"
    v, _ = validate_candidates([{"technique_id": "T9002.001", "confidence": "high"}], cat, specific=True)
    assert v[0]["technique_id"] == "T9002.001"

    # 3) 알 수 없는 신뢰도는 낮음으로 처리한다
    assert validate_candidates([{"technique_id": "T9001", "confidence": "certain"}], cat)[0][0]["confidence"] == "low"

    # 4) 상태 규칙(D6): AI 제안은 확정으로 세지 않고, 사람 확인은 센다, 기각과 no_match는 비운다
    cand = [{"technique_id": "T9001", "confidence": "medium"}]
    assert effective_techniques({"status": "ai_suggested", "candidates": cand}, cat)[0]["counted"] is False
    assert effective_techniques({"status": "human_confirmed", "candidates": cand}, cat)[0]["counted"] is True
    assert effective_techniques({"status": "human_rejected", "candidates": cand}, cat) == []
    assert effective_techniques({"status": "no_match", "candidates": cand}, cat) == []

    # 5) 뼈대 유도(D8): 이름 있는 악성코드는 기법을 가져오되 이름표를 붙이고, 모르는 악성코드는 추측하지 않는다
    d = derive_from_malware(["ExampleBackdoor", "UnknownTool"], software, cat)
    assert len(d) == 1 and d[0]["id"] == "T9003.002" and d[0]["label"] == consts.BACKBONE_DERIVED_LABEL
    assert d[0]["counted"] is False and d[0]["from_malware"] == ["ExampleBackdoor"]

    # 6) 사건 하나의 기법 층: 서술형이 먼저, 매핑 상태가 다르고, 문서가 직접 쓴 기법과 유도 기법이 구분된다
    triplets = [
        _t("USED_BEHAVIOR", "forged login tokens with a retained signing key", "confirmed", "d1"),
        _t("USED_BEHAVIOR", "forged login tokens with a retained signing key", "confirmed", "d2"),
        _t("USED_BEHAVIOR", "used an autonomous AI penetration tool", "claimed", "d3"),
        _t("USED_BEHAVIOR", "replaced CDN scripts", "confirmed", "d4"),
        _t("USED_TECHNIQUE", "Example Supply Chain Technique", "confirmed", "d4"),
        _t("USED_TECHNIQUE", "Some Made Up Technique", "inferred", "d5"),
        _t("USED_MALWARE", "ExampleBackdoor", "confirmed", "d6"),
    ]
    records = {
        "forged login tokens with a retained signing key": {"status": "ai_suggested", "candidates": [{"technique_id": "T9002.001", "confidence": "medium"}]},
        "used an autonomous AI penetration tool": {"status": "no_match", "candidates": []},
    }
    layer = summarize_attack_layer(triplets, records, software, cat)
    by = {b["behavior"]: b for b in layer["behaviors"]}
    forged = by["forged login tokens with a retained signing key"]
    assert forged["n_documents"] == 2 and forged["mapping_status"] == "ai_suggested"
    assert forged["techniques"][0]["id"] == "T9002" and forged["techniques"][0]["counted"] is False   # 상위로 올림 + 확정 아님
    assert by["used an autonomous AI penetration tool"]["mapping_status"] == "no_match" and not by["used an autonomous AI penetration tool"]["techniques"]
    assert by["replaced CDN scripts"]["mapping_status"] == "unmapped"                                   # 매핑 기록이 없으면 사라지지 않고 "아직 안 됨"
    assert [x["id"] for x in layer["documented_techniques"]] == ["T9001"]
    assert layer["unrecognized_techniques"] == ["Some Made Up Technique"]                               # 목록에 없는 이름을 조용히 받지 않는다
    assert [x["id"] for x in layer["derived_techniques"]] == ["T9003.002"]

    # 7) 전술 집계는 출처를 나눠서 센다: 확정(문서가 쓴 것)과 AI 제안과 뼈대 유도가 섞이지 않는다
    tc = layer["tactics"]
    assert tc["initial-access"] == {"documented": 1}
    assert tc["credential-access"] == {"ai_suggested": 1}
    assert tc["defense-evasion"] == {consts.BACKBONE_DERIVED_LABEL: 1}

    # 8) 사람이 확인하면 확정으로 센다. 기각하면 빠진다
    records["forged login tokens with a retained signing key"]["status"] = "human_confirmed"
    assert summarize_attack_layer(triplets, records, software, cat)["tactics"]["credential-access"] == {"confirmed": 1}
    records["forged login tokens with a retained signing key"]["status"] = "human_rejected"
    assert "credential-access" not in summarize_attack_layer(triplets, records, software, cat)["tactics"]

    # 9) STIX 번들에서 카탈로그와 소프트웨어 대응을 만든다 (시험용 가짜 번들)
    bundle = {"objects": [
        {"type": "attack-pattern", "id": "ap--1", "name": "Example A", "external_references": [{"source_name": "mitre-attack", "external_id": "T9101"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]},
        {"type": "attack-pattern", "id": "ap--2", "name": "Example A Sub", "external_references": [{"source_name": "mitre-attack", "external_id": "T9101.001"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]},
        {"type": "attack-pattern", "id": "ap--3", "name": "Old", "revoked": True, "external_references": [{"source_name": "mitre-attack", "external_id": "T9102"}]},
        {"type": "malware", "id": "mw--1", "name": "FakeMalware"},
        {"type": "relationship", "id": "rel--1", "relationship_type": "uses", "source_ref": "mw--1", "target_ref": "ap--2"},
    ]}
    c2 = load_catalog_from_stix(bundle)
    assert set(c2) == {"T9101", "T9101.001"} and c2["T9101.001"]["parent"] == "T9101"      # 폐기된 항목은 제외
    assert load_software_map(bundle, c2) == {"fakemalware": ["T9101.001"]}

    # 10) 유도 기법을 끄면 나오지 않는다 (D8의 설정)
    old = consts.INCLUDE_BACKBONE_DERIVED_TECHNIQUES
    consts.INCLUDE_BACKBONE_DERIVED_TECHNIQUES = False
    try:
        assert derive_from_malware(["ExampleBackdoor"], software, cat) == []
    finally:
        consts.INCLUDE_BACKBONE_DERIVED_TECHNIQUES = old

    # 11) documented는 출처의 확정 수준을 따른다: claimed, inferred로 적힌 기법은 확정으로 세지 않는다 (재현된 버그 1)
    tr = [_t("USED_TECHNIQUE", "T9001", "claimed", "d1"), _t("USED_TECHNIQUE", "T9002", "inferred", "d2"),
          _t("USED_TECHNIQUE", "T9003", "confirmed", "d3")]
    L = summarize_attack_layer(tr, {}, {}, cat)
    cnt = {x["id"]: x["counted"] for x in L["documented_techniques"]}
    assert cnt == {"T9001": False, "T9002": False, "T9003": True}
    assert L["tactics"]["initial-access"] == {"documented_unconfirmed": 1} and L["tactics"]["defense-evasion"] == {"documented": 1}

    # 12) 같은 기법의 여러 출처 주장을 모두 보존하고 입력 순서에 따라 결과가 달라지지 않는다
    tr = [_t("USED_TECHNIQUE", "T9001", "claimed", "d1"), _t("USED_TECHNIQUE", "T9001", "confirmed", "d2")]
    d1 = summarize_attack_layer(tr, {}, {}, cat)["documented_techniques"][0]
    d2 = summarize_attack_layer(list(reversed(tr)), {}, {}, cat)["documented_techniques"][0]
    assert d1["counted"] is True and d1["best_status"] == "confirmed" and d1["n_documents"] == 2 and len(d1["claims"]) == 2
    assert (d1["counted"], d1["best_status"], d1["n_documents"]) == (d2["counted"], d2["best_status"], d2["n_documents"])

    # 13) 사람이 확정한 하위 기법은 근거(specific_evidence)가 있으면 유지하고, 없으면 상위로 올린다 (재현된 버그 2)
    rec_ev = {"status": "human_confirmed", "candidates": [{"technique_id": "T9002.001", "confidence": "high",
                                                           "specific_evidence": "the text says a forged login token was used", "evidence_strength": "direct"}]}
    rec_no = {"status": "human_confirmed", "candidates": [{"technique_id": "T9002.001", "confidence": "high"}]}
    r1, r2 = effective_techniques(rec_ev, cat)[0], effective_techniques(rec_no, cat)[0]
    assert r1["id"] == "T9002.001" and r1["counted"] is True and r1["evidence_strength"] == "direct"
    assert r2["id"] == "T9002" and r2["note"] == "rolled_up_from_T9002.001"
    assert validate_candidates([{"technique_id": "T9001", "evidence_strength": "certain"}], cat)[0][0]["evidence_strength"] == "inferred"

    # 14) 같은 기법을 가리키는 여러 행동과 출처가 전술 집계를 부풀리지 않는다 (재현된 버그 3)
    tr = [_t("USED_BEHAVIOR", "a", "confirmed", "d1"), _t("USED_BEHAVIOR", "b", "confirmed", "d2"),
          _t("USED_TECHNIQUE", "T9001", "confirmed", "d3")]
    rec = {"a": {"status": "human_confirmed", "candidates": [{"technique_id": "T9001"}]},
           "b": {"status": "human_confirmed", "candidates": [{"technique_id": "T9001"}]}}
    L = summarize_attack_layer(tr, rec, {}, cat)
    assert L["tactics"]["initial-access"] == {"confirmed": 1}                  # 세 출처가 있어도 하나
    assert L["technique_summary"]["T9001"] == {"label": "confirmed", "sources": ["confirmed", "documented"]}

    # 15) 폐기된 기법은 대체 ID로 바꾸거나 stale로 남기고 조용히 사라지지 않는다 (재현된 버그 4)
    cat2 = {k: v for k, v in cat.items() if k != "T9001"}
    rec_old = {"status": "human_confirmed", "candidates": [{"technique_id": "T9001"}]}
    st = effective_techniques(rec_old, cat2, replaced={"T9001": None})
    assert st[0]["stale"] is True and st[0]["note"] == "stale_id" and st[0]["counted"] is False
    st = effective_techniques(rec_old, cat2, replaced={"T9001": "T9002"})
    assert st[0]["id"] == "T9002" and st[0]["note"] == "replaced_from_T9001" and st[0].get("stale") is None
    L = summarize_attack_layer([_t("USED_BEHAVIOR", "a", "confirmed", "d1")], {"a": rec_old}, {}, cat2, replaced={"T9001": None})
    assert L["stale_techniques"][0]["id"] == "T9001" and "※ATT&CK 갱신" in render_attack_layer(L)
    assert effective_techniques({"status": "ai_suggested", "candidates": [{"technique_id": "T7777"}]}, cat2) == []   # AI 후보는 버려도 된다

    # 16) 악성코드 별칭으로도 유도 기법을 찾는다 (재현된 버그 5). 유도 기법은 끝까지 확정으로 세지 않는다
    sw = software_map_from_catalog({"S0001": {"name": "ExampleBackdoor", "aliases": ["ExampleBackdoor", "OldName"], "techniques": ["T9003.002"]}})
    d = derive_from_malware(["oldname"], sw, cat)
    assert d and d[0]["id"] == "T9003.002" and d[0]["counted"] is False

    print("자체 시험 16개 통과\n")
    records["forged login tokens with a retained signing key"]["status"] = "ai_suggested"
    print(render_attack_layer(summarize_attack_layer(triplets, records, software, cat)))


if __name__ == "__main__":
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass
    self_test()
