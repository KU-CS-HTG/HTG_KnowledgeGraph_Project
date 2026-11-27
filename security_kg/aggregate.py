"""사건 하나의 답을 칸((a) 취약점, (b) 약점·관리 실패, (c) 기법)별로 집계한다. 최소안.

원칙: 부재를 추측하지 않는다.
  - 칸에 해당하는 트리플렛이 있으면 상태는 "found"이고, 확정>주장>추정, 같으면 더 많은 문서가 말한 것 순으로 보여 준다.
  - 없으면 "없음"이 아니라 "not_mentioned"이고, 처리한 문서 수를 함께 쓴다.

입력: 한 사건(Incident)에 대한 트리플렛 목록. 각 항목은 dict이며 사용하는 키는 아래와 같다.
  relation, target_entity_instance, assertion_status, doc_id
  (assertion_status와 doc_id는 원본 파이프라인에 없는 칸이라 추출 단계에서 추가해야 한다)
n_documents: 이 사건을 다루는 것으로 처리한 문서 수 (문서 단위 필드 incident_mentions로 센다).

참고 정보(공격자 유형, 배후 지목)는 summarize_context로 같은 규칙을 적용한다. 질문의 칸에는 섞이지 않는다.

사용: python aggregate.py   # 자체 시험 실행
"""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402


def _group(triplets: list[dict], relations: list[str]) -> dict:
    groups = defaultdict(lambda: {"docs": set(), "statuses": set()})
    for t in triplets:
        if t.get("relation") in relations:
            g = groups[(t["relation"], t["target_entity_instance"])]
            g["docs"].add(t.get("doc_id"))
            g["statuses"].add(t.get("assertion_status", "inferred"))
    return groups


def canonical_state(state: str) -> str:
    """집계의 칸 상태(found, not_mentioned)를 정답표의 어휘(answered, not_mentioned_in_sources)로 바꾼다.
    not_confirmed(조사 중)는 이 최소안이 표현하지 못한다(README의 보류한 확장안)."""
    return consts.SLOT_STATE_ALIASES.get(state, state)


def summarize_context(triplets: list[dict], n_documents: int) -> dict:
    """참고 정보(공격자 유형, 배후 지목 등). 칸과 같은 규칙이고, 값이 여러 개면 사람이 확인하도록 표시한다."""
    out = summarize_fields(triplets, n_documents, consts.CONTEXT_FIELDS)
    for field in consts.REVIEW_IF_MULTIPLE_VALUES:
        out[field]["needs_review"] = len({i["target"] for i in out[field]["items"]}) > 1
    for i in out["actor_origin"]["items"]:      # VERIS 데이터와 비교할 수 있도록 대응값을 붙인다
        i["veris"] = consts.ACTOR_ORIGIN_TO_VERIS.get(i["target"])
    return out


def summarize_incident(triplets: list[dict], n_documents: int) -> dict:
    return summarize_fields(triplets, n_documents, consts.ANSWER_SLOTS)


def summarize_fields(triplets: list[dict], n_documents: int, fields: dict) -> dict:
    result = {}
    for slot, relations in fields.items():
        groups = _group(triplets, relations)
        if not groups:
            text = (consts.NOT_MENTIONED_TEXT.format(n=n_documents) if n_documents > 0
                    else consts.NO_DOCUMENTS_TEXT)
            result[slot] = {"state": "not_mentioned", "n_documents": n_documents, "text": text, "items": []}
            continue
        items = []
        for (relation, target), g in groups.items():
            best = min(g["statuses"], key=lambda s: consts.ASSERTION_RANK.get(s, 99))
            items.append({
                "relation": relation, "target": target, "best_status": best,
                "statuses": sorted(g["statuses"], key=lambda s: consts.ASSERTION_RANK.get(s, 99)),
                "n_documents": len(g["docs"]),
                "mixed_statuses": len(g["statuses"]) > 1,   # 문서마다 확정/주장/추정이 다르게 쓴 경우
            })
        items.sort(key=lambda i: (consts.ASSERTION_RANK.get(i["best_status"], 99), -i["n_documents"], i["target"]))
        result[slot] = {"state": "found", "n_documents": n_documents, "items": items}
    return result


def summarize_campaign(members: dict[str, dict]) -> dict:
    """묶음(Campaign)의 답 = 소속 사건들의 답을 합산한 것 (결정 D1).
    members: {incident_id: {"triplets": [...], "n_documents": int}}.
    같은 답이 더 많은 사건에서 나오면 먼저 보여 준다(예: 여러 금융사에 공통으로 쓰인 기법)."""
    total_docs = sum(m["n_documents"] for m in members.values())
    result = {}
    for slot, relations in consts.ANSWER_SLOTS.items():
        groups = defaultdict(lambda: {"incidents": set(), "docs": set(), "statuses": set()})
        for inc_id, m in members.items():
            for t in m["triplets"]:
                if t.get("relation") in relations:
                    g = groups[(t["relation"], t["target_entity_instance"])]
                    g["incidents"].add(inc_id)
                    g["docs"].add((inc_id, t.get("doc_id")))
                    g["statuses"].add(t.get("assertion_status", "inferred"))
        if not groups:
            result[slot] = {"state": "not_mentioned", "n_incidents": len(members), "items": [],
                            "text": f"확인되지 않음: 소속 사건 {len(members)}개(문서 {total_docs}개) 모두에서 언급 없음"}
            continue
        items = [{"relation": r, "target": tg,
                  "n_incidents": len(g["incidents"]), "incident_ids": sorted(g["incidents"]),
                  "n_documents": len(g["docs"]),
                  "best_status": min(g["statuses"], key=lambda s: consts.ASSERTION_RANK.get(s, 99)),
                  "statuses": sorted(g["statuses"], key=lambda s: consts.ASSERTION_RANK.get(s, 99))}
                 for (r, tg), g in groups.items()]
        items.sort(key=lambda i: (-i["n_incidents"], consts.ASSERTION_RANK.get(i["best_status"], 99), -i["n_documents"], i["target"]))
        answered = {inc for i in items for inc in i["incident_ids"]}
        result[slot] = {"state": "found", "n_incidents": len(members), "n_incidents_with_answer": len(answered), "items": items}
    return result


def render_campaign(name: str, summary: dict) -> str:
    lines = [f"[묶음: {name}]"]
    for slot, s in summary.items():
        if s["state"] == "not_mentioned":
            lines.append(f"  {NAMES[slot]}: {s['text']}")
            continue
        lines.append(f"  {NAMES[slot]} (소속 사건 {s['n_incidents']}개 중 {s['n_incidents_with_answer']}개에서 답이 나옴):")
        for i in s["items"]:
            lines.append(f"    - {i['target']} [{i['best_status']}, 사건 {i['n_incidents']}개, 문서 {i['n_documents']}개]")
    return "\n".join(lines)


NAMES = {
    "a_vulnerability": "(a) 취약점", "b_weakness_or_failure": "(b) 약점·관리 실패", "c_technique": "(c) 기법",
    "actor_origin": "참고: 공격자 유형", "attribution": "참고: 배후 지목",
    "account_owner_origin": "참고: 도용·악용된 계정 소유자 유형", "affected_asset": "참고: 침해된 시스템",
}


def render(incident: str, summary: dict, context: dict | None = None, attack_layer: dict | None = None) -> str:
    """attack_layer: attack_mapping.summarize_attack_layer의 결과. 주면 (c) 기법 층(매핑 상태, 뼈대 유도, 전술 집계)을 덧붙인다."""
    lines = [f"[{incident}]"]
    for part in (summary, context or {}):
        for slot, s in part.items():
            if s["state"] == "not_mentioned":
                lines.append(f"  {NAMES[slot]}: {s['text']}")
                continue
            review = "  ※ 값이 여러 개: 사람이 확인 필요" if s.get("needs_review") else ""
            lines.append(f"  {NAMES[slot]}:{review}")
            for i in s["items"]:
                mark = " (구분이 문서마다 다름: " + "/".join(i["statuses"]) + ")" if i["mixed_statuses"] else ""
                veris = f" (VERIS: {i['veris']})" if i.get("veris") else ""
                lines.append(f"    - {i['target']}{veris} [{i['best_status']}, 문서 {i['n_documents']}개]{mark}")
    if attack_layer is not None:
        import attack_mapping
        lines.append(attack_mapping.render_attack_layer(attack_layer))
    return "\n".join(lines)


def _t(relation, target, status, doc):
    return {"relation": relation, "target_entity_instance": target, "assertion_status": status, "doc_id": doc}


def self_test() -> None:
    # 1) 취약점·약점·기법이 모두 있는 사건 (SK텔레콤 유형): 두 문서가 같은 취약점을 확정으로 말함
    skt = [
        _t("EXPLOITED_VULNERABILITY", "CVE-2016-5195", "confirmed", "d1"),
        _t("EXPLOITED_VULNERABILITY", "CVE-2016-5195", "confirmed", "d2"),
        _t("HAS_ROOT_CAUSE", "UNPATCHED_KNOWN_VULNERABILITY", "confirmed", "d1"),
        _t("HAS_ROOT_CAUSE", "INSUFFICIENT_ENCRYPTION", "inferred", "d3"),
        _t("USED_MALWARE", "BPFDoor", "confirmed", "d1"),
    ]
    s = summarize_incident(skt, n_documents=3)
    assert all(v["state"] == "found" for v in s.values())
    assert s["a_vulnerability"]["items"][0]["n_documents"] == 2
    # 확정이 추정보다 먼저
    assert [i["target"] for i in s["b_weakness_or_failure"]["items"]] == ["UNPATCHED_KNOWN_VULNERABILITY", "INSUFFICIENT_ENCRYPTION"]

    # 2) 취약점 칸에 아무 문서도 말하지 않은 사건 (쿠팡 유형): "없음"이 아니라 "언급 없음 + 문서 수"
    coupang = [_t("HAS_ROOT_CAUSE", "CREDENTIAL_OR_KEY_MISMANAGEMENT", "confirmed", "d1")]
    s = summarize_incident(coupang, n_documents=4)
    assert s["a_vulnerability"]["state"] == "not_mentioned"
    assert s["a_vulnerability"]["text"] == "확인되지 않음: 처리한 문서 4개 중 언급 없음"
    assert s["b_weakness_or_failure"]["state"] == "found"
    assert s["c_technique"]["state"] == "not_mentioned"

    # 3) 다른 원인이 있다고 해서 취약점 칸을 '없음'으로 추론하지 않는다
    assert s["a_vulnerability"]["items"] == []

    # 4) 문서마다 구분이 다르면 표시한다 (공격자 주장과 피해 조직 확인이 섞인 경우)
    mixed = [_t("USED_TECHNIQUE", "Valid Accounts", "claimed", "d1"),
             _t("USED_TECHNIQUE", "Valid Accounts", "confirmed", "d2")]
    it = summarize_incident(mixed, 2)["c_technique"]["items"][0]
    assert it["best_status"] == "confirmed" and it["mixed_statuses"] and it["n_documents"] == 2

    # 5) 관계 없는 트리플렛은 어떤 칸에도 들어가지 않는다
    other = [_t("ATTRIBUTED_TO", "SomeGroup", "claimed", "d1")]
    assert all(v["state"] == "not_mentioned" for v in summarize_incident(other, 1).values())

    # 6) 문서가 하나도 없을 때
    assert summarize_incident([], 0)["a_vulnerability"]["text"] == consts.NO_DOCUMENTS_TEXT

    # 7) 공격자 유형: 쿠팡 유형(전직 직원)은 '있음', 배후 지목은 '언급 없음'. 칸의 결과에는 영향이 없다
    coupang_ctx = coupang + [_t("HAS_ACTOR_ORIGIN", "FORMER_INSIDER", "confirmed", "d1"),
                             _t("HAS_ACTOR_ORIGIN", "FORMER_INSIDER", "confirmed", "d2")]
    c = summarize_context(coupang_ctx, 4)
    assert c["actor_origin"]["state"] == "found" and c["actor_origin"]["items"][0]["target"] == "FORMER_INSIDER"
    assert c["actor_origin"]["items"][0]["n_documents"] == 2 and not c["actor_origin"]["needs_review"]
    assert c["attribution"]["state"] == "not_mentioned"
    assert summarize_incident(coupang_ctx, 4) == summarize_incident(coupang, 4)   # 참고 정보는 칸에 섞이지 않는다

    # 8) 값이 여러 개면 사람이 확인하도록 표시하고, 확정이 먼저 나온다 (문서마다 다르게 말하거나 행위자가 둘 이상)
    multi = [_t("HAS_ACTOR_ORIGIN", "INTERNAL", "claimed", "d1"), _t("HAS_ACTOR_ORIGIN", "EXTERNAL", "confirmed", "d2")]
    m = summarize_context(multi, 2)["actor_origin"]
    assert m["needs_review"] and [i["target"] for i in m["items"]] == ["EXTERNAL", "INTERNAL"]

    # 9) 이름 없는 공격자는 ThreatActor가 없어도 유형만 기록되고, 배후 지목은 주장으로 구분된다
    ext = [_t("HAS_ACTOR_ORIGIN", "EXTERNAL", "inferred", "d1"), _t("ATTRIBUTED_TO", "ShinyHunters", "claimed", "d1")]
    e = summarize_context(ext, 1)
    assert e["actor_origin"]["items"][0]["best_status"] == "inferred"
    assert e["attribution"]["items"][0]["best_status"] == "claimed"

    # 10) VERIS 대응: 전직자는 VERIS에서 External이고 현직은 Internal이다. 세분화된 값은 그대로 유지된다
    v = summarize_context(coupang_ctx + [_t("HAS_ACTOR_ORIGIN", "INTERNAL", "claimed", "d3")], 4)["actor_origin"]
    mapped = {i["target"]: i["veris"] for i in v["items"]}
    assert mapped == {"FORMER_INSIDER": "External", "INTERNAL": "Internal"}
    # 경계 사례의 기대값은 모두 시드 안의 값이거나 None(기록하지 않음)이다
    assert all(e is None or e in consts.ACTOR_ORIGIN_SEED for _, e in consts.ACTOR_ORIGIN_BOUNDARY_EXAMPLES)
    assert consts.ACTOR_PAIRING == "incident_level"

    # 11) 묶음(D1): 소속 사건의 답을 합산하고, 더 많은 사건에 공통인 답을 먼저 보여 준다 (금융권 동시다발 유형)
    camp = summarize_campaign({
        "INC-신한은행-202510": {"triplets": [_t("USED_TECHNIQUE", "Valid Accounts", "confirmed", "d1"),
                                             _t("USED_TECHNIQUE", "AI penetration tool", "claimed", "d1")], "n_documents": 2},
        "INC-KB국민은행-202510": {"triplets": [_t("USED_TECHNIQUE", "Valid Accounts", "claimed", "d2")], "n_documents": 1},
        "INC-하나은행-202510": {"triplets": [], "n_documents": 1},
    })
    tech = camp["c_technique"]
    assert [i["target"] for i in tech["items"]] == ["Valid Accounts", "AI penetration tool"]
    assert tech["items"][0]["n_incidents"] == 2 and tech["items"][0]["best_status"] == "confirmed"
    assert tech["n_incidents_with_answer"] == 2 and tech["n_incidents"] == 3
    # 12) 어느 소속 사건에서도 언급이 없으면 '없음'이 아니라 "소속 사건 n개 모두에서 언급 없음"
    assert camp["a_vulnerability"]["state"] == "not_mentioned"
    assert camp["a_vulnerability"]["text"] == "확인되지 않음: 소속 사건 3개(문서 4개) 모두에서 언급 없음"

    # 13) 기법 층을 붙여 출력한다: AI 제안은 "사람 확인 전", 뼈대 유도는 "문서의 주장이 아님"으로 표시된다
    import attack_mapping as am
    cat = am._test_catalog()
    trip = [_t("USED_BEHAVIOR", "forged login tokens", "confirmed", "d1"), _t("USED_MALWARE", "ExampleBackdoor", "confirmed", "d2")]
    layer = am.summarize_attack_layer(trip, {"forged login tokens": {"status": "ai_suggested", "candidates": [{"technique_id": "T9002", "confidence": "high"}]}},
                                      {"examplebackdoor": ["T9003.002"]}, cat)
    text = render("시험", summarize_incident(trip, 2), None, layer)
    assert "(c) 기법 층" in text and "사람 확인 전" in text and "문서의 주장이 아님" in text

    # 14) 집계의 상태 이름은 정답표의 이름으로 바꿀 수 있고, 참고 정보에 계정 소유자와 침해된 자산이 따로 나온다
    assert canonical_state("found") == "answered" and canonical_state("not_mentioned") == "not_mentioned_in_sources"
    assert canonical_state("answered") == "answered"
    ctx = summarize_context([_t("HAS_ACTOR_ORIGIN", "EXTERNAL", "confirmed", "d1"),
                             _t("ACCOUNT_OWNER_ORIGIN", "PARTNER", "confirmed", "d1"),
                             _t("AFFECTED_ASSET", "business support system", "confirmed", "d1")], 1)
    assert ctx["actor_origin"]["items"][0]["target"] == "EXTERNAL" and ctx["account_owner_origin"]["items"][0]["target"] == "PARTNER"
    assert ctx["account_owner_origin"]["state"] == "found" and ctx["affected_asset"]["state"] == "found"   # 공격자 유형과 계정 소유자가 섞이지 않는다
    print("자체 시험 14개 통과\n")
    print(render("SK텔레콤 유형", summarize_incident(skt, 3), summarize_context(skt, 3)))
    print()
    print(render("쿠팡 유형", summarize_incident(coupang_ctx, 4), summarize_context(coupang_ctx, 4)))
    print()
    print(render("값이 여러 개인 경우", summarize_incident([], 2), summarize_context(multi, 2)))
    print()
    print(render_campaign("금융권 동시다발 유형", camp))


if __name__ == "__main__":
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass
    self_test()
