"""사건 하나의 답을 칸((a) 취약점, (b) 약점·관리 실패, (c) 기법)별로 집계한다. 최소안.

원칙: 부재를 추측하지 않는다.
  - 칸에 해당하는 트리플렛이 있으면 상태는 "found"이고, 확정>주장>추정, 같으면 더 많은 문서가 말한 것 순으로 보여 준다.
  - 없으면 "없음"이 아니라 "not_mentioned"이고, 처리한 문서 수를 함께 쓴다.

입력: 한 사건(Incident)에 대한 트리플렛 목록. 각 항목은 dict이며 사용하는 키는 아래와 같다.
  relation, target_entity_instance, assertion_status, doc_id
  (assertion_status와 doc_id는 원본 파이프라인에 없는 칸이라 추출 단계에서 추가해야 한다)
n_documents: 이 사건을 다루는 것으로 처리한 문서 수 (문서 단위 필드 incident_names로 센다).

사용: python aggregate.py   # 자체 시험 실행
"""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402


def summarize_incident(triplets: list[dict], n_documents: int) -> dict:
    result = {}
    for slot, relations in consts.ANSWER_SLOTS.items():
        groups = defaultdict(lambda: {"docs": set(), "statuses": set()})
        for t in triplets:
            if t.get("relation") in relations:
                g = groups[(t["relation"], t["target_entity_instance"])]
                g["docs"].add(t.get("doc_id"))
                g["statuses"].add(t.get("assertion_status", "inferred"))
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


def render(incident: str, summary: dict) -> str:
    names = {"a_vulnerability": "(a) 취약점", "b_weakness_or_failure": "(b) 약점·관리 실패", "c_technique": "(c) 기법"}
    lines = [f"[{incident}]"]
    for slot, s in summary.items():
        if s["state"] == "not_mentioned":
            lines.append(f"  {names[slot]}: {s['text']}")
        else:
            lines.append(f"  {names[slot]}:")
            for i in s["items"]:
                mark = " (구분이 문서마다 다름: " + "/".join(i["statuses"]) + ")" if i["mixed_statuses"] else ""
                lines.append(f"    - {i['target']} [{i['best_status']}, 문서 {i['n_documents']}개]{mark}")
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

    print("자체 시험 6개 통과\n")
    print(render("SK텔레콤 유형", summarize_incident(skt, 3)))
    print()
    print(render("쿠팡 유형", summarize_incident(coupang, 4)))


if __name__ == "__main__":
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass
    self_test()
