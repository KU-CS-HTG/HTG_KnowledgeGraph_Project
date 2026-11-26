"""사건 사실 확인표(fact_check/incident_facts.csv) 점검: 입력한 값이 규칙에 맞는지 보고, 진행 상황을 요약한다.

확인표는 다섯 사건의 핵심 사실(검색 요약에서 정리한 것, 미검증)을 한 줄씩 담고 있다. 사람이 1차 자료(피해 조직 공지, 정부·규제기관
발표 등)를 읽고 `official_url`, `result`, `correction`, `checked_by`, `checked_date`를 채운다.

규칙:
  result는 비어 있거나 일치, 일부 일치, 불일치, 확인 불가 중 하나
  result가 일치, 일부 일치, 불일치이면 official_url, checked_by, checked_date가 있어야 한다(Claude가 데이터 파일로 확인한 행은 URL 대신 note)
  result가 일부 일치, 불일치이면 correction이 있어야 한다(정정한 내용을 적는다)
  id는 중복되지 않는다

사용: python fact_check.py [fact_check/incident_facts.csv]    # 점검과 요약
      python fact_check.py --self-test
"""
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT = HERE / "fact_check" / "incident_facts.csv"
RESULTS = ["일치", "일부 일치", "불일치", "확인 불가"]
HEADER = ["id", "incident", "category", "claim", "related_question", "design_impact", "our_source_url", "our_source_type",
          "priority", "check_where", "official_url", "result", "correction", "checked_by", "checked_date", "note"]
PRIORITIES = ["높음", "보통", "낮음"]


def load(path) -> list:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def check(rows: list) -> list:
    """규칙 위반 목록(문자열)을 돌려준다."""
    problems, seen = [], set()
    for r in rows:
        i = r.get("id", "").strip()
        if not i:
            problems.append("id가 빈 행이 있음")
            continue
        if i in seen:
            problems.append(f"{i}: id 중복")
        seen.add(i)
        res = r.get("result", "").strip()
        if r.get("priority", "").strip() not in PRIORITIES:
            problems.append(f"{i}: priority는 {PRIORITIES} 중 하나여야 함")
        if not res:
            continue
        if res not in RESULTS:
            problems.append(f"{i}: result '{res}'는 {RESULTS} 중 하나여야 함")
            continue
        if res != "확인 불가":
            if not r.get("official_url", "").strip() and not r.get("note", "").strip():
                problems.append(f"{i}: result가 '{res}'이면 official_url이 필요함(근거를 note로 대신하려면 note에 적을 것)")
            if not r.get("checked_by", "").strip() or not r.get("checked_date", "").strip():
                problems.append(f"{i}: checked_by와 checked_date가 필요함")
        if res in ("일부 일치", "불일치") and not r.get("correction", "").strip():
            problems.append(f"{i}: result가 '{res}'이면 correction(정정 내용)이 필요함")
        if res == "확인 불가" and not (r.get("note", "").strip() or r.get("correction", "").strip()):
            problems.append(f"{i}: '확인 불가'이면 이유를 note에 적을 것")
    return problems


def summarize(rows: list) -> dict:
    by_inc = defaultdict(Counter)
    for r in rows:
        by_inc[r["incident"]][r.get("result", "").strip() or "미확인"] += 1
    todo_high = [r["id"] for r in rows if r.get("priority") == "높음" and not r.get("result", "").strip()]
    return {"total": len(rows), "by_incident": {k: dict(v) for k, v in by_inc.items()},
            "overall": dict(Counter(r.get("result", "").strip() or "미확인" for r in rows)), "high_priority_unchecked": todo_high}


def self_test() -> None:
    base = {"id": "X1", "incident": "A", "priority": "높음", "result": "", "official_url": "", "checked_by": "", "checked_date": "",
            "correction": "", "note": ""}
    ok = [dict(base)]
    assert check(ok) == []                                                           # 비어 있으면 문제 없음(미확인)
    assert check([{**base, "result": "일치", "official_url": "u", "checked_by": "k", "checked_date": "2026-11-26"}]) == []
    p = check([{**base, "result": "일치"}])                                          # 근거와 확인자가 없음
    assert any("official_url" in x for x in p) and any("checked_by" in x for x in p)
    assert check([{**base, "result": "일치", "note": "ATT&CK 파일로 확인", "checked_by": "c", "checked_date": "d"}]) == []   # note가 근거를 대신
    p = check([{**base, "result": "불일치", "official_url": "u", "checked_by": "k", "checked_date": "d"}])
    assert any("correction" in x for x in p)                                         # 불일치는 정정 내용이 필요
    assert any("확인 불가" in x for x in check([{**base, "result": "확인 불가"}]))                # 이유가 필요
    assert check([{**base, "result": "확인 불가", "note": "공식 발표 없음"}]) == []
    assert any("중 하나" in x for x in check([{**base, "result": "맞음"}]))
    assert any("중복" in x for x in check([dict(base), dict(base)]))
    assert any("priority" in x for x in check([{**base, "priority": "중요"}]))
    s = summarize([dict(base), {**base, "id": "X2", "priority": "낮음", "result": "일치"}, {**base, "id": "X3", "incident": "B"}])
    assert s["total"] == 3 and s["overall"] == {"미확인": 2, "일치": 1} and s["high_priority_unchecked"] == ["X1", "X3"]
    print("자체 시험 통과")


if __name__ == "__main__":
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass
    a = [x for x in sys.argv[1:] if not x.startswith("--")]
    if "--self-test" in sys.argv:
        self_test()
    else:
        rows = load(a[0] if a else DEFAULT)
        miss = [h for h in HEADER if h not in rows[0]]
        if miss:
            sys.exit(f"열이 빠져 있음: {miss}")
        probs = check(rows)
        s = summarize(rows)
        print(f"총 {s['total']}행 | 전체: {s['overall']}")
        for k, v in s["by_incident"].items():
            print(f"  {k}: {v}")
        print(f"우선순위 '높음'인데 아직 확인 안 한 행 {len(s['high_priority_unchecked'])}개: {', '.join(s['high_priority_unchecked'])}")
        print("점검 결과:", "문제 없음" if not probs else f"문제 {len(probs)}건")
        for p in probs:
            print(" -", p)
