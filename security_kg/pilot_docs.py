"""파일럿 문서 목록(`fact_check/pilot_docs.csv`) 점검과 현황 요약 (운영-D3).

목록은 문서 원본이 아니라 **메타데이터**다. 원본(PDF, HTML)은 저장소에 올리지 않고 공유 폴더에 둔다(저작권과 용량 때문. `file_name`은 그 폴더의
파일 이름). 단계: 1단계(phase 1)는 이미 읽은 문서, 2단계(phase 2)는 추가로 모을 문서(`status: planned`).

점검하는 것:
  1. 열, 값의 범위(사건, 출처 유형, 상태, 단계, 평가 사용 여부)
  2. doc_id 중복, 수집한 문서(`collected`)의 필수 칸(발행처, 제목, 수집한 사람), 날짜 형식
  3. 사건별 합계와 출처 유형별 합계가 결정한 목표(TARGET_BY_INCIDENT, TARGET_BY_TYPE)와 같은가
  4. 출처 유형 목록에 없는 문서(`third_party`)는 평가에서 제외(`use_in_eval: 아니오`)되어 있는가

사용: python pilot_docs.py            # 점검과 현황
      python pilot_docs.py --self-test
"""
import csv
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402

HERE = Path(__file__).resolve().parent
PATH = HERE / "fact_check" / "pilot_docs.csv"
COLUMNS = ["doc_id", "incident", "source_type", "publisher", "title", "url", "published_date", "language", "format", "status", "phase",
           "use_in_eval", "collected_by", "file_name", "note"]
INCIDENTS = ["SK텔레콤", "쿠팡", "레벨인피니트", "2026 금융권"]
STATUSES = ["collected", "planned", "excluded"]
PHASES = ["1", "2"]
EXTRA_TYPES = ["third_party"]            # SOURCE_TYPES에 없는 유형(위키 등). 평가에서 제외한다
# 2026-11-27에 정한 목표(운영-D3): 사건별 합계와 출처 유형별 합계(합계 37건)
TARGET_BY_INCIDENT = {"SK텔레콤": 7, "쿠팡": 7, "레벨인피니트": 8, "2026 금융권": 15}
TARGET_BY_TYPE = {"official_government": 6, "affected_organization": 10, "security_vendor": 6, "media": 12, "researcher": 2, "third_party": 1}


def load(path=PATH) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def check(rows, header=None, targets=True) -> list[str]:
    problems = []
    if header is not None and header != COLUMNS:
        return [f"열이 다름: {header}"]
    seen = set()
    valid_types = set(consts.SOURCE_TYPES) | set(EXTRA_TYPES)
    for i, r in enumerate(rows, 2):
        where = f"{i}행 {r['doc_id']}"
        if r["doc_id"] in seen:
            problems.append(f"{where}: doc_id 중복")
        seen.add(r["doc_id"])
        if r["incident"] not in INCIDENTS:
            problems.append(f"{where}: 사건 '{r['incident']}'")
        if r["source_type"] not in valid_types:
            problems.append(f"{where}: source_type '{r['source_type']}'")
        if r["status"] not in STATUSES:
            problems.append(f"{where}: status '{r['status']}'")
        if r["phase"] not in PHASES:
            problems.append(f"{where}: phase '{r['phase']}'")
        if r["use_in_eval"] not in ("예", "아니오"):
            problems.append(f"{where}: use_in_eval '{r['use_in_eval']}'")
        if r["source_type"] in EXTRA_TYPES and r["use_in_eval"] != "아니오":
            problems.append(f"{where}: 출처 유형 목록에 없는 유형은 평가에서 제외해야 함(use_in_eval: 아니오)")
        if r["status"] == "collected":
            for k in ("publisher", "title", "collected_by"):
                if not r[k].strip():
                    problems.append(f"{where}: 수집한 문서인데 {k}가 비어 있음")
            if r["published_date"] and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", r["published_date"]):
                problems.append(f"{where}: 날짜 형식 '{r['published_date']}'(YYYY-MM-DD)")
            if not r["published_date"] and not r["note"].strip():
                problems.append(f"{where}: 발행일이 없으면 note에 이유를 적어야 함")
        if r["phase"] == "1" and r["status"] == "planned":
            problems.append(f"{where}: 1단계 문서가 아직 수집 전(planned)임")
    if targets:
        by_inc = Counter(r["incident"] for r in rows if r["status"] != "excluded")
        by_type = Counter(r["source_type"] for r in rows if r["status"] != "excluded")
        for inc, n in TARGET_BY_INCIDENT.items():
            if by_inc[inc] != n:
                problems.append(f"{inc}: 문서 {by_inc[inc]}건, 목표 {n}건")
        for t, n in TARGET_BY_TYPE.items():
            if by_type[t] != n:
                problems.append(f"출처 유형 {t}: {by_type[t]}건, 목표 {n}건")
    return problems


def summary(rows) -> str:
    lines = []
    for inc in INCIDENTS:
        rs = [r for r in rows if r["incident"] == inc]
        done = sum(1 for r in rs if r["status"] == "collected")
        lines.append(f"  {inc}: 수집 {done}/{len(rs)}건 (목표 {TARGET_BY_INCIDENT[inc]})")
    c = Counter((r["source_type"], r["status"]) for r in rows)
    lines.append("  출처 유형(수집/계획): " + ", ".join(f"{t} {c[(t, 'collected')]}/{c[(t, 'planned')]}" for t in TARGET_BY_TYPE))
    return "\n".join(lines)


def self_test():
    ok = {"doc_id": "X-01", "incident": "쿠팡", "source_type": "media", "publisher": "p", "title": "t", "url": "", "published_date": "2026-01-01",
          "language": "ko", "format": "html", "status": "collected", "phase": "1", "use_in_eval": "예", "collected_by": "me", "file_name": "", "note": ""}
    assert check([ok], COLUMNS, targets=False) == []
    bad = lambda **kw: check([{**ok, **kw}], COLUMNS, targets=False)
    assert bad(incident="캔버스") and bad(source_type="blog") and bad(status="done") and bad(phase="3") and bad(use_in_eval="Y")
    assert bad(source_type="third_party")                                   # 유형 목록에 없는 것은 평가에서 제외해야 함
    assert not bad(source_type="third_party", use_in_eval="아니오")
    assert bad(title="") and bad(collected_by="") and bad(published_date="2026/01/01")
    assert bad(published_date="") and not bad(published_date="", note="발행일을 알 수 없음")
    assert bad(status="planned", phase="1")
    assert check([ok, ok], COLUMNS, targets=False)                           # doc_id 중복
    assert check([ok], COLUMNS, targets=True)                                # 목표와 다르면 알려 준다
    assert check([ok], ["x"], targets=False)
    assert sum(TARGET_BY_INCIDENT.values()) == sum(TARGET_BY_TYPE.values()) == 37
    print("자체 시험 통과")


def main():
    if "--self-test" in sys.argv:
        return self_test()
    with open(PATH, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        header = reader.fieldnames
    problems = check(rows, header)
    print(f"문서 {len(rows)}건 (수집 {sum(r['status'] == 'collected' for r in rows)}, 계획 {sum(r['status'] == 'planned' for r in rows)})")
    print(summary(rows))
    print("점검 결과:", "문제 없음" if not problems else "")
    for p in problems:
        print(" -", p)
    if problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
