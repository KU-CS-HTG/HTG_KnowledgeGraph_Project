"""정답표 초안(`fact_check/answer_key_draft.csv`) 검사 (운영-D4).

실행: python answer_key.py
검사하는 것:
  1. 열과 값(slot, slot_state, assertion_status)이 정해진 범위인가
  2. fact_rows가 사실 확인표(incident_facts.csv)에 실제로 있는 행인가
  3. standard_candidates의 ID가 뼈대 데이터(backbone/export)에 실제로 있는가(ID의 존재만 확인하고,
     그 후보가 이 사실에 맞는지는 확인하지 않는다. 그것은 사람이 판단한다)
  3-1. slot_state 5가지(answered, not_confirmed, not_mentioned_in_sources, not_applicable, not_assessed)의 정의는 consts.ANSWER_KEY_SLOT_STATES
  4. 모든 사건에 (a), (b), (c) 칸이 있는가. 칸이 비어 있어도 상태(slot_state)로 기록돼 있는가
"""
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402

HERE = Path(__file__).resolve().parent
KEY = HERE / "fact_check" / "answer_key_draft.csv"
FACTS = HERE / "fact_check" / "incident_facts.csv"
EXPORT = HERE / "backbone" / "export"

COLUMNS = ["answer_id", "incident", "slot", "slot_state", "answer", "assertion_status",
           "basis_source_type", "fact_rows", "standard_candidates", "candidate_note"]
SLOTS = {"a", "b", "c", "ref", "asset"}
SLOT_STATES = set(consts.ANSWER_KEY_SLOT_STATES)   # 정의와 사용 조건은 consts.ANSWER_KEY_SLOT_STATES
STATUSES = {"confirmed", "claimed", "inferred", "n/a"}
REQUIRED_SLOTS = {"a", "b", "c"}


def _ids(path, col="id"):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return {r[col] for r in csv.DictReader(f)}


def check(key=KEY, facts=FACTS):
    problems = []
    with open(key, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != COLUMNS:
            return [f"열이 다름: {reader.fieldnames}"], []
        rows = list(reader)
    fact_ids = _ids(facts)
    cwe = _ids(EXPORT / "cwe_weaknesses.csv")
    tech = _ids(EXPORT / "attack_techniques.csv")
    soft = _ids(EXPORT / "attack_software.csv")
    kev_text = (EXPORT / "kev.csv").read_text(encoding="utf-8-sig")
    seen, coverage = set(), {}
    for i, r in enumerate(rows, 2):
        if r["answer_id"] in seen:
            problems.append(f"{i}: answer_id 중복 {r['answer_id']}")
        seen.add(r["answer_id"])
        if r["slot"] not in SLOTS:
            problems.append(f"{i}: slot '{r['slot']}'")
        if r["slot_state"] not in SLOT_STATES:
            problems.append(f"{i}: slot_state '{r['slot_state']}'")
        if r["assertion_status"] not in STATUSES:
            problems.append(f"{i}: assertion_status '{r['assertion_status']}'")
        if (r["slot_state"] == "answered") != (r["assertion_status"] != "n/a"):
            problems.append(f"{i}: answered인 행만 confirmed/claimed/inferred를 가진다")
        for fid in filter(None, (x.strip() for x in r["fact_rows"].split(","))):
            if fid not in fact_ids:
                problems.append(f"{i}: fact_rows '{fid}'가 사실 확인표에 없음")
        if not r["fact_rows"].strip() and r["slot_state"] != "not_assessed":
            problems.append(f"{i}: fact_rows가 비어 있음(근거 없는 정답 금지. 아직 평가하지 않은 칸만 예외)")
        for c in filter(None, (x.strip() for x in r["standard_candidates"].split(";"))):
            ok = (c in cwe if c.startswith("CWE-") else c in tech if c.startswith("T")
                  else c in soft if re.fullmatch(r"S\d{4}", c)
                  else (c + ",") in kev_text if c.startswith("CVE-")
                  else c == "FORMER_INSIDER")
            if not ok:
                problems.append(f"{i}: 표준 후보 '{c}'가 뼈대 데이터에 없음")
        coverage.setdefault(r["incident"], set()).add(r["slot"])
    for inc, slots in coverage.items():
        miss = REQUIRED_SLOTS - slots
        if miss:
            problems.append(f"{inc}: 칸 {sorted(miss)}가 없음")
    return problems, rows


def self_test():
    """일부러 틀린 정답표로 검사가 걸러내는지 본다."""
    import tempfile
    good = KEY.read_text(encoding="utf-8-sig")
    cases = {
        "없는 사실 행": good.replace("L10", "L99", 1),
        "없는 CWE": good.replace("CWE-312", "CWE-99999", 1),
        "없는 CVE": good.replace("CVE-2016-5195", "CVE-1999-0000", 1),
        "잘못된 상태": good.replace(",not_confirmed,", ",unknown,", 1),
        "근거 없는 정답": good.replace('"L6"', '""', 1) if '"L6"' in good else good.replace(",L6,", ",,", 1),
    }
    for name, text in cases.items():
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "k.csv"
            p.write_text(text, encoding="utf-8-sig")
            problems, _ = check(p)
        assert problems, f"{name}: 검사가 걸러내지 못함"
    assert not check()[0]

    # 새 상태 두 가지: not_applicable은 근거 행이 있어야 하고, not_assessed는 근거 없이도 허용된다
    import csv
    import io
    rows = list(csv.DictReader(io.StringIO(good)))
    def with_row(**changes):
        r = dict(rows[0]); r.update(changes)
        o = io.StringIO(); w = csv.DictWriter(o, COLUMNS, lineterminator="\n"); w.writeheader(); w.writerows(rows[1:] + [r])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "k.csv"; p.write_text(o.getvalue(), encoding="utf-8-sig")
            return check(p)[0]
    assert not with_row(slot_state="not_applicable", assertion_status="n/a")                     # 근거 행이 있으면 통과
    assert with_row(slot_state="not_applicable", assertion_status="n/a", fact_rows="")           # 근거 없는 not_applicable은 걸러냄
    assert not with_row(slot_state="not_assessed", assertion_status="n/a", fact_rows="")         # 평가 전 칸은 근거 없이 허용
    assert with_row(slot_state="answered", assertion_status="n/a")                              # answered는 assertion_status가 있어야 함
    print(f"자체 시험 {len(cases) + 5}개 통과")


def main():
    if "--self-test" in sys.argv:
        return self_test()
    problems, rows = check()
    by = {}
    for r in rows:
        by.setdefault(r["incident"], []).append(r)
    print(f"총 {len(rows)}행")
    for inc, rs in by.items():
        states = {}
        for r in rs:
            states[r["slot_state"]] = states.get(r["slot_state"], 0) + 1
        print(f"  {inc}: {len(rs)}행 {states}")
    if problems:
        print("문제:")
        for p in problems:
            print("  -", p)
        sys.exit(1)
    print("점검 결과: 문제 없음")


if __name__ == "__main__":
    main()
