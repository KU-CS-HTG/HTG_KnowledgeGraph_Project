"""정답표 초안 검토표(`fact_check/answer_key_review.csv`, 운영-D4의 Taegyu 확인).

정답표(`fact_check/answer_key_draft.csv`)의 한 행마다 근거가 된 사실 확인표의 행(주장, 결과, 근거 쪽수)을 옆에 붙여 보여 주고,
사람이 두 가지를 판정하게 한다:
  - judge_answer: 이 정답이 맞는가(칸 (a)(b)(c), 상태, 확정·주장·추정 구분, 문장을 모두 포함)
  - judge_candidates: 표준 후보(CVE, CWE, ATT&CK 번호 등)가 적절한가(후보가 있는 행만)
이 스크립트는 **판정하지 않는다.** 사람이 채운 뒤 집계하고 정답표와 어긋나지 않는지 검사한다.

사용: python answer_key_review.py --sheet         # 검토표를 만든다(판정이 들어 있으면 덮어쓰지 않는다)
      python answer_key_review.py                 # 판정 집계와 정답표와의 일치 검사
      python answer_key_review.py --self-test
"""
import csv
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEY = HERE / "fact_check" / "answer_key_draft.csv"
FACTS = HERE / "fact_check" / "incident_facts.csv"
PATH = HERE / "fact_check" / "answer_key_review.csv"
GLOSSARY = HERE / "fact_check" / "candidate_glossary.csv"
COLUMNS = ["행", "answer_id", "incident", "slot", "slot_state", "assertion_status", "answer", "basis_source_type", "evidence",
           "standard_candidates", "candidate_details", "candidate_en", "candidate_note", "judge_answer", "judge_candidates", "judge_note"]
JUDGE_ANSWER = ["맞음", "수정 필요", "삭제", "판단 불가"]
JUDGE_CANDIDATES = ["적절", "부적절", "판단 불가"]
NEEDS_NOTE = ["수정 필요", "삭제", "판단 불가"]


def _cut(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n] + "…"


def evidence_text(fact_ids: str, facts: dict) -> str:
    """근거가 된 사실 확인표 행들을 한 칸에 보여 준다: `id 주장 [결과] 근거: 쪽수`."""
    out = []
    for fid in [x.strip() for x in fact_ids.split(",") if x.strip()]:
        f = facts.get(fid)
        if f is None:
            out.append(f"{fid}: (사실 확인표에 없음)")
            continue
        note = f["note"].strip()
        note = note[len("근거:"):].strip() if note.startswith("근거:") else note        # 메모가 이미 '근거:'로 시작하는 경우가 많다
        out.append(f"{fid} {_cut(f['claim'], 150)} [{f['result']}] 근거: {_cut(note, 170)}")
    return " ‖ ".join(out)


def candidate_texts(cands: str, glossary: dict) -> tuple[str, str]:
    """후보 번호마다 한국어 이름·정의(와 비고), 영어 원문을 만든다. 용어집에 없으면 그렇게 표시한다."""
    ko, en = [], []
    for c in [x.strip() for x in cands.split(";") if x.strip()]:
        g = glossary.get(c)
        if g is None:
            ko.append(f"{c}: (용어집에 없음)")
            en.append(f"{c}: (용어집에 없음)")
            continue
        extra = f" ※ {g['extra_ko']}" if g["extra_ko"] else ""
        ko.append(f"{c} [{g['kind']}] {g['name_ko']} — {g['definition_ko']}{extra}")
        en.append(f"{c} {g['name_en']}: {g['definition_en']}")
    return " ‖ ".join(ko), " ‖ ".join(en)


def build_rows(key_rows=None, facts_rows=None, glossary=None) -> list[dict]:
    if glossary is None:
        with open(GLOSSARY, encoding="utf-8-sig", newline="") as f:
            glossary = {r["id"]: r for r in csv.DictReader(f)}
    if key_rows is None:
        with open(KEY, encoding="utf-8-sig", newline="") as f:
            key_rows = list(csv.DictReader(f))
    if facts_rows is None:
        with open(FACTS, encoding="utf-8-sig", newline="") as f:
            facts_rows = list(csv.DictReader(f))
    facts = {r["id"]: r for r in facts_rows}
    rows = []
    for k in key_rows:
        det, en = candidate_texts(k["standard_candidates"], glossary)
        rows.append({"행": len(rows) + 2, "answer_id": k["answer_id"], "incident": k["incident"], "slot": k["slot"], "slot_state": k["slot_state"],
                     "assertion_status": k["assertion_status"], "answer": k["answer"], "basis_source_type": k["basis_source_type"],
                     "evidence": evidence_text(k["fact_rows"], facts), "standard_candidates": k["standard_candidates"],
                     "candidate_details": det, "candidate_en": en, "candidate_note": k["candidate_note"], "judge_answer": "", "judge_candidates": "", "judge_note": ""})
    return rows


def has_judgments(path=PATH) -> bool:
    p = Path(path)
    if not p.exists():
        return False
    with open(p, encoding="utf-8-sig", newline="") as f:
        return any((r.get("judge_answer") or "").strip() or (r.get("judge_candidates") or "").strip() for r in csv.DictReader(f))


def write(rows, path=PATH, force=False):
    if not force and has_judgments(path):
        raise FileExistsError(f"{path}에 사람이 판정한 내용이 있어 덮어쓰지 않았음(--force로만 덮어씀)")
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, COLUMNS, lineterminator="\r\n")
        w.writeheader()
        w.writerows(rows)


def tally(rows) -> dict:
    g = lambda r, k: (r.get(k) or "").strip()
    ans = [r for r in rows if g(r, "judge_answer") in JUDGE_ANSWER]
    return {
        "total": len(rows), "answered": len(ans), "overall": Counter(g(r, "judge_answer") for r in ans),
        "empty": [r for r in rows if not g(r, "judge_answer")],
        "unknown": [r for r in rows if (g(r, "judge_answer") and g(r, "judge_answer") not in JUDGE_ANSWER)
                    or (g(r, "judge_candidates") and g(r, "judge_candidates") not in JUDGE_CANDIDATES)],
        "need_change": [r for r in ans if g(r, "judge_answer") in ("수정 필요", "삭제")],
        "unsure": [r for r in ans if g(r, "judge_answer") == "판단 불가"],
        "cand_missing": [r for r in rows if g(r, "standard_candidates") and g(r, "judge_answer") and not g(r, "judge_candidates")],
        "cand_bad": [r for r in rows if g(r, "judge_candidates") == "부적절"],
        "note_missing": [r for r in rows if (g(r, "judge_answer") in NEEDS_NOTE or g(r, "judge_candidates") in ("부적절", "판단 불가")) and not g(r, "judge_note")],
    }


def check_against_key(rows, key_rows=None) -> list[str]:
    """검토표의 행이 정답표와 어긋나지 않는지 검사한다(정답표가 바뀌었으면 검토표를 다시 확인해야 함)."""
    if key_rows is None:
        with open(KEY, encoding="utf-8-sig", newline="") as f:
            key_rows = list(csv.DictReader(f))
    key = {k["answer_id"]: k for k in key_rows}
    problems = []
    for r in rows:
        k = key.get(r["answer_id"])
        if k is None:
            problems.append(f"행 {r['행']} {r['answer_id']}: 정답표에 없는 행")
            continue
        for col in ("answer", "slot", "slot_state", "assertion_status", "standard_candidates"):
            if r[col] != k[col]:
                problems.append(f"행 {r['행']} {r['answer_id']}: {col}이 정답표와 다름(정답표가 바뀌었으면 검토표를 다시 확인)")
    for i in key:
        if i not in {r["answer_id"] for r in rows}:
            problems.append(f"{i}: 정답표에 있으나 검토표에 없음")
    return problems


def self_test():
    facts = [{"id": "F1", "claim": "주장 하나", "result": "일치", "note": "근거 3쪽"}]
    key = [{"answer_id": "A1", "incident": "x", "slot": "a", "slot_state": "answered", "assertion_status": "confirmed", "answer": "문장",
            "basis_source_type": "official_government", "fact_rows": "F1, F9", "standard_candidates": "CWE-1", "candidate_note": ""},
           {"answer_id": "A2", "incident": "x", "slot": "b", "slot_state": "not_confirmed", "assertion_status": "n/a", "answer": "문장2",
            "basis_source_type": "official_government", "fact_rows": "F1", "standard_candidates": "", "candidate_note": ""}]
    gl = {"CWE-1": {"id": "CWE-1", "kind": "약점", "name_ko": "이름", "name_en": "Name", "definition_ko": "정의", "definition_en": "Def", "extra_ko": "비고"}}
    rows = build_rows(key, facts, gl)
    assert "CWE-1 [약점] 이름 — 정의 ※ 비고" in rows[0]["candidate_details"] and rows[0]["candidate_en"] == "CWE-1 Name: Def" and rows[1]["candidate_details"] == ""
    assert "용어집에 없음" in candidate_texts("CWE-9", gl)[0]
    assert [r["행"] for r in rows] == [2, 3]
    assert "F1 주장 하나 [일치] 근거: 근거 3쪽" in rows[0]["evidence"] and "F9: (사실 확인표에 없음)" in rows[0]["evidence"]
    assert check_against_key(rows, key) == []
    rows[0]["judge_answer"], rows[1]["judge_answer"] = "수정 필요", "맞음"
    t = tally(rows)
    assert t["answered"] == 2 and [r["answer_id"] for r in t["need_change"]] == ["A1"]
    assert [r["answer_id"] for r in t["cand_missing"]] == ["A1"] and [r["answer_id"] for r in t["note_missing"]] == ["A1"]
    rows[0]["judge_candidates"], rows[0]["judge_note"] = "적절", "이유"
    t = tally(rows)
    assert not t["cand_missing"] and not t["note_missing"]
    rows[1]["judge_answer"] = "ok"
    assert tally(rows)["unknown"]
    changed = [{**rows[0], "answer": "다른 문장"}]
    assert any("answer" in p for p in check_against_key(changed, key)) and any("없음" in p for p in check_against_key(changed, key))
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "r.csv"
        write(build_rows(key, facts, gl), p)
        write(rows, p, force=True)
        try:
            write(rows, p)
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
    with open(PATH, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    t = tally(rows)
    print(f"정답 판정 {t['answered']}/{t['total']}행: {dict(t['overall'])}")
    show = lambda rs: [(r["행"], r["answer_id"]) for r in rs]
    for label, key in (("아직 판정하지 않은 행", "empty"), ("인식하지 못한 값이 있는 행", "unknown"), ("수정 필요 또는 삭제", "need_change"),
                       ("판단 불가", "unsure"), ("후보 판정이 비어 있는 행", "cand_missing"), ("후보를 부적절로 본 행", "cand_bad"),
                       ("메모가 필요한데 비어 있는 행", "note_missing")):
        if t[key]:
            print(f"  {label}:", show(t[key]))
    problems = check_against_key(rows)
    print("검토표와 정답표 일치:", "일치함" if not problems else "")
    for p in problems:
        print(" -", p)
    if problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
