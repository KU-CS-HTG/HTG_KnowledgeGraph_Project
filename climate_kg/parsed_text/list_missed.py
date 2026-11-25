"""본문에는 나오지만 파이프라인이 못 가져온 CMIP 정답(놓친 109개)을 원인별로 정리한다.

입력: run_analysis.py가 만든 missed_ground_truth_parsed_presence.json
출력: CSV(엑셀에서 열림, UTF-8 BOM)와 콘솔 요약

  python parsed_text/list_missed.py
  python parsed_text/list_missed.py --input <missed_ground_truth_parsed_presence.json>
"""
import argparse, csv, json, re, sys
from collections import Counter
from pathlib import Path

STATUS_KO = {
    "final_same_type_near_label": "비슷한 이름은 추출됨(표기·버전 차이)",
    "final_wrong_type_exact": "같은 이름이 다른 종류로 추출됨",
    "mentioned_in_pipeline_record_not_entity": "파이프라인 기록엔 언급되나 엔티티로 안 뽑힘",
    "raw_same_type_near_label": "검증 전 단계에는 비슷한 이름이 있었음",
    "not_found_exact_or_near_in_pipeline_outputs": "파이프라인 출력 어디에도 없음",
}

def alnum(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

def near_label(rec: dict) -> str:
    dm = rec.get("downstream_match") or {}
    if rec.get("downstream_status") == "final_wrong_type_exact":
        return f"{dm.get('label')} ({dm.get('entity_type')})"
    return dm.get("label") or ""

def main() -> None:
    for s in (sys.stdout, sys.stderr):
        try: s.reconfigure(errors="replace")
        except Exception: pass
    root = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, default=root / "output" / "analysis" / "missed_ground_truth_parsed_presence.json")
    ap.add_argument("--out", type=Path, default=None, help="CSV 경로(기본: 입력 파일과 같은 폴더)")
    a = ap.parse_args()
    recs = json.loads(a.input.read_text(encoding="utf-8"))
    present = [r for r in recs if (r.get("parsed_presence") or {}).get("matched")]
    out = a.out or a.input.with_name("missed_present_in_text.csv")
    cols = ["논문ID", "논문 제목", "종류", "정답 엔티티", "원인", "파이프라인이 낸 비슷한 이름", "표기만 다름", "본문 일치 방식", "본문 발췌"]
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f); w.writerow(cols)
        for r in sorted(present, key=lambda r: (r["entity_type"], r["downstream_status"], r["ground_truth_entity"])):
            lab = near_label(r)
            fmt = "예" if lab and alnum(lab) == alnum(r["ground_truth_entity"]) else ""
            pp = r["parsed_presence"]
            w.writerow([r["paper_id"], r["title"], r["entity_type"], r["ground_truth_entity"],
                        STATUS_KO.get(r["downstream_status"], r["downstream_status"]), lab, fmt,
                        pp.get("match_type"), (pp.get("snippet") or "").replace("\n", " ")[:300]])
    print(f"전체 놓친 정답 {len(recs)}개 중 본문에 나오는 것 {len(present)}개 ({len({r['paper_id'] for r in present})}편)")
    print("\n[종류 x 원인]")
    for t in ("sources", "experiments", "frequencies", "activities"):
        c = Counter(STATUS_KO.get(r["downstream_status"], r["downstream_status"]) for r in present if r["entity_type"] == t)
        print(f"  {t:12s} {sum(c.values()):3d}  " + ", ".join(f"{k} {v}" for k, v in c.most_common()))
    fmt_only = [r for r in present if near_label(r) and alnum(near_label(r)) == alnum(r["ground_truth_entity"])]
    print(f"\n'표기만 다름'(하이픈·공백·대소문자 차이뿐): {len(fmt_only)}개")
    print("\n[엔티티별 상위]")
    for (t, e), n in Counter((r["entity_type"], r["ground_truth_entity"]) for r in present).most_common(10):
        print(f"  {n:3d}  {t:11s} {e}")
    print(f"\nCSV 저장: {out}")

if __name__ == "__main__":
    main()
