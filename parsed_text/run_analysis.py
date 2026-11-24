"""파싱된 본문으로 '본문에 나오는 정답만' 분모로 한 CMIP 재현율을 계산하고 논문 Table 8과 비교한다.

사전 조건: download_pdfs.py 와 pdf_to_text.py 를 먼저 실행해 papers/parsed/<date>/*.md 가 있어야 한다.
stats/output/<stage>/<date>/ (stats/data 의 tarball을 푼 것)도 필요하다.
"""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXP = ROOT / "cmip_recall" / "extraction" / "experiments"
DATE = "2026-02-01"
STAGES = ["extracted_papers", "validated_papers", "ontology_conformed_papers", "evidence_validated_papers", "evaluated_papers"]
PAPER = {  # 논문 Table 8: (정답, 추출, 재현율%)
    "sources": (797, 774, 97.11), "experiments": (196, 162, 82.65),
    "frequencies": (85, 57, 67.06), "activities": (55, 30, 54.55), "micro": (1133, 1023, 90.29),
}

def main() -> None:
    for _s in (sys.stdout, sys.stderr):  # Windows cp949 콘솔에서 특수문자로 죽지 않게
        try: _s.reconfigure(errors="replace")
        except Exception: pass
    parsed = ROOT / "cmip_recall" / "extraction" / "papers" / "parsed" / DATE
    n_md = len(list(parsed.glob("*.md")))
    if n_md == 0:
        sys.exit(f"파싱된 본문이 없습니다: {parsed}")
    eval_dir = sorted((EXP / "output" / "cmip_moreinfo_entity_evaluation").glob("*/"))[-1]
    out = ROOT / "parsed_text" / "output" / "analysis"
    cmd = [sys.executable, "analyze_cmip_missing_entities_in_parsed_papers.py",
           "--comparison", str(eval_dir / "paper_entity_comparison.json"),
           "--parsed-dir", str(parsed), "--output-dir", str(out)]
    for s in STAGES:
        cmd += ["--pipeline-dir", str(ROOT / "stats" / "output" / s / DATE)]
    print(f"본문 {n_md}편으로 분석 중 ...", flush=True)
    subprocess.run(cmd, cwd=EXP, check=True, stdout=subprocess.DEVNULL)
    res = json.loads((out / "recall_ground_truth_present_only.json").read_text(encoding="utf-8"))
    miss = res.get("missing_parsed_files") or 0
    miss = len(miss) if isinstance(miss, (list, dict)) else int(miss)
    m = res["metrics"]
    tot = m["micro"]["ground_truth_present_in_parsed"] + m["micro"]["ground_truth_absent_from_parsed"]
    print(f"\n정답 {tot}개 중 본문에 나오는 비율: {100*m['micro']['ground_truth_present_in_parsed']/tot:.2f}%  (논문 50.78%)")
    if miss: print(f"주의: 본문 파일이 없는 항목 {miss}개 (이 논문들의 정답은 '본문에 없음'으로 계산됨)")
    print(f"\n{'종류':12s}{'정답(본문에 있음)':>20s}{'맞힘':>8s}{'재현율%':>10s}   | 논문: 정답 / 추출 / 재현율%")
    for k in ["sources", "experiments", "frequencies", "activities", "micro"]:
        b = m[k]; pg, pe, pr = PAPER[k]
        print(f"{k:12s}{b['ground_truth_present_in_parsed']:>20d}{b['correct_present_in_parsed']:>8d}"
              f"{100*b['recall_on_present_ground_truth']:>10.2f}   | {pg:>5d} / {pe:>4d} / {pr:.2f}")
    print(f"\n자세한 결과: {out}")

if __name__ == "__main__":
    main()
