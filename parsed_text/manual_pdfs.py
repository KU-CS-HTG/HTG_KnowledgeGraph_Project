"""자동 다운로드가 막힌 논문(봇 확인 페이지 등)을 브라우저로 받은 뒤 정해진 이름으로 정리한다.

  python parsed_text/manual_pdfs.py list                    # 아직 없는 논문과 열어 볼 주소 목록
  python parsed_text/manual_pdfs.py import --src <폴더>      # 브라우저로 받은 PDF를 매칭해 이름 붙여 복사

매칭은 DOI 끝부분(예: s00382-012-1555-1)이 파일 이름에 들어 있는지로 한다.
Springer는 보통 `s00382-012-1555-1.pdf` 또는 `10.1007_s00382-012-1555-1.pdf` 로 저장된다.
"""
import argparse, json, re, shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATE = "2026-02-01"

def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())

def is_pdf(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            return f.read(5) == b"%PDF-"
    except OSError:
        return False

def doi_key(paper: dict) -> str:
    doi = (paper.get("doi") or "").rstrip("/")
    return norm(doi.split("/", 3)[-1]) if doi else ""   # https://doi.org/10.1007/xyz -> 10.1007/xyz 이후 전체

def missing(manifest: Path, pdf_dir: Path) -> list[dict]:
    papers = json.loads(manifest.read_text(encoding="utf-8"))["papers"]
    return [p for p in papers if not ((pdf_dir / f"{p['id']}.pdf").exists() and is_pdf(pdf_dir / f"{p['id']}.pdf"))]

def match(paper: dict, files: list[Path]) -> list[Path]:
    key = doi_key(paper)
    if not key:
        return []
    last = norm((paper.get("doi") or "").rstrip("/").split("/")[-1])  # DOI의 마지막 조각
    hits = [f for f in files if key in norm(f.stem) or (len(last) >= 8 and last in norm(f.stem))]
    return sorted(hits, key=lambda f: f.stat().st_mtime, reverse=True)

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["list", "import"])
    ap.add_argument("--src", type=Path, default=Path.home() / "Downloads")
    ap.add_argument("--manifest", type=Path, default=HERE / "data" / "cmip_papers_pdf_urls.json")
    ap.add_argument("--pdf-root", type=Path, default=HERE.parent / "cmip_recall" / "extraction" / "papers" / "pdfs")
    a = ap.parse_args()
    pdf_dir = a.pdf_root / DATE; pdf_dir.mkdir(parents=True, exist_ok=True)
    todo = missing(a.manifest, pdf_dir)
    if a.cmd == "list":
        print(f"PDF가 없는 논문 {len(todo)}편\n")
        for p in todo:
            print(f"{p['id']}  {p['pdf_url']}\n    {p['title'][:90]}")
        return
    files = [f for f in a.src.glob("*.pdf") if is_pdf(f)]
    print(f"{a.src} 의 PDF {len(files)}개에서 매칭 중 (필요 {len(todo)}편)")
    done = 0; unmatched = []
    for p in todo:
        hits = match(p, files)
        if not hits:
            unmatched.append(p); continue
        shutil.copy2(hits[0], pdf_dir / f"{p['id']}.pdf"); done += 1
        extra = f" (후보 {len(hits)}개 중 가장 최근 파일)" if len(hits) > 1 else ""
        print(f"  {p['id']} <- {hits[0].name}{extra}")
    print(f"\n정리 {done}편, 아직 없음 {len(unmatched)}편")
    for p in unmatched:
        print(f"  없음: {p['id']}  {p['pdf_url']}")

if __name__ == "__main__":
    main()
