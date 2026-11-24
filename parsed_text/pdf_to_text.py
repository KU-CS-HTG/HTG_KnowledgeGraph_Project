"""PDF를 텍스트로 바꿔 papers/parsed/<date>/<id>.md 로 저장한다.

주의: 논문은 olmOCR로 파싱했다. 이 스크립트는 PyMuPDF(없으면 pypdf)로 텍스트를 직접 꺼내는 근사 방법이라
파싱 결과가 달라 재현율 수치가 논문과 정확히 같지 않을 수 있다.
"""
import argparse, re, sys
from pathlib import Path

def extract(pdf: Path) -> str:
    try:
        try:
            import pymupdf as fitz  # PyMuPDF 1.24+
        except ImportError:
            import fitz  # 구버전 이름
        with fitz.open(pdf) as doc:
            return "\n\n".join(page.get_text("text", sort=True) for page in doc)
    except ImportError:
        from pypdf import PdfReader
        return "\n\n".join((p.extract_text() or "") for p in PdfReader(str(pdf)).pages)

def main() -> None:
    for _s in (sys.stdout, sys.stderr):  # Windows cp949 콘솔에서 특수문자로 죽지 않게
        try: _s.reconfigure(errors="replace")
        except Exception: pass
    root = Path(__file__).resolve().parent.parent / "cmip_recall" / "extraction" / "papers"
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--date", default="2026-02-01")
    ap.add_argument("--pdf-dir", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=None)
    a = ap.parse_args()
    pdf_dir = a.pdf_dir or root / "pdfs" / a.date
    out_dir = a.out_dir or root / "parsed" / a.date
    out_dir.mkdir(parents=True, exist_ok=True)
    n = bad = 0
    for pdf in sorted(pdf_dir.glob("*.pdf")):
        try:
            text = re.sub(r"[ \t]+\n", "\n", extract(pdf))
            (out_dir / f"{pdf.stem}.md").write_text(text, encoding="utf-8")
            n += 1
            if len(text) < 2000: print(f"짧음(스캔본 가능성): {pdf.name} {len(text)}자"); bad += 1
        except Exception as exc:  # noqa: BLE001
            print(f"실패: {pdf.name}: {exc}"); bad += 1
    print(f"변환 {n}편, 확인 필요 {bad}편 -> {out_dir}")

if __name__ == "__main__":
    main()
