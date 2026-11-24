"""매니페스트의 pdf_url에서 PDF를 받아 papers/pdfs/<date>/<OpenAlexID>.pdf 로 저장한다.

- 이미 유효한 PDF가 있으면 건너뛴다(이어받기 가능).
- 출판사 서버에 부담을 주지 않도록 요청 사이에 대기한다.
- 실패한 논문은 failures.json 에 이유와 함께 남긴다.
"""
import argparse, json, time
from pathlib import Path
import requests

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
           "Accept": "application/pdf,*/*;q=0.8"}
MAX_BYTES = 100 * 1024 * 1024

def is_pdf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(5) == b"%PDF-"
    except OSError:
        return False

def download(url: str, out: Path, timeout: int, retries: int) -> str | None:
    """성공하면 None, 실패하면 이유 문자열을 돌려준다."""
    last = "unknown"
    for attempt in range(retries + 1):
        try:
            with requests.get(url, headers=HEADERS, timeout=timeout, stream=True, allow_redirects=True) as r:
                if r.status_code != 200:
                    last = f"HTTP {r.status_code}"
                    if r.status_code in (403, 404, 410):
                        return last
                    raise RuntimeError(last)
                tmp = out.with_suffix(".part"); total = 0
                with tmp.open("wb") as f:
                    for chunk in r.iter_content(8192):
                        total += len(chunk)
                        if total > MAX_BYTES:
                            tmp.unlink(missing_ok=True); return "too large"
                        f.write(chunk)
            if not is_pdf(tmp):
                tmp.unlink(missing_ok=True); return "not a PDF (HTML 응답일 수 있음)"
            tmp.replace(out); return None
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"[:200]
            time.sleep(2 * (attempt + 1))
    return last

def main() -> None:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", type=Path, default=here / "data" / "cmip_papers_pdf_urls.json")
    ap.add_argument("--out-root", type=Path, default=here.parent / "cmip_recall" / "extraction" / "papers" / "pdfs")
    ap.add_argument("--limit", type=int, default=None, help="앞에서 N편만(시험용)")
    ap.add_argument("--delay", type=float, default=1.5)
    ap.add_argument("--timeout", type=int, default=45)
    ap.add_argument("--retries", type=int, default=2)
    a = ap.parse_args()
    m = json.loads(a.manifest.read_text(encoding="utf-8"))
    out_dir = a.out_root / m["date"]; out_dir.mkdir(parents=True, exist_ok=True)
    papers = m["papers"][: a.limit] if a.limit else m["papers"]
    fails, ok, skipped = [], 0, 0
    for i, p in enumerate(papers, 1):
        out = out_dir / f"{p['id']}.pdf"
        if out.exists() and is_pdf(out):
            skipped += 1; continue
        why = download(p["pdf_url"], out, a.timeout, a.retries)
        if why is None: ok += 1
        else: fails.append({"id": p["id"], "title": p["title"], "pdf_url": p["pdf_url"], "reason": why})
        print(f"[{i}/{len(papers)}] {p['id']} {'OK' if why is None else 'FAIL ' + why}", flush=True)
        time.sleep(a.delay)
    (out_dir / "failures.json").write_text(json.dumps(fails, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n받음 {ok} / 이미 있음 {skipped} / 실패 {len(fails)}  (실패 목록: {out_dir / 'failures.json'})")

if __name__ == "__main__":
    main()
