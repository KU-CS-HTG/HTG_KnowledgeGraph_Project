"""문서 원본(pdf, hwpx, html, txt, md)에서 본문 텍스트를 뽑는다. 원본은 PDF를 모델에 직접 올렸지만,
우리 문서는 형식이 섞여 있고(hwpx 등) 근거 문장이 원문에 있는지 검사해야 해서 텍스트로 바꿔 쓴다.
`.hwp`(옛 한글 형식)는 지원하지 않는다: hwpx나 pdf로 저장해서 쓴다."""
import re
import subprocess
import zipfile
from html.parser import HTMLParser
from pathlib import Path


class _Strip(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        elif tag in ("p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def _pdf(path: Path) -> str:
    out = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, check=True)
    return out.stdout


def _hwpx(path: Path) -> str:
    texts = []
    with zipfile.ZipFile(path) as z:
        for name in sorted(n for n in z.namelist() if re.search(r"Contents/section\d+\.xml$", n)):
            xml = z.read(name).decode("utf-8", errors="replace")
            for para in re.findall(r"<hp:p\b.*?</hp:p>", xml, flags=re.S):
                t = "".join(re.findall(r"<hp:t>(.*?)</hp:t>", para, flags=re.S))
                texts.append(re.sub(r"<[^>]+>", "", t))
    return "\n".join(texts)


def _html(path: Path) -> str:
    p = _Strip()
    p.feed(path.read_text(encoding="utf-8", errors="replace"))
    return "".join(p.parts)


def extract_text(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".pdf":
        text = _pdf(path)
    elif ext == ".hwpx":
        text = _hwpx(path)
    elif ext in (".html", ".htm"):
        text = _html(path)
    elif ext in (".txt", ".md"):
        text = path.read_text(encoding="utf-8", errors="replace")
    else:
        raise ValueError(f"지원하지 않는 형식: {ext} ({path.name}). hwp는 hwpx나 pdf로 저장해서 쓰세요")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    if len(text) < 200:
        raise ValueError(f"{path.name}: 추출된 글자가 {len(text)}자뿐이다. 스캔 이미지 PDF일 수 있다(글자 인식이 필요)")
    return text
