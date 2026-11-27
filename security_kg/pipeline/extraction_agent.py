"""문서 → 추출 JSON (원본 `extraction_agent.py`의 보안 분야판, Claude 사용).

문서마다 호출 3번: (1) 문서 단위 메타데이터(출처 유형, 날짜, 사건 언급) (2) 관계 목록 (3) 개체 목록.
원본의 논문 전용 호출(분야, 문제, 방법, 관측 데이터셋, 기후 모델, 논문 선별)은 없앴다. 수치는 별도 층(`measurements.py`)이다.
출력 파일 `<doc_id>.json`이 이미 있으면 건너뛴다(중단 뒤 이어서 실행).

사용: python extraction_agent.py --docs-dir DIR --out-dir DIR [--model M] [--metadata-model M] [--max-workers N]
키는 환경변수 ANTHROPIC_API_KEY. 저장소에 쓰지 않는다. 문서 원본(DIR)도 저장소에 올리지 않는다(운영-D2).
"""
import argparse
import concurrent.futures
import json
from pathlib import Path

from conformance import check_entity, check_triplet
from doc_text import extract_text
from llm import DEFAULT_METADATA_MODEL, DEFAULT_MODEL, ClaudeClient
from models import Document_Meta_Model, Entity_Extraction_Model, Kg_Extraction_Model
from prompts import DOCUMENT_META_PROMPT, ENTITY_EXTRACTION_PROMPT, KG_EXTRACTION_PROMPT

SUPPORTED = {".pdf", ".hwpx", ".html", ".htm", ".txt", ".md"}


def process_document(doc_id: str, path: Path, client, model: str, metadata_model: str) -> dict:
    text = extract_text(path)
    meta = client.structured(DOCUMENT_META_PROMPT, text, Document_Meta_Model, model=metadata_model)
    triplets = client.structured(KG_EXTRACTION_PROMPT, text, Kg_Extraction_Model, model=model, as_list=True)
    mentions = client.structured(ENTITY_EXTRACTION_PROMPT, text, Entity_Extraction_Model, model=model, as_list=True)
    entities = []
    for m in mentions:
        d = m.model_dump()
        d["issues"] = check_entity(d["entity_type"], d["entity_instance"])
        entities.append(d)
    return {
        "doc_id": doc_id,
        "source_file": path.name,
        "text_chars": len(text),
        "models": {"extraction": model, "metadata": metadata_model},
        **meta.model_dump(),
        "kg_extraction_triplets": [check_triplet(t.model_dump(), text) for t in triplets],
        "entities_extracted": entities,
    }


def run(docs_dir: Path, out_dir: Path, client, model: str, metadata_model: str, max_workers: int = 4) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in docs_dir.iterdir() if p.suffix.lower() in SUPPORTED)
    todo = [p for p in files if not (out_dir / f"{p.stem}.json").exists()]
    stats = {"found": len(files), "skipped_existing": len(files) - len(todo), "done": 0, "failed": {}}

    def one(p: Path):
        try:
            result = process_document(p.stem, p, client, model, metadata_model)
            (out_dir / f"{p.stem}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            return p.stem, None
        except Exception as e:                       # 한 문서의 실패가 나머지를 멈추지 않게 한다
            return p.stem, f"{type(e).__name__}: {e}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for doc_id, err in ex.map(one, todo):
            if err:
                stats["failed"][doc_id] = err
            else:
                stats["done"] += 1
    return stats


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--docs-dir", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--metadata-model", default=DEFAULT_METADATA_MODEL)
    ap.add_argument("--max-workers", type=int, default=4)
    a = ap.parse_args()
    stats = run(a.docs_dir, a.out_dir, ClaudeClient(), a.model, a.metadata_model, a.max_workers)
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
