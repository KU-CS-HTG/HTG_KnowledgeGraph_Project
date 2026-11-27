"""임베딩 모델 시험(운영-D5 4단계 준비): 한국어 언급이 뼈대의 영어 항목에 가장 가깝게 나오는가.

뼈대 색인(ATT&CK 기법, 전술, 소프트웨어, 그룹과 별칭, CWE, RootCause 시드)을 만들고, `embedding_eval_cases.csv`의 질의마다
같은 종류 안에서 가장 가까운 항목 3개를 찾아 정답과 비교한다. 부정 예(`NEGATIVE`)는 어떤 항목과도 맞으면 안 되는 말이며,
정답 점수와 부정 점수가 얼마나 떨어져 있는지를 보고 임계값을 정한다.
정답 라벨은 별칭 검토표 4행을 빼고 Claude가 썼다(사람 확인 전). 이 시험은 모델 선택용 첫 확인이지 정확도 평가가 아니다.

사용: python embedding_eval.py [--model BAAI/bge-m3] [--out embedding_eval_result.csv]
"""
import argparse
import csv
import json
from pathlib import Path

import numpy as np

from _paths import ROOT, consts

CASES = Path(__file__).with_name("embedding_eval_cases.csv")


def build_index() -> dict[str, list[tuple[str, str]]]:
    """종류 → [(색인할 글, 항목 ID)]. 별칭은 글을 따로 만들고 같은 ID에 연결한다."""
    att = json.load(open(ROOT / "data" / "attack_catalog.json", encoding="utf-8"))
    cwe = json.load(open(ROOT / "data" / "cwe_catalog.json", encoding="utf-8"))
    idx = {"Technique": [], "Tactic": [], "MalwareFamily": [], "ThreatActor": [], "Weakness": [], "RootCause": []}
    for tid, t in att["techniques"].items():
        idx["Technique"].append((t["name"], tid))
    for name, t in att["tactics"].items():
        idx["Tactic"].append((t["name"], name))
    for sid, s in att["software"].items():
        for text in dict.fromkeys([s["name"], *s.get("aliases", [])]):
            idx["MalwareFamily"].append((text, sid))
    for gid, g in att["groups"].items():
        for text in dict.fromkeys([g["name"], *g.get("aliases", [])]):
            idx["ThreatActor"].append((text, gid))
    for cid, w in cwe["weaknesses"].items():
        idx["Weakness"].append((w["name"], f"CWE-{cid}"))
    for rc in consts.ROOT_CAUSE_SEED:
        idx["RootCause"].append((rc.replace("_", " ").lower(), rc))
        idx["RootCause"].append((consts.ROOT_CAUSE_MEANING.get(rc, rc), rc))
    return idx


def encode(model, texts: list[str]) -> np.ndarray:
    return np.asarray(model.encode(texts, batch_size=32, normalize_embeddings=True, show_progress_bar=False), dtype=np.float32)


def top_matches(q: np.ndarray, mat: np.ndarray, ids: list[str], k: int = 3) -> list[tuple[str, float]]:
    """같은 ID가 여러 글(별칭)로 있으면 그 ID의 가장 높은 점수를 쓴다."""
    scores = mat @ q
    best: dict[str, float] = {}
    for i in np.argsort(-scores)[: k * 20]:
        best.setdefault(ids[i], float(scores[i]))
        if len(best) == k:
            break
    return sorted(best.items(), key=lambda x: -x[1])


def evaluate(model, cases: list[dict], idx: dict) -> list[dict]:
    mats = {k: (encode(model, [t for t, _ in v]), [i for _, i in v]) for k, v in idx.items()}
    out = []
    for c in cases:
        q = encode(model, [c["query"]])[0]
        kinds = list(mats) if c["kind"] == "NEGATIVE" else [c["kind"]]
        cand = sorted((m for k in kinds for m in top_matches(q, *mats[k])), key=lambda x: -x[1])[:3]
        exp = set(filter(None, c["expected"].split("|")))
        top1 = cand[0] if cand else ("", 0.0)
        rank = next((n for n, (i, _) in enumerate(cand, 1) if i in exp), 0)
        out.append({**c, "top1": top1[0], "top1_score": round(top1[1], 3), "top3": "; ".join(f"{i} {s:.3f}" for i, s in cand),
                    "rank_of_expected": rank if exp else "", "hit_top1": (rank == 1) if exp else "", "hit_top3": (rank > 0) if exp else ""})
    return out


def summarize(rows: list[dict]) -> dict:
    pos = [r for r in rows if r["kind"] != "NEGATIVE"]
    neg = [r for r in rows if r["kind"] == "NEGATIVE"]
    by = {}
    for r in pos:
        d = by.setdefault(r["kind"], {"n": 0, "top1": 0, "top3": 0})
        d["n"] += 1; d["top1"] += bool(r["hit_top1"]); d["top3"] += bool(r["hit_top3"])
    hit = sorted(r["top1_score"] for r in pos if r["hit_top1"])
    miss = sorted(r["top1_score"] for r in pos if not r["hit_top1"])
    return {"by_kind": by, "positives": len(pos), "top1": sum(bool(r["hit_top1"]) for r in pos), "top3": sum(bool(r["hit_top3"]) for r in pos),
            "score_when_top1_correct": hit, "score_when_top1_wrong": miss, "negative_top1_scores": sorted(r["top1_score"] for r in neg)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="BAAI/bge-m3")
    ap.add_argument("--out", type=Path, default=Path(__file__).with_name("embedding_eval_result.csv"))
    a = ap.parse_args()
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer(a.model, device="cpu")
    idx = build_index()
    cases = list(csv.DictReader(open(CASES, encoding="utf-8-sig")))
    known = {i for v in idx.values() for _, i in v}
    for c in cases:                                   # 정답 ID가 뼈대에 없으면 라벨이 틀린 것이다
        for e in filter(None, c["expected"].split("|")):
            if e not in known:
                print(f"주의: 정답 {e}가 뼈대에 없음 ({c['query']})")
    rows = evaluate(model, cases, idx)
    with open(a.out, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, list(rows[0]), lineterminator="\r\n"); w.writeheader(); w.writerows(rows)
    print(json.dumps(summarize(rows), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
