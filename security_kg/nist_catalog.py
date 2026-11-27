"""NIST CSF 2.0와 SP 800-53 Rev. 5의 항목 번호를 공식 목록에서 확인한다(RootCause 표준 매핑 후보의 검증).

하는 일: 공식 OSCAL 목록(NIST의 GitHub 저장소 usnistgov/oscal-content)을 읽어 번호와 제목만 담은 작은 파일
`data/nist_catalog.json`을 만들고, `consts.ROOT_CAUSE_STANDARD_MAP`의 번호가 모두 실제로 있는지 검사한다.
**번호가 있다는 것은 그 RootCause에 적합하다는 뜻이 아니다.** 적합성은 사람이 검토한다(mapping_status).

사용: python nist_catalog.py                       # data/nist_catalog.json으로 후보 번호가 있는지 검사한다
      python nist_catalog.py --build CSF.json R5.json   # 내려받은 두 OSCAL 파일로 data/nist_catalog.json을 만든다
      python nist_catalog.py --fetch                    # 두 파일을 내려받아(backbone/raw/nist/) 만든다
      python nist_catalog.py --build CSF.json R5.json --review-sheet   # 만들면서 후보 검토표(data/nist_candidate_review.csv)도 만든다
      python nist_catalog.py --tally-review data/nist_candidate_review.csv   # 사람이 채운 판정을 집계한다
      python nist_catalog.py --self-test

내려받는 파일: NIST_CSF_v2.0_catalog.json, NIST_SP-800-53_rev5_catalog.json. GitHub의 main 브랜치 사본이라 커밋 해시는 없고
파일의 sha256과 제목, 버전, last-modified를 기록해 재현할 수 있게 한다. 10MB 원본은 저장소에 올리지 않는다(backbone/raw/는 제외 폴더).
"""
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402

HERE = Path(__file__).resolve().parent
OUT = HERE / "data" / "nist_catalog.json"
RAW = HERE / "backbone" / "raw" / "nist"
BASE = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov"
SOURCES = {
    "csf_2_0": f"{BASE}/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json",
    "sp800_53_rev5": f"{BASE}/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
}
CSF_FN = re.compile(r"^[A-Z]{2}$")
CSF_CAT = re.compile(r"^[A-Z]{2}\.[A-Z]{2}$")
CSF_SUB = re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d{2}$")


def _status(node):
    """OSCAL props의 status(예: withdrawn). 이전 버전에서 철회된 항목도 파일에 남아 있어 구분해야 한다."""
    for p in node.get("props", []):
        if p.get("name") == "status":
            return p.get("value")
    return None


def _statement(node, limit=1500):
    """항목의 본문(statement 부분)만 모은다. 지침(guidance)과 구현 예시는 넣지 않는다. 항목이 여럿이면 이어 붙인다."""
    out = []

    def walk(part):
        if part.get("prose"):
            out.append(part["prose"].strip())
        for q in part.get("parts", []):
            walk(q)

    for p in node.get("parts", []):
        if p.get("name") == "statement":
            walk(p)
    text = " ".join(out)
    text = re.sub(r"\{\{ insert: param, [^}]*\}\}", "[조직이 정함]", text)   # OSCAL의 조직 정의 값 자리표시
    return text[:limit]


def _prose(node):
    return " ".join(p.get("prose", "") for p in node.get("parts", []) if p.get("prose")).strip()


def _walk(node, visit):
    for key in ("groups", "controls"):
        for c in node.get(key, []):
            visit(c)
            _walk(c, visit)


def parse_csf(doc: dict) -> dict:
    cat = doc["catalog"]
    ids = {}

    def visit(c):
        i = c["id"].upper()
        kind = "function" if CSF_FN.match(i) else "category" if CSF_CAT.match(i) else "subcategory" if CSF_SUB.match(i) else None
        if kind:
            title, st = c.get("title", ""), _statement(c)
            ids[i] = {"type": kind, "title": title if title and title.upper() != i else st[:160], "status": _status(c), "statement": st}

    _walk(cat, visit)
    return {"title": cat["metadata"]["title"], "version": cat["metadata"].get("version"),
            "last_modified": cat["metadata"].get("last-modified"), "ids": ids}


def _norm_80053(i: str) -> str:
    """OSCAL의 'ac-2.1'을 'AC-2(1)'로, 'ac-2'를 'AC-2'로 바꾼다."""
    i = i.upper()
    return re.sub(r"\.(\d+)$", r"(\1)", i)


def parse_80053(doc: dict) -> dict:
    cat = doc["catalog"]
    ids = {}

    def visit(c):
        i = _norm_80053(c["id"])
        if re.match(r"^[A-Z]{2}$", i):
            ids[i] = {"type": "family", "title": c.get("title", ""), "status": _status(c)}
        elif re.match(r"^[A-Z]{2}-\d{1,2}$", i):
            ids[i] = {"type": "control", "title": c.get("title", ""), "status": _status(c), "statement": _statement(c)}
        elif re.match(r"^[A-Z]{2}-\d{1,2}\(\d+\)$", i):
            ids[i] = {"type": "enhancement", "title": c.get("title", ""), "status": _status(c)}

    _walk(cat, visit)
    return {"title": cat["metadata"]["title"], "version": cat["metadata"].get("version"),
            "last_modified": cat["metadata"].get("last-modified"), "ids": ids}


def build(csf_path, r5_path, out=OUT) -> dict:
    out = Path(out)
    result = {}
    for key, path, parser in (("csf_2_0", csf_path, parse_csf), ("sp800_53_rev5", r5_path, parse_80053)):
        raw = Path(path).read_bytes()
        d = parser(json.loads(raw.decode("utf-8")))
        d["source"] = {"url": SOURCES[key], "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                       "note": "GitHub main 브랜치 사본. 커밋 해시는 기록하지 못함"}
        result[key] = d
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return result


def fetch(dest=RAW) -> dict:
    import os
    import ssl
    import urllib.request
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    cafile = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    paths = {}
    for key, url in SOURCES.items():
        p = dest / url.rsplit("/", 1)[1]
        with urllib.request.urlopen(url, timeout=120, context=ctx) as r:
            p.write_bytes(r.read())
        paths[key] = p
    return paths


def check_standard_map(catalog: dict, standard_map: dict | None = None) -> list[str]:
    """ROOT_CAUSE_STANDARD_MAP의 모든 번호가 공식 목록에 있는지 검사한다. 반환: 문제 목록(없으면 통과)."""
    standard_map = consts.ROOT_CAUSE_STANDARD_MAP if standard_map is None else standard_map
    problems = []
    csf, r5 = catalog["csf_2_0"]["ids"], catalog["sp800_53_rev5"]["ids"]
    for seed, m in standard_map.items():
        for i in m["nist_csf"]:
            if i not in csf:
                problems.append(f"{seed}: CSF 2.0에 없는 번호 {i}")
            elif csf[i].get("status") == "withdrawn":
                problems.append(f"{seed}: CSF에서 철회된 번호 {i}(이전 버전의 항목)")
        for i in m["nist_800_53"]:
            if i not in r5:
                problems.append(f"{seed}: SP 800-53 Rev. 5에 없는 번호 {i}")
            elif r5[i]["type"] == "family":
                problems.append(f"{seed}: 패밀리가 아니라 개별 통제 번호여야 함 {i}")
            elif r5[i].get("status") == "withdrawn":
                problems.append(f"{seed}: SP 800-53에서 철회된 통제 {i}")
    return problems


# ── 후보 검토표: 사람이 각 후보가 그 RootCause에 맞는지 판정한다 ─────────────────────────────
REVIEW_COLUMNS = ["행", "root_cause", "meaning", "failure_nature", "standard", "id", "kind", "official_title", "official_statement",
                  "also_used_by", "judge_fit", "judge_note"]
JUDGE_VALUES = ["적합", "부분 적합", "부적합", "판단 불가"]
REVIEW_PATH = HERE / "data" / "nist_candidate_review.csv"
STANDARD_NAMES = {"csf_2_0": "NIST CSF 2.0", "sp800_53_rev5": "SP 800-53 Rev. 5"}


def review_rows(catalog: dict, standard_map: dict | None = None, meanings: dict | None = None, attributes: dict | None = None) -> list[dict]:
    """후보 번호마다 한 줄. 공식 제목과 설명문을 붙이고, 같은 번호를 쓰는 다른 RootCause를 알려 준다.
    `행`은 엑셀에서 보이는 행 번호(제목줄이 1행이라 2부터)와 같게 매긴다."""
    standard_map = consts.ROOT_CAUSE_STANDARD_MAP if standard_map is None else standard_map
    meanings = consts.ROOT_CAUSE_MEANING if meanings is None else meanings
    attributes = consts.ROOT_CAUSE_ATTRIBUTES if attributes is None else attributes
    used = {}
    for seed, m in standard_map.items():
        for key, field in (("csf_2_0", "nist_csf"), ("sp800_53_rev5", "nist_800_53")):
            for i in m[field]:
                used.setdefault((key, i), []).append(seed)
    rows = []
    for seed, m in standard_map.items():
        for key, field in (("csf_2_0", "nist_csf"), ("sp800_53_rev5", "nist_800_53")):
            for i in m[field]:
                info = catalog[key]["ids"][i]
                rows.append({
                    "행": len(rows) + 2, "root_cause": seed, "meaning": meanings.get(seed, ""),
                    "failure_nature": attributes.get(seed, {}).get("failure_nature") or "미정", "standard": STANDARD_NAMES[key],
                    "id": i, "kind": info["type"], "official_title": info.get("title", ""),
                    "official_statement": info.get("statement", ""),
                    "also_used_by": "; ".join(x for x in used[(key, i)] if x != seed),
                    "judge_fit": "", "judge_note": ""})
    return rows


def write_review(rows, path=REVIEW_PATH):
    import csv
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, REVIEW_COLUMNS, lineterminator="\r\n")
        w.writeheader()
        w.writerows(rows)


def tally_review(rows) -> dict:
    """판정 집계. 비어 있거나 인식하지 못한 값은 따로 알린다."""
    from collections import Counter
    empty = [r for r in rows if not r["judge_fit"].strip()]
    unknown = [r for r in rows if r["judge_fit"].strip() and r["judge_fit"] not in JUDGE_VALUES]
    judged = [r for r in rows if r["judge_fit"] in JUDGE_VALUES]
    by_seed = {}
    for r in judged:
        by_seed.setdefault(r["root_cause"], Counter())[r["judge_fit"]] += 1
    return {"total": len(judged), "empty": empty, "unknown": unknown, "overall": Counter(r["judge_fit"] for r in judged),
            "by_seed": by_seed, "rejected": [r for r in judged if r["judge_fit"] == "부적합"]}


def self_test():
    csf = {"catalog": {"metadata": {"title": "T", "version": "1", "last-modified": "d"}, "groups": [
        {"id": "gv", "title": "GOVERN", "groups": [{"id": "gv.sc", "title": "Supply Chain", "controls": [
            {"id": "gv.sc-01", "title": "gv.sc-01", "parts": [{"name": "statement", "prose": "A program is established"}]}]}]}]}}
    r5 = {"catalog": {"metadata": {"title": "R", "version": "5.2.0", "last-modified": "d"}, "groups": [
        {"id": "ac", "title": "Access Control", "controls": [{"id": "ac-2", "title": "Account Management",
                                                               "controls": [{"id": "ac-2.1", "title": "Automated"}]}]}]}}
    c, r = parse_csf(csf), parse_80053(r5)
    assert c["ids"]["GV"]["type"] == "function" and c["ids"]["GV.SC"]["type"] == "category"
    assert "{{" not in _statement({"parts": [{"name": "statement", "prose": "Protect the {{ insert: param, x }} of data"}]}) \
        and "[조직이 정함]" in _statement({"parts": [{"name": "statement", "prose": "Protect the {{ insert: param, x }} of data"}]})
    assert c["ids"]["GV.SC-01"] == {"type": "subcategory", "title": "A program is established", "status": None,
                                    "statement": "A program is established"}
    assert r["ids"]["AC"]["type"] == "family" and r["ids"]["AC-2"]["type"] == "control" and r["ids"]["AC-2(1)"]["type"] == "enhancement"
    cat = {"csf_2_0": c, "sp800_53_rev5": r}
    ok = {"A": {"nist_csf": ["GV.SC", "GV.SC-01"], "nist_800_53": ["AC-2"]}}
    assert check_standard_map(cat, ok) == []
    assert len(check_standard_map(cat, {"A": {"nist_csf": ["GV.SC-99"], "nist_800_53": ["AC-9"]}})) == 2   # 없는 번호
    assert check_standard_map(cat, {"A": {"nist_csf": [], "nist_800_53": ["AC"]}})                          # 패밀리는 개별 통제가 아님
    # 검토표: 후보마다 한 줄, 같은 번호를 쓰는 다른 RootCause 표시, 행 번호는 엑셀 행과 같음
    sm = {"S1": {"nist_csf": ["GV.SC-01"], "nist_800_53": ["AC-2"]}, "S2": {"nist_csf": ["GV.SC-01"], "nist_800_53": []}}
    rows = review_rows(cat, sm, {"S1": "뜻1", "S2": "뜻2"}, {"S1": {"failure_nature": "X"}, "S2": {"failure_nature": None}})
    assert [r["행"] for r in rows] == [2, 3, 4] and rows[0]["official_statement"] == "A program is established"
    assert rows[0]["also_used_by"] == "S2" and rows[2]["also_used_by"] == "S1" and rows[2]["failure_nature"] == "미정"
    rows[0]["judge_fit"], rows[1]["judge_fit"], rows[2]["judge_fit"] = "적합", "부적합", "맞음"
    t = tally_review(rows)
    assert t["total"] == 2 and len(t["unknown"]) == 1 and [r["id"] for r in t["rejected"]] == ["AC-2"]
    # 철회된 항목은 번호가 파일에 있어도 통과시키지 않는다
    wd = {"catalog": {"metadata": {"title": "T"}, "groups": [{"id": "pr", "title": "PROTECT", "groups": [
        {"id": "pr.ac", "title": "Old", "props": [{"name": "status", "value": "withdrawn"}]}]}]}}
    cw = {"csf_2_0": parse_csf(wd), "sp800_53_rev5": r}
    assert cw["csf_2_0"]["ids"]["PR.AC"]["status"] == "withdrawn"
    assert any("철회" in x for x in check_standard_map(cw, {"A": {"nist_csf": ["PR.AC"], "nist_800_53": []}}))
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        a, b = Path(d) / "c.json", Path(d) / "r.json"
        a.write_text(json.dumps(csf)); b.write_text(json.dumps(r5))
        res = build(a, b, Path(d) / "o.json")
        assert res["csf_2_0"]["source"]["sha256"] and json.loads((Path(d) / "o.json").read_text())["sp800_53_rev5"]["version"] == "5.2.0"
    print("자체 시험 통과")


def main():
    if "--self-test" in sys.argv:
        return self_test()
    if "--tally-review" in sys.argv:
        import csv
        path = Path(sys.argv[sys.argv.index("--tally-review") + 1])
        with open(path, encoding="utf-8-sig", newline="") as f:
            t = tally_review(list(csv.DictReader(f)))
        print(f"판정 {t['total']}건: {dict(t['overall'])}")
        if t["empty"] or t["unknown"]:
            print(f"  비어 있음 {len(t['empty'])}건, 인식하지 못한 값 {len(t['unknown'])}건: {sorted({r['judge_fit'] for r in t['unknown']})}")
        for seed, c in t["by_seed"].items():
            print(f"  {seed}: {dict(c)}")
        print("부적합으로 판정한 후보(엑셀 행):", [(r["행"], r["root_cause"], r["id"]) for r in t["rejected"]])
        return
    if "--fetch" in sys.argv:
        paths = fetch()
        res = build(paths["csf_2_0"], paths["sp800_53_rev5"])
    elif "--build" in sys.argv:
        i = sys.argv.index("--build")
        res = build(sys.argv[i + 1], sys.argv[i + 2])
    else:
        res = json.loads(OUT.read_text(encoding="utf-8"))
    if "--review-sheet" in sys.argv:
        write_review(review_rows(res))
        print(f"검토표를 만들었습니다: {REVIEW_PATH} ({len(review_rows(res))}행)")
    for k, v in res.items():
        print(f"{k}: {v['title']} (버전 {v['version']}, last-modified {v['last_modified']}), 번호 {len(v['ids'])}개, sha256 {v['source']['sha256'][:12]}…")
    problems = check_standard_map(res)
    n = sum(len(m["nist_csf"]) + len(m["nist_800_53"]) for m in consts.ROOT_CAUSE_STANDARD_MAP.values())
    print(f"후보 번호 {n}개 검사:", "모두 공식 목록에 있음(적합성은 확인하지 않음)" if not problems else "")
    for p in problems:
        print(" -", p)
    if problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
