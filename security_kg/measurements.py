"""수치 층: 피해 규모와 금액을 별도 기록으로 정규화하고 출처별로 나란히 보여 준다 (결정 D9~D12).

문제: 수치는 트리플렛의 도착이 개체가 아니라 값이고, 단위(명/건/GB/원), 정확도(약/이상/범위), 시점, 출처에 따라
뜻이 달라진다. 그래서 단위·정확도·시점·출처가 붙은 별도 기록으로 둔다.

  - 지표는 닫힌 소수 목록(consts.MEASUREMENT_METRICS) + other. 사람 수, 건수, 용량, 금액은 서로 합치거나 비교하지 않는다.
  - 출처 간 차이는 조정하지 않는다. 같은 지표(단위 종류, 통화) 안에서만 최솟값~최댓값 범위를 보여 준다.
  - 정규화는 AI 없이 규칙으로 한다. 읽지 못하면 버리지 않고 review 사유를 붙인다.
  - 통화는 환산하지 않는다.

기록(입력): {"incident", "metric", "raw", "evidence", "as_of", "doc_id", "source_type", "assertion_status"}
  raw: 문서의 수치 표현 그대로(예: "약 3,367만 건"), evidence: 그 표현이 나온 근거 문장

한계: 한국어 수 표기 규칙은 일반 지식으로 만든 것이고 실제 문서로 시험하지 않았다.
      영어는 thousand/million/billion/trillion만 읽는다. 읽지 못한 표기는 review로 간다.

사용: python measurements.py   # 자체 시험 실행
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402

_NUM = r"\d[\d,]*(?:\.\d+)?"
_KO_SMALL = {"천": 1_000, "백": 100}
_KO_BIG = {"만": 10_000, "억": 100_000_000, "조": 1_000_000_000_000}
_EN_SCALE = {"thousand": 1e3, "million": 1e6, "billion": 1e9, "trillion": 1e12}
_TOKEN = re.compile(rf"({_NUM})|([천백만억조])|\b(thousand|million|billion|trillion)\b", re.I)
_BYTES = {"B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12, "PB": 1e15}   # 십진 단위로 계산한다

_QUALIFIER_PATTERNS = [   # 먼저 맞는 것이 이긴다
    ("lower_bound", re.compile(r"이상|초과|넘[는게]|at least|more than|over\b|\d\s*\+", re.I)),
    ("upper_bound", re.compile(r"이하|미만|최대|up to|at most|no more than", re.I)),
    ("approx", re.compile(r"약\s|약\d|대략|가량|안팎|about|approximately|roughly|around|estimated", re.I)),
]


def _parse_number_span(text: str):
    """텍스트에서 첫 숫자 덩어리(한국어 만/억/조, 영어 million 등 포함)를 읽어 값을 돌려준다. 없으면 None."""
    toks = list(_TOKEN.finditer(text))
    first = next((i for i, m in enumerate(toks) if m.group(1)), None)
    if first is None:
        return None
    total, section, num, used_ko = 0.0, 0.0, None, False
    en_mult, base = None, None
    prev_end = None
    for m in toks[first:]:
        if prev_end is not None and text[prev_end:m.start()].strip() != "":
            break
        prev_end = m.end()
        if m.group(1):
            if num is not None:            # 숫자가 연달아 나오면 한 덩어리가 아님
                break
            num = float(m.group(1).replace(",", ""))
        elif m.group(2):
            used_ko = True
            ch = m.group(2)
            if ch in _KO_SMALL:
                section += (num if num is not None else 1) * _KO_SMALL[ch]
                num = None
            else:
                section += (num or 0)
                if section == 0:
                    section = 1
                total += section * _KO_BIG[ch]
                section, num = 0.0, None
        else:
            en_mult = _EN_SCALE[m.group(3).lower()]
            base = num
            num = None
            break
    if en_mult is not None and not used_ko:
        return (base or 0) * en_mult
    return total + section + (num or 0)


def _detect_unit(text: str):
    """(unit_kind, currency). 읽지 못하면 (None, None)."""
    if re.search(r"\$|USD|달러|dollars?\b", text, re.I):
        return "money", "USD"
    if re.search(r"KRW|원(?![가-힣])|\bwon\b", text, re.I):
        return "money", "KRW"
    if re.search(r"EUR|유로|euros?\b", text, re.I):
        return "money", "EUR"
    if re.search(r"JPY|엔(?![가-힣])|\byen\b", text, re.I):
        return "money", "JPY"
    if re.search(r"(?<![A-Za-z])(PB|TB|GB|MB|KB)(?![A-Za-z])", text, re.I):
        return "bytes", None
    if re.search(r"명(?![가-힣])|\b(people|persons|users|customers|individuals|subscribers)\b", text, re.I):
        return "people", None
    if re.search(r"건(?![가-힣])|\brecords?\b|\bentries\b|\brows\b", text, re.I):
        return "records", None
    return None, None


def parse_quantity(raw: str) -> dict:
    """수치 표현을 정규화한다. 반환: value, value_high, unit_kind, currency, qualifier, review(사유 목록)."""
    review, text = [], raw.strip()
    unit_kind, currency = _detect_unit(text)
    qualifier = "exact"
    for q, pat in _QUALIFIER_PATTERNS:
        if pat.search(text):
            qualifier = q
            break
    parts = re.split(r"\s*~\s*|\s+to\s+", text, maxsplit=1)
    value = value_high = None
    if len(parts) == 2:
        lo, hi = _parse_number_span(parts[0]), _parse_number_span(parts[1])
        if lo is not None and hi is not None:
            value, value_high, qualifier = lo, hi, "range"
    if value is None:
        value = _parse_number_span(text)
    if value is None:
        review.append("no_number")
        qualifier = "approx"
    elif unit_kind == "bytes":
        m = re.search(r"(?<![A-Za-z])(PB|TB|GB|MB|KB)(?![A-Za-z])", text, re.I)
        factor = _BYTES[m.group(1).upper()]
        value = value * factor
        value_high = value_high * factor if value_high is not None else None
    if value is not None and unit_kind is None:
        review.append("unit_unknown")
    if value is not None:
        value = int(round(value))
        value_high = int(round(value_high)) if value_high is not None else None
    return {"value": value, "value_high": value_high, "unit_kind": unit_kind, "currency": currency,
            "qualifier": qualifier, "review": review}


def normalize_measurement(rec: dict) -> dict:
    """원문 기록에 정규화 결과를 붙인다. 문제가 있어도 버리지 않고 review 사유를 붙인다."""
    out = dict(rec)
    metric = rec.get("metric")
    if metric not in consts.MEASUREMENT_METRICS:
        out["metric"] = "other"
        out["review"] = ["unknown_metric"]
    else:
        out["review"] = []
    q = parse_quantity(rec.get("raw", ""))
    out.update({k: q[k] for k in ("value", "value_high", "unit_kind", "currency", "qualifier")})
    out["review"] += q["review"]
    want = consts.MEASUREMENT_METRICS[out["metric"]]["unit_kind"]
    if want and q["unit_kind"] and q["unit_kind"] != want:
        out["review"].append("unit_mismatch")
    if rec.get("evidence") is not None and rec.get("raw", "") not in rec["evidence"]:
        out["review"].append("raw_not_in_evidence")
    out.setdefault("assertion_status", "inferred")
    return out


def _compare_key(r: dict):
    """같은 지표 안에서만 비교한다: 지표 + 단위 종류 + 통화."""
    return (r["metric"], r["unit_kind"], r["currency"])


def summarize_measurements(records: list[dict], incident: str, n_documents: int) -> dict:
    """사건 하나의 수치를 지표별로 나란히 정리한다. 출처 간 차이는 조정하지 않는다."""
    rows = [normalize_measurement(r) for r in records if r.get("incident") == incident]
    if not rows:
        return {"incident": incident, "groups": [], "review": [],
                "text": consts.MEASUREMENT_NOT_MENTIONED_TEXT.format(n=n_documents)}
    groups = defaultdict(list)
    review = []
    for r in rows:
        if r["review"]:
            review.append(r)
        groups[_compare_key(r)].append(r)
    out = []
    for key, items in groups.items():
        items.sort(key=lambda r: (consts.ASSERTION_RANK.get(r["assertion_status"], 9), r.get("as_of") or ""))
        usable = [r for r in items if r["value"] is not None and not r["review"]]
        values = [v for r in usable for v in (r["value"], r["value_high"]) if v is not None]
        out.append({
            "metric": key[0], "unit_kind": key[1], "currency": key[2], "rows": items,
            "range": (min(values), max(values)) if values else None,
            "sources_differ": len(set(values)) > 1,
            "includes_bounds": any(r["qualifier"] in ("lower_bound", "upper_bound") for r in usable),
        })
    order = list(consts.MEASUREMENT_METRICS)
    out.sort(key=lambda g: order.index(g["metric"]))
    return {"incident": incident, "groups": out, "review": review, "text": None}


def render_measurements(summary: dict) -> str:
    if summary["text"]:
        return f"{summary['incident']}: {summary['text']}"
    lines = [f"{summary['incident']}"]
    for g in summary["groups"]:
        unit = g["currency"] or g["unit_kind"] or "단위 미상"
        lines.append(f"  [{g['metric']}] ({unit})")
        for r in g["rows"]:
            val = "값 없음" if r["value"] is None else (
                f"{r['value']:,}~{r['value_high']:,}" if r["value_high"] is not None else f"{r['value']:,}")
            flag = f"  ← 사람 확인: {', '.join(r['review'])}" if r["review"] else ""
            lines.append(f"    {val} ({r['qualifier']}) | \"{r['raw']}\" | {r.get('source_type', '?')}, "
                         f"{r['assertion_status']}, {r.get('as_of') or '시점 없음'}{flag}")
        if g["sources_differ"]:
            lo, hi = g["range"]
            note = " (하한/상한 표현 포함)" if g["includes_bounds"] else ""
            lines.append(f"    → 출처 간 차이: {lo:,} ~ {hi:,}{note}. 어느 쪽이 맞는지는 판정하지 않는다")
    return "\n".join(lines)


# ── 자체 시험 ──────────────────────────────────────────────────────────────
def _rec(incident, metric, raw, src="media", st="confirmed", as_of="2026-01", ev=None, doc="d1"):
    return {"incident": incident, "metric": metric, "raw": raw, "evidence": ev if ev is not None else f"... {raw} ...",
            "as_of": as_of, "doc_id": doc, "source_type": src, "assertion_status": st}


def self_test() -> None:
    q = parse_quantity
    # 1) 한국어 수 표기
    assert q("2,324만 명")["value"] == 23_240_000 and q("2,324만 명")["unit_kind"] == "people"
    assert q("1억 2,300만 명")["value"] == 123_000_000
    assert q("3천5백만 건")["value"] == 35_000_000
    assert q("1.5억 건")["value"] == 150_000_000
    # 2) 정확도 표현
    assert q("약 3,367만 건")["qualifier"] == "approx"
    assert q("3,000만 건 이상")["qualifier"] == "lower_bound"
    assert q("최대 100만 명")["qualifier"] == "upper_bound"
    r = q("2,000만~2,500만 명")
    assert (r["value"], r["value_high"], r["qualifier"]) == (20_000_000, 25_000_000, "range")
    # 3) 용량과 영어
    assert q("9.82GB")["value"] == 9_820_000_000 and q("9.82GB")["unit_kind"] == "bytes"
    r = q("23.24 million users")
    assert r["value"] == 23_240_000 and r["unit_kind"] == "people"
    r = q("$1.5 billion")
    assert r["value"] == 1_500_000_000 and (r["unit_kind"], r["currency"]) == ("money", "USD")
    r = q("100억 원")
    assert r["value"] == 10_000_000_000 and r["currency"] == "KRW"
    # 4) 읽지 못하면 버리지 않고 확인 대상
    r = q("수백만 건")
    assert r["value"] is None and "no_number" in r["review"]
    assert "unit_unknown" in q("3,367만")["review"]

    # 5) 지표와 단위가 맞지 않으면 확인, 근거 문장에 원문이 없으면 확인
    n = normalize_measurement(_rec("X", "affected_people", "3,367만 건"))
    assert "unit_mismatch" in n["review"]
    n = normalize_measurement(_rec("X", "affected_records", "3,367만 건", ev="다른 문장"))
    assert "raw_not_in_evidence" in n["review"]
    n = normalize_measurement(_rec("X", "bogus_metric", "10만 명"))
    assert n["metric"] == "other" and "unknown_metric" in n["review"]

    # 6) 같은 사건에 사람 수와 건수가 있어도 섞지 않는다
    recs = [_rec("X", "affected_people", "2,324만 명"), _rec("X", "affected_records", "3,367만 건"),
            _rec("X", "data_volume", "9.82GB")]
    s = summarize_measurements(recs, "X", 3)
    assert len(s["groups"]) == 3 and all(g["range"][0] == g["range"][1] for g in s["groups"])
    assert not any(g["sources_differ"] for g in s["groups"])

    # 7) 출처마다 값이 다르면 조정하지 않고 범위와 차이만 표시한다. 확정이 먼저 나온다
    recs = [_rec("X", "affected_records", "약 3,300만 건", st="inferred", doc="d2"),
            _rec("X", "affected_records", "3,367만 건", src="official_government", doc="d1")]
    g = summarize_measurements(recs, "X", 2)["groups"][0]
    assert g["sources_differ"] and g["range"] == (33_000_000, 33_670_000)
    assert g["rows"][0]["assertion_status"] == "confirmed"

    # 8) 통화는 환산하지 않고 따로 둔다. 확인 대상은 범위에서 뺀다
    recs = [_rec("X", "fine", "100억 원"), _rec("X", "fine", "$5 million"), _rec("X", "fine", "수십억 원")]
    s = summarize_measurements(recs, "X", 3)
    assert len(s["groups"]) == 2                        # KRW, USD. '수십억 원'은 통화는 읽혀 KRW 묶음에 남는다
    assert len(s["review"]) == 1 and "no_number" in s["review"][0]["review"]
    by_cur = {g["currency"]: g for g in s["groups"]}
    assert by_cur["KRW"]["range"] == (10_000_000_000, 10_000_000_000)
    assert by_cur["USD"]["range"] == (5_000_000, 5_000_000)
    assert len(by_cur["KRW"]["rows"]) == 2              # 값을 못 읽은 행도 버리지 않고 남긴다

    # 9) 수치를 말한 문서가 없으면 '없음'이 아니라 '확인 안 됨'
    s = summarize_measurements([], "Y", 4)
    assert "4" in s["text"] and "확인되지 않음" in s["text"]

    print("자체 시험 9개 통과\n")
    demo = [_rec("SK텔레콤 유형", "affected_people", "2,324만 명", src="affected_organization"),
            _rec("SK텔레콤 유형", "data_volume", "9.82GB", src="official_government"),
            _rec("SK텔레콤 유형", "affected_people", "약 2,300만 명", src="media", st="inferred", doc="d2")]
    print(render_measurements(summarize_measurements(demo, "SK텔레콤 유형", 2)))


if __name__ == "__main__":
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass
    self_test()
