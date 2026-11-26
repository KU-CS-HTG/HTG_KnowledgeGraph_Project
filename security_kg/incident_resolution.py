"""같은 사건을 여러 문서가 쓸 때 하나로 합치는 규칙 (사건 해소).

원본은 새 노드를 이름 의미 유사도 0.8 이상이면 합친다. 사건에서는 두 방향으로 틀린다.
  - 같은 회사의 다른 사건이 이름이 비슷하다는 이유로 합쳐진다(답이 섞여 오염됨).
  - 같은 사건인데 문서마다 이름과 시점이 달라 쪼개진다(답이 흩어짐).
그래서 이름은 약한 신호로만 쓰고, 조직과 시간을 먼저 본다.

입력: 사건 언급(mention) 목록. 각 항목은 dict이며 키는 아래와 같다(구조는 consts.INCIDENT_MENTION_FIELDS).
  mention_id, doc_id, name, breached_org, headline_date(YYYY | YYYY-MM | YYYY-MM-DD | None),
  attack_span({"start": ..., "end": ...} | None), signals(CVE·악성코드·행위자 이름 목록)

규칙(결정 D1~D4, 숫자는 consts.INCIDENT_RESOLUTION):
  1. 침해 조직이 같아야 한다(별칭은 먼저 합친다). 다르면 다른 사건.
  2. 시간은 headline_date로 본다. 한쪽의 공격 기간이 다른 쪽의 headline_date를 포함하면 가깝다고 본다.
     - 90일 이내: 시간상 같은 사건 후보 / 365일 초과: 다른 사건 / 그 사이나 날짜 없음: 사람 확인
  3. 시간이 가깝더라도 공유 신호(같은 CVE·악성코드·행위자)나 이름 유사가 있어야 합친다. 없으면 사람 확인.
  4. 애매하면 합치지 않고 확인 대기열로 보낸다(정밀도 우선).

사용: python incident_resolution.py   # 자체 시험 실행
"""
import calendar
import re
import sys
from datetime import date
from difflib import SequenceMatcher
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402

_CORP_WORDS = re.compile(r"(주식회사|\(주\)|inc\.?|corp\.?|co\.?,?\s*ltd\.?|ltd\.?)", re.I)


# ── 조직 ──────────────────────────────────────────────────────────────────
def _org_key(name: str) -> str:
    s = _CORP_WORDS.sub("", name or "").casefold()
    return re.sub(r"[\s,.\-()]+", "", s)


def build_alias_index(alias_seed: dict | None = None) -> dict:
    index = {}
    for canon, aliases in (alias_seed if alias_seed is not None else consts.ORG_ALIAS_SEED).items():
        for n in [canon] + list(aliases):
            index[_org_key(n)] = canon
    return index


def canonical_org(name: str | None, index: dict) -> str | None:
    if not name or not name.strip():
        return None
    return index.get(_org_key(name), name.strip())


# ── 날짜 ──────────────────────────────────────────────────────────────────
def parse_interval(value) -> tuple[date, date] | None:
    """'2025', '2025-04', '2025-04-18'을 (시작일, 종료일) 구간으로 바꾼다. 못 읽으면 None."""
    if not value:
        return None
    m = re.fullmatch(r"(\d{4})(?:-(\d{1,2})(?:-(\d{1,2}))?)?", str(value).strip())
    if not m:
        return None
    y, mo, d = int(m.group(1)), m.group(2), m.group(3)
    try:
        if mo is None:
            return date(y, 1, 1), date(y, 12, 31)
        mo = int(mo)
        if d is None:
            return date(y, mo, 1), date(y, mo, calendar.monthrange(y, mo)[1])
        return date(y, mo, int(d)), date(y, mo, int(d))
    except ValueError:
        return None


def _overlap(a, b) -> bool:
    return a is not None and b is not None and a[0] <= b[1] and b[0] <= a[1]


def _span(m: dict):
    s = (m.get("attack_span") or {})
    a, b = parse_interval(s.get("start")), parse_interval(s.get("end") or s.get("start"))
    if a and b:
        return a[0], b[1]
    return None


def gap_days(m1: dict, m2: dict) -> tuple[int | None, str]:
    """두 언급의 시간 간격(일)과 근거. 계산할 수 없으면 (None, 이유)."""
    h1, h2 = parse_interval(m1.get("headline_date")), parse_interval(m2.get("headline_date"))
    if h1 is None or h2 is None:
        return None, "missing_headline_date"
    if _overlap(h1, h2):
        return 0, "headline_overlap"
    # 문서마다 다른 시점(공개 시점 vs 침입 시점)을 쓴 경우를 잇는다
    if _overlap(h1, _span(m2)) or _overlap(h2, _span(m1)):
        return 0, "attack_span_covers_headline"
    early, late = (h1, h2) if h1[1] < h2[0] else (h2, h1)
    return (late[0] - early[1]).days, "headline_gap"


# ── 신호 ──────────────────────────────────────────────────────────────────
def name_similarity(a: str, b: str) -> float:
    """이름 유사도(약한 신호). 운영에서는 임베딩으로 바꿀 수 있다. 서로 다른 언어의 이름은 낮게 나온다."""
    norm = lambda s: re.sub(r"\s+", "", (s or "").casefold())
    return SequenceMatcher(None, norm(a), norm(b)).ratio()


def _sig(m: dict) -> set:
    return {str(s).casefold() for s in (m.get("signals") or [])}


def _cves(sigs: set) -> set:
    return {s for s in sigs if s.startswith("cve-")}


# ── 두 언급의 비교 ────────────────────────────────────────────────────────
def compare(m1: dict, m2: dict, alias_index: dict, cfg: dict | None = None, sim_fn=name_similarity):
    """('merge' | 'separate' | 'review', [이유...])"""
    cfg = cfg or consts.INCIDENT_RESOLUTION
    o1, o2 = canonical_org(m1.get("breached_org"), alias_index), canonical_org(m2.get("breached_org"), alias_index)
    if o1 is None or o2 is None:
        return "review", ["missing_breached_org"]
    if _org_key(o1) != _org_key(o2):
        return "separate", ["different_org"]

    gap, why = gap_days(m1, m2)
    if gap is None:
        return "review", [why]
    if gap > cfg["different_after_days"]:
        return "separate", [f"date_gap_over_{cfg['different_after_days']}d"]
    if gap > cfg["same_within_days"]:
        return "review", [f"date_gap_{gap}d_between_thresholds"]

    s1, s2 = _sig(m1), _sig(m2)
    c1, c2 = _cves(s1), _cves(s2)
    if c1 and c2 and not (c1 & c2):
        return "review", ["conflicting_cve_signals"]          # 같은 조직·가까운 시점이어도 CVE가 다르면 확인
    shared = s1 & s2
    sim = sim_fn(m1.get("name", ""), m2.get("name", ""))
    if shared:
        return "merge", [why, "shared_signal:" + ",".join(sorted(shared))]
    if sim >= cfg["name_similarity_for_merge"]:
        return "merge", [why, f"name_similarity_{sim:.2f}"]
    return "review", [why, f"close_in_time_but_no_shared_signal_and_name_similarity_{sim:.2f}"]


# ── 묶기 ──────────────────────────────────────────────────────────────────
def effective_headlines(members: list[dict]) -> list[tuple[date, date]]:
    """묶음의 사건 시점 후보. 다른 언급의 공격 기간 안에 들어가면서 그 언급의 시점보다 이른 날짜는
    공개 시점이 아니라 침입 단계의 날짜(오추출)로 보고 뺀다. 예: 공격 기간 2021-08~2025-04, 시점 2025-04인 문서가 있으면
    시점을 2021-08로 쓴 문서의 날짜는 제외한다."""
    heads = [(m, parse_interval(m.get("headline_date"))) for m in members]
    keep = []
    for m, h in heads:
        if h is None:
            continue
        shadowed = False
        for o, oh in heads:
            if o is m or oh is None:
                continue
            sp = _span(o)
            if sp and _overlap(h, sp) and h[1] < oh[0]:
                shadowed = True
        if not shadowed:
            keep.append(h)
    return keep


def resolve(mentions: list[dict], alias_seed: dict | None = None, cfg: dict | None = None, sim_fn=name_similarity) -> dict:
    cfg = cfg or consts.INCIDENT_RESOLUTION
    idx = build_alias_index(alias_seed)
    ids = [m["mention_id"] for m in mentions]
    by_id = {m["mention_id"]: m for m in mentions}
    parent = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    decisions = {}
    for i, a in enumerate(mentions):
        for b in mentions[i + 1:]:
            decision, reasons = compare(a, b, idx, cfg, sim_fn)
            decisions[(a["mention_id"], b["mention_id"])] = (decision, reasons)
            if decision == "merge":
                parent[find(a["mention_id"])] = find(b["mention_id"])

    clusters = {}
    for i in ids:
        clusters.setdefault(find(i), []).append(i)

    incidents, used_ids, mention_to_incident = [], set(), {}
    review_pairs = [{"a": a, "b": b, "reasons": r} for (a, b), (d, r) in decisions.items() if d == "review"]
    for members in sorted(clusters.values(), key=lambda ms: ms[0]):
        reasons = []
        org = canonical_org(by_id[members[0]].get("breached_org"), idx) or "unknown-org"
        starts = effective_headlines([by_id[m] for m in members])
        # 연쇄 합치기로 시간 폭이 커졌거나, 묶음 안에 '다른 사건'으로 판정된 쌍이 있으면 확인
        if starts and (max(s[1] for s in starts) - min(s[0] for s in starts)).days > cfg["different_after_days"]:
            reasons.append("cluster_time_span_over_limit")
        if any(decisions.get((a, b), decisions.get((b, a), ("", [])))[0] == "separate"
               for k, a in enumerate(members) for b in members[k + 1:]):
            reasons.append("contains_pair_judged_separate")
        ym = min(s[0] for s in starts).strftime("%Y%m") if starts else "undated"
        base = cfg["id_format"].format(org=re.sub(r"[\s]+", "", org), yyyymm=ym)
        inc_id, n = base, 2
        while inc_id in used_ids:
            inc_id, n = f"{base}-{n}", n + 1
        used_ids.add(inc_id)
        for m in members:
            mention_to_incident[m] = inc_id
        incidents.append({
            "incident_id": inc_id, "breached_org": org,
            "mention_ids": members, "doc_ids": sorted({by_id[m]["doc_id"] for m in members}),
            "needs_review": bool(reasons), "review_reasons": reasons,
        })
    # 사람이 확인할 일은 언급 쌍이 아니라 '서로 다른 두 사건 묶음' 단위로 한 건씩 보여 준다.
    queue = {}
    for p in review_pairs:
        ia, ib = mention_to_incident[p["a"]], mention_to_incident[p["b"]]
        if ia == ib:
            continue                                   # 같은 묶음 안의 확인 쌍은 이미 합쳐졌으므로 제외
        q = queue.setdefault(frozenset((ia, ib)), {"incident_a": min(ia, ib), "incident_b": max(ia, ib),
                                                   "n_mention_pairs": 0, "reasons": set()})
        q["n_mention_pairs"] += 1
        q["reasons"].update(r for r in p["reasons"] if not r.startswith(("headline_", "attack_span_")))
    review_queue = sorted(({**q, "reasons": sorted(q["reasons"])} for q in queue.values()),
                          key=lambda q: (q["incident_a"], q["incident_b"]))
    return {"incidents": incidents, "mention_to_incident": mention_to_incident,
            "review_queue": review_queue, "review_pairs": review_pairs}


def signals_from_triplets(triplets: list[dict]) -> list[str]:
    """한 문서의 한 사건 트리플렛에서 같은 사건의 증거가 되는 이름(CVE, 악성코드, 행위자)을 모은다."""
    rels = {"EXPLOITED_VULNERABILITY", "USED_MALWARE", "ATTRIBUTED_TO"}
    return sorted({t["target_entity_instance"] for t in triplets if t.get("relation") in rels})


# ── 자체 시험 ─────────────────────────────────────────────────────────────
def _m(i, doc, name, org, headline, span=None, signals=()):
    return {"mention_id": i, "doc_id": doc, "name": name, "breached_org": org, "headline_date": headline,
            "attack_span": span, "signals": list(signals)}


def self_test() -> None:
    idx = build_alias_index()

    # 1) 같은 회사의 다른 사건: 이름이 같아도 절대 합치지 않는다.
    #    Instructure 2025-09 vs 2026-04는 간격이 183일이라 기준(90/365일) 사이에 있어 "자동으로 다른 사건"이 아니라 사람 확인이다.
    a = _m("a", "d1", "Instructure data breach", "Instructure", "2025-09")
    b = _m("b", "d2", "Instructure data breach", "Instructure, Inc.", "2026-04", signals=["ShinyHunters"])
    dec, reasons = compare(a, b, idx)
    assert dec == "review" and "date_gap_183d_between_thresholds" in reasons
    far = _m("far", "d0", "Instructure data breach", "Instructure", "2024-09")      # 365일을 넘으면 자동으로 다른 사건
    assert compare(far, b, idx)[0] == "separate"

    # 2) 연속 파동(D4): 같은 조직, 90일 이내, 같은 행위자 → 하나로 합친다 (Canvas 4/29 탐지, 5/7 추가 침해)
    c = _m("c", "d3", "Canvas security incident", "Instructure", "2026-04-29", signals=["ShinyHunters"])
    d = _m("d", "d4", "Canvas portal defacement", "Instructure", "2026-05-07", signals=["shinyhunters"])
    assert compare(c, d, idx)[0] == "merge"

    # 3) 정밀도 우선(D3): 같은 조직·가까운 시점이어도 공유 신호도 없고 이름도 다르면 합치지 않고 확인으로 보낸다 (쿠팡의 다른 표현)
    e = _m("e", "d5", "쿠팡 개인정보 유출 사건", "쿠팡", "2025-11")
    f = _m("f", "d6", "Coupang unauthorized access investigation", "Coupang", "2025-11")
    dec, reasons = compare(e, f, idx)
    assert dec == "review" and any("no_shared_signal" in r for r in reasons)

    # 4) 같은 사건이면 이름이 달라도 공유 신호가 있으면 합친다
    f2 = dict(f, signals=["signing-key-abuse"]); e2 = dict(e, signals=["Signing-Key-Abuse"])
    assert compare(e2, f2, idx)[0] == "merge"

    # 5) 서로 다른 시점을 쓴 문서를 공격 기간으로 잇는다. 날짜는 SK텔레콤 사건의 1차 자료(과기정통부 2025-07-04 보도자료)를 따랐다:
    #    한쪽은 유출 시점 2025-04, 다른 쪽은 최초 침투 시점 2021-08(2021-08-06 CrossC2 설치). 문서 이름과 내용은 시험용 가상이다
    s1 = _m("s1", "d7", "SK텔레콤 유심 정보 유출", "SK텔레콤", "2025-04", span={"start": "2021-08", "end": "2025-04"}, signals=["BPFDoor"])
    s2 = _m("s2", "d8", "SKT 악성코드 설치", "SKT", "2021-08", signals=["bpfdoor"])
    assert gap_days(s1, s2) == (0, "attack_span_covers_headline") and compare(s1, s2, idx)[0] == "merge"
    s3 = dict(s2, attack_span=None)          # 공격 기간이 없으면 연결하지 못하고 다른 사건으로 판정한다(한계)
    assert compare(dict(s1, attack_span=None), s3, idx)[0] == "separate"

    # 6) 조직 별칭을 먼저 합친다. 다른 조직은 다른 사건이다
    assert canonical_org("SK Telecom", idx) == canonical_org("에스케이텔레콤", idx) == "SK텔레콤"
    kt = _m("k", "d9", "통신사 유출", "KT", "2025-04", signals=["BPFDoor"])
    assert compare(s1, kt, idx) == ("separate", ["different_org"])

    # 7) 날짜가 없으면 사람 확인
    assert compare(_m("x", "d", "n", "쿠팡", None), e, idx)[0] == "review"

    # 8) 전체 묶기: 합친 것과 확인 대기열, 정규 ID
    out = resolve([a, b, c, d, e, f, s1, s2, kt])
    by_org = {i["breached_org"]: i for i in out["incidents"] if i["breached_org"] != "Instructure"}
    inst = [i for i in out["incidents"] if i["breached_org"] == "Instructure"]
    assert len(inst) == 2 and {i["incident_id"] for i in inst} == {"INC-Instructure-202509", "INC-Instructure-202604"}
    q = [x for x in out["review_queue"] if {x["incident_a"], x["incident_b"]} == {"INC-Instructure-202509", "INC-Instructure-202604"}]
    assert len(q) == 1 and q[0]["n_mention_pairs"] == 3                                # 합치지는 않지만 사람이 확인한다. 쌍 3개가 한 건으로
    canvas = next(i for i in inst if i["incident_id"].endswith("202604"))
    assert set(canvas["mention_ids"]) == {"b", "c", "d"}      # 같은 행위자를 공유하는 2026년 언급이 모두 하나의 사건
    assert out["mention_to_incident"]["s1"] == out["mention_to_incident"]["s2"] != out["mention_to_incident"]["k"]
    skt = next(i for i in out["incidents"] if i["breached_org"] == "SK텔레콤")
    assert skt["incident_id"] == "INC-SK텔레콤-202504" and not skt["needs_review"]   # 침입 단계 날짜(2021-08)는 ID 기준에서 제외
    assert out["mention_to_incident"]["e"] != out["mention_to_incident"]["f"]          # 확인 대기열로 갔으므로 합치지 않음
    assert any({x["incident_a"], x["incident_b"]} == {"INC-쿠팡-202511", "INC-쿠팡-202511-2"} for x in out["review_queue"])

    # 9) 연쇄 합치기 방지: 가까운 쌍을 잇다 보면 시간 폭이 365일을 넘는 묶음을 확인으로 표시한다
    ym = lambda i: f"{2025 + (2 * i) // 12}-{(2 * i) % 12 + 1:02d}"                    # 2개월 간격: 2025-01 … 2026-01
    chain = [_m(f"m{i}", f"d{i}", "Acme breach", "Acme", ym(i), signals=["X"]) for i in range(7)]
    r = resolve(chain)
    assert len(r["incidents"]) == 1 and r["incidents"][0]["needs_review"]
    assert "cluster_time_span_over_limit" in r["incidents"][0]["review_reasons"]

    # 10) 같은 연월이라도 ID가 겹치면 구분한다
    twins = resolve([_m("p", "d1", "N1", "Acme", "2025-03", signals=["A"]), _m("q", "d2", "N2", "Acme", "2025-03", signals=["B"])])
    ids = {i["incident_id"] for i in twins["incidents"]}
    assert len(ids) == len(twins["incidents"])                                         # 합쳐지지 않은 경우의 ID는 유일해야 한다

    # 11) 날짜 해석
    assert parse_interval("2025-04") == (date(2025, 4, 1), date(2025, 4, 30)) and parse_interval("2025-13") is None

    print("자체 시험 11개 통과\n")
    print("사건 묶음 결과 (예시):")
    for i in out["incidents"]:
        flag = " ※확인필요" if i["needs_review"] else ""
        print(f"  {i['incident_id']}: 언급 {i['mention_ids']}, 문서 {i['doc_ids']}{flag}")
    print("사람 확인 대기열(사건 묶음 단위):")
    for x in out["review_queue"]:
        print(f"  {x['incident_a']} ↔ {x['incident_b']} (언급 쌍 {x['n_mention_pairs']}개): {', '.join(x['reasons'])}")


if __name__ == "__main__":
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass
    self_test()
