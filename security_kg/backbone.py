"""뼈대 데이터: ATT&CK, CISA KEV, MISP 갤럭시를 내려받아 가벼운 목록으로 바꾸고, CVE는 번호로 하나씩 조회한다.

내려받는 곳(모두 raw.githubusercontent.com, 저장소의 원문 파일):
  - ATT&CK Enterprise STIX 번들  : mitre-attack/attack-stix-data   (정식 번호 파일 enterprise-attack-<버전>.json)
  - CISA KEV                     : cisagov/kev-data                (www.cisa.gov는 이 환경에서 막혀 있어 GitHub 사본을 쓴다)
  - MISP 갤럭시 위협 행위자       : MISP/misp-galaxy                (clusters/threat-actor.json)
  - CVE 레코드(한 건씩)           : CVEProject/cvelistV5            (cves/<연도>/<번호 천 단위>xxx/<CVE-ID>.json)

이 환경에서 확인한 제약: NVD API와 cve.org 전체 목록(압축 파일, git 저장소 전체)에는 접근할 수 없다.
  → CVE 전체 목록은 만들지 못하고, 문서가 인용한 CVE를 번호로 조회해 존재를 확인한다(lookup_cve).
  → NVD의 CPE 사전도 받을 수 없어 Product는 CVE 레코드의 vendor/product 이름만 쓴다.

원본(수십 MB)은 저장소에 올리지 않는다(`backbone/raw/`는 무시). 변환 결과만 data/에 둔다.
사용:
  python backbone.py build [attack|kev|misp|all]   # 내려받아 data/에 저장하고 스냅샷 정보를 출력
  python backbone.py export [폴더]                  # 확인용 CSV 만들기(기본 backbone/export/, 저장소에 올리지 않음)
  python backbone.py cve CVE-2021-44228            # 한 건 조회
  python backbone.py                               # 자체 시험(네트워크 없이)
"""
import json
import os
import re
import ssl
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import consts  # noqa: E402
import attack_mapping  # noqa: E402

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
RAW = HERE / "backbone" / "raw"
GH = "https://raw.githubusercontent.com"
URLS = {
    "attack_index": f"{GH}/mitre-attack/attack-stix-data/master/index.json",
    "attack_bundle": GH + "/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{version}.json",
    "kev": f"{GH}/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    "misp_threat_actor": f"{GH}/MISP/misp-galaxy/main/clusters/threat-actor.json",
    "cve": GH + "/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve}.json",
}
CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")


# ── 내려받기 ───────────────────────────────────────────────────────────────
def _ctx():
    ca = os.environ.get("SSL_CERT_FILE") or "/root/.ccr/ca-bundle.crt"
    return ssl.create_default_context(cafile=ca) if os.path.exists(ca) else ssl.create_default_context()


def fetch(url: str, dest: Path | None = None, timeout: int = 120) -> bytes:
    """URL을 내려받는다. dest가 있으면 저장하고 이미 있으면 다시 받지 않는다."""
    if dest is not None and dest.exists():
        return dest.read_bytes()
    req = urllib.request.Request(url, headers={"User-Agent": "security-kg-backbone"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
        body = r.read()
    if dest is not None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
    return body


# ── ATT&CK ────────────────────────────────────────────────────────────────
def _attack_id(o):
    return next((r.get("external_id") for r in o.get("external_references", [])
                 if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)


def build_attack(bundle: dict) -> dict:
    """STIX 번들 → 기법, 전술, 소프트웨어, 그룹 목록과 폐기된 ID의 대체 정보."""
    objs = {o["id"]: o for o in bundle["objects"] if "id" in o}
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")   # noqa: E731
    techniques = attack_mapping.load_catalog_from_stix(bundle)
    tactics = {o["x_mitre_shortname"]: {"id": _attack_id(o), "name": o["name"]}
               for o in objs.values() if o["type"] == "x-mitre-tactic" and live(o)}
    tid = {sid: _attack_id(o) for sid, o in objs.items() if o["type"] == "attack-pattern" and _attack_id(o) in techniques}
    sw = {sid: o for sid, o in objs.items() if o["type"] in ("malware", "tool") and live(o)}
    groups = {sid: o for sid, o in objs.items() if o["type"] == "intrusion-set" and live(o)}
    uses_tech, uses_sw = defaultdict(set), defaultdict(set)
    for o in objs.values():
        if o["type"] == "relationship" and o.get("relationship_type") == "uses" and not o.get("revoked"):
            s, t = o["source_ref"], o["target_ref"]
            if t in tid and (s in sw or s in groups):
                uses_tech[s].add(tid[t])
            elif t in sw and s in groups:
                uses_sw[s].add(sw[t]["name"])
    software = {_attack_id(o): {"name": o["name"], "type": o["type"], "aliases": o.get("x_mitre_aliases", [o["name"]]),
                                "techniques": sorted(uses_tech[sid])} for sid, o in sw.items() if _attack_id(o)}
    grp = {_attack_id(o): {"name": o["name"], "aliases": o.get("aliases", [o["name"]]),
                           "techniques": sorted(uses_tech[sid]), "software": sorted(uses_sw[sid])}
           for sid, o in groups.items() if _attack_id(o)}
    # 폐기·취소된 기법 ID → 대체 ID (revoked-by 관계). 대체가 없으면 None
    replaced = {}
    for o in objs.values():
        if o["type"] == "attack-pattern" and (o.get("revoked") or o.get("x_mitre_deprecated")) and _attack_id(o):
            replaced[_attack_id(o)] = None
    for o in objs.values():
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            old, new = objs.get(o["source_ref"]), objs.get(o["target_ref"])
            if old and new and old["type"] == "attack-pattern" and _attack_id(old) in replaced:
                replaced[_attack_id(old)] = _attack_id(new)
    coll = next((o for o in objs.values() if o["type"] == "x-mitre-collection"), {})
    return {"version": coll.get("x_mitre_version"), "name": coll.get("name"),
            "techniques": techniques, "tactics": tactics, "software": software, "groups": grp, "replaced_techniques": replaced}


def resolve_technique(tid: str, atk: dict) -> dict:
    """문서가 쓴 기법 ID를 판정한다: link / replaced(대체 ID로 안내) / review(없음)."""
    if tid in atk["techniques"]:
        return {"id": tid, "action": "link", "name": atk["techniques"][tid]["name"]}
    if tid in atk["replaced_techniques"]:
        new = atk["replaced_techniques"][tid]
        return {"id": tid, "action": "replaced" if new else "review",
                "reason": "revoked_or_deprecated", "replacement": new}
    return {"id": tid, "action": "review", "reason": "unknown_id", "replacement": None}


# ── KEV ───────────────────────────────────────────────────────────────────
def build_kev(raw: dict) -> dict:
    """KEV → CVE별 요약. 긴 설명과 조치문은 뺀다."""
    vulns = {}
    for v in raw["vulnerabilities"]:
        vulns[v["cveID"]] = {"vendor": v.get("vendorProject"), "product": v.get("product"), "name": v.get("vulnerabilityName"),
                             "date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
                             "ransomware": v.get("knownRansomwareCampaignUse"), "cwes": v.get("cwes", [])}
    return {"catalog_version": raw.get("catalogVersion"), "date_released": raw.get("dateReleased"),
            "count": raw.get("count"), "vulnerabilities": vulns}


# ── MISP 위협 행위자 ───────────────────────────────────────────────────────
def build_misp_actors(raw: dict) -> dict:
    """MISP 위협 행위자 → 이름, 별칭, 국가. ATT&CK 그룹과는 합치지 않고 따로 둔다(합치기 규칙은 미정)."""
    actors = []
    for v in raw["values"]:
        meta = v.get("meta", {})
        actors.append({"name": v["value"], "uuid": v.get("uuid"), "synonyms": meta.get("synonyms", []),
                       "country": meta.get("country"), "state_sponsor": meta.get("cfr-suspected-state-sponsor")})
    return {"galaxy_version": raw.get("version"), "count": len(actors), "actors": actors}


# ── CVE 한 건 조회 ─────────────────────────────────────────────────────────
def cve_url(cve: str) -> str:
    m = CVE_RE.match(cve.strip())
    if not m:
        raise ValueError(f"CVE 형식이 아님: {cve}")
    year, num = m.group(1), int(m.group(2))
    return URLS["cve"].format(year=year, bucket=f"{num // 1000}xxx", cve=cve.strip())


def parse_cve_record(rec: dict) -> dict:
    """CVE JSON 5 레코드 → 존재, 상태, 날짜, 제목, CWE, 제품 이름. CWE는 CNA와 ADP 항목을 합치고 출처를 구분한다."""
    meta, cna = rec.get("cveMetadata", {}), rec.get("containers", {}).get("cna", {})

    def cwes(c):
        return sorted({d["cweId"] for p in c.get("problemTypes", []) for d in p.get("descriptions", []) if d.get("cweId")})
    adp = {a.get("providerMetadata", {}).get("shortName", "adp"): cwes(a) for a in rec.get("containers", {}).get("adp", [])}
    return {"id": meta.get("cveId"), "state": meta.get("state"), "published": meta.get("datePublished"),
            "title": cna.get("title"), "cwes_cna": cwes(cna), "cwes_adp": {k: v for k, v in adp.items() if v},
            "products": sorted({(a.get("vendor"), a.get("product")) for a in cna.get("affected", [])
                                if a.get("vendor") or a.get("product")}, key=str)}


def lookup_cve(cve: str, cache: bool = True) -> dict:
    """CVE 번호 하나를 조회한다. 없으면 exists=False(그 번호는 연결하지 않고 사람 확인으로 보낸다)."""
    cve = cve.strip().upper()
    if not CVE_RE.match(cve):
        return {"id": cve, "exists": False, "reason": "bad_format"}
    try:
        body = fetch(cve_url(cve), (RAW / "cve" / f"{cve}.json") if cache else None, timeout=30)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"id": cve, "exists": False, "reason": "not_in_cvelist"}
        raise
    return {"exists": True, **parse_cve_record(json.loads(body))}


# ── 전체 만들기 ────────────────────────────────────────────────────────────
def _save(obj, name):
    DATA.mkdir(exist_ok=True)
    p = DATA / name
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return f"{name} ({p.stat().st_size / 1024:.0f}KB)"


def build(which: str = "all") -> dict:
    snap = {}
    if which in ("attack", "all"):
        idx = json.loads(fetch(URLS["attack_index"], RAW / "attack_index.json"))
        ent = next(c for c in idx["collections"] if c["name"] == "Enterprise ATT&CK")
        ver = ent["versions"][0]                       # 목록 맨 앞이 최신(내려받은 index.json 기준)
        bundle = json.loads(fetch(URLS["attack_bundle"].format(version=ver["version"]),
                                  RAW / f"enterprise-attack-{ver['version']}.json", timeout=300))
        atk = build_attack(bundle)
        snap["attack"] = f"Enterprise {atk['version']} (modified {ver['modified'][:10]}), 기법 {len(atk['techniques'])}, " \
                         f"소프트웨어 {len(atk['software'])}, 그룹 {len(atk['groups'])}"
        print("저장:", _save(atk, "attack_catalog.json"))
    if which in ("kev", "all"):
        kev = build_kev(json.loads(fetch(URLS["kev"], RAW / "kev.json")))
        snap["kev"] = f"catalogVersion {kev['catalog_version']} ({kev['date_released'][:10]}), {kev['count']}건"
        print("저장:", _save(kev, "kev.json"))
    if which in ("misp", "all"):
        mp = build_misp_actors(json.loads(fetch(URLS["misp_threat_actor"], RAW / "misp_threat_actor.json")))
        snap["misp_galaxy"] = f"threat-actor 갤럭시 version {mp['galaxy_version']}, {mp['count']}개 (main 브랜치에서 받음)"
        print("저장:", _save(mp, "misp_threat_actors.json"))
    return snap


# ── 확인용 CSV ─────────────────────────────────────────────────────────────
def _join(x) -> str:
    return "; ".join(str(i) for i in x) if isinstance(x, (list, tuple, set)) else ("" if x is None else str(x))


def _write_csv(path: Path, header: list, rows: list) -> str:
    """엑셀에서 한글이 깨지지 않도록 BOM이 붙은 UTF-8로 쓴다."""
    import csv
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return f"{path.name} ({len(rows)}행)"


def export_csv(dest: Path | None = None, data_dir: Path | None = None) -> list:
    """data/의 JSON을 사람이 보기 편한 CSV로 바꾼다. 중첩된 목록은 '; '로 이어 한 칸에 쓴다(정보가 일부 줄어든다).
    JSON에서 다시 만들 수 있으므로 저장소에 올리지 않는다."""
    dest, data_dir, done = Path(dest or HERE / "backbone" / "export"), Path(data_dir or DATA), []
    load = lambda n: json.loads((data_dir / n).read_text(encoding="utf-8")) if (data_dir / n).exists() else None   # noqa: E731
    atk = load("attack_catalog.json")
    if atk:
        done.append(_write_csv(dest / "attack_techniques.csv", ["id", "name", "tactics", "parent"],
                               [[k, v["name"], _join(v["tactics"]), v["parent"] or ""] for k, v in sorted(atk["techniques"].items())]))
        done.append(_write_csv(dest / "attack_tactics.csv", ["shortname", "id", "name"],
                               [[k, v["id"], v["name"]] for k, v in sorted(atk["tactics"].items(), key=lambda x: x[1]["id"])]))
        done.append(_write_csv(dest / "attack_software.csv", ["id", "name", "type", "aliases", "technique_count", "techniques"],
                               [[k, v["name"], v["type"], _join(v["aliases"]), len(v["techniques"]), _join(v["techniques"])]
                                for k, v in sorted(atk["software"].items())]))
        done.append(_write_csv(dest / "attack_groups.csv", ["id", "name", "aliases", "technique_count", "software"],
                               [[k, v["name"], _join(v["aliases"]), len(v["techniques"]), _join(v["software"])]
                                for k, v in sorted(atk["groups"].items())]))
        done.append(_write_csv(dest / "attack_replaced_techniques.csv", ["old_id", "replaced_by"],
                               [[k, v or ""] for k, v in sorted(atk["replaced_techniques"].items())]))
    kev = load("kev.json")
    if kev:
        done.append(_write_csv(dest / "kev.csv", ["cve", "vendor", "product", "name", "date_added", "due_date", "ransomware", "cwes"],
                               [[k, v["vendor"], v["product"], v["name"], v["date_added"], v["due_date"], v["ransomware"], _join(v["cwes"])]
                                for k, v in sorted(kev["vulnerabilities"].items())]))
    misp = load("misp_threat_actors.json")
    if misp:
        done.append(_write_csv(dest / "misp_threat_actors.csv", ["name", "synonyms", "country", "state_sponsor"],
                               [[a["name"], _join(a["synonyms"]), a["country"] or "", a["state_sponsor"] or ""] for a in misp["actors"]]))
    cwe = load("cwe_catalog.json")
    if cwe:
        done.append(_write_csv(dest / "cwe_weaknesses.csv", ["id", "name", "abstraction", "status", "mapping_usage", "suggested", "parents"],
                               [[f"CWE-{k}", v["name"], v["abstraction"], v["status"], v["usage"] or "",
                                 _join(f"CWE-{s['id']}" for s in v["suggestions"]), _join(f"CWE-{p}" for p in v["parents"])]
                                for k, v in sorted(cwe["weaknesses"].items(), key=lambda x: int(x[0]))]))
        done.append(_write_csv(dest / "cwe_groupings.csv", ["id", "name", "status", "members"],
                               [[f"CWE-{k}", v["name"], v["status"], _join(f"CWE-{m}" for m in v["members"])]
                                for k, v in sorted(cwe["groupings"].items(), key=lambda x: int(x[0]))]))
    return done


# ── 자체 시험(네트워크 없음, 가짜 번들) ────────────────────────────────────
def self_test() -> None:
    ref = lambda i: [{"source_name": "mitre-attack", "external_id": i}]   # noqa: E731
    bundle = {"objects": [
        {"id": "c", "type": "x-mitre-collection", "name": "Fake", "x_mitre_version": "9.9"},
        {"id": "ta", "type": "x-mitre-tactic", "name": "Fake Tactic", "x_mitre_shortname": "fake-tactic", "external_references": ref("TA9")},
        {"id": "t1", "type": "attack-pattern", "name": "Fake T", "external_references": ref("T9001"),
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "fake-tactic"}]},
        {"id": "t2", "type": "attack-pattern", "name": "Fake Old", "revoked": True, "external_references": ref("T9002")},
        {"id": "t3", "type": "attack-pattern", "name": "Fake Gone", "x_mitre_deprecated": True, "external_references": ref("T9003")},
        {"id": "m1", "type": "malware", "name": "FakeMal", "x_mitre_aliases": ["FakeMal", "FM"], "external_references": ref("S9")},
        {"id": "g1", "type": "intrusion-set", "name": "FakeGroup", "aliases": ["FakeGroup", "FG"], "external_references": ref("G9")},
        {"id": "r1", "type": "relationship", "relationship_type": "uses", "source_ref": "m1", "target_ref": "t1"},
        {"id": "r2", "type": "relationship", "relationship_type": "uses", "source_ref": "g1", "target_ref": "m1"},
        {"id": "r3", "type": "relationship", "relationship_type": "uses", "source_ref": "g1", "target_ref": "t1"},
        {"id": "r4", "type": "relationship", "relationship_type": "revoked-by", "source_ref": "t2", "target_ref": "t1"},
    ]}
    a = build_attack(bundle)
    assert a["version"] == "9.9" and list(a["techniques"]) == ["T9001"] and a["tactics"]["fake-tactic"]["id"] == "TA9"
    assert a["software"]["S9"]["techniques"] == ["T9001"] and a["software"]["S9"]["aliases"] == ["FakeMal", "FM"]
    assert a["groups"]["G9"]["software"] == ["FakeMal"] and a["groups"]["G9"]["techniques"] == ["T9001"]
    assert a["replaced_techniques"] == {"T9002": "T9001", "T9003": None}
    assert resolve_technique("T9001", a)["action"] == "link"
    r = resolve_technique("T9002", a)
    assert (r["action"], r["replacement"]) == ("replaced", "T9001")          # 폐기: 대체 ID를 안내
    assert resolve_technique("T9003", a)["action"] == "review"               # 폐기이고 대체 없음
    assert resolve_technique("T0000", a)["reason"] == "unknown_id"

    k = build_kev({"catalogVersion": "v", "dateReleased": "2099-01-01T00:00:00Z", "count": 1, "vulnerabilities": [
        {"cveID": "CVE-2099-1234", "vendorProject": "V", "product": "P", "vulnerabilityName": "N", "shortDescription": "long text",
         "dateAdded": "2099-01-01", "dueDate": "2099-01-22", "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-1"]}]})
    assert k["vulnerabilities"]["CVE-2099-1234"]["cwes"] == ["CWE-1"] and "shortDescription" not in k["vulnerabilities"]["CVE-2099-1234"]

    m = build_misp_actors({"version": 1, "values": [{"value": "Fake", "uuid": "u", "meta": {"synonyms": ["F"], "country": "XX"}}]})
    assert m["actors"][0]["synonyms"] == ["F"]

    # CVE 주소: 번호 천 단위 폴더. 4자리, 5자리, 6자리 번호
    assert cve_url("CVE-2021-44228").endswith("/cves/2021/44xxx/CVE-2021-44228.json")
    assert cve_url("CVE-2016-0001").endswith("/cves/2016/0xxx/CVE-2016-0001.json")
    assert cve_url("CVE-2026-132224").endswith("/cves/2026/132xxx/CVE-2026-132224.json")
    try:
        cve_url("CVE-21-1")
        raise AssertionError("형식 오류를 못 잡음")
    except ValueError:
        pass
    p = parse_cve_record({"cveMetadata": {"cveId": "CVE-2099-1", "state": "PUBLISHED", "datePublished": "2099-01-01"},
                          "containers": {"cna": {"title": "t", "affected": [{"vendor": "V", "product": "P"}],
                                                 "problemTypes": [{"descriptions": [{"cweId": "CWE-2"}, {"description": "no id"}]}]},
                                         "adp": [{"providerMetadata": {"shortName": "X"}, "problemTypes": [{"descriptions": [{"cweId": "CWE-3"}]}]}]}})
    assert p["cwes_cna"] == ["CWE-2"] and p["cwes_adp"] == {"X": ["CWE-3"]} and p["products"] == [("V", "P")]
    assert lookup_cve("garbage")["reason"] == "bad_format"

    # 확인용 CSV: 가짜 data 폴더로 만들고 다시 읽어 본다
    import csv
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "data"
        d.mkdir()
        (d / "attack_catalog.json").write_text(json.dumps(a), encoding="utf-8")
        (d / "kev.json").write_text(json.dumps(k), encoding="utf-8")
        (d / "misp_threat_actors.json").write_text(json.dumps(m), encoding="utf-8")
        out = export_csv(Path(td) / "out", d)
        assert len(out) == 7                                       # ATT&CK 5개 + KEV + MISP. CWE는 데이터가 없어 만들지 않음
        raw = (Path(td) / "out" / "attack_software.csv").read_bytes()
        assert raw.startswith(b"\xef\xbb\xbf")                       # 엑셀용 BOM
        rows = list(csv.reader(raw.decode("utf-8-sig").splitlines()))
        assert rows[1][:3] == ["S9", "FakeMal", "malware"] and rows[1][3] == "FakeMal; FM" and rows[1][4] == "1"
        assert list(csv.reader((Path(td) / "out" / "attack_replaced_techniques.csv").read_text("utf-8-sig").splitlines()))[1:] == \
            [["T9002", "T9001"], ["T9003", ""]]
    print("자체 시험 13개 통과")


if __name__ == "__main__":
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass
    a = sys.argv[1:]
    if not a:
        self_test()
    elif a[0] == "build":
        print(json.dumps(build(a[1] if len(a) > 1 else "all"), ensure_ascii=False, indent=1))
    elif a[0] == "export":
        for line in export_csv(a[1] if len(a) > 1 else None):
            print("저장:", line)
    elif a[0] == "cve":
        print(json.dumps(lookup_cve(a[1]), ensure_ascii=False, indent=1, default=list))
