"""`Weakness`(CWE) 닫힌 목록 만들기: CWE XML에서 가벼운 목록을 뽑고, 문서가 인용한 번호를 어떻게 다룰지 판정한다.

입력: MITRE의 CWE 전체 XML(예: cwec_v5.0.xml, 18MB). 이 파일은 저장소에 올리지 않는다(용량). 변환 결과만 올린다
      → data/cwe_catalog.json (약점 984개 + 그룹 431개의 이름, 상태, 매핑 사용 구분, 제안, 부모. 설명문은 뺐다)

판정 규칙(resolve_cwe): 문서가 'CWE-n'을 인용했을 때
  link          : 약점이고 매핑 사용 구분이 Allowed 또는 Allowed-with-Review → 연결한다 (후자는 note에 표시)
  link_specific : Discouraged(포괄 항목) → 연결하되 MITRE가 제안한 더 구체적인 번호를 함께 알린다
  review        : 그룹, 폐기(Deprecated), Prohibited, 목록에 없음 → 연결하지 않고 사람 확인으로 보낸다. 버리지 않는다.

한계: XML 구조(Mapping_Notes/Usage, Suggestion, Has_Member)는 올려 받은 5.0 파일을 읽어 맞춘 것이며 다른 버전에서는
      태그가 다를 수 있다. 폐기 항목의 '대체 번호'는 설명문에서 CWE 번호를 찾아낸 힌트일 뿐 확정이 아니다.

사용: python cwe_catalog.py <cwec.xml> [--out data/cwe_catalog.json]   # 목록 만들기
      python cwe_catalog.py                                            # 자체 시험
"""
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_OUT = Path(__file__).resolve().parent / "data" / "cwe_catalog.json"


def _ns(root) -> str:
    return root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""


def build_catalog(xml_source) -> dict:
    """XML(파일 경로 또는 XML 문자열)에서 가벼운 목록을 만든다."""
    root = ET.fromstring(xml_source) if str(xml_source).lstrip().startswith("<") else ET.parse(xml_source).getroot()
    ns = _ns(root)
    weaknesses, groupings = {}, {}
    for w in root.iterfind(f"{ns}Weaknesses/{ns}Weakness"):
        usage = w.find(f"{ns}Mapping_Notes/{ns}Usage")
        rec = {
            "name": w.get("Name"), "abstraction": w.get("Abstraction"), "status": w.get("Status"),
            "usage": usage.text.strip() if usage is not None and usage.text else None,
            "suggestions": [{"id": s.get("CWE_ID"), "comment": s.get("Comment")}
                            for s in w.iterfind(f".//{ns}Mapping_Notes//{ns}Suggestion")],
            "parents": [r.get("CWE_ID") for r in w.iterfind(f".//{ns}Related_Weakness")
                        if r.get("Nature") == "ChildOf" and r.get("View_ID") in (None, "1000")],
        }
        if w.get("Status") == "Deprecated":   # 폐기 설명문에서 번호를 힌트로만 모은다
            desc = w.find(f"{ns}Description")
            text = " ".join("".join(desc.itertext()).split()) if desc is not None else ""
            rec["see_hint"] = sorted(set(re.findall(r"CWE-(\d+)", text)), key=int)
        weaknesses[w.get("ID")] = rec
    for g in root.iterfind(f"{ns}Groupings/{ns}Grouping"):
        groupings[g.get("ID")] = {"name": g.get("Name"), "status": g.get("Status"),
                                  "members": [m.get("CWE_ID") for m in g.iterfind(f".//{ns}Has_Member")]}
    return {"version": root.get("Version"), "date": root.get("Date"),
            "weaknesses": weaknesses, "groupings": groupings}


def _num(cwe) -> str:
    return re.sub(r"^CWE-", "", str(cwe).strip(), flags=re.I)


def resolve_cwe(cwe, cat: dict) -> dict:
    """문서가 인용한 CWE를 어떻게 다룰지 판정한다. 반환: {"id", "action", "name", "reason", "suggest"}."""
    n = _num(cwe)
    out = {"id": f"CWE-{n}", "action": None, "name": None, "reason": None, "suggest": []}
    if n in cat["groupings"]:
        g = cat["groupings"][n]
        out.update(action="review", name=g["name"], reason="grouping_not_mappable",
                   suggest=[f"CWE-{m}" for m in g["members"]])
    elif n in cat["weaknesses"]:
        w = cat["weaknesses"][n]
        out["name"] = w["name"]
        if w["status"] == "Deprecated":
            out.update(action="review", reason="deprecated", suggest=[f"CWE-{i}" for i in w.get("see_hint", [])])
        elif w["usage"] == "Prohibited":
            out.update(action="review", reason="prohibited")
        elif w["usage"] == "Discouraged":
            out.update(action="link_specific", reason="discouraged_use_more_specific",
                       suggest=[f"CWE-{s['id']}" for s in w["suggestions"]])
        else:
            out.update(action="link", reason="allowed_with_review" if w["usage"] == "Allowed-with-Review" else "allowed")
    else:
        out.update(action="review", reason="unknown_id")
    return out


def summarize(cat: dict) -> dict:
    from collections import Counter
    W = cat["weaknesses"].values()
    return {"version": cat["version"], "date": cat["date"], "weaknesses": len(cat["weaknesses"]),
            "groupings": len(cat["groupings"]),
            "usage": dict(Counter(w["usage"] for w in W)), "status": dict(Counter(w["status"] for w in W)),
            "linkable": sum(1 for n in cat["weaknesses"] if resolve_cwe(n, cat)["action"] in ("link", "link_specific"))}


# ── 자체 시험(작은 가짜 XML. 실제 번호·이름이 아니다) ─────────────────────────
_FAKE = """<?xml version="1.0"?>
<Weakness_Catalog Name="CWE" Version="9.9" Date="2099-01-01" xmlns="http://cwe.mitre.org/cwe-8">
<Weaknesses>
 <Weakness ID="1" Name="Fake Allowed" Abstraction="Base" Status="Draft"><Mapping_Notes><Usage>Allowed</Usage></Mapping_Notes></Weakness>
 <Weakness ID="2" Name="Fake Review" Abstraction="Class" Status="Incomplete"><Mapping_Notes><Usage>Allowed-with-Review</Usage></Mapping_Notes></Weakness>
 <Weakness ID="3" Name="Fake Broad" Abstraction="Pillar" Status="Incomplete"><Mapping_Notes><Usage>Discouraged</Usage>
   <Reasons><Reason Type="Abstraction"/></Reasons><Suggestions><Suggestion CWE_ID="1" Comment="child a"/><Suggestion CWE_ID="2" Comment="child b"/></Suggestions></Mapping_Notes></Weakness>
 <Weakness ID="4" Name="DEPRECATED: Fake Old" Abstraction="Base" Status="Deprecated"><Description>This entry has been deprecated. See CWE-1 and CWE-2.</Description><Mapping_Notes><Usage>Prohibited</Usage></Mapping_Notes></Weakness>
 <Weakness ID="5" Name="Fake Incomplete Prohibited" Abstraction="Base" Status="Incomplete"><Mapping_Notes><Usage>Prohibited</Usage></Mapping_Notes></Weakness>
 <Weakness ID="6" Name="Fake Child" Abstraction="Variant" Status="Draft"><Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="3" View_ID="1000"/></Related_Weaknesses><Mapping_Notes><Usage>Allowed</Usage></Mapping_Notes></Weakness>
</Weaknesses>
<Groupings>
 <Grouping ID="7" Name="Fake Group" Status="Obsolete"><Relationships><Has_Member CWE_ID="1"/><Has_Member CWE_ID="2"/></Relationships><Mapping_Notes><Usage>Prohibited</Usage></Mapping_Notes></Grouping>
 <Grouping ID="8" Name="Fake Empty Group" Status="Obsolete"/>
</Groupings>
</Weakness_Catalog>"""


def self_test() -> None:
    cat = build_catalog(_FAKE)
    assert cat["version"] == "9.9" and len(cat["weaknesses"]) == 6 and len(cat["groupings"]) == 2
    assert cat["weaknesses"]["6"]["parents"] == ["3"]
    r = resolve_cwe("CWE-1", cat)
    assert (r["action"], r["reason"]) == ("link", "allowed")
    r = resolve_cwe("cwe-2", cat)                                  # 대소문자와 접두사 허용
    assert (r["action"], r["reason"]) == ("link", "allowed_with_review")
    r = resolve_cwe("3", cat)                                      # 포괄 항목: 연결하되 구체적인 번호를 알린다
    assert r["action"] == "link_specific" and r["suggest"] == ["CWE-1", "CWE-2"]
    r = resolve_cwe("CWE-4", cat)                                  # 폐기: 연결하지 않고 확인, 대체 힌트
    assert (r["action"], r["reason"]) == ("review", "deprecated") and r["suggest"] == ["CWE-1", "CWE-2"]
    assert resolve_cwe("CWE-5", cat)["reason"] == "prohibited"
    r = resolve_cwe("CWE-7", cat)                                  # 그룹: 멤버 약점을 제안
    assert (r["action"], r["reason"]) == ("review", "grouping_not_mappable") and r["suggest"] == ["CWE-1", "CWE-2"]
    r = resolve_cwe("CWE-8", cat)
    assert r["action"] == "review" and r["suggest"] == []         # 멤버 없는 그룹
    assert resolve_cwe("CWE-999", cat)["reason"] == "unknown_id"   # 목록에 없는 번호도 버리지 않고 확인
    s = summarize(cat)
    assert s["linkable"] == 4                                      # 1, 2, 3(구체 번호 안내), 6
    print("자체 시험 9개 통과")


if __name__ == "__main__":
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass
    args = sys.argv[1:]
    if not args:
        self_test()
    else:
        out = Path(args[args.index("--out") + 1]) if "--out" in args else DEFAULT_OUT
        cat = build_catalog(args[0])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(cat, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        print(json.dumps(summarize(cat), ensure_ascii=False, indent=1))
        print(f"저장: {out} ({out.stat().st_size / 1024:.0f}KB)")
