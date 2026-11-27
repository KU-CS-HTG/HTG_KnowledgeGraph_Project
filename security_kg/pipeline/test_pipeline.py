"""키 없이 도는 시험: 가짜 LLM 응답으로 문서 → 추출 JSON → 적합성 검사까지의 흐름을 확인한다. 실행: python test_pipeline.py"""
import json
import tempfile
from pathlib import Path

from conformance import check_entity, check_triplet, quote_in_document
from doc_text import extract_text
from extraction_agent import run
from types import SimpleNamespace as NS

from llm import ClaudeClient, FakeClient, _tool_schema
from models import Kg_Extraction_Model

DOC = ("쿠팡은 2025년 12월 개인정보 유출 사고를 공지했다. " * 6 + "\n\n"
       "개인정보위는 '취약한 인증체계 설계·운영, 과도한 접근권한 부여, 관리정책 부재'로 판단했다. 전직 직원이 퇴사 후 서명키를 악용했다.\n"
       "The attacker exploited CVE-2016-5195 on the server.")


def triplet(**kw):
    t = {"source_entity_instance": "쿠팡 유출", "source_entity_type": "Incident", "relation": "HAS_ROOT_CAUSE",
         "target_entity_instance": "WEAK_ACCESS_CONTROL", "target_entity_type": "RootCause", "assertion_status": "confirmed",
         "evidence_quote": "과도한 접근권한 부여"}
    t.update(kw)
    return t


def main():
    # 1) 근거 문장 검사와 규칙 검사
    assert quote_in_document("과도한  접근권한\n부여", DOC) and not quote_in_document("없는 문장", DOC)
    ok = check_triplet(triplet(), DOC)
    assert ok["ontology_conformed"] and ok["quote_verified"] and ok["issues"] == []
    bad = check_triplet(triplet(relation="EXPLOITED_VULNERABILITY", target_entity_type="Vulnerability",
                                target_entity_instance="DirtyCow", evidence_quote="지어낸 문장"), DOC)
    assert not bad["ontology_conformed"] and not bad["quote_verified"] and any("ID 형식" in i for i in bad["issues"])
    assert check_entity("RootCause", "NOT_A_SEED") and check_entity("ActorOrigin", "FORMER_INSIDER") == []
    assert check_entity("Vulnerability", "CVE-2016-5195") == [] and check_entity("Foo", "x")
    # 2) 구조화 출력 틀: 목록은 객체로 감싸야 도구 입력이 된다
    s = _tool_schema(Kg_Extraction_Model, True)
    assert s["type"] == "object" and s["properties"]["items"]["type"] == "array"
    # 2-1) ClaudeClient: 가짜 API 객체로 도구 호출 응답을 해석하는지, 실패하면 다시 시도하는지 확인
    calls = []

    class FakeApi:
        class messages:
            @staticmethod
            def create(**kw):
                calls.append(kw)
                if len(calls) == 1:
                    raise ConnectionError("일시 오류")
                return NS(content=[NS(type="tool_use", input={"items": [triplet()]})])
    import llm
    llm.time.sleep = lambda s: None
    got = ClaudeClient(FakeApi, retries=2).structured("질문", DOC, Kg_Extraction_Model, model="m", as_list=True)
    assert len(got) == 1 and len(calls) == 2 and calls[1]["tool_choice"] == {"type": "tool", "name": "record"}
    assert calls[1]["messages"][0]["content"][0]["cache_control"] == {"type": "ephemeral"}
    # 3) 문서 → JSON 전체 흐름(가짜 LLM)
    fake = FakeClient({
        "Document_Meta_Model": {"source_type": "official_government", "document_date": "2025-12",
                                "incident_mentions": [{"name": "쿠팡 유출", "breached_org": "쿠팡", "signals": []}]},
        "Kg_Extraction_Model": [triplet(), triplet(relation="USED_BEHAVIOR", target_entity_type="AttackBehavior",
                                                  target_entity_instance="서명키 악용", evidence_quote="서명키를 악용했다")],
        "Entity_Extraction_Model": [{"entity_instance": "CVE-2016-5195", "entity_type": "Vulnerability"},
                                    {"entity_instance": "DirtyCow", "entity_type": "Vulnerability"}],
    })
    with tempfile.TemporaryDirectory() as d:
        docs, out = Path(d, "docs"), Path(d, "out")
        docs.mkdir()
        (docs / "CPG-01.txt").write_text(DOC, encoding="utf-8")
        (docs / "bad.hwp").write_text("x")                      # 지원하지 않는 확장자는 대상에서 빠진다
        (docs / "SHORT.txt").write_text("짧음")                  # 글자가 너무 적으면 실패로 기록한다
        stats = run(docs, out, fake, "m1", "m2", max_workers=1)
        assert stats["found"] == 2 and stats["done"] == 1 and "SHORT" in stats["failed"], stats
        r = json.loads((out / "CPG-01.json").read_text(encoding="utf-8"))
        assert r["source_type"] == "official_government" and len(r["kg_extraction_triplets"]) == 2
        assert all(t["quote_verified"] and t["ontology_conformed"] for t in r["kg_extraction_triplets"])
        assert r["models"] == {"extraction": "m1", "metadata": "m2"}
        assert r["entities_extracted"][1]["issues"], "ID 형식이 아닌 개체를 표시하지 못함"
        assert run(docs, out, fake, "m1", "m2")["skipped_existing"] == 1      # 이어서 실행
    # 4) 글자 추출(html, hwpx)
    with tempfile.TemporaryDirectory() as d:
        h = Path(d, "a.html"); h.write_text("<html><script>x()</script><p>" + "본문 " * 80 + "</p></html>", encoding="utf-8")
        assert "x()" not in extract_text(h) and "본문" in extract_text(h)
        import zipfile
        z = Path(d, "a.hwpx")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Contents/section0.xml", "<hs:sec><hp:p><hp:run><hp:t>" + "한글 문단 " * 60 + "</hp:t></hp:run></hp:p></hs:sec>")
        assert "한글 문단" in extract_text(z)
    print("파이프라인 자체 시험 통과")


if __name__ == "__main__":
    main()
