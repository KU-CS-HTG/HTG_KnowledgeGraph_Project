# 보안 사건 추출 파이프라인 (운영-D5, 1~3단계)

원본 ClimateKG 코드를 고쳐 쓰는 대신, 보안 분야용 코드를 이 폴더에 새로 쓰고 원본은 `_original_climatekg/`에 읽기 전용으로 두었다(출처 커밋은 그 폴더의 README).
LLM은 Gemini에서 **Claude**로 바꿨다. 모델은 `llm.py`에서만 부른다.

**상태: 구조와 가짜 응답 시험까지만 확인했다. 실제 LLM으로 실행한 적이 없고, 추출 품질도 평가하지 않았다.**

## 원본과의 대응

| 원본(`_original_climatekg/`) | 여기 | 바뀐 점 |
| --- | --- | --- |
| `extraction_agent.py` (Gemini, PDF 업로드, 컨텍스트 캐시, 문서당 약 5회 호출) | `extraction_agent.py`, `llm.py` | Claude, 문서를 텍스트로 바꿔 전달(프롬프트 캐시 블록), 문서당 3회(메타데이터, 관계, 개체). 논문 전용 호출(분야, 문제, 방법, 관측, 기후 모델, 논문 선별)은 없앰. 수치는 `measurements.py`의 별도 층이라 여기서 받지 않음 |
| `models.py` | `models.py` | `assertion_status` 추가, `paragraph` → `evidence_quote`(원문 그대로), `Document_Meta_Model`(source_type, document_date, incident_mentions) 추가 |
| `prompts_deprecated.py`, `consts.py`의 기후 정의 | `prompts.py` | `extraction/consts.py`의 정의, 관계, 시드, 규칙을 읽어 프롬프트를 만든다(다시 쓰지 않음) |
| `ontology_conformance_agent.py` (기후 어휘 집합 6개) | `conformance.py` | 관계·종류 조합, ID 형식(`ID_PATTERNS`), 닫힌 시드(RootCause, ActorOrigin) 검사. **근거 문장이 원문에 실제로 있는지**도 검사(`quote_verified`). 버리지 않고 표시만 한다 |
| `find_papers.py`, `parse_pdfs_olmocr.py` | `doc_text.py` | pdf(pdftotext), hwpx, html, txt, md에서 본문 추출. `.hwp`는 미지원 |
| `entity_linking.py`, `create_embeddings.py`, `kg_create/` | **아직 안 함** | 아래 "남은 일" |
| `validation_agent.py`, `evaluation_agent.py`, `evidence_validation_agent.py` | **아직 안 함** | 같은 `llm.py`로 옮길 예정. 근거 문장 검사로 일부 대체 가능한지 먼저 본다 |

## 실행

```bash
pip install anthropic pydantic        # pdftotext(poppler-utils)도 필요
python pipeline/test_pipeline.py      # 키 없이 구조 시험
export ANTHROPIC_API_KEY=...          # 키는 저장소에 쓰지 않는다
python pipeline/extraction_agent.py --docs-dir <문서 폴더> --out-dir <출력 폴더>
```

문서 원본은 저장소에 올리지 않는다(운영-D2: 드라이브에 보관, 파일 이름 `<doc_id>.<확장자>`). 출력은 `<doc_id>.json`이고, 이미 있으면 건너뛴다.

## 남은 일 (4~6단계)
1. `entity_linking.py` 대체: `EXACT_ID_ENTITIES`(CVE, CWE, ATT&CK ID는 정확히 일치), `Incident`는 `incident_resolution.py`, `Organization`은 별칭 사전, 나머지는 이름 유사도(임베딩 모델은 아직 정하지 않음).
2. 그래프 적재 코드(`neo4j_v2.py` 대체)와 뼈대 노드 생성.
3. 기법 매핑 단계(`attack_mapping.py`)를 추출 뒤에 연결.
4. 실제 문서 22건으로 소규모 실행, 정답표 28행과 대조. 문서와 키가 필요하다.

## 알아 둘 점
- `llm.py`의 모델 이름(`claude-sonnet-5-5`, `claude-haiku-5-5`)과 도구 호출 방식은 이 세션에서 실제 API로 시험하지 못했다.
- 긴 문서는 한 번에 보낸다(쪼개지 않음). 문서가 모델 입력 한도를 넘으면 실패로 기록된다.
- 스캔 이미지 PDF는 글자가 안 뽑혀 실패로 기록된다(글자 인식 필요).
