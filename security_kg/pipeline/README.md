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

## 임베딩 모델 시험 결과 (BAAI/bge-m3, 2026-11-27)

`embedding_eval.py`, 질의 `embedding_eval_cases.csv`(40개), 결과 `embedding_eval_result.csv`. 뼈대 색인은 ATT&CK 기법 706, 전술 15, 소프트웨어와 별칭, 그룹과 별칭, CWE 984, RootCause 시드를 쓴다. CPU에서 약 1분.

| 질의 종류 | 개수 | 1위가 정답 | 3위 안에 정답 |
| --- | --- | --- | --- |
| 전체 | 35 | 21 (60%) | 29 (83%) |
| 행위자(별칭 검토표의 4행) | 4 | 4 | 4 |
| 악성코드(BPFDoor, 비피에프도어 등) | 4 | 4 | 4 |
| 전술 | 3 | 3 | 3 |
| 기법 | 12 | 4 | 7 |
| 약점(CWE) | 7 | 3 | 6 |
| RootCause | 5 | 3 | 5 |

- **이름은 잘 맞고 서술은 잘 못 맞는다.** 한국어 음역(김수키, 라자루스, 비피에프도어)은 영어 항목에 맞았다. 반면 "공급망 침해", "무차별 대입 공격"처럼 기법을 서술한 말은 영어 기법 이름과 맞추지 못한 경우가 많았다(기법 12개 중 1위 정답 4개. 예: "공급망 침해"는 `T1195 Supply Chain Compromise`를 3위 안에 넣지 못함).
- **점수로 맞고 틀림을 가를 수 없다.** 1위가 정답일 때 점수는 0.55~1.0, 오답일 때 0.53~0.84로 겹치고, 부정 예(개인정보보호위원회, 쿠팡 등 뼈대와 무관한 말)의 1위 점수도 0.56~0.65였다. 원본의 0.8 같은 임계값은 이 모델에서 쓸 수 없다. 점수만으로 합치지 않는다.
- **질의를 영어로 옮기면 나아진다(탐색적 확인).** 한국어 서술이 틀렸던 14개를 사람이 영어로 옮겨 다시 넣었더니 1위 정답이 0개에서 6개, 3위 안이 11개로 늘었다. 실제로는 Claude가 옮기게 한다.
- **정답 라벨에 모호함이 있다.** 하드코딩된 비밀번호(CWE-798 대 CWE-259), 경쟁 상태(CWE-362 대 CWE-364), 인증 누락(CWE-306 대 CWE-862)처럼 서로 가까운 항목은 오답이 아니라 라벨이 애매한 것일 수 있다. 정답 라벨은 별칭 검토표 4행을 빼고 Claude가 썼고 사람이 확인하지 않았다.

**결정(제안): 임베딩은 후보를 찾는 데만 쓴다.** 연결 순서는 (1) 정확 일치(ID, 이름, 별칭 사전) (2) 질의를 Claude가 영어로 옮긴 뒤 임베딩으로 상위 5개 후보 (3) Claude가 후보 중에 같은 것이 있는지 판정, 없으면 `no_match` (4) 애매하면 사람 확인. 점수 임계값으로 자동 합치지 않는다.

## 남은 일 (4~6단계)
1. `entity_linking.py` 대체: `EXACT_ID_ENTITIES`(CVE, CWE, ATT&CK ID는 정확히 일치), `Incident`는 `incident_resolution.py`, `Organization`은 별칭 사전, 나머지는 이름 유사도(임베딩 모델은 아직 정하지 않음).
2. 그래프 적재 코드(`neo4j_v2.py` 대체)와 뼈대 노드 생성.
3. 기법 매핑 단계(`attack_mapping.py`)를 추출 뒤에 연결.
4. 실제 문서 22건으로 소규모 실행, 정답표 28행과 대조. 문서와 키가 필요하다.

## 알아 둘 점
- `llm.py`의 모델 이름(`claude-sonnet-5-5`, `claude-haiku-5-5`)과 도구 호출 방식은 이 세션에서 실제 API로 시험하지 못했다.
- 긴 문서는 한 번에 보낸다(쪼개지 않음). 문서가 모델 입력 한도를 넘으면 실패로 기록된다.
- 스캔 이미지 PDF는 글자가 안 뽑혀 실패로 기록된다(글자 인식 필요).
