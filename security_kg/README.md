# 보안 사고 지식 그래프 설정 초안

ClimateKG 파이프라인을 보안 사고 분석에 적용하기 위한 `consts.py` 초안이다. 이 파이프라인으로 실행해 본 적이 없고, 분야 전문가의 검토도 받지 않았다.

## 질문 틀

> 사건 X에서 공격자는 (a) 어떤 취약점 (b) 어떤 약점·관리 실패 (c) 어떤 기법을 이용했는가? 각 답에 출처와 확정/주장/추정 구분을 붙여라.

대상 사건(초안): 레벨인피니트 CDN 해킹, SK텔레콤 유심 정보 유출, 2026 금융권 동시다발 해킹, 2026 Canvas 해킹, 2025 쿠팡 개인정보 유출.

## 설계 요약

| 질문의 칸 | 개체 종류 | 관계 | 출처 |
| --- | --- | --- | --- |
| 사건 | `Incident`, `Organization`, `Campaign` | `BREACHED_ORGANIZATION`, `AFFECTED_ORGANIZATION`, `PART_OF_CAMPAIGN` | 문서(열린 종류) |
| (a) 취약점 | `Vulnerability` (CVE) | `EXPLOITED_VULNERABILITY` | 뼈대(CVE, 닫힌 목록) |
| (b) 약점 | `Weakness` (CWE) | `EXPLOITED_WEAKNESS` | 뼈대(CWE) |
| (b) 관리 실패 | `RootCause` | `HAS_ROOT_CAUSE` | 손으로 만든 시드 + 문서 추가 |
| (c) 기법 | `Technique`, `Tactic`, `MalwareFamily` | `USED_TECHNIQUE`, `USED_MALWARE` | 뼈대(ATT&CK, MISP) |
| (참고) 배후 | `ThreatActor` | `ATTRIBUTED_TO` | 뼈대 + 문서 추가 |
| (참고) 공격자 유형 | `ActorOrigin` | `HAS_ACTOR_ORIGIN` | 닫힌 시드 4개(아래) |

개체 종류 12개, 관계 16개(문서에서 받는 10개, 표준에서 오는 6개). 배후와 공격자 유형은 질문의 칸이 아니라 **참고 정보**다. 기후 버전은 개체 36종, 관계 75개였다.
표준 데이터가 이미 가진 관계(CVE→CWE, 기법→전술 등)는 문서에서 다시 받지 않는다. 기후에서 모델→변수 같은 관계를 받지 않는 것과 같은 논리로 보이나, 저자가 그렇게 설명한 것은 아니다.

## 확정/주장/추정 구분을 담는 방법

- 사실(트리플렛)마다 `assertion_status`(`confirmed`, `claimed`, `inferred`)를 붙인다.
- 문서마다 `source_type`(정부, 피해 조직, 보안 업체, 언론, 공격자 주장, 연구자)을 붙인다. 사실의 출처는 그 사실이 나온 문서이므로 별도의 `Claim` 노드는 두지 않았다.
- 원본의 추출 스키마에는 이 칸이 없어서 **코드 수정이 필요하다**(아래).

## 답의 집계: "없음"과 "언급 없음"의 구분 (최소안)

문제: 트리플렛이 없다는 것만으로는 "원래 없다"와 "문서가 말하지 않았다"를 구분하지 못한다.

방침(1단계): **부재를 추측하지 않는다.** 새 개체 종류나 관계를 추가하지 않고 집계에서 해결한다.

| 칸의 상태 | 조건 | 보여 주는 것 |
| --- | --- | --- |
| `found` | 그 칸의 관계(`consts.ANSWER_SLOTS`)로 된 트리플렛이 하나 이상 있음 | 답을 확정 > 주장 > 추정, 같으면 더 많은 문서가 말한 순으로. 문서마다 구분이 다르면 표시 |
| `not_mentioned` | 없음 | "확인되지 않음: 처리한 문서 n개 중 언급 없음" |

- **"없음"이라고 쓰지 않는다.** 다른 칸에 답이 있다고 해서 이 칸을 "없음"으로 추론하지도 않는다(예: 쿠팡 유형은 (b)가 있어도 (a)는 "언급 없음").
- **문서 수를 항상 함께 쓴다.** "언급 없음"의 무게가 문서 1개일 때와 20개일 때 다르기 때문이다.
- 구현: `aggregate.py`(`summarize_incident`, `render`). 자체 시험 12개가 위 규칙을 확인한다(묶음 합산 포함).
- 문서 수를 세려면 문서 단위로 `incident_mentions`(사건 해소 절 참고), `document_date`, `source_type`을 추가로 뽑아야 한다(`consts.NEW_DOCUMENT_LEVEL_FIELDS`). 원본에는 없다.

### 보류한 확장안: 명시적 부재 진술을 추출

문서가 "밝히지 않았다", "해당하지 않는다", "있었으나 식별되지 않았다"라고 **직접 말하는 경우**를 `StatusValue`(`NOT_APPLICABLE`, `UNDISCLOSED`, `EXISTS_UNIDENTIFIED`)로 추출해 "미공개"와 "언급 없음"을 구분하는 방식이다.
최소안으로 파일럿을 돌려 보고 **그 구분이 실제로 필요하다고 확인될 때** 도입한다. 도입할 때의 변경은 다음과 같다.

```python
ENTITY_TYPE_DEFINITIONS["StatusValue"] = "A statement about whether an answer exists. Use ONLY when the text explicitly says so."
STATUS_VALUE_SEED = ["NOT_APPLICABLE", "UNDISCLOSED", "EXISTS_UNIDENTIFIED"]
FILTERED_RELATIONSHIP_SOURCE_TO_TARGET += [
    ("Incident", "StatusValue", "VULNERABILITY_STATUS"),
    ("Incident", "StatusValue", "WEAKNESS_STATUS"),
    ("Incident", "StatusValue", "TECHNIQUE_STATUS"),
]
```

도입 전에 풀어야 할 것: AI가 근거 없이 "없음"을 만드는 문제(명시적 문장일 때만 내도록 지시하고 처음에는 사람이 표본 검토), "미공개"의 시점(문서 날짜로 새 문서 우선), 평가용 정답을 사람이 만드는 일.
`EXISTS_UNIDENTIFIED`가 필요한 이유: Canvas처럼 "취약점이 있었다고는 밝혔으나 CVE가 없는" 경우를 `Vulnerability`(CVE로 정의)로는 담을 수 없다.

## 공격자 유형: 내부자 표현 (옵션 B)

질문 틀 (a)(b)(c)에는 "누가"가 없다. 그러나 쿠팡 같은 사건에서 공격자가 전직 개발자라는 사실은 잃고 싶지 않다. 그래서 **참고 정보**로만 기록한다.

| 값(`ACTOR_ORIGIN_SEED`) | 뜻 |
| --- | --- |
| `INTERNAL` | 현직 직원·계약자 |
| `FORMER_INSIDER` | 전직 직원·계약자. 퇴사 후에도 남은 접근 권한이나 지식을 이용. **VERIS에서는 `External`** (우리가 추가한 값) |
| `PARTNER` | 협력사·공급사·서드파티 |
| `EXTERNAL` | 피해 조직과 정당한 관계가 없는 외부 |

- **속성이 아니라 "닫힌 값 목록을 가리키는 관계"로 둔 이유**: 파이프라인은 (출발, 관계, 도착) 트리플렛만 뽑는다. 사건의 속성으로 두면 근거 문장과 기존 검사 단계(형식, 출처, AI 재검증)를 받을 방법이 없다. 관계로 두면 근거 문장이 붙고 검사를 그대로 통과한다.
- **VERIS와의 관계(결정 1: 세분화를 유지하고 대응표를 둔다)**: `INTERNAL`/`EXTERNAL`/`PARTNER`는 VERIS의 최상위 행위자 구분(내부, 외부, 협력사)과 같은 이름 체계다. VERIS 위키의 행위자 설명은 **전직 직원을 외부(External) 위협의 예로 들고** 내부(Internal)는 현재 구성원으로 설명하므로, 우리가 추가한 `FORMER_INSIDER`는 VERIS에서 `External`에 해당한다. 그래서 `consts.ACTOR_ORIGIN_TO_VERIS`로 대응표를 두어 VERIS 데이터와 비교할 수 있게 했다. 세분화된 값은 상위 값으로 합칠 수 있지만 합친 값은 다시 쪼갤 수 없어서 손실이 없는 쪽을 택했다. 주의: VERIS 위키 사본 페이지로 확인한 것이므로 정확한 값 목록은 VERIS 스키마 저장소로 대조해야 한다.
- **경계 규칙(결정 2)**: 유형은 **공격(접근)이 일어난 시점의 고용 상태**로 정한다(발견 시점이 아니다). 그 시점에 재직 중이었으면 `INTERNAL`(퇴사 직전의 오용 포함), 이미 퇴사했으면 `FORMER_INSIDER`. 문서에 시점이 없으면 추측하지 않고 `inferred`로 하거나 기록하지 않는다. 사례 6개는 `consts.ACTOR_ORIGIN_BOUNDARY_EXAMPLES`에 있고 프롬프트의 예시로 쓴다.
- **`UNKNOWN`은 값으로 두지 않는다.** 문서가 말하지 않은 것은 "언급 없음, 문서 n개"로 집계한다(부재를 추측하지 않는 원칙과 같다).
- **추론 금지**: 공격자의 국적, 위치, 수법의 정교함으로 유형을 추론하지 않는다. 쿠팡 사건의 "중국 국적"은 유형과 무관하다. 관계가 암시만 될 때는 `assertion_status`를 `inferred`로 한다.
- **이름 있는 행위자는 `ThreatActor`, 이름 없는 공격자는 `ActorOrigin`만 기록한다.** 둘은 같이 나올 수 있다(예: 이름 있는 외부 집단 = `ThreatActor` + `EXTERNAL`).
- **집계**: `consts.CONTEXT_FIELDS`(`actor_origin`, `attribution`)를 `aggregate.summarize_context`가 칸과 같은 규칙으로 보여 준다. 값이 여러 개(문서들이 다르게 말했거나 행위자가 둘 이상)면 "사람이 확인 필요"로 표시한다.
- **원인과의 관계**: 쿠팡 유형은 `HAS_ACTOR_ORIGIN = FORMER_INSIDER`와 `HAS_ROOT_CAUSE = CREDENTIAL_OR_KEY_MISMANAGEMENT`가 함께 나온다. 앞의 것은 "누구", 뒤의 것은 "왜 가능했나"이고 서로 대체하지 않는다.

**다중 행위자(결정 3: 사건 단위만 기록, 보류)**: 한 사건에 행위자가 둘 이상일 때 값과 행위자 이름을 짝짓는 일(`ACTOR_PAIRING = "incident_level"`)은 하지 않는다. 값이 여러 개면 `aggregate.py`가 "사람이 확인 필요"로 표시한다. 다섯 사건은 모두 공격자 서사가 하나로 보여서(검색 요약 기준, 미검증) 이 문제가 거의 생기지 않을 것으로 본다. **행위자별 질문("누가 무엇을 했나")이 실제로 필요하다고 확인될 때** 사건과 행위자 사이에 중간 개체를 두는 방식을 검토한다. 이 경우 같은 중간 개체를 여러 문서에서 합치는 문제(열린 설계 문제 3번)가 함께 생긴다.

미해결: 실제 문서가 공격 시점의 고용 상태를 분명히 쓰는지(파일럿에서 확인), VERIS 스키마의 정확한 값 목록과의 대조.

## 사건 해소: 같은 사건 합치기

문제: 원본은 새 노드를 **이름의 의미 유사도 0.8 이상이면 합친다**(`SourceComponent`만 AI가 확인). 날짜와 조직을 보지 않아서 사건에서는 두 방향으로 틀린다.
같은 회사의 다른 사건이 이름이 비슷해 합쳐지거나(답이 섞여 오염), 같은 사건이 문서마다 이름과 시점이 달라 쪼개진다(답이 흩어짐).

### 결정 (D1~D4)

| 결정 | 내용 |
| --- | --- |
| **D1 단위** | `Incident` = **침해된 조직 1곳**의 사건(`BREACHED_ORGANIZATION`). 파급 피해 조직은 `AFFECTED_ORGANIZATION`. 여러 조직에 걸친 사건은 `Campaign`(`PART_OF_CAMPAIGN`)으로 묶고, **묶음의 답은 소속 사건의 답을 합산**한다(`aggregate.summarize_campaign`) |
| **D2 기준** | 같은 침해 조직이 필수 → **문서가 제시하는 사건 시점(공개 시점)** 으로 90일 이내면 같은 사건 후보, 365일 초과면 다른 사건 → 공유 신호(같은 CVE·악성코드·행위자)나 이름 유사가 있어야 합침. 이름은 약한 신호 |
| **D3 애매할 때** | **합치지 않고 사람 확인 대기열**로 보낸다(정밀도 우선). 잘못 합친 사건은 답을 오염시킨다 |
| **D4 연속 파동** | 같은 조직이고 90일 이내면 하나의 사건(예: 탐지 후 1주 뒤의 추가 침해) |

숫자(90일, 365일, 이름 유사도 0.8)는 `consts.INCIDENT_RESOLUTION`의 **출발점**이다. 다섯 사건으로는 보정할 수 없어서 파일럿에서 조정한다.

### 동작 (`incident_resolution.py`)

1. 문서마다 **사건 언급**(`incident_mentions`: 이름, 침해 조직, 시점, 공격 기간, 신호)을 뽑는다(`consts.INCIDENT_MENTION_FIELDS`). 날짜는 그래프의 트리플렛이 아니라 **문서 단위 메타데이터**로만 둔다.
2. 조직 이름을 별칭 사전(`consts.ORG_ALIAS_SEED`)으로 먼저 합친다. 사전에 없는 이름은 다른 조직으로 취급되어 사건이 쪼개질 수 있다.
3. 언급 쌍마다 `merge`/`separate`/`review`를 판정하고, `merge`만 묶는다. 결과는 정규 ID(`INC-{조직}-{연월}`), 언급→사건 대응, **사건 묶음 단위의 확인 대기열**이다.
4. 문서마다 다른 시점(공개 시점 vs 침입 시점)을 쓴 경우: 한쪽의 **공격 기간이 다른 쪽의 시점을 포함하면 가깝다고 본다.** 이때 침입 단계로 보이는 이른 날짜는 ID 기준에서 뺀다(SK텔레콤 유형: 시점 2025-04, 공격 기간 2022-06~2025-04).
5. 연쇄 합치기로 시간 폭이 365일을 넘는 묶음, 묶음 안에 "다른 사건"으로 판정된 쌍이 있는 묶음은 확인으로 표시한다.

자체 시험 11개는 다섯 사건에서 예상되는 오류 유형(같은 회사의 다른 사건, 연속 파동, 표현만 다른 같은 사건, 서로 다른 시점을 쓴 문서, 조직 별칭, 날짜 없음, 연쇄 합치기)을 확인한다.

### 알려진 한계

- **90일~365일 사이는 모두 사람 확인이다.** 예를 들어 Instructure의 2025년 9월 사고와 2026년 4월 사고(간격 183일)는 합쳐지지 않지만 확인 대기열에 들어간다.
- **공격 기간이 없으면 다른 시점을 쓴 문서를 잇지 못한다.** SK텔레콤 유형에서 공격 기간이 빠지면 서로 다른 사건으로 판정된다.
- **조직 별칭 사전이 작다.** 7개 조직만 있고 실제 문서를 보며 늘려야 한다.
- **이름 유사도는 간단한 문자열 비교**이고 다른 언어의 이름은 낮게 나온다. 운영에서는 임베딩으로 바꿀 수 있다(`sim_fn`).
- `Campaign` 이름의 합치기는 아직 규칙이 없다(수가 적어서 원본 방식으로 시작할 수 있으나 같은 오류 위험이 있다).
- 시점(`headline_date`)을 AI가 일정하게 뽑는지는 확인하지 못했다.

## 원본 코드에서 고쳐야 할 곳

`consts.py`만 바꿔서는 동작하지 않는다.

| 원본 파일 | 할 일 |
| --- | --- |
| `extraction/models.py` | `Kg_Extraction_Model`에 `assertion_status` 칸 추가 |
| `extraction/extraction_agent.py` | 문서 단위 항목에 `incident_mentions`, `document_date`, `source_type` 추가(사건 해소와 문서 수 집계용) |
| `extraction/entity_linking.py` | `Incident`는 원본의 이름 유사도 합치기(`consolidate_addable_entity`)를 쓰지 않고 `incident_resolution.py`의 결과로 대체. `Organization`은 별칭 사전으로 먼저 합침 |
| `extraction/prompts_deprecated.py` | 개체·관계 정의, 경계 규칙, 질문 틀 지시로 교체. "climate" 문구 약 39곳 교체 |
| `extraction/ontology_conformance_agent.py` | 기후 어휘 6개 집합을 이 분야 규칙으로 교체(예: `ID_PATTERNS` 검사) |
| `extraction/entity_linking.py` | `EXACT_ID_ENTITIES`(CVE, CWE, ATT&CK ID는 정확히 일치) 처리 추가 |
| `extraction/create_embeddings.py` | 새 뼈대 목록으로 임베딩 인덱스 생성 |
| `kg_create/` | CVE, CWE, ATT&CK, KEV를 그래프로 바꾸는 코드를 새로 작성(`neo4j_v2.py` 대체) |
| `extraction/find_papers.py` | 논문 검색이 아니라 뉴스·보고서 수집으로 교체 |
| 검증·평가 프롬프트 | "climate modeling" 문구 교체 |

## 5개 사건으로 본 시험 (검색 요약 기준, 미검증)

| 사건 | (a) 취약점 | (b) 약점·관리 실패 | (c) 기법 |
| --- | --- | --- | --- |
| 레벨인피니트 | 미공개 | 명시 없음 | CDN 스크립트 변조(공급망), 원격 제어 악성코드 |
| SK텔레콤 | 더티카우(CVE-2016-5195로 알려짐) | 패치 미적용, 계정정보 관리 부실, 암호화 미흡, 과거 침해 대응 미흡 | 웹쉘, BPFDoor |
| 금융권 | 확인 못 함 | 확인 못 함 | 모바일 조회·업무지원 시스템 공격, AI 침투 도구 분석(미확정) |
| Canvas | Free-for-Teacher 취약점(세부 미공개, CVE 없음) | 미공개 | 취약점 악용, 로그인 포털 변조, 갈취 |
| 쿠팡 | 없음 | 서명키 미폐기(키 관리 실패) | 서명키 탈취, 전자 출입증(토큰) 위조 |

이 표에서 CVE 번호로 답할 수 있는 칸은 SK텔레콤 한 곳뿐이다. 다른 사건은 `HAS_ROOT_CAUSE`와 `USED_TECHNIQUE`가 중심이 된다.

## 열린 설계 문제

1. ~~**"취약점 없음/미공개"를 어떻게 기록하나.**~~ **1단계(최소안) 반영됨**: 부재를 추측하지 않고 "언급 없음, 문서 n개"로 집계한다(위 "답의 집계"). "미공개"와 "언급 없음"을 구분하는 확장안은 파일럿 뒤로 보류.
2. ~~**내부자 여부.**~~ **반영됨(옵션 B)**: `ActorOrigin` 시드 4개와 `HAS_ACTOR_ORIGIN`을 참고 정보로 추가. 경계 규칙(공격 시점의 고용 상태), VERIS 대응표, 다중 행위자 보류까지 결정됨(위 "공격자 유형").
3. ~~**같은 사건을 여러 문서가 쓸 때 `Incident`를 합치는 규칙**이 없다.~~ **반영됨(D1~D4)**: 조직 단위 `Incident` + `Campaign`, 같은 조직 필수 + 공개 시점 + 공유 신호, 애매하면 사람 확인(위 "사건 해소"). 숫자는 파일럿에서 보정.
4. **기법 수준.** 뉴스는 "악성코드 설치" 정도로 쓰고 ATT&CK 기법 이름은 분석가가 맞춰야 한다.
5. **날짜와 수치.** 날짜는 사건 해소에 필요해서 **문서 단위 메타데이터**(`headline_date`, `attack_span`, `document_date`)로 도입했다. 트리플렛에는 넣지 않는다. 수치(피해 규모, 금액)는 아직 이 틀에 없고, 출처 간 차이 비교 질문에는 필요하다.
6. `RootCause` 시드 8개는 5개 사건의 검색 요약에서 일반화한 것이라 전문가 검토가 필요하다.

## 자체 검사

```bash
python extraction/consts.py   # 설정의 일관성 검사
python aggregate.py           # 집계 규칙 자체 시험(12개)
python incident_resolution.py # 사건 해소 규칙 자체 시험(11개)
```

`consts.py` 검사는 관계의 개체 종류 정의 여부, FILTERED ⊂ ALL, 닫힌 목록 종류의 연결 방법, `ANSWER_SLOTS`가 문서에서 받는 관계만 쓰는지 등을 확인한다.
