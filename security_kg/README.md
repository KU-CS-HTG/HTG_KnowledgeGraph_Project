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
| (c) 기법 | `AttackBehavior`(서술형), `Technique`, `Tactic`, `MalwareFamily` | `USED_BEHAVIOR`, `USED_TECHNIQUE`, `USED_MALWARE` | 서술형은 문서, 기법은 뼈대(ATT&CK, MISP). 매핑은 별도 단계 |
| (참고) 배후 | `ThreatActor` | `ATTRIBUTED_TO` | 뼈대 + 문서 추가 |
| (참고) 공격자 유형 | `ActorOrigin` | `HAS_ACTOR_ORIGIN` | 닫힌 시드 4개(아래) |

개체 종류 13개, 관계 17개(문서에서 받는 11개, 표준에서 오는 6개). 배후와 공격자 유형은 질문의 칸이 아니라 **참고 정보**다. 기후 버전은 개체 36종, 관계 75개였다.
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
- 구현: `aggregate.py`(`summarize_incident`, `render`). 자체 시험 13개가 위 규칙을 확인한다(묶음 합산, 기법 층 출력 포함).
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

## 기법 층: 서술형 행동 → ATT&CK 매핑 → 뼈대 유도 (D5~D8)

문제: 뉴스는 "악성코드를 설치했다"처럼 평이하게 쓰고 ATT&CK는 표준 이름의 기법이다. 닫힌 목록에 맞추다 실패하면 **사실이 버려지고**, 억지로 맞추면 **틀린 매핑**이 생긴다.
CISA의 매핑 지침은 모든 행동이 ATT&CK에 있는 것은 아니라고 하고, 연구들은 AI가 기법 ID를 지어내거나 엉뚱한 기법에 맞출 수 있다고 지적한다.

### 결정

| 결정 | 내용 |
| --- | --- |
| **D5 방식** | **2층.** ① 문서가 말한 행동을 서술형(`AttackBehavior`)으로 먼저 기록 ② ATT&CK 매핑은 별도 단계 ③ 이름 있는 악성코드는 뼈대에서 기법을 유도 |
| **D6 매핑 책임** | AI가 후보를 제안하고 **사람이 확인**(파일럿). 사람이 확인하기 전의 AI 제안은 확정으로 세지 않는다 |
| **D7 수준** | 사건 간 비교는 **전술**, 상세는 **기법**, 하위 기법은 문서가 구체적일 때만(아니면 상위 기법으로 올림) |
| **D8 유도된 기법** | 답에 포함하되 "문서의 주장이 아니라 뼈대 유도"로 구분해서 표시 |

### 동작 (`attack_mapping.py`, 설정은 `consts.py` 5-1절)

- **서술형은 사라지지 않는다.** 매핑이 안 되거나(`unmapped`) 맞는 기법이 없어도(`no_match`) 서술형 행동으로 남는다.
- **문서가 ATT&CK 기법 이름·ID를 직접 쓴 경우만** `USED_TECHNIQUE`로 받는다(`documented`). 목록에서 찾지 못한 이름은 조용히 받지 않고 "찾지 못함"으로 따로 알린다.
- **AI가 낸 후보는 검증한다.** 내려받은 ATT&CK 목록에 없는 ID는 버린다(환각 방지). 후보에는 신뢰도(`high`/`medium`/`low`)와 근거가 붙는다.
- **상태**: `documented`, `ai_suggested`(사람 확인 전), `human_confirmed`, `human_rejected`(답에서 제외), `no_match`(억지로 맞추지 않음).
- **뼈대 유도**: ATT&CK 소프트웨어 정보에서 악성코드 → 기법을 가져온다. 모르는 악성코드는 추측하지 않는다. 예: BPFDoor는 ATT&CK 소프트웨어(S1161)이고 Socket Filters 기법(T1205.002) 등과 연결된다(검색으로 확인).
- **전술 단위 집계**는 출처(문서가 쓴 것, 사람이 확인한 것, AI 제안, 뼈대 유도)별로 나눠서 센다. 서로 섞이지 않는다.
- `load_catalog_from_stix`, `load_software_map`이 ATT&CK STIX 번들에서 목록과 소프트웨어 대응을 만든다.
- 매핑 결과는 신뢰도와 근거가 필요해서 트리플렛이 아니라 **별도 기록**이다: `{"behavior", "candidates": [{"technique_id", "confidence", "evidence"}], "status"}`.

### 알려진 한계

- **매핑 정확도는 보장되지 않는다.** 관련 연구의 정확도는 데이터셋마다 달라 비교할 수 없고, 우리 문서에서의 정확도는 사람이 만든 정답으로 재야 한다. 분석가 둘이 결과를 비교하는 것이 MITRE의 권고다.
- **ATT&CK 버전이 바뀐다.** 2026년에만 v19(4월), v20(10월)이 나왔으니 이름과 ID가 달라질 수 있다. 내려받은 버전을 `BACKBONE_SNAPSHOTS["attack"]`에 기록한다.
- **서술형 행동은 표현이 제각각이다.** 사건 안에서만 의미가 있고, 사건 간 비교는 매핑된 전술·기법으로 한다. 같은 행동의 다른 표현을 합치는 규칙은 아직 없다.
- **STIX 필드 이름**은 실제 ATT&CK Enterprise 20.1 번들로 확인했다(뒤의 "뼈대 데이터" 절). 다른 번들(ICS, Mobile)이나 다른 버전은 확인하지 않았다.
- **시험 목록은 가짜다.** 시험에 쓴 기법 ID, 이름, 전술은 실제 ATT&CK 값이 아니다(확인하지 않은 값을 단정하지 않으려는 것).
- 매핑 단계의 AI 호출은 이 저장소에 없다. 후보를 받아 검증하고 집계하는 부분만 있다.

## 수치 층: 피해 규모와 금액 (D9~D12)

수치는 트리플렛의 도착이 개체가 아니라 값이고, 단위(명/건/GB/원), 정확도(약/이상/범위), 시점, 출처에 따라 뜻이 달라진다. 사람 수와 건수는 다른 지표이고(한 사람이 여러 건일 수 있다), 초기 발표와 조사 후 수치가 다르며, 같은 사건도 문서마다 다른 수치를 낸다.

### 결정

| 결정 | 구현 |
| --- | --- |
| **D9 별도 기록** | 트리플렛이나 값 노드가 아니라 단위·정확도·시점·출처가 붙은 기록. 값 노드는 연결 단계가 이름 유사도로 합칠 위험이 있다(3번과 같은 문제) |
| **D10 닫힌 소수 지표 + `other`** | `affected_people`, `affected_records`, `data_volume`, `fine`, `loss_estimate`, `other`. 사람·건수·용량·금액은 합치거나 비교하지 않는다 |
| **D11 조정하지 않고 나란히** | 출처 유형, 확정/주장/추정, 시점, 정확도 표현(`exact`, `approx`, `lower_bound`, `upper_bound`, `range`)을 같이 표시. **같은 지표(단위 종류, 통화) 안에서만** 최솟값~최댓값 범위를 보이고 어느 쪽이 맞는지는 판정하지 않는다 |
| **D12 원문 보존, 규칙으로 정규화** | 원문 수치 문자열(`raw`)과 근거 문장(`evidence`)을 같이 기록. 정규화는 AI 없이 규칙. 단위를 못 읽으면 버리지 않고 `unit_unknown`으로 사람 확인 |

### 동작 (`measurements.py`, 설정은 `consts.py` 5-2절)

- 기록: `{"incident", "metric", "raw", "evidence", "as_of", "doc_id", "source_type", "assertion_status"}`. 정규화 결과로 `value`, `value_high`, `unit_kind`, `currency`, `qualifier`, `review`가 붙는다.
- 읽는 표기: 한국어 만/억/조/천/백(`2,324만`, `1억 2,300만`, `3천5백만`), 영어 thousand~trillion, 용량(KB~PB, 십진), 통화 USD/KRW/EUR/JPY, 범위(`~`, `to`).
- 사람 확인 사유(`consts.MEASUREMENT_REVIEW_REASONS`): 숫자 없음(`수백만`), 단위 모름, 지표와 단위 불일치(예: `affected_people`인데 `건`), 원문이 근거 문장에 없음, 정의되지 않은 지표(`other`로 바꿈). 확인 대상은 범위 계산에서 빠지지만 기록은 남는다.
- 통화는 환산하지 않고 통화별로 따로 둔다(환율 시점 문제).
- 수치를 말한 문서가 없으면 "없음"이 아니라 "확인되지 않음: 처리한 문서 n개 중 수치 언급 없음".

### 알려진 한계

- **한국어 수 표기 규칙은 일반 지식으로 만든 것이고 실제 문서로 시험하지 않았다.** 합성 표현 9개 시험만 통과했다.
- 지표 5개는 다섯 사건에서 일반화한 출발점이라 파일럿에서 조정해야 한다.
- 영어 약어(`23M`, `1.5bn`)와 "2,000만~2,500만" 외의 범위 표현(`between A and B`)은 읽지 못해 확인 대상이 된다.
- `계정(accounts)`처럼 사람인지 건수인지 모호한 단위는 읽지 않고 `unit_unknown`으로 보낸다.
- 수치 추출(AI 호출)은 이 저장소에 없다. 추출된 기록을 받아 정규화하고 정리하는 부분만 있다.
- `as_of`(수치의 기준 시점)를 AI가 일정하게 뽑는지는 확인하지 못했다. 같은 출처의 수치 갱신은 시점으로만 구분한다.

## RootCause 시드 검토 자료: CWE 대응표와 경계 규칙

열린 문제 6번(`RootCause` 시드 8개가 내 일반화일 뿐이라는 점)의 **준비 작업**이다. 전문가 검토를 대신하지 않는다. 설정은 `consts.py` 4-1절(`ROOT_CAUSE_CWE_MAP`, `ROOT_CAUSE_BOUNDARY_RULES`, `ROOT_CAUSE_BOUNDARY_EXAMPLES`)에 있다.

### CWE 대응표

| RootCause | 대응 | CWE (MITRE 매핑 구분) |
| --- | --- | --- |
| `UNPATCHED_KNOWN_VULNERABILITY` | partial | CWE-1395 (Allowed-with-Review), CWE-1104 (Allowed) |
| `CREDENTIAL_OR_KEY_MISMANAGEMENT` | partial | CWE-798 (Allowed-with-Review), CWE-324 (Allowed) |
| `INSUFFICIENT_ENCRYPTION` | close | CWE-311 (Discouraged), CWE-327 (Allowed-with-Review), CWE-326 (Allowed-with-Review) |
| `WEAK_ACCESS_CONTROL` | close | CWE-284 (Discouraged), CWE-862 (Allowed-with-Review), CWE-863 (Allowed-with-Review), CWE-306 (Allowed) |
| `INSUFFICIENT_MONITORING_DETECTION` | close | CWE-778 (Allowed) |
| `INADEQUATE_INCIDENT_RESPONSE` | none | - |
| `THIRD_PARTY_OR_SUPPLY_CHAIN_RISK` | partial | CWE-1395 (Allowed-with-Review), CWE-1357 (Allowed-with-Review) |
| `MISCONFIGURATION` | partial | CWE-1188 (Allowed) |

- **모든 CWE는 CWE 5.0 파일(2026-10-28, `cwec_v5.0.xml`)에서 이름, 상태, MITRE의 매핑 사용 구분을 확인했다.** 괄호 안이 그 구분이다: `Allowed`, `Allowed-with-Review`(검토 후 사용), `Discouraged`(포괄 항목이라 더 구체적인 하위 항목을 쓰라는 뜻). 이 파일의 버전 표기가 CWE 사이트 메인 페이지의 다른 표기와 어긋나서 최신 여부는 확인하지 못했다.
- **대응 정도**: `close`는 분명히 대응, `partial`은 일부만 맞음, `none`은 CWE에 대응이 없음이다.
- **의도적으로 뺀 CWE** (`ROOT_CAUSE_CWE_EXCLUDED`):
  - **CWE-320 (Key Management Errors)**: 그룹이고 폐기(Obsolete)이며 파일의 매핑 주석이 `Prohibited`이다. 멤버 약점 322, 323, 324, 798을 쓴다.
  - **CWE-16 (Configuration)**: 그룹이고 폐기이며 `Prohibited`이고 멤버 약점이 없다. 파일의 주석은 설정 오류를 "그 설정이 만든 행동의 약점"(접근 통제 계열 등)으로 매핑하라고 한다.
- **`Discouraged`인 311과 284**는 목록에 두되, 매핑할 때는 파일이 제안하는 하위 항목을 쓴다(311 → 312 저장, 319 전송 / 284 → 862, 863, 732, 306 등).
- 이 대응표는 **전문가 검토를 대신하지 않는다.** 번호가 존재하고 사용 가능하다는 것까지만 확인했고, 각 RootCause가 그 CWE로 충분히 설명되는지는 판단하지 않았다.

### 대응표에서 보이는 것

1. **RootCause는 두 수준을 섞고 있다.** `ENCRYPTION`, `ACCESS_CONTROL`, `MONITORING`은 제품의 기술 약점이라 CWE와 잘 맞는다. 반면 `INADEQUATE_INCIDENT_RESPONSE`는 대응이 아예 없고 `UNPATCHED`, `CREDENTIAL`, `THIRD_PARTY`, `MISCONFIGURATION`은 일부만 맞는다. CWE는 **제품의 약점**을 다루고 이 항목들은 **조직의 운영·절차 실패**이기 때문이다.
2. 조직 수준 항목을 다른 표준에 대응시킬지는 열려 있다(예: 보안 관리 프레임워크). 확인하지 않았다.
3. 질문 틀의 칸 (b)는 "약점·관리 실패"이므로 두 수준을 한 칸에 두는 것은 의도와 맞다. 다만 사건 간 비교에서 두 수준을 섞어 세지 않도록 표시를 달지는 정해야 한다(전문가에게 묻는 질문).

### 경계 규칙

원칙은 **문서가 말한 "실패한 통제"로 고르고 결과(피해)로 고르지 않는다**이다. 서로 다른 실패가 둘이면 값도 둘이고, 한 실패에 값을 둘 붙이지 않는다. 겹치는 쌍 5개의 규칙은 `ROOT_CAUSE_BOUNDARY_RULES`에 있다.

- 키·자격 증명의 **수명주기** 실패 → `CREDENTIAL`, 권한의 범위·분리·인증 요구 부재 → `WEAK_ACCESS_CONTROL`
- 자기 시스템의 공개 패치 미적용 → `UNPATCHED`, 외부 공급사·협력사 침해 → `THIRD_PARTY`
- 침입을 못 알아챔 → `MONITORING`, 알고도 대응 안 함 → `INCIDENT_RESPONSE`
- 잘못된 설정·기본값 → `MISCONFIGURATION`, 통제 자체가 없음 → `WEAK_ACCESS_CONTROL`
- `ENCRYPTION`은 암호화가 없거나 약하다고 말할 때만

경계 사례 11개(`ROOT_CAUSE_BOUNDARY_EXAMPLES`)는 시드 8개를 모두 한 번씩 보이고, 한 문장에 실패가 둘인 경우, 피해만 말한 경우, 원인을 밝히지 않은 경우(기록하지 않음)를 포함한다. **문장은 규칙을 시험하려고 만든 가상 문장이며 실제 사건의 사실이 아니다.**

### 한계

- 경계 규칙은 내가 만든 것이고 실제 문서로 AI가 일관되게 따르는지는 확인하지 못했다. 사례는 프롬프트 예시와 사람 검토용이다.
- 시드에서 빠진 원인(피싱 교육, 백업, 물리 보안 등)은 이 작업으로 드러나지 않는다. 파일럿에서 `other`로 빠지는 값을 모아야 한다.

## `Weakness` 닫힌 목록: CWE 목록 변환 (`cwe_catalog.py`)

`Weakness`는 CWE 번호로만 연결하는 닫힌 종류다. 목록의 재료는 MITRE의 CWE 전체 XML이다. 작은 일부(예: Top 25)로 한정하면 문서가 인용한 CWE가 25개 밖일 때 연결에 실패해 사실이 버려지므로 **전체 목록**을 쓴다.

- `python cwe_catalog.py <cwec.xml>`이 XML에서 가벼운 목록 `data/cwe_catalog.json`(약 228KB)을 만든다. 원본 XML(18MB)은 올리지 않는다. 설명문은 뺐고 이름, 추상화 수준, 상태, 매핑 사용 구분, 제안, 부모만 둔다.
- **이번 5.0 파일의 구성**: 약점 984개(폐기 28개 포함), 그룹 431개. 매핑 사용 구분은 Allowed 755, Allowed-with-Review 100, Discouraged 44, Prohibited 85이다.
- **문서가 CWE 번호를 인용했을 때의 판정** (`resolve_cwe`):

| 판정 | 조건 | 처리 |
| --- | --- | --- |
| `link` | 약점이고 Allowed 또는 Allowed-with-Review | 연결한다(후자는 검토 필요 표시) |
| `link_specific` | Discouraged(포괄 항목) | 연결하되 MITRE가 제안한 더 구체적인 번호를 알린다 |
| `review` | 그룹, 폐기, Prohibited, 목록에 없는 번호 | **연결하지 않고 사람 확인으로 보낸다. 버리지 않는다** |

- 5.0 파일 기준으로 연결 가능한 약점은 899개이다(폐기 28개와 Prohibited 57개가 `review`).
- **상태(Draft, Incomplete 등)로는 거르지 않는다.** 약점 대부분이 Incomplete(498)나 Draft(432)이고 Stable은 26개뿐이라, 상태로 거르면 쓸 수 있는 목록이 사라진다.
- **폐기 항목**은 설명문에서 찾은 CWE 번호를 대체 힌트로만 알린다(예: CWE-1187 → CWE-908). 확정이 아니다.

### 알려진 한계

- XML 태그(`Mapping_Notes/Usage`, `Suggestion`, `Has_Member`)는 올려 받은 5.0 파일을 읽어 맞춘 것이다. 다른 버전에서는 달라질 수 있다.
- 자체 시험은 작은 가짜 XML로 하고, 실제 5.0 파일에서는 대응표 14개의 구분이 `consts.py`의 값과 모두 일치하는지, 제외한 두 번호가 `review`로 가는지를 확인했다.
- CWE 사이트에는 접속할 수 없어(이 환경의 프록시가 차단) 파일은 사용자가 올린 것을 썼고, 사이트의 최신 파일과 같은지는 확인하지 못했다.
- 이 변환은 약점 목록만 만든다. 연결 단계(문서의 CWE 번호를 이 목록에 맞추는 코드)는 아직 이 저장소에 없다.

## 뼈대 데이터: 내려받기와 변환 (`backbone.py`)

닫힌 종류(`Vulnerability`, `Technique`, `Tactic`, `MalwareFamily`, `ThreatActor`)의 목록 재료다. 모두 `raw.githubusercontent.com`의 원문 파일이고(이 환경에서 접근 가능한 곳), 내려받은 날짜는 2026-11-25이다. 원본(ATT&CK 55MB 등)은 올리지 않고(`backbone/raw/`는 무시) 변환 결과만 `data/`에 둔다. 사용: `python backbone.py build all`.

| 종류 | 재료 | 결과 | 상태 |
| --- | --- | --- | --- |
| `Weakness` | CWE 5.0 XML | `data/cwe_catalog.json` | 완료(앞 절) |
| `Technique`, `Tactic` | ATT&CK Enterprise 20.1 | `data/attack_catalog.json` (334KB) | 기법 706(하위 479 포함), 전술 15, **폐기 기법 161개의 대체 ID 포함** |
| `MalwareFamily`, `ThreatActor` | ATT&CK 소프트웨어 842, 그룹 178 | 같은 파일 | 별칭, 쓰는 기법, 그룹이 쓰는 소프트웨어 포함 |
| `Vulnerability`(주목받는 부분집합) | CISA KEV(GitHub 사본, 2026.11.24) | `data/kev.json` (401KB) | 1,795건. 악용 확인된 CVE와 CWE, 랜섬웨어 사용 여부 |
| `ThreatActor` 별칭 보충 | MISP threat-actor 갤럭시 | `data/misp_threat_actors.json` (150KB) | 1,132개. **ATT&CK 그룹과 합치지 않고 따로 둠** |
| `Vulnerability`(전체) | CVE 레코드 | `backbone.lookup_cve` | **전체 목록은 못 받음.** 번호로 한 건씩 조회해 존재 확인, CWE, 제품 이름을 가져옴 |
| `Product` | NVD CPE 사전 | **없음** | NVD API가 이 환경에서 막혀 받지 못함. CVE 레코드의 vendor/product 이름만 가능 |

### 실제 파일로 확인한 것

- **`attack_mapping.load_catalog_from_stix`와 `load_software_map`이 실제 ATT&CK 번들에서 동작한다.** 이전에는 가짜 번들로만 시험했었다. 기법 706개(전체 867개에서 폐기·취소 161개를 뺀 값)가 나왔고, BPFDoor는 ATT&CK 소프트웨어 S1161로 기법 13개(T1205.002 포함)에 연결된다.
- **20.1 버전은 전술 이름이 바뀌었다.** 전술이 15개이고 `stealth`(TA0005)와 `defense-impairment`(TA0112)가 있다. 이전 버전의 `defense-evasion`을 가정한 코드나 사례는 맞지 않는다. 시험용 가짜 목록에는 `defense-evasion`이 남아 있으나 가짜 값이다. 버전이 바뀔 때마다 `BACKBONE_SNAPSHOTS["attack"]`를 확인해야 한다.
- **폐기된 기법 ID는 대체 ID로 안내한다**(`resolve_technique`: `link`, `replaced`, `review`). 폐기 161개 중 대체가 있는 것은 149개이다.
- **KEV는 실제 데이터로 CWE 판정 규칙을 시험해 준다.** KEV가 인용한 CWE 1,754건 중 **63건(3.6%)이 그룹**(예: CWE-264, CWE-310, CWE-255)이라 `review`로 가고, 397건은 `Discouraged`(포괄 항목)라 하위 번호 안내와 함께 `link_specific`으로 간다. CWE가 비어 있는 KEV 항목도 175건이다. 앞서 만든 "그룹은 연결하지 않고 사람 확인" 규칙이 실제로 필요하다는 근거이다.
- **CVE 레코드 조회**: CVE-2021-44228은 `PUBLISHED`, CWE 20, 400, 502, 제품 Apache Log4j2로 나왔고, 6자리 번호(CVE-2026-132224)도 폴더 규칙(`132xxx`)대로 조회된다. 없는 번호는 `exists: false`로 돌려준다.

### 알려진 한계

- **CVE 전체 목록이 없다.** 문서가 인용한 번호를 한 건씩 조회하는 방식이라 건당 네트워크 호출이 필요하고, 이 환경 밖에서 돌릴 때는 `cvelistV5` 전체를 받는 방식을 따로 정해야 한다.
- **CVE→CWE는 CVE 레코드의 `problemTypes`(CNA와 ADP)로 대신했다.** NVD의 CPE 매핑과 CVSS는 받지 못했다. NVD가 매긴 CWE와 CNA가 매긴 CWE는 다를 수 있어 둘을 구분해 보관한다.
- **KEV는 GitHub 사본**이다. 원본(`www.cisa.gov`)과 같은지는 확인하지 못했다.
- **MISP 갤럭시는 `main`에서 받았고 커밋 해시를 기록하지 못했다.** 재현이 필요하면 특정 커밋으로 고정해야 한다. MISP 행위자와 ATT&CK 그룹을 같은 행위자로 합치는 규칙은 정하지 않았다(합치기 오류 위험은 사건 해소와 같다).
- **ATT&CK은 Enterprise만 받았다.** ICS와 Mobile은 받지 않았다.
- **Mapping 결과의 정확성은 평가하지 않았다.** 이 절은 목록이 만들어졌고 형식대로 읽힌다는 것까지만 확인한다.
- 그래프에 넣는 코드(원본 `neo4j_v2.py`에 해당)와 임베딩 인덱스는 아직 없다.

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
| `kg_create/` | CVE, CWE, ATT&CK, KEV를 그래프로 바꾸는 코드를 새로 작성(`neo4j_v2.py` 대체). ATT&CK 번들에서 `attack_mapping.load_catalog_from_stix`로 목록을 만들 것 |
| 새 단계: 기법 매핑 | 추출 뒤, 연결 전에 서술형 행동마다 ATT&CK 후보를 AI로 제안받고 사람이 확인하는 단계를 새로 만든다(`attack_mapping.py`가 검증과 집계를 맡음) |
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
4. ~~**기법 수준.**~~ **반영됨(D5~D8)**: 서술형 행동을 먼저 기록하고 ATT&CK 매핑은 별도 단계(AI 제안 + 사람 확인), 비교는 전술 수준, 유도된 기법은 구분해서 표시(위 "기법 층").
5. ~~**날짜와 수치.**~~ **반영됨**: 날짜는 문서 단위 메타데이터(`headline_date`, `attack_span`, `document_date`)로 트리플렛 밖에 둔다. 수치는 별도 기록으로 정규화하고 출처별로 나란히 보여 준다(D9~D12, 위 "수치 층").
6. `RootCause` 시드 8개는 5개 사건의 검색 요약에서 일반화한 것이라 **전문가 검토가 필요하다.** 준비 작업으로 CWE 대응표와 경계 규칙·사례를 만들었다(위 "RootCause 시드 검토 자료"). CWE 5.0 파일로 대응표를 확인하고 고쳤다(320, 16 제외, 863 추가 등). 대응이 없거나 일부인 항목(조직 절차 수준)을 어떻게 다룰지는 전문가에게 묻는 질문으로 남아 있다.

## 자체 검사

```bash
python extraction/consts.py   # 설정의 일관성 검사
python aggregate.py           # 집계 규칙 자체 시험(13개)
python attack_mapping.py      # 기법 층 규칙 자체 시험(10개)
python incident_resolution.py # 사건 해소 규칙 자체 시험(11개)
python measurements.py        # 수치 층 규칙 자체 시험(9개)
python cwe_catalog.py         # CWE 목록 변환 규칙 자체 시험(9개)
python backbone.py            # 뼈대 변환 규칙 자체 시험(12개, 네트워크 없이)
```

`consts.py` 검사는 관계의 개체 종류 정의 여부, FILTERED ⊂ ALL, 닫힌 목록 종류의 연결 방법, `ANSWER_SLOTS`가 문서에서 받는 관계만 쓰는지 등을 확인한다.
