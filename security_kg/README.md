# 보안 사고 지식 그래프 설정 초안

ClimateKG 파이프라인을 보안 사고 분석에 적용하기 위한 `consts.py` 초안이다. 이 파이프라인으로 실행해 본 적이 없고, 분야 전문가의 검토도 받지 않았다.

## 질문 틀

> 사건 X에서 확인된 공격과 관련하여 다음을 분석한다.
>
> (a) **악용된 취약점**: 공격에 사용된 것으로 확인된 CVE 등 알려진 취약점은 무엇인가?
>
> (b) **보안 약점 및 관리 실패**: 공격을 가능하게 하거나 피해를 확대시킨 기술적 약점과 조직적 통제 실패는 무엇인가?
>
> (c) **공격 행동 및 기법**: 공격자가 실제로 수행한 행동은 무엇이며, MITRE ATT&CK의 어떤 기법에 해당하는가?
>
> 각 항목에 출처, 출처 유형, 확정·주장·추정 상태를 기록한다. 출처에 없는 사실은 추측하지 않는다.

(2026-11-27 전문가 검토 의견으로 문장을 보완했다. 세 칸의 구조는 유지한다. 칸의 역할: (a) CVE, NVD, KEV (b) CWE와 조직 통제(NIST CSF, SP 800-53) (c) ATT&CK. 같은 원인을 두 칸에 중복 집계하지 않는다: 패치를 안 한 사건이면 (a)는 실제 악용된 CVE, (b)는 패치 관리 실패, (c)는 공격자가 한 행동이다.)

대상 사건(초안): 레벨인피니트 CDN 해킹, SK텔레콤 유심 정보 유출, 2026 금융권 동시다발 해킹, 2026 Canvas 해킹(공식 문서를 구하지 못해 사실 확인표에서 제외, 미검증 예시), 2025 쿠팡 개인정보 유출.

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

개체 종류 14개(`Asset` 추가), 관계 19개(문서에서 받는 13개, 표준에서 오는 6개). 배후, 공격자 유형, **도용된 계정 소유자 유형**, **침해된 시스템**은 질문의 칸이 아니라 **참고 정보**다. 기후 버전은 개체 36종, 관계 75개였다.
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
- 구현: `aggregate.py`(`summarize_incident`, `render`). 자체 시험 14개가 위 규칙을 확인한다(묶음 합산, 기법 층 출력, 상태 이름 대응 포함).
- 문서 수를 세려면 문서 단위로 `incident_mentions`(사건 해소 절 참고), `document_date`, `source_type`을 추가로 뽑아야 한다(`consts.NEW_DOCUMENT_LEVEL_FIELDS`). 원본에는 없다.

### 칸 상태 5가지의 정의 (정답표 기준, 2026-11-27 전문가 검토 반영)

정답표(`fact_check/answer_key_draft.csv`)의 `slot_state`가 쓰는 값이다. 집계(`aggregate.py`)의 `found`는 `answered`, `not_mentioned`는 `not_mentioned_in_sources`에 대응한다(`consts.SLOT_STATE_ALIASES`, `aggregate.canonical_state`).

| 상태 | 의미와 사용 조건 |
| --- | --- |
| `answered` | 처리한 문서가 이 칸의 답을 제시함. assertion_status(confirmed, claimed, inferred)를 함께 붙인다 |
| `not_confirmed` | 관련 정보가 있으나 출처가 '조사 중', '확인하지 못함'이라고 말해 확정되지 않음 |
| `not_mentioned_in_sources` | 문서를 처리했으나 이 칸에 해당하는 언급이 없음. '없다'는 뜻이 아니다 |
| `not_applicable` | 출처가 이 질문이 이 사건에 해당하지 않는다고 직접 말함. 출처의 직접 진술이 있을 때만 쓴다 |
| `not_assessed` | 아직 이 칸을 평가하지 않았거나 문서를 처리하지 않음. 정답표를 만드는 도중의 상태 |

- `not_mentioned_in_sources`와 `not_confirmed`를 혼동하지 않는다. 앞의 것은 문서가 말하지 않은 것, 뒤의 것은 문서가 "확인 중"이라고 말한 것이다.
- `not_confirmed`는 집계 코드가 아직 표현하지 못해(아래 보류한 확장안의 `UNDISCLOSED`와 함께) 파일럿에서 도입한다. `not_applicable`과 `not_assessed`는 지금 정답표에 쓰인 행이 없다.

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
`EXISTS_UNIDENTIFIED`가 필요한 이유: Canvas처럼(미검증 예시) "취약점이 있었다고는 밝혔으나 CVE가 없는" 경우를 `Vulnerability`(CVE로 정의)로는 담을 수 없다.

## 공격자 유형: 내부자 표현 (옵션 B)

질문 틀 (a)(b)(c)에는 "누가"가 없다. 그러나 쿠팡 같은 사건에서 공격자가 전직 개발자라는 사실은 잃고 싶지 않다. 그래서 **참고 정보**로만 기록한다.

| 값(`ACTOR_ORIGIN_SEED`) | 뜻 |
| --- | --- |
| `INTERNAL` | 공격(접근) 시점에 피해 조직의 직원 또는 계약자 신분인 행위자 |
| `FORMER_INSIDER` | 공격 시점에는 퇴직·계약 종료 상태이며 **과거 조직 관계에서 얻은 권한·정보·접근 수단을 공격에 이용**한 행위자. 전직자라는 사실만으로 주지 않는다. **VERIS에서는 `External`**(actor.external.variety의 `Former employee`, 공식 스키마로 확인함) (우리가 추가한 값) |
| `PARTNER` | 협력사·공급사 등 외부 조직과의 정당한 업무 관계를 통해 접근한 행위자 |
| `EXTERNAL` | 피해 조직과 직접적인 정당한 업무 관계가 없는 행위자 |

- **속성이 아니라 "닫힌 값 목록을 가리키는 관계"로 둔 이유**: 파이프라인은 (출발, 관계, 도착) 트리플렛만 뽑는다. 사건의 속성으로 두면 근거 문장과 기존 검사 단계(형식, 출처, AI 재검증)를 받을 방법이 없다. 관계로 두면 근거 문장이 붙고 검사를 그대로 통과한다.
- **VERIS와의 관계(결정 1: 세분화를 유지하고 대응표를 둔다)**: `INTERNAL`/`EXTERNAL`/`PARTNER`는 VERIS의 최상위 행위자 구분(내부, 외부, 협력사)과 같은 이름 체계다. VERIS 위키의 행위자 설명은 **전직 직원을 외부(External) 위협의 예로 들고** 내부(Internal)는 현재 구성원으로 설명하며, **2026-11-27에 VERIS 공식 스키마(`vz-risk/veris`의 `verisc-merged.json`)로 확인했다**: 행위자 최상위는 `external`, `internal`, `partner`, `unknown`이고 `actor.external.variety`에 `Former employee`가 있다. 그래서 우리가 추가한 `FORMER_INSIDER`는 VERIS의 `External / Former employee`에 해당한다(`consts.ACTOR_ORIGIN_VERIS_VARIETY`). `python veris_check.py`가 같은 검사를 한다. 스키마 파일에는 버전과 커밋 해시가 없어 받은 날짜, 크기, sha256을 기록했다(`BACKBONE_SNAPSHOTS["veris"]`). 그래서 `consts.ACTOR_ORIGIN_TO_VERIS`로 대응표를 두어 VERIS 데이터와 비교할 수 있게 했다. 세분화된 값은 상위 값으로 합칠 수 있지만 합친 값은 다시 쪼갤 수 없어서 손실이 없는 쪽을 택했다. 주의: VERIS 위키 사본 페이지로 확인한 것이므로 정확한 값 목록은 VERIS 스키마 저장소로 대조해야 한다.
- **경계 규칙(결정 2)**: 유형은 **공격(접근)이 일어난 시점의 고용 상태**로 정한다(발견 시점이 아니다). 그 시점에 재직 중이었으면 `INTERNAL`(퇴사 직전의 오용 포함), 이미 퇴사했으면 `FORMER_INSIDER`. 문서에 시점이 없으면 추측하지 않고 `inferred`로 하거나 기록하지 않는다. 사례 6개는 `consts.ACTOR_ORIGIN_BOUNDARY_EXAMPLES`에 있고 프롬프트의 예시로 쓴다.
- **공격자와 계정 소유자는 별개다**(2026-11-27 반영): 외부 공격자가 협력사 직원의 계정을 탈취해 썼다면 공격자는 `EXTERNAL`이고 계정 소유자는 `PARTNER`다. 소유자는 `ACCOUNT_OWNER_ORIGIN` 관계(참고 정보 `account_owner_origin`)로 따로 기록하며 공격자 유형에 섞지 않는다. 협력사 직원 본인이 공격했으면 `PARTNER`. 시험 사례는 `ACCOUNT_OWNER_EXAMPLES`. 경계 사례 `ACTOR_ORIGIN_BOUNDARY_EXAMPLES`는 6개에서 8개로 늘었다(도용된 계정 사례를 `EXTERNAL`로 고치고, 협력사 직원의 직접 공격과 과거 접근을 쓰지 않은 전직자를 추가).
- **`UNKNOWN`은 값으로 두지 않는다.** 문서가 말하지 않은 것은 "언급 없음, 문서 n개"로 집계한다(부재를 추측하지 않는 원칙과 같다).
- **추론 금지**: 공격자의 국적, 위치, 수법의 정교함으로 유형을 추론하지 않는다. 쿠팡 사건의 "중국 국적"은 유형과 무관하다. 관계가 암시만 될 때는 `assertion_status`를 `inferred`로 한다.
- **이름 있는 행위자는 `ThreatActor`, 이름 없는 공격자는 `ActorOrigin`만 기록한다.** 둘은 같이 나올 수 있다(예: 이름 있는 외부 집단 = `ThreatActor` + `EXTERNAL`).
- **집계**: `consts.CONTEXT_FIELDS`(`actor_origin`, `attribution`)를 `aggregate.summarize_context`가 칸과 같은 규칙으로 보여 준다. 값이 여러 개(문서들이 다르게 말했거나 행위자가 둘 이상)면 "사람이 확인 필요"로 표시한다.
- **원인과의 관계**: 쿠팡 유형은 `HAS_ACTOR_ORIGIN = FORMER_INSIDER`와 `HAS_ROOT_CAUSE = CREDENTIAL_OR_KEY_MISMANAGEMENT`가 함께 나온다. 앞의 것은 "누구", 뒤의 것은 "왜 가능했나"이고 서로 대체하지 않는다.

**다중 행위자(결정 3: 사건 단위만 기록, 보류)**: 한 사건에 행위자가 둘 이상일 때 값과 행위자 이름을 짝짓는 일(`ACTOR_PAIRING = "incident_level"`)은 하지 않는다. 값이 여러 개면 `aggregate.py`가 "사람이 확인 필요"로 표시한다. 다섯 사건은 모두 공격자 서사가 하나로 보여서(검색 요약 기준, 미검증) 이 문제가 거의 생기지 않을 것으로 본다. **행위자별 질문("누가 무엇을 했나")이 실제로 필요하다고 확인될 때** 사건과 행위자 사이에 중간 개체를 두는 방식을 검토한다. 이 경우 같은 중간 개체를 여러 문서에서 합치는 문제(열린 설계 문제 3번)가 함께 생긴다.

미해결: 실제 문서가 공격 시점의 고용 상태를 분명히 쓰는지(파일럿에서 확인). (VERIS 스키마와의 대조는 2026-11-27에 끝났다.)

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
4. 문서마다 다른 시점(공개 시점 vs 침입 시점)을 쓴 경우: 한쪽의 **공격 기간이 다른 쪽의 시점을 포함하면 가깝다고 본다.** 이때 침입 단계로 보이는 이른 날짜는 ID 기준에서 뺀다(SK텔레콤 사례: 공개·유출 시점 2025-04, 공격 기간 2021-08~2025-04. 1차 자료인 과기정통부 2025-07-04 보도자료 기준이며, 최초 침투는 2021-08-06이고 2022-06은 추가 거점이다).
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
- **상태**: `documented`, `ai_suggested`(사람 확인 전), `human_confirmed`, `human_rejected`(답에서 제외), `no_match`(억지로 맞추지 않음). 유도된 기법은 `backbone_derived`로 따로 센다. `documented`(문서가 기법을 언급함)와 `human_confirmed`(사람이 매핑을 확인함)는 서로 다른 축이라 합치지 않는다.
- **뼈대 유도**: ATT&CK 소프트웨어 정보에서 악성코드 → 기법을 가져온다. 모르는 악성코드는 추측하지 않는다. 예: BPFDoor는 ATT&CK 소프트웨어(S1161)이고 Socket Filters 기법(T1205.002) 등과 연결된다(검색으로 확인).
- **전술 단위 집계**는 출처(문서가 쓴 것, 사람이 확인한 것, AI 제안, 뼈대 유도)별로 나눠서 센다. 서로 섞이지 않고, **같은 기법은 출처가 여럿이어도 가장 강한 하나만 센다**(`consts.TECHNIQUE_LABEL_PRIORITY`).

**2026-11-27 수정 (전문가 검토와 코드 재현으로 확인한 문제)**

| 문제 | 수정 |
| --- | --- |
| 문서가 쓴 기법(`documented`)을 출처의 확정 수준과 무관하게 확정으로 셈 | 출처의 `assertion_status`가 `confirmed`일 때만 확정. 아니면 `documented_unconfirmed`로 따로 셈 |
| 같은 기법이 여러 문서에 나오면 첫 기록만 남음(입력 순서에 따라 결과가 달라짐) | 문서마다의 주장(`claims`)을 모두 보존하고 최고 수준, 문서 수를 계산 |
| 사람이 확정한 하위 기법도 항상 상위로 올려짐(`specific`이 전달되지 않음) | 하위 기법은 근거(`specific_evidence`)가 있으면 유지, 없으면 상위로 올림 |
| 같은 기법을 가리키는 행동이나 출처가 여럿이면 전술 집계가 부풀려짐 | 기법마다 가장 강한 출처 하나만 셈 |
| 확정한 기법 ID가 ATT&CK 갱신으로 폐기되면 조용히 사라짐 | 대체 ID가 있으면 대체(`replaced_from_...`), 없으면 `stale` 항목으로 남기고 다시 확인하도록 표시 |
| 악성코드 별칭(예: JustForFun)으로 유도 기법을 못 찾음 | `software_map_from_catalog`가 이름과 별칭을 모두 키로 둠 |

- **근거 필드**: 후보와 기록에 `specific_evidence`(하위 기법을 고른 이유), `evidence_quote`(원문 근거), `evidence_strength`(`direct`, `implied`, `inferred`; AI `confidence`와 별개), 검토자(`reviewed_by`), 검토일(`reviewed_at`), `attack_version`을 둔다. 모르는 `evidence_strength`는 `inferred`로 낮춘다.
- **하위 기법 지침(전문가)**: "출처에서 하위 기법을 구별하는 구체적인 공격 대상·수행 방식·접근 경로 중 해당 하위 기법의 정의에 부합하는 행동이 직접 확인될 때만 하위 기법을 선택하고, 구별 근거가 부족하면 상위 기법까지만 매핑한다." 하위 기법마다 모든 상황에 적용되는 필수 조건 목록이 있다고 가정하지 않는다.
- **검토 역할(전문가 의견)**: 1차 분석가가 모든 후보를 검토하고, 중요하거나 논쟁적인 매핑은 2차 분석가가 교차 검토한다(초기 파일럿은 표본만). 운영 방식은 파일럿 뒤에 정한다.
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

열린 문제 6번(`RootCause` 시드가 내 일반화일 뿐이라는 점)의 **준비 작업**이다. 2026-11-27에 전문가 검토 의견을 반영해 시드가 8개에서 10개가 되었다(모니터링 시드에 하위 2개 추가). 전문가 검토를 대신하지 않는다. 설정은 `consts.py` 4-1절(`ROOT_CAUSE_CWE_MAP`, `ROOT_CAUSE_BOUNDARY_RULES`, `ROOT_CAUSE_BOUNDARY_EXAMPLES`)에 있다.

### CWE 대응표

| RootCause | 대응 | CWE (MITRE 매핑 구분) |
| --- | --- | --- |
| `UNPATCHED_KNOWN_VULNERABILITY` | partial | CWE-1395 (Allowed-with-Review), CWE-1104 (Allowed) |
| `CREDENTIAL_OR_KEY_MISMANAGEMENT` | partial | CWE-798 (Allowed-with-Review), CWE-324 (Allowed) |
| `INSUFFICIENT_ENCRYPTION` | close | CWE-311 (Discouraged), CWE-327 (Allowed-with-Review), CWE-326 (Allowed-with-Review) |
| `WEAK_ACCESS_CONTROL` | close | CWE-284 (Discouraged), CWE-862 (Allowed-with-Review), CWE-863 (Allowed-with-Review), CWE-306 (Allowed) |
| `INSUFFICIENT_MONITORING_DETECTION` | partial | CWE-778 (Allowed) |
| `INSUFFICIENT_LOGGING_AUDIT` | close | CWE-778 (Allowed) |
| `INSUFFICIENT_SECURITY_MONITORING_OPERATIONS` | none | - |
| `INADEQUATE_INCIDENT_RESPONSE` | none | - |
| `THIRD_PARTY_OR_SUPPLY_CHAIN_RISK` | partial | CWE-1395 (Allowed-with-Review), CWE-1357 (Allowed-with-Review) |
| `MISCONFIGURATION` | partial | CWE-1188 (Allowed) |

- **모든 CWE는 CWE 5.0 파일(2026-10-28, `cwec_v5.0.xml`)에서 이름, 상태, MITRE의 매핑 사용 구분을 확인했다.** 괄호 안이 그 구분이다: `Allowed`, `Allowed-with-Review`(검토 후 사용), `Discouraged`(포괄 항목이라 더 구체적인 하위 항목을 쓰라는 뜻). 이 파일은 사용자가 CWE 사이트에서 받은 공식 파일이며, 우리 변환 결과와 완전히 같음을 2026-11-26에 확인했다(확인-A4).
- **대응 정도**: `close`는 분명히 대응, `partial`은 일부만 맞음, `none`은 CWE에 대응이 없음이다.
- **의도적으로 뺀 CWE** (`ROOT_CAUSE_CWE_EXCLUDED`):
  - **CWE-320 (Key Management Errors)**: 그룹이고 폐기(Obsolete)이며 파일의 매핑 주석이 `Prohibited`이다. 멤버 약점 322, 323, 324, 798을 쓴다.
  - **CWE-16 (Configuration)**: 그룹이고 폐기이며 `Prohibited`이고 멤버 약점이 없다. 파일의 주석은 설정 오류를 "그 설정이 만든 행동의 약점"(접근 통제 계열 등)으로 매핑하라고 한다.
- **`Discouraged`인 311과 284**는 목록에 두되, 매핑할 때는 파일이 제안하는 하위 항목을 쓴다(311 → 312 저장, 319 전송 / 284 → 862, 863, 732, 306 등).
- 이 대응표는 **전문가 검토를 대신하지 않는다.** 번호가 존재하고 사용 가능하다는 것까지만 확인했고, 각 RootCause가 그 CWE로 충분히 설명되는지는 판단하지 않았다.

### 대응표에서 보이는 것

1. **RootCause는 두 수준을 섞고 있다.** `ENCRYPTION`, `ACCESS_CONTROL`, `LOGGING_AUDIT`은 제품의 기술 약점이라 CWE와 잘 맞는다(전문가 검토로 모니터링을 로깅과 관제 운영으로 나눈 뒤). 반면 `INADEQUATE_INCIDENT_RESPONSE`는 대응이 아예 없고 `UNPATCHED`, `CREDENTIAL`, `THIRD_PARTY`, `MISCONFIGURATION`은 일부만 맞는다. CWE는 **제품의 약점**을 다루고 이 항목들은 **조직의 운영·절차 실패**이기 때문이다.
2. 조직 수준 항목은 CWE가 아니라 NIST CSF 2.0과 SP 800-53에 대응시키기로 했다(아래 "표준 매핑 후보"). 억지로 CWE에 연결하지 않는다.
3. 질문 틀의 칸 (b)는 "약점·관리 실패"이므로 두 수준을 한 칸에 두는 것은 의도와 맞다. 다만 사건 간 비교에서 두 수준을 섞어 세지 않도록 표시를 달지는 정해야 한다(전문가에게 묻는 질문).

### 경계 규칙

원칙은 **문서가 말한 "실패한 통제"로 고르고 결과(피해)로 고르지 않는다**이다. 서로 다른 실패가 둘이면 값도 둘이고, 한 실패에 값을 둘 붙이지 않는다. 겹치는 쌍 10개의 규칙은 `ROOT_CAUSE_BOUNDARY_RULES`에 있다. 공통 부여 규칙은 `ROOT_CAUSE_ASSIGNMENT_RULES`.

- 키·자격 증명의 **수명주기** 실패 → `CREDENTIAL`, 권한의 범위·분리·인증 요구 부재 → `WEAK_ACCESS_CONTROL`
- 자기 시스템의 공개 패치 미적용 → `UNPATCHED`, 외부 공급사·협력사 침해 → `THIRD_PARTY`
- 침입을 못 알아챔 → `MONITORING` 계열, 알고도 대응 안 함 → `INCIDENT_RESPONSE`
- 탐지 실패만 말하고 이유를 말하지 않음 → 상위 `MONITORING`, 로그가 생성·보존되지 않았다고 말함 → `LOGGING_AUDIT`, 관제 인력·절차가 없다고 말함 → `SECURITY_MONITORING_OPERATIONS`
- 탐지 규칙이나 로그 설정이 잘못됨 → `MISCONFIGURATION`, 로그 기능 자체가 없음 → `LOGGING_AUDIT`
- 잘못된 설정·기본값 → `MISCONFIGURATION`, 통제 자체가 없음 → `WEAK_ACCESS_CONTROL`
- `ENCRYPTION`은 암호화가 없거나 약하다고 말할 때만

경계 사례 15개(`ROOT_CAUSE_BOUNDARY_EXAMPLES`)는 시드 10개를 모두 한 번씩 보이고, 한 문장에 실패가 둘인 경우, 피해만 말한 경우, 원인을 밝히지 않은 경우(기록하지 않음)를 포함한다. **문장은 규칙을 시험하려고 만든 가상 문장이며 실제 사건의 사실이 아니다.**

### 한계

- 경계 규칙은 내가 만든 것이고 실제 문서로 AI가 일관되게 따르는지는 확인하지 못했다. 사례는 프롬프트 예시와 사람 검토용이다.
- 시드에서 빠진 원인(피싱 교육, 백업, 물리 보안 등)은 이 작업으로 드러나지 않는다. 파일럿에서 `other`로 빠지는 값을 모아야 한다. 우리 정답표의 (b) 사실은 기존 시드로 설명되거나 "확정 전"이라 새 시드를 추가할 근거는 아직 없다(전문가도 파일럿 뒤에 추가하라고 했다).

### 시드의 계층과 파생 속성 (2026-11-27 전문가 검토 반영)

**모니터링 시드는 상위로 유지하고 하위 2개를 추가했다**(`ROOT_CAUSE_PARENT`). 전문가는 기존 시드를 지우고 둘로 바꾸라고 했지만, 결과만 적힌 사례는 어느 하위에도 배정할 수 없어 정보를 잃는다. 쿠팡 K13("이상 행위를 장기간 탐지하지 못했고 원인은 서술 없음")과 경계 예시 "침입자가 3년 동안 알려지지 않았다"가 그 예다. 상위 시드는 "탐지 실패는 확인되었으나 어느 통제의 실패인지 말하지 않음", 하위 시드는 출처가 직접 말할 때만 쓴다.

| 시드 | 성격(`failure_nature`) | 영역(`control_domain`) | 표시용 묶음 |
| --- | --- | --- | --- |
| `UNPATCHED_KNOWN_VULNERABILITY` | ORGANIZATIONAL_PROCESS_FAILURE | VULNERABILITY_MANAGEMENT | 취약점 관리 실패 |
| `CREDENTIAL_OR_KEY_MISMANAGEMENT` | ORGANIZATIONAL_PROCESS_FAILURE | IDENTITY_AND_ACCESS_MANAGEMENT | 자산·계정 관리 실패 |
| `INSUFFICIENT_ENCRYPTION` | TECHNICAL_CONTROL_FAILURE | DATA_PROTECTION | 기술적 통제 실패 |
| `WEAK_ACCESS_CONTROL` | TECHNICAL_CONTROL_FAILURE | IDENTITY_AND_ACCESS_MANAGEMENT | 기술적 통제 실패 |
| `INSUFFICIENT_MONITORING_DETECTION` | 미정 | SECURITY_MONITORING | 보안 운영 실패 |
| `INSUFFICIENT_LOGGING_AUDIT` | TECHNICAL_CONTROL_FAILURE | SECURITY_MONITORING | 기술적 통제 실패 |
| `INSUFFICIENT_SECURITY_MONITORING_OPERATIONS` | ORGANIZATIONAL_PROCESS_FAILURE | SECURITY_MONITORING | 보안 운영 실패 |
| `INADEQUATE_INCIDENT_RESPONSE` | ORGANIZATIONAL_PROCESS_FAILURE | INCIDENT_RESPONSE | 보안 운영 실패 |
| `THIRD_PARTY_OR_SUPPLY_CHAIN_RISK` | ORGANIZATIONAL_PROCESS_FAILURE | SUPPLY_CHAIN_SECURITY | 외부 의존성 관리 실패 |
| `MISCONFIGURATION` | TECHNICAL_CONTROL_FAILURE | CONFIGURATION_MANAGEMENT | 기술적 통제 실패 |

- **성격과 영역은 시드에서 파생되는 속성**이다. 문서에서 따로 뽑지 않아 추출 스키마와 프롬프트는 바뀌지 않고, 사람이 근거와 함께 사건 단위로 덮어쓸 때만 다른 값을 둔다(`ROOT_CAUSE_ATTRIBUTES`). 독립 필드로 뽑으면 같은 사건에서 시드와 모순되는 값이 생기고 CSF 카테고리와 세 갈래로 중복된다.
- **성격은 두 값**(기술 통제 실패, 조직 절차 실패)이다. 전문가가 제안한 `EXTERNAL_DEPENDENCY_FAILURE`는 실패의 성격이 아니라 실패가 일어난 위치라서 성격에 넣지 않았다(`THIRD_PARTY` 시드가 이미 그 위치를 나타낸다).
- **`display_group`**(전문가의 5개 상위 분류)은 화면 표시용이고 사건 간 비교 기준이 아니다.
- 성격이 미정(None)인 것은 하위가 있는 상위 시드뿐이다(추측하지 않는다).

### 표준 매핑 후보 (CWE, NIST CSF 2.0, SP 800-53 Rev. 5)

역할: **CWE는 기술적 약점, CSF는 조직의 위험관리 영역, SP 800-53은 구체적 통제, SP 800-61은 사고 대응 지침, ATT&CK는 공격자 행동**이다. 조직 절차 실패를 CWE에 억지로 연결하지 않는다.

| RootCause | CWE | NIST CSF 2.0 | SP 800-53 통제 | 부분 적합(참고) |
| --- | --- | --- | --- | --- |
| `UNPATCHED_KNOWN_VULNERABILITY` | CWE-1395, CWE-1104 | PR.PS-02 | SI-2, CM-3 | ID.RA-01, ID.RA-05, RA-5 |
| `CREDENTIAL_OR_KEY_MISMANAGEMENT` | CWE-798, CWE-324 | PR.AA-01 | IA-5 | - |
| `INSUFFICIENT_ENCRYPTION` | CWE-311, CWE-327, CWE-326 | PR.DS-01, PR.DS-02 | SC-8, SC-13, SC-28 | - |
| `WEAK_ACCESS_CONTROL` | CWE-284, CWE-862, CWE-863, CWE-306 | PR.AA-03, PR.AA-05, PR.IR-01 | AC-2, AC-3, AC-6 | - |
| `INSUFFICIENT_MONITORING_DETECTION` | CWE-778 | DE.CM, DE.AE | - | - |
| `INSUFFICIENT_LOGGING_AUDIT` | CWE-778 | PR.PS-04 | AU-2, AU-3, AU-12 | - |
| `INSUFFICIENT_SECURITY_MONITORING_OPERATIONS` | - | DE.AE-02, DE.AE-03 | SI-4, CA-7, AU-6 | - |
| `INADEQUATE_INCIDENT_RESPONSE` | - | RS.MA, RS.MI-01, RS.MI-02 | IR-4, IR-6, IR-8 | IR-5 |
| `THIRD_PARTY_OR_SUPPLY_CHAIN_RISK` | CWE-1395, CWE-1357 | GV.SC | SR-3, SR-5, SR-6, SA-9 | - |
| `MISCONFIGURATION` | CWE-1188 | PR.PS-01 | CM-2, CM-6, CM-7 | - |

- **2026-11-27 Taegyu가 후보 55개를 검토해 확정했다**(`mapping_status: confirmed`, `reviewed_by`, `reviewed_at`). 결과는 적합 42, 부분 적합 4, 부적합 9이고, **적합은 위 표의 CSF, 800-53 열에, 부분 적합은 "부분 적합(참고)" 열(`nist_partial`)에 두고 부적합은 뺐다.** 부분 적합은 기본 매핑으로 쓰지 않는 참고 후보다. 번호가 공식 목록에 실제로 있는지는 `nist_catalog.py`가 확인한다(CSF 2.0과 SP 800-53 Rev. 5.2.0의 OSCAL 목록, 철회된 항목은 거른다). **번호가 있다는 것은 적합하다는 뜻이 아니고, 적합 판정은 사람의 검토 결과다.**
- **부적합으로 뺀 9개**: CREDENTIAL의 PR.AA-03, PR.AA-05, AC-2, AC-6(WEAK_ACCESS_CONTROL에 더 가까움, 그쪽이 가짐), MISCONFIGURATION의 PR.IR-01(WEAK_ACCESS_CONTROL에 더 가까움)과 CM-3(UNPATCHED에 더 가까움, 그쪽이 가짐), OPERATIONS의 DE.CM-01, DE.CM-03, DE.CM-09("Monitoring에 더 가까움"). **결정(2026-11-27)**: 마지막 셋(DE.CM-01, 03, 09)을 상위 `INSUFFICIENT_MONITORING_DETECTION`의 후보로 **옮기지 않는다**. 상위 시드가 이미 `DE.CM` 카테고리 전체를 가지므로 세 항목을 포함하고, 세부 범주를 두면 이유를 말하지 않은 탐지 실패에 세부 원인을 암시하게 되기 때문이다. 부적합 판정은 기록으로 남긴다(같은 후보를 다시 붙이지 않도록). 사건 문서에서 세부 항목을 특정하는 원인이 반복해서 나오고 로깅이나 관제 운영이 아니면, 새 하위 시드를 만들면서 이 세 항목을 그 후보로 검토한다(파일럿에서 판단).
- 부분 적합 4개: UNPATCHED의 ID.RA-01, ID.RA-05, RA-5(패치 내용을 구성하는 단계에 불과함), INCIDENT_RESPONSE의 IR-5(대응 관련 내용이 명시적으로 표현되어 있지 않음).
- 전문가 후보의 범위 표기(`GV.SC-01~10`, `RS.MA-01~05`)는 구별하는 힘이 없어 카테고리 단위(`GV.SC`, `RS.MA`)만 두었다. 800-53은 패밀리(`AC`)가 아니라 개별 통제 ID만 허용한다.
- SP 800-61 Rev. 3는 통제 목록이 아니라 지침 문서라 번호 검증 대상이 아니며, 제목과 버전은 미검증이다.
- 한 곳에서 보려면 `consts.root_cause_standard_view(시드)`.
- **적합성 검토표**: `data/nist_candidate_review.csv`(후보 55행)는 각 후보의 공식 제목과 설명문, 같은 번호를 쓰는 다른 RootCause, 사람의 판정(`judge_fit`: `적합`, `부분 적합`, `부적합`)과 메모(`judge_note`)를 담은 **판정 기록**이다. 행 번호(`행`)는 엑셀 행 번호와 같다. 대응표와 이 기록이 어긋나지 않는지는 `python nist_catalog.py`가 검사한다. 집계는 `python nist_catalog.py --tally-review data/nist_candidate_review.csv`. **판정이 들어 있으면 `--review-sheet`는 덮어쓰지 않는다**(`--force`로만). 판정은 사람의 결정이라 `data/`에 둔다(`backbone/export/`는 저장소에서 제외된 결과물 폴더).

## `Weakness` 닫힌 목록: CWE 목록 변환 (`cwe_catalog.py`)

`Weakness`는 CWE 번호로만 연결하는 닫힌 종류다. 목록의 재료는 MITRE의 CWE 전체 XML이다. 작은 일부(예: Top 25)로 한정하면 문서가 인용한 CWE가 25개 밖일 때 연결에 실패해 사실이 버려지므로 **전체 목록**을 쓴다.

- `python cwe_catalog.py <cwec.xml>`이 XML에서 가벼운 목록 `data/cwe_catalog.json`(약 360KB)을 만든다. 원본 XML(18MB)은 올리지 않는다. 설명문은 뺐고 이름, 추상화 수준, 상태, 매핑 사용 구분, 제안, 부모만 둔다.
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
| `Technique`, `Tactic` | ATT&CK Enterprise 20.1 | `data/attack_catalog.json` (600KB) | 기법 706(하위 479 포함), 전술 15, **폐기 기법 161개의 대체 ID 포함** |
| `MalwareFamily`, `ThreatActor` | ATT&CK 소프트웨어 842, 그룹 178 | 같은 파일 | 별칭, 쓰는 기법, 그룹이 쓰는 소프트웨어 포함 |
| `Vulnerability`(주목받는 부분집합) | CISA KEV(GitHub 사본 `cisagov/kev-data`, 2026.11.25) | `data/kev.json` (1.1MB) | 1,805건(2026-11-27 갱신, 공식 CSV와 같음). 악용 확인된 CVE와 CWE, 랜섬웨어 사용 여부 |
| `ThreatActor` 별칭 보충 | MISP threat-actor 갤럭시 | `data/misp_threat_actors.json` (220KB) | 1,132개. **ATT&CK 그룹과 합치지 않고 후보로만 제시** (`actors.py`) |
| `Vulnerability`(전체) | CVE 레코드 | `backbone.lookup_cve` | **전체 목록은 못 받음.** 번호로 한 건씩 조회해 존재 확인, CWE, 제품 이름을 가져옴 |
| `Product` | NVD CPE 사전 | **없음** | NVD API가 이 환경에서 막혀 받지 못함. CVE 레코드의 vendor/product 이름만 가능 |

### KEV의 CWE: 출처별로 보관 (`enrich-kev`)

KEV의 `cwes`는 CISA가 붙인 값이고, 같은 CVE의 CVE 레코드에는 발급 기관(CNA)과 CISA의 보강 정보(ADP)가 따로 CWE를 붙인다. 셋은 다를 수 있어서 **합치지 않고 출처별로 담는다.**

- `python backbone.py enrich-kev`가 KEV 1,805건을 CVE 레코드와 대조해 `kev.json`에 항목을 더한다(처음에 약 40초, 레코드는 `backbone/raw/cve/`에 캐시).
- 항목: `cwe_by_source`(`kev`, `cna`, `adp`: 제공자별), `cwe_display`와 `cwe_display_source`(보여 줄 대표값과 그 출처), `cwe_conflict`(출처끼리 값이 다른가), `cve_record`(`found`, `missing`, `error`, `not_checked`).
- **대표값 규칙은 `CNA → ADP → KEV` 순서의 기본값**이다(`CWE_DISPLAY_ORDER`). 보관은 출처별이라 규칙을 바꿔도 다시 받을 필요가 없다.
- 약점 분류가 어디에도 없으면 `cwe_display_source`가 `none`이다. "아직 안 채움"이 아니라 "분류된 적 없음"이다. 부재를 추측하지 않는다.

**2026-11-25 기준 결과**:

| 항목 | 건수 |
| --- | --- |
| 레코드 조회 | 찾음 1,805, 없음 0 (2026-11-25 기준으로는 1건이 없었는데 그 CVE-2026-132165의 레코드가 이후 올라와 2026-11-27 갱신에서 찾음) |
| 대표값 출처 | CNA 727, ADP 863, KEV만 106, **없음 109** |
| **출처끼리 값이 다른 건** | **233 (12.9%)** (2026-11-25 기준 232건에서 1건 늘었다: CVE-2026-132165의 레코드가 새로 조회되어 CNA와 KEV가 다름) |

- 다른 233건 중 196건은 **ADP와 KEV의 차이**이고(둘 다 CISA 쪽 정보인데도), 32건은 CNA와 KEV, 5건은 셋 모두 있다. 233건 중 68건은 한쪽이 다른 쪽의 일부(예: KEV `CWE-456`, ADP `CWE-123, CWE-456`)이고 165건은 서로 겹치지 않는 값이 있다.
- **어느 쪽이 맞는지는 판단하지 않았다.** 차이가 나는 이유(갱신 시점, 기준 차이 등)도 확인하지 못했다.
- `python backbone.py export`의 `kev.csv`에 출처별 열이 들어간다.

**충돌 검토용 표본 (`kev_conflict_sample.py`, 기본값-C1)**: 충돌 233건을 대표값과 다른 출처의 관계로 분류한다(`subset` 한쪽이 다른 쪽의 일부 68건, `hierarchy` 상하위 74건, `unrelated` 서로 무관 91건; 사람이 판정한 표본은 2026-11-26의 232건에서 뽑았다). 어느 쪽이 맞는지는 판단하지 않는다. 사람이 볼 표본 30건(무관 20, 상하위 5, 일부 5, seed 고정)을 `backbone/export/kev_conflict_sample.csv`에 만들고 `judge_correct`, `judge_note` 칸을 비워 둔다. 전체 분류는 `kev_conflicts_all.csv`. 대표값이 CNA인 경우는 37건, ADP인 경우는 196건이다.

**판정 결과 (표본 30건, 사람이 판정)**: `python kev_conflict_sample.py --tally data/kev_conflict_judgement.csv`로 집계한다. 판정은 `data/kev_conflict_judgement.csv`에 있다(`backbone/export/`는 `.gitignore`에 있어 결과물만 두는 폴더라 사람의 판정은 `data/`에 둔다).

| 유형 | 건수 | 규칙과 일치 | 판정 |
| --- | --- | --- | --- |
| A Red Hat(제3자 ADP)만 다름 | 5 | 4 | cna 3, 판단 불가 1, 둘 다 맞음 1 |
| B CNA가 대표, KEV 다름 | 5 | 3 | cna 3, kev 2 |
| C CISA-ADP가 대표, KEV 다름 | 20 | 16 | adp 16, kev 2, 판단 불가 2 |

- 규칙과 다른 7건(엑셀 행 5, 8, 12, 14, 19, 24, 25)은 모두 KEV가 맞다고 본 4건이거나 판단 불가 3건이다. CNA와 ADP 사이의 순서(CNA가 ADP보다 앞)를 뒤집는 판정은 없었다.
- KEV가 맞다고 본 4건 중 12행과 25행은 CISA-ADP가 대표인 경우, 5행과 14행은 CNA가 대표인 경우다. 25행은 KEV가 CWE를 두 개(259 + 78) 달고 있어 대표값이 정보를 덜 담은 사례다.
- **표본이 30건이라 규칙을 바꿀 근거로는 부족하다.** 일치 77%이고 KEV를 앞세우면 나아지는 방향의 증거가 없어 현재 순서를 유지하는 쪽을 권한다. 결정은 Taegyu가 한다.


### 행위자 이름 연결 (`actors.py`, 설정은 `consts.py`의 `ACTOR_NAME_LINKING`, `ACTOR_ALIAS_SEED`, `ACTOR_NEW_NODE_POLICY`)

같은 행위자를 업체마다 다른 이름으로 부르고(Kimsuky, Velvet Chollima, Thallium, 김수키), 한 별칭이 서로 다른 행위자에 쓰이기도 한다. 이름 문자열만으로 합치면 사건 해소에서 본 것과 같은 **잘못된 합치기**가 생기므로 **정확히 일치할 때만 연결하고 나머지는 사람이 확인한다.** MISP는 연결에 쓰지 않고 후보로만 제시한다(옵션 A).

**조회 순서** (`lookup_actor`, 대소문자와 공백만 무시한 정확한 일치. 부분 일치와 비슷한 이름은 쓰지 않음):

| 순서 | 조건 | 판정 |
| --- | --- | --- |
| 1 | ATT&CK 그룹 한 곳의 이름이나 별칭과 일치 | `link` |
| 2 | ATT&CK 그룹 둘 이상에 일치 | `review`(모호, 새 노드를 만들지 않음) |
| 3 | **별칭 사전**(`ACTOR_ALIAS_SEED`)에 있음 | `link`(사람이 확인한 별칭만 들어 있음) |
| 4 | ATT&CK 소프트웨어(악성코드, 도구)의 이름과 일치 | `review`(행위자가 아니라 종류 오류일 수 있음) |
| 5 | MISP에만 일치 | `review`(후보 제시, 합치지 않음) |
| 6 | 어디에도 없음 | `none` |

**새 노드 계획** (`plan_actor`, 결정 5):

- 연결되면 새 노드가 없다. 모호하거나 소프트웨어 이름이면 **노드를 만들지 않고** 사람 확인으로 보낸다.
- 5, 6번(MISP에만 있거나 어디에도 없음)은 `ThreatActor` 노드를 만들되 **`origin: document_added`, `status: pending_review`** 로 표시해 표준(ATT&CK)에서 온 노드와 구분한다.
- **이름 유사도로 자동 합치지 않는다**(원본의 합치기를 이 종류에는 쓰지 않음). 같은 철자(대소문자와 공백만 무시)로 여러 문서에서 나온 것만 한 대기 항목으로 묶는다(`consolidate_pending`). `Unknown Crew`와 `Unknown Crews`는 묶지 않는다.
- AI가 영문명을 제안하면(`ai_english_name`) 같은 조회를 해서 `ai_suggestion`으로만 붙이고 **연결하지 않는다.** 상태는 `ai_suggested`(사람 확인 전)이다.
- **별칭 사전**은 사람이 확인한 한국어 표기, 줄임말만 넣는다. 현재 3개 그룹(Kimsuky, Lazarus Group, Andariel)의 시드가 있으나 **제 일반 지식으로 만든 후보이고 이 세션에서 확인하지 않았다.** 사용 전에 사람이 확인해야 하고, 사람이 확정한 별칭을 계속 추가하는 방식으로 키운다. `validate_alias_seed`가 그룹 ID와 이름이 ATT&CK 목록과 맞는지 점검한다.
- `python actors.py "김수키"`로 한 이름의 계획을 보고, `python actors.py review`로 MISP와 ATT&CK 별칭 겹침 CSV(`backbone/export/actor_alias_candidates.csv`)를 만든다.

**실제 데이터로 확인한 것**:

| 이름 | 결과 |
| --- | --- |
| `Kimsuky`, `Hidden Cobra` | ATT&CK 별칭으로 연결(G0094, G0032) |
| `김수키`, `라자루스`, `Lazarus`, `안다리엘` | 별칭 사전으로 연결(G0094, G0032, G0032, G0138) |
| `BPFDoor` | 악성코드 이름이라 새 행위자 노드를 만들지 않고 확인(`matches_software`) |
| `APT45` | ATT&CK에는 없고 MISP에만 있어 후보를 제시하고 확인 대기 노드 |
| `솔트 타이푼`(AI 영문명 `Salt Typhoon`) | 확인 대기 노드, ATT&CK G1045를 `ai_suggested`로만 제안 |
| `솔트 타이푼`(AI 영문명 `Salt Typhon`, 철자 오류) | 확인 대기 노드, 제안 없음(정확 일치가 아니라서) |
| `완전히 새로운 해커 조직` | 확인 대기 노드 |

MISP 1,132개 중 ATT&CK 그룹과 별칭이 겹치는 것은 정확히 한 그룹이 173개, 둘 이상이 11개, 겹치지 않는 것이 948개이다. **이름 범위가 출처마다 다른 실제 사례**도 있다. `Andariel`은 ATT&CK에서 독립 그룹(G0138)이고 MISP에서는 Lazarus Group의 별칭이며, MISP의 Lazarus Group 항목은 ATT&CK 그룹 다섯 개와 별칭이 겹친다. 합치기로 정했다면 서로 다른 그룹이 섞였을 것이다.

### 알려진 한계

- **별칭 사전이 작고 확인되지 않았다.** 한국어 표기가 얼마나 많은지는 실제 문서를 봐야 안다. 사전에 없는 한국어 이름은 모두 확인 대기 노드가 된다.
- **정확 일치뿐이다.** 철자 변형, 오타, 다른 언어 표기, 줄임말은 사전에 있어야만 연결된다. 비슷한 이름을 자동으로 찾는 기능은 일부러 넣지 않았다.
- 새 노드가 쌓이면 사람이 확인할 대기열이 커진다. 처리 절차는 아래 "확인 대기열 처리"에 있으나 화면은 없고 CSV 시트로 한다.
- **AI 프롬프트는 초안이고 실제 모델로 시험하지 않았다.** 이 저장소에는 AI 호출 코드가 없어, 응답이 형식대로 나오는지는 확인하지 못했다.

### 확인 대기열 처리 (`actor_review.py`, 결정 저장소는 `data/actor_decisions.json`)

`actors.consolidate_pending`이 만든 확인 대기 항목을 사람이 처리하는 절차다. 화면은 없고 CSV 시트로 한다.

1. **시트 만들기**: `python actor_review.py sheet pending.json sheet.csv`. 이름, 나온 문서, 사유, 후보(ATT&CK, MISP, 소프트웨어), AI 제안이 나오고 `decision`과 `note` 칸이 비어 있다.
2. **사람이 `decision` 칸을 채운다**: `link:G0094`(이 이름은 그 ATT&CK 그룹의 별칭), `new`(ATT&CK에 없는 새 행위자가 맞음), `reject`(행위자가 아님. `reject:malware`처럼 종류를 적으면 그 종류로 다시 보냄), 빈칸(미결정).
3. **반영**: `python actor_review.py apply sheet.csv --by 이름`. 누가 확인했는지(`--by`)와 날짜를 기록한다. **잘못된 칸은 반영하지 않고 이유를 알려 준다**: 없는 그룹 ID, 이미 ATT&CK 이름·별칭과 일치, 이미 다른 그룹의 별칭, 읽을 수 없는 값. 다시 반영해도 중복되지 않는다.
4. **효과**: 확정한 별칭은 별칭 사전에 더해져 다음부터 자동으로 연결되고(`plan_actor(decisions=...)`), `new`는 노드 상태가 `pending_review`에서 `confirmed_new`로 바뀌고, `reject`는 `rejected`로 새 노드를 만들지 않는다. 결정이 있어도 ATT&CK에 정확히 일치하면 연결이 우선한다.

**스냅샷을 갱신했을 때 옮기기**: `backbone.py build`로 ATT&CK을 새로 받은 뒤 `python actor_review.py migrate [pending.json]`을 실행한다. 확인 대기와 확정 새 행위자 이름이 이제 ATT&CK에 정확히 일치하는지(`now_in_attack`), 모호해졌는지(`ambiguous_now`), 별칭 사전의 그룹이 새 스냅샷에서 사라졌거나 이름이 바뀌었는지(`group_missing_in_snapshot`, `group_renamed`)를 보고서로 보여 준다. **자동으로 옮기지 않는다.** `apply_migration`으로 사람이 승인한 이름만 `migrated`에 기록하고 `confirmed_new`에서 뺀다.

**AI 영문명 프롬프트** (`consts.ACTOR_NAME_EXTRACTION_PROMPT`)와 응답 검증(`parse_ai_name_response`): 프롬프트는 원문 이름을 그대로 베끼게 하고, 확신이 없으면 영문명을 `null`로 두게 하며, 악성코드·도구 이름은 `threat_actor`가 아닌 종류로 표시하게 한다. 응답 검증은 형식, 종류(악성코드는 행위자가 아님), 원문에 이름이 있는지(문서 텍스트를 주면)를 점검하고, 영문명이 문자열이 아니면 버린다. 영문명은 `plan_actor`가 ATT&CK과 대조해 `ai_suggested` 후보로만 쓴다.

**실제 데이터로 확인한 것**: `솔트 타이푼`(AI 제안 `Salt Typhoon → G1045`)을 `link:G1045`로, `APT45`를 `new`로, `BPFDoor`를 `reject:malware`로 결정해 반영하면 `plan_actor`가 각각 연결, `confirmed_new` 노드, 행위자 노드 없음으로 바꾼다. 미결정 항목은 `pending_review`로 남는다.

### 한계 (확인 대기열 처리)

- 화면이 없고 시트를 사람이 직접 편집한다. 결정 저장소는 JSON 파일이라 동시에 여러 사람이 편집하는 경우는 다루지 않는다.
- 이 절의 모든 시험은 가짜 데이터와 소수의 실제 이름으로만 했다. 실제 문서에서 나온 대기열로 돌려 본 것이 아니다.
- 그래프(Neo4j)에 노드를 넣거나 옮기는 코드는 이 저장소에 없다. 여기서 말하는 노드는 계획 기록이고, 옮김 기록(`migrated`)은 그래프에 반영하는 단계가 따로 있어야 의미가 있다.
- `migrate`는 이름이 정확히 일치하는 경우만 찾는다. 이름이 바뀐 그룹이나 별칭이 다른 그룹으로 옮겨진 경우는 별칭 사전 점검(`group_renamed`)이 일부만 잡는다.

### 확인용 CSV

`data/*.json`은 들여쓰기로 저장한다(저장소에서 바로 읽히고, 갱신할 때 `git diff`가 바뀐 줄만 보여 준다). 훑어보고 정렬·검색하려면 CSV가 편하다.

```bash
python backbone.py export    # security_kg/backbone/export/ 에 CSV 9개 (저장소에는 올리지 않음)
```

`attack_techniques`, `attack_tactics`, `attack_software`, `attack_groups`, `attack_replaced_techniques`, `kev`, `misp_threat_actors`, `cwe_weaknesses`, `cwe_groupings`. 엑셀에서 한글이 깨지지 않도록 BOM이 붙은 UTF-8이다. 중첩된 목록(별칭, 기법)은 `; `로 이어 한 칸에 쓰므로 정보가 일부 줄어든다. JSON에서 언제든 다시 만들 수 있다.

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
- **MISP 갤럭시 출처 기록(2026-11-27)**: 받은 파일의 sha256 `5bffee604295…`이 `MISP/misp-galaxy`의 `main`(커밋 `779b780a13f6…`)의 같은 파일과 **내용이 같음을 확인**해 `data/misp_threat_actors.json`의 `source`에 기록했다. 이 파일을 마지막으로 바꾼 커밋은 아니며, `main`이 바뀌어 같은 파일이 달라지면 이 커밋으로 고정해 재현한다. `python backbone.py build`는 이제 KEV, MISP, ATT&CK를 받을 때마다 주소, 크기, sha256, 받은 날짜와 (확인되면) 커밋을 `source`로 남긴다. MISP 행위자와 ATT&CK 그룹은 합치지 않는다(옵션 A, 아래 "행위자 이름 연결").
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

> 이 표의 사실을 1차 자료와 대조하는 확인표가 `fact_check/incident_facts.csv`에 있다(`fact_check/README.md` 참고). 확인하기 전에는 평가용 정답으로 쓰지 않는다. **SK텔레콤 행은 1차 자료(과기정통부 2025-07-04, 개인정보위 2025-08-28 보도자료)와 대조했다**(`fact_check/drafts/S_SK텔레콤_대조초안.md`). 이 표의 SK텔레콤 행은 대조 전 값이고, 대조로 바뀐 것은 공격 기간(최초 침투 2021-08-06)과 더티카우 CVE 번호의 근거(본문이 아니라 도판) 등이다. 나머지 사건은 아직 대조하지 않았다.

| 사건 | (a) 취약점 | (b) 약점·관리 실패 | (c) 기법 |
| --- | --- | --- | --- |
| 레벨인피니트 | 미공개 | 명시 없음 | CDN 스크립트 변조(공급망), 원격 제어 악성코드 |
| SK텔레콤 | 더티카우(CVE-2016-5195로 알려짐) | 패치 미적용, 계정정보 관리 부실, 암호화 미흡, 과거 침해 대응 미흡 | 웹쉘, BPFDoor |
| 금융권 | 확인 못 함 | 확인 못 함 | AI 침투 도구 분석(업체 주장, 미확정). 모바일 조회·업무지원 시스템 등은 기법이 아니라 침해된 자산 |
| Canvas (미검증 예시, 확인표에서 제외) | Free-for-Teacher 취약점(세부 미공개, CVE 없음) | 미공개 | 취약점 악용, 로그인 포털 변조, 갈취 |
| 쿠팡 | 없음 | 서명키 미폐기(키 관리 실패) | 서명키 탈취, 전자 출입증(토큰) 위조 |

이 표에서 CVE 번호로 답할 수 있는 칸은 SK텔레콤 한 곳뿐이다. 다른 사건은 `HAS_ROOT_CAUSE`와 `USED_TECHNIQUE`가 중심이 된다.

## 열린 설계 문제

1. ~~**"취약점 없음/미공개"를 어떻게 기록하나.**~~ **1단계(최소안) 반영됨**: 부재를 추측하지 않고 "언급 없음, 문서 n개"로 집계한다(위 "답의 집계"). "미공개"와 "언급 없음"을 구분하는 확장안은 파일럿 뒤로 보류.
2. ~~**내부자 여부.**~~ **반영됨(옵션 B)**: `ActorOrigin` 시드 4개와 `HAS_ACTOR_ORIGIN`을 참고 정보로 추가. 경계 규칙(공격 시점의 고용 상태), VERIS 대응표, 다중 행위자 보류까지 결정됨(위 "공격자 유형").
3. ~~**같은 사건을 여러 문서가 쓸 때 `Incident`를 합치는 규칙**이 없다.~~ **반영됨(D1~D4)**: 조직 단위 `Incident` + `Campaign`, 같은 조직 필수 + 공개 시점 + 공유 신호, 애매하면 사람 확인(위 "사건 해소"). 숫자는 파일럿에서 보정.
4. ~~**기법 수준.**~~ **반영됨(D5~D8)**: 서술형 행동을 먼저 기록하고 ATT&CK 매핑은 별도 단계(AI 제안 + 사람 확인), 비교는 전술 수준, 유도된 기법은 구분해서 표시(위 "기법 층").
5. ~~**날짜와 수치.**~~ **반영됨**: 날짜는 문서 단위 메타데이터(`headline_date`, `attack_span`, `document_date`)로 트리플렛 밖에 둔다. 수치는 별도 기록으로 정규화하고 출처별로 나란히 보여 준다(D9~D12, 위 "수치 층").
6. `RootCause` 시드 8개는 5개 사건의 검색 요약에서 일반화한 것이라 **전문가 검토가 필요하다.** 준비 작업으로 CWE 대응표와 경계 규칙·사례를 만들었다(위 "RootCause 시드 검토 자료"). CWE 5.0 파일로 대응표를 확인하고 고쳤다(320, 16 제외, 863 추가 등). 대응이 없거나 일부인 항목(조직 절차 수준)을 어떻게 다룰지는 전문가에게 묻는 질문으로 남아 있다. **2026-11-27 전문가 검토 의견을 반영했다**(모니터링 시드의 계층화, 성격·영역 속성, 표준 매핑 후보, 공격자와 계정 소유자 분리, 상태값 5가지).

## 확인 체크리스트 (파일럿 전에 사람이 확인할 것)

이 문서의 설계 결정 `D1~D12`(예: D4 연속 파동)와 번호가 겹치지 않도록, 체크리스트 항목은 **분류 이름을 앞에 붙여** 부른다.
예: `운영-D4`(정답 데이터를 누가 만드는지)와 설계 결정 `D4`(연속 파동)는 다른 항목이다.

| 분류 | 번호 | 뜻 |
| --- | --- | --- |
| **확인** | 확인-A1~A5 | 제가 검증하지 못한 사실과 데이터 |
| **전문가** | 전문가-B1~B5 | 보안 전문가의 판단이 필요한 것 |
| **기본값** | 기본값-C1~C5 | 이미 정한 기본값의 재검토 |
| **운영** | 운영-D1~D5 | 팀이 정해야 하는 운영 결정 |

상태는 확인한 것만 적었다. "—"는 아직 이 표에서 확인하지 않았다는 뜻이다.

### 확인 (사실과 데이터)

| 번호 | 확인할 것 | 상태 |
| --- | --- | --- |
| 확인-A1 | 사건의 핵심 사실을 1차 자료로 확인 | **완료(2026-11-26)**: `fact_check/incident_facts.csv` 75행을 Taegyu가 확인. 네 사건(레벨인피니트, SK텔레콤, 금융권, 쿠팡). **Canvas는 공식 문서가 없어 제외**. 미확인 항목은 각 행의 note에 있음 |
| 확인-A2 | 별칭 사전(한국어 표기 3개 그룹, `ORG_ALIAS_SEED` 7개 조직)이 같은 대상을 가리키는지 | **검토표 준비 완료(2026-11-27), 판정 대기.** `data/alias_review.csv`(16행: 행위자 4, 조직 12)에 별칭마다 ATT&CK 그룹 별칭에 있는지, 다른 그룹도 쓰는지, MISP가 어떤 그룹을 묶는지, 사실 확인표에서 쓰인 횟수를 붙였고 `judge_same` 칸(`같음`, `일부만 같음`, `다름`, `판단 불가`)이 비어 있다. **한국어 표기는 표준에 없어 한국 기사나 보안 업체 보고서로 사람이 확인해야 한다.** 집계와 사전 일치 검사는 `python alias_review.py` |
| 확인-A3 | VERIS 대응(`ACTOR_ORIGIN_TO_VERIS`)을 공식 스키마와 대조 | **완료(2026-11-27)**: 공식 스키마의 행위자 최상위(`external`, `internal`, `partner`, `unknown`)와 `actor.external.variety`의 `Former employee`를 확인. `python veris_check.py`로 다시 확인 가능 |
| 확인-A4 | 내려받은 데이터가 최신인지(CWE 버전 표기, KEV와 MISP의 출처 기록) | **완료(2026-11-27).** CWE: 사용자가 받은 공식 `cwec_v5.0.xml`(버전 5.0, 2026-10-28)을 변환한 결과가 `data/cwe_catalog.json`과 **완전히 같음**. KEV: 사본(2026-11-24, 1,795건)이 공식 CSV와 같았고 2026-11-25에 추가된 10건을 반영해 **1,805건(catalogVersion 2026.11.25)으로 갱신**, 공식 CSV와 번호와 CWE가 모두 같음. MISP: sha256과 커밋(`779b780a13f6…`에서 내용 같음)을 기록. KEV는 `cisagov/kev-data` develop의 `51e0a777743f…`에서 내용이 같음. 출처는 각 데이터 파일의 `source` 키와 `consts.BACKBONE_SNAPSHOTS`에 있다 |
| 확인-A5 | 이 환경에서 받지 못한 것(CVE 전체 목록, NVD) | — |

### 전문가 (판단이 필요한 것)

| 번호 | 물어볼 것 |
| --- | --- |
| 전문가-B1 | `RootCause` 시드(현재 10개, 처음 8개에서 모니터링 하위 2개 추가)가 쓸 만한 분류인가, 빠진 원인은 없는가 |
| 전문가-B2 | 조직 절차 실패는 CWE에 대응이 없는데 어떤 표준에 대응시킬까 |
| 전문가-B3 | `ActorOrigin` 경계(전직자 세분, "공격 시점의 고용 상태") |
| 전문가-B4 | 질문 틀 (a)취약점 (b)약점·관리 실패 (c)기법이 분석 목적에 맞는가 |
| 전문가-B5 | AI가 제안한 ATT&CK 매핑을 누가 확인하나(설계 결정 D6) |

### 전문가 검토 결과 반영 (2026-11-27)

| 번호 | 전문가 판단 | 반영 |
| --- | --- | --- |
| 전문가-B1 | 시드 8개 유지, 모니터링은 분리 권고, 상위 분류 재설계 | **수정 반영**: 모니터링은 대체하지 않고 상위 유지 + 하위 2개(정보 손실을 피하려고 전문가안에서 변경). 성격과 영역은 시드에서 파생. 새 원인은 파일럿 뒤 |
| 전문가-B2 | CWE 유지 + NIST CSF 2.0, SP 800-53 추가 | **반영 완료**: `ROOT_CAUSE_STANDARD_MAP`, `nist_catalog.py`로 번호 존재 확인. **후보 55개를 Taegyu가 검토해 확정(2026-11-27: 적합 42, 부분 적합 4, 부적합 9)**, 부적합 9개는 뺐다. 상위 MONITORING으로 옮기지 않기로 결정(DE.CM-01, 03, 09, 상위의 DE.CM 카테고리가 이미 포함) |
| 전문가-B3 | 4값 유지, 공격자와 계정 소유자 분리, VERIS `Former employee` | **반영**: `ACCOUNT_OWNER_ORIGIN`, 사례 수정과 추가. VERIS 세부 대응은 공식 스키마로 확인함(확인-A3 완료) |
| 전문가-B4 | (a)(b)(c) 유지, 상태 2개 추가 | **반영**: 질문 문장 보완, 상태 5가지 정의, 집계 어휘 대응. `Asset`과 `AFFECTED_ASSET` 추가 |
| 전문가-B5 | D5~D8 유지, 매핑 검증 보완 | **반영**: `attack_mapping.py` 수정(위 "기법 층")과 시험 6개 추가 |

전문가에게 되묻고 정리한 것: 모니터링 시드의 성격(기술 대 조직)과 상위 분류의 비교 기준. 후속 답변으로 시드를 나누라는 의견이 왔고, 우리는 상위를 유지하는 쪽을 택했다(결과만 적힌 사례의 정보 손실 방지). 이 선택을 전문가에게 다시 확인할 수 있다.

### 기본값 (재검토)

| 번호 | 기본값 | 상태 |
| --- | --- | --- |
| 기본값-C1 | CWE 대표값 규칙 `CNA → ADP → KEV` (2026-11-26 표본은 KEV 1,795건 중 232건이 출처끼리 다른 것에서 뽑음. 2026-11-27 갱신 후 1,805건 중 233건) | **판정 완료(2026-11-26, Taegyu).** 표본 30건 중 현재 규칙과 일치 23건(77%): ADP가 대표인 20건 중 16건, CNA가 대표인 10건 중 7건. 규칙과 다른 7건은 `kev` 4건과 `판단 불가` 3건이고 `adp`나 `cna`가 규칙을 뒤집은 경우는 없음. 판정은 `security_kg/data/kev_conflict_judgement.csv`. **규칙 변경은 아직 하지 않음**(표본이 작아 유지 권고) |
| 기본값-C2 | 사건 해소 숫자: 90일, 365일, 이름 유사도 0.8, 별칭 7개 (설계 결정 D2의 출발점 값) | — |
| 기본값-C3 | 수치 지표 5개 + `other`, 한국어 수 표기 규칙 | — |
| 기본값-C4 | ATT&CK 20.1의 전술 이름 변경(`stealth`, `defense-impairment`)과 전술 수준 비교 | — |
| 기본값-C5 | MISP는 후보로만, 새 노드는 확인 대기 | — |

### 운영 (팀 결정)

| 번호 | 결정할 것 | 상태 |
| --- | --- | --- |
| 운영-D1 | 대화 기록 문서(`docs/20261125까지_대화기록.md`)를 `main`에 둘지(로컬 경로와 붙여 넣은 로그가 들어 있고 이미 병합됨) | — |
| 운영-D2 | 원본 파일(CWE XML 18MB, ATT&CK 55MB) 보관 위치와 파일명 규칙 | — |
| 운영-D3 | 문서 수집 범위와 양(사건별 건수, 출처 유형) | — |
| 운영-D4 | 정답 데이터(사건별 취약점, 약점, 기법)를 누가 만드는지 | **초안 완료(2026-11-26, Taegyu 확인 전).** `fact_check/answer_key_draft.csv` 28행(네 사건), 설명은 `fact_check/drafts/정답표_초안_설명.md`. 시드 이름에 묶지 않고 "문서가 말한 사실 단위"로 작성. 작성자는 Claude 초안 + Taegyu 확인 |
| 운영-D5 | 원본 코드 교체(2번) 시작 시점. 확인-A1은 소규모 실행(3번) 전에 끝나야 함 | 확인-A1은 충족(Canvas 제외) |

**전문가 검토 자료 묶음**: `python expert_review_bundle.py`가 B1~B5에 필요한 자료를 한 개의 zip(`security_kg/expert_review/전문가검토자료.zip`)으로 만든다. 저장소에는 올리지 않는 결과물이며, README와 설정 파일에서 필요한 부분만 뽑아 전문가가 읽기 쉽게 다시 쓴다.

권장 순서: ① 확인-A1과 운영-D4를 같이 시작 ② 확인-A4, A5와 기본값-C1 ③ 전문가를 만날 수 있을 때 전문가-B1~B5(B1, B2가 가장 중요) ④ 소규모 실행 뒤 기본값-C2~C5 조정.

## 자체 검사

```bash
python extraction/consts.py   # 설정의 일관성 검사
python aggregate.py           # 집계 규칙 자체 시험(14개)
python attack_mapping.py      # 기법 층 규칙 자체 시험(16개)
python incident_resolution.py # 사건 해소 규칙 자체 시험(11개)
python measurements.py        # 수치 층 규칙 자체 시험(9개)
python answer_key.py          # 정답표 초안 검사(근거 행과 표준 후보 ID의 존재)
python answer_key.py --self-test
python kev_conflict_sample.py --self-test   # KEV CWE 충돌 표본 분류 시험
python expert_review_bundle.py --self-test   # 전문가 검토 자료 묶음 시험
python nist_catalog.py --self-test         # NIST 항목 번호 검사 시험
python nist_catalog.py                     # 표준 매핑 번호가 공식 목록에 있고 검토표와 일치하는지 검사
python veris_check.py --self-test          # VERIS 스키마 대조 시험
python alias_review.py --self-test         # 별칭 검토표 시험
python alias_review.py                     # 별칭 검토표의 판정을 집계하고 별칭 사전과 일치하는지 검사
python cwe_catalog.py         # CWE 목록 변환 규칙 자체 시험(9개)
python backbone.py            # 뼈대 변환 규칙 자체 시험(네트워크 없이)
python actors.py              # 행위자 이름 연결 자체 시험
python actor_review.py        # 확인 대기열 처리 자체 시험
python fact_check.py          # 사건 사실 확인표 점검과 진행 상황
```

`consts.py` 검사는 관계의 개체 종류 정의 여부, FILTERED ⊂ ALL, 닫힌 목록 종류의 연결 방법, `ANSWER_SLOTS`가 문서에서 받는 관계만 쓰는지 등을 확인한다.
