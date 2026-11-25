"""
보안 사고 지식 그래프용 설정 초안 (ClimateKG의 extraction/consts.py를 대체하는 틀).

질문 틀:
    사건 X에서 공격자는 (a) 어떤 취약점 (b) 어떤 약점·관리 실패 (c) 어떤 기법을 이용했는가?
    각 답에 출처와 확정/주장/추정 구분을 붙여라.

원본과의 관계
- 아래 5개 이름(GEMINI_MIN_CACHE_TOKEN_LIMIT, EMBEDDING_MATCH_ENTITIES, ENTITY_TYPES_TO_ADD_INSTANCES,
  FILTERED_RELATIONSHIP_SOURCE_TO_TARGET, ALL_RELATIONSHIP_SOURCE_TO_TARGET)은 원본과 같은 이름이라
  원본 코드가 그대로 가져다 쓸 수 있다.
- "[신규]" 표시가 붙은 상수는 원본 코드가 읽지 않는다. 쓰려면 코드 수정이 필요하다(README 참고).

주의: 초안이다. 분야 전문가의 검토를 받지 않았고, 이 파일로 파이프라인을 실행해 보지 않았다.
"""

GEMINI_MIN_CACHE_TOKEN_LIMIT = 4096  # 원본과 같은 기술 설정값


# ──────────────────────────────────────────────────────────────────────────
# 1. 개체 종류와 정의 [신규: 정의 사전]
#    원본은 정의를 프롬프트 안에 두었다. 여기서는 한곳에 모아 프롬프트가 읽게 하는 것을 권장한다.
# ──────────────────────────────────────────────────────────────────────────
ENTITY_TYPE_DEFINITIONS = {
    # ── 문서가 채우는 종류 ──
    "Incident": (
        "A breach, intrusion, data leak or tampering of ONE organization's systems (the breached organization), "
        "identified by a short descriptive name. One incident per breached organization: a coordinated attack on "
        "several organizations is several Incidents grouped by a Campaign. Later waves of the same breach of the "
        "same organization belong to the same Incident. Not a general attack category."
    ),
    "Organization": (
        "A company, institution or agency that is breached (BREACHED_ORGANIZATION), suffers downstream harm "
        "(AFFECTED_ORGANIZATION), or investigates an incident. Not a product or a person."
    ),
    "Campaign": (
        "A named group of two or more Incidents at different organizations that the sources present as connected "
        "by a common cause, attacker or method (e.g. simultaneous attacks on several financial institutions). "
        "Not a single incident and not an attacker group."
    ),
    "RootCause": (
        "An organizational or operational failure that made the incident possible, such as a missing patch, "
        "unrevoked credential, missing encryption or late incident response. Not a software defect with a "
        "CVE identifier (that is a Vulnerability) and not an attacker action (that is a Technique)."
    ),
    # ── 표준(뼈대)에서 오는 종류 ──
    "Vulnerability": (
        "A publicly catalogued software or hardware flaw identified by a CVE identifier "
        "(CVE-YYYY-NNNN), or a named flaw that is known by such an identifier. "
        "A misconfiguration or mishandled key without a CVE is NOT a Vulnerability."
    ),
    "Weakness": (
        "A class of code-level or design-level defect from the CWE catalogue (e.g. improper authentication). "
        "An organizational failure is NOT a Weakness; use RootCause."
    ),
    "Technique": (
        "An attacker behaviour from MITRE ATT&CK (e.g. supply chain compromise, web shell, valid account abuse). "
        "Not a malware name, not a tool, not a vulnerability."
    ),
    "Tactic": (
        "The attacker's goal at one phase of an attack in MITRE ATT&CK (e.g. initial access, persistence, "
        "exfiltration). Only Techniques belong to Tactics."
    ),
    "MalwareFamily": (
        "A named malware family or attacker tool (e.g. BPFDoor). Generic words such as 'malware' or "
        "'backdoor' alone are NOT a MalwareFamily."
    ),
    "ThreatActor": (
        "A named attacker group or named individual. Unnamed 'hackers' or 'attackers' are NOT a ThreatActor; "
        "do not create an entity for them (record their relationship to the victim with ActorOrigin instead)."
    ),
    "ActorOrigin": (
        "How the attacker relates to the victim organization: INTERNAL (a current employee or contractor with "
        "authorized access), FORMER_INSIDER (a former employee or contractor who used access or knowledge "
        "retained from that role), PARTNER (a supplier, vendor or other third party with a business relationship), "
        "EXTERNAL (no authorized relationship, e.g. a named criminal or state-linked group or outsiders). "
        "Decide by the attacker's employment status at the time of the access or attack, not at the time of "
        "discovery: still employed then = INTERNAL (including misuse shortly before leaving); already left = "
        "FORMER_INSIDER. If the text does not say when, do not guess: mark the assertion as inferred or omit it. "
        "Use ONLY when the text states or clearly implies the relationship; when it is only implied, mark the "
        "assertion as inferred. Never infer it from the attacker's nationality, location or skill."
    ),
    "Product": (
        "A named software product or operating system affected by a Vulnerability, as in a CPE name "
        "(e.g. a Linux kernel). Not a vendor and not an organization."
    ),
}

ENTITY_TYPES = sorted(ENTITY_TYPE_DEFINITIONS)

# 표준에서 가져와 닫힌 목록(뼈대)으로 쓰는 종류와 그 출처
BACKBONE_ENTITY_TYPES = {
    "Vulnerability": "CVE list (+ NVD enrichment, CISA KEV flag)",
    "Weakness": "CWE",
    "Technique": "MITRE ATT&CK (STIX 2.1)",
    "Tactic": "MITRE ATT&CK (STIX 2.1)",
    "MalwareFamily": "MITRE ATT&CK software (+ MISP galaxy aliases)",
    "ThreatActor": "MITRE ATT&CK groups (+ MISP galaxy aliases)",
    "Product": "NVD CPE dictionary (partial; names vary)",
    "RootCause": "hand-written seed list below (needs expert review)",
    "ActorOrigin": "hand-written seed list below; INTERNAL/EXTERNAL/PARTNER follow the top-level actor categories of VERIS",
}

# [신규] 뼈대 내려받은 날짜·버전 기록용. 내려받을 때 채운다(재현을 위해 필수).
BACKBONE_SNAPSHOTS = {
    "cve": None,      # 예: cvelistV5 내려받은 날짜
    "nvd": None,
    "cwe": None,      # 검색상 2026-10-28 발표 CWE 5.0이 최신으로 보임. 내려받을 파일로 확인
    "attack": None,   # 검색상 v20(2026-10-13)이 최신으로 보임. 내려받을 파일로 확인
    "kev": None,
    "misp_galaxy": None,
}


# ──────────────────────────────────────────────────────────────────────────
# 2. 연결(entity linking) 설정
# ──────────────────────────────────────────────────────────────────────────

# 이름(문자열 유사도 + 필요 시 AI 보조)으로 뼈대의 기존 노드와 맞출 종류 → 비교할 속성
EMBEDDING_MATCH_ENTITIES = {
    "Weakness": "name",
    "Technique": "name",
    "Tactic": "name",
    "MalwareFamily": "name",   # 별칭이 많아 별칭 목록과 함께 인덱스를 만들 것
    "ThreatActor": "name",     # 같은 이유
    "Product": "name",         # 표기가 제각각이라 연결이 가장 어려운 종류
    "RootCause": "name",
}

# [신규] 식별자 형식이 엄격해서 유사도가 아니라 '정확히 같은 ID'로만 연결할 종류 → 속성
EXACT_ID_ENTITIES = {
    "Vulnerability": "cve_id",
    "Weakness": "cwe_id",       # 이름 유사도와 ID 일치를 모두 허용하려면 위 EMBEDDING_MATCH_ENTITIES도 유지
    "Technique": "attack_id",
    "ActorOrigin": "name",      # 닫힌 시드(ACTOR_ORIGIN_SEED). ID는 아니지만 '정확히 일치'로만 연결한다
}
ID_PATTERNS = {                 # 형식은 일반적으로 알려진 것이며 이 세션에서 확인하지 않았다
    "Vulnerability": r"^CVE-\d{4}-\d{4,}$",
    "Weakness": r"^CWE-\d+$",
    "Technique": r"^T\d{4}(\.\d{3})?$",
}

# 문서에서 새 노드를 추가할 수 있는 종류(뼈대 목록에 없으면 새로 만든다)
ENTITY_TYPES_TO_ADD_INSTANCES = [
    "Incident",         # 이름 유사도로 합치지 않는다. 아래 INCIDENT_RESOLUTION 규칙으로 합친다(원본의 합치기 우회)
    "Organization",     # 별칭 사전(ORG_ALIAS_SEED)으로 먼저 합친다
    "Campaign",
    "RootCause",        # 시드에 없는 원인은 일단 추가하되 사람이 정리한다
    "MalwareFamily",    # 새 악성코드 계열이 계속 생김
    "ThreatActor",      # 새 행위자와 별칭이 계속 생김
    "Product",
]
# Vulnerability, Weakness, Technique, Tactic은 닫힌 목록이다. 목록에 없으면 연결 실패로 버린다.
# (CVE 번호는 있지만 아직 목록에 반영되지 않은 신규 CVE는 뼈대를 다시 내려받아 해결한다.)


# ──────────────────────────────────────────────────────────────────────────
# 3. 허용 관계: (출발 종류, 도착 종류, 관계)
# ──────────────────────────────────────────────────────────────────────────

# 문서에서 받을 관계. 질문 틀의 (a), (b), (c)에 해당한다.
FILTERED_RELATIONSHIP_SOURCE_TO_TARGET = [
    ("Incident", "Organization", "BREACHED_ORGANIZATION"),   # 침해된 조직. 사건 식별(같은 사건 판단)의 기준
    ("Incident", "Organization", "AFFECTED_ORGANIZATION"),   # 파급 피해 조직 (예: 플랫폼 침해로 피해를 입은 학교)
    ("Incident", "Campaign", "PART_OF_CAMPAIGN"),            # 여러 조직에 걸친 묶음의 소속
    ("Incident", "Vulnerability", "EXPLOITED_VULNERABILITY"),  # (a) 취약점
    ("Incident", "Weakness", "EXPLOITED_WEAKNESS"),          # (b) 코드·설계 수준 약점 (CWE)
    ("Incident", "RootCause", "HAS_ROOT_CAUSE"),             # (b) 조직·운영의 관리 실패
    ("Incident", "Technique", "USED_TECHNIQUE"),             # (c) 기법
    ("Incident", "MalwareFamily", "USED_MALWARE"),           # (c) 악성코드·도구
    ("Incident", "ThreatActor", "ATTRIBUTED_TO"),            # 배후 지목(주장인 경우가 많음)
    ("Incident", "ActorOrigin", "HAS_ACTOR_ORIGIN"),         # 공격자와 피해 조직의 관계(내부자, 외부자 등)
]

# 표준 데이터가 이미 가진 관계. 문서에서 다시 받지 않고 뼈대로 만든다.
BACKBONE_RELATIONSHIP_SOURCE_TO_TARGET = [
    ("Vulnerability", "Weakness", "HAS_WEAKNESS"),           # CVE → CWE (NVD)
    ("Vulnerability", "Product", "AFFECTS_PRODUCT"),         # CVE → 제품 (CPE)
    ("Technique", "Tactic", "PART_OF_TACTIC"),               # ATT&CK
    ("MalwareFamily", "Technique", "USES_TECHNIQUE"),        # ATT&CK 소프트웨어
    ("ThreatActor", "Technique", "USES_TECHNIQUE"),          # ATT&CK 그룹
    ("ThreatActor", "MalwareFamily", "USES_MALWARE"),
]

ALL_RELATIONSHIP_SOURCE_TO_TARGET = (
    FILTERED_RELATIONSHIP_SOURCE_TO_TARGET + BACKBONE_RELATIONSHIP_SOURCE_TO_TARGET
)


# ──────────────────────────────────────────────────────────────────────────
# 4. 약점·관리 실패(RootCause)의 시드 목록 [신규, 초안]
#    5개 사건의 검색 요약에서 나온 원인들을 일반화한 것이며 전문가 검토가 필요하다.
# ──────────────────────────────────────────────────────────────────────────
ROOT_CAUSE_SEED = [
    "UNPATCHED_KNOWN_VULNERABILITY",       # 알려진 취약점 패치 미적용
    "CREDENTIAL_OR_KEY_MISMANAGEMENT",     # 자격 증명·키 관리 미흡 (예: 퇴사자 키 미폐기)
    "INSUFFICIENT_ENCRYPTION",             # 암호화 미흡
    "WEAK_ACCESS_CONTROL",                 # 접근 통제 미흡
    "INSUFFICIENT_MONITORING_DETECTION",   # 모니터링·탐지 미흡 (장기 잠복)
    "INADEQUATE_INCIDENT_RESPONSE",        # 과거 침해 대응 미흡
    "THIRD_PARTY_OR_SUPPLY_CHAIN_RISK",    # 서드파티·공급망 관리 미흡
    "MISCONFIGURATION",                    # 설정 오류
]


# ──────────────────────────────────────────────────────────────────────────
# 4-2. 공격자 유형(ActorOrigin)의 시드 목록 [신규]
#      질문 틀 (a)(b)(c)에는 '누가'가 없다. 그래서 이 값은 답의 칸이 아니라 참고 정보(CONTEXT_FIELDS)다.
#      UNKNOWN은 값으로 두지 않는다: 문서가 말하지 않은 것은 "언급 없음"으로 집계한다(부재를 추측하지 않는 원칙).
# ──────────────────────────────────────────────────────────────────────────
ACTOR_ORIGIN_SEED = [
    "INTERNAL",         # 현직 직원·계약자
    "FORMER_INSIDER",   # 전직 직원·계약자. 퇴사 후에도 남은 접근 권한이나 지식을 이용(우리가 추가한 값. VERIS에서는 External)
    "PARTNER",          # 협력사·공급사·서드파티
    "EXTERNAL",         # 피해 조직과 정당한 관계가 없는 외부
]

# 결정 기록(1): 세분화를 유지하고 VERIS 값으로 합치는 대응표를 둔다(옵션 B).
# 세분화된 값은 상위 값으로 합칠 수 있지만 합친 값은 다시 쪼갤 수 없으므로 손실이 없는 쪽을 택했다.
# 근거: VERIS 위키의 행위자 설명은 전직 직원을 외부(External) 위협의 예로 들고, 내부(Internal)는 현재 구성원으로 설명한다.
# 주의: VERIS 위키 사본 페이지로 확인한 것이며 정확한 값 목록은 VERIS 스키마 저장소로 대조해야 한다.
ACTOR_ORIGIN_TO_VERIS = {
    "INTERNAL": "Internal",
    "FORMER_INSIDER": "External",
    "PARTNER": "Partner",
    "EXTERNAL": "External",
}

# 결정 기록(2): 경계는 "공격(접근)이 일어난 시점의 고용 상태"로 정한다. 추출 프롬프트의 예시와 시험에 쓴다.
# (사례, 기대하는 값). 기대값이 None이면 값을 기록하지 않는다(추측 금지).
ACTOR_ORIGIN_BOUNDARY_EXAMPLES = [
    ("퇴사 후에 남아 있던 인증 서명키로 접근했다", "FORMER_INSIDER"),
    ("재직 중이던 개발자가 퇴사 직전에 데이터를 복사해 갔다", "INTERNAL"),
    ("퇴사 의사를 밝힌 직원이 아직 재직 중일 때 권한을 오용했다", "INTERNAL"),
    ("협력사 직원의 계정이 도용되어 침입에 쓰였다", "PARTNER"),
    ("이름 있는 해킹 조직이 외부에서 침입했다", "EXTERNAL"),
    ("개발자가 가진 접근 권한으로 침해가 일어났다(고용 상태와 시점이 적혀 있지 않음)", None),
]

# 결정 기록(3): 행위자가 둘 이상일 때 값과 이름의 짝 짓기는 파일럿에서 필요가 확인될 때까지 하지 않는다(옵션 i).
# 지금은 사건 단위로만 기록하고 값이 여러 개면 aggregate.py가 "사람이 확인 필요"로 표시한다.
ACTOR_PAIRING = "incident_level"   # 행위자별 기록("actor_level")은 보류


# ──────────────────────────────────────────────────────────────────────────
# 5. 출처와 확정/주장/추정 구분 [신규]
#    질문 틀의 "각 답에 출처와 구분을 붙여라"를 위한 어휘.
#    - assertion_status: 사실(트리플렛) 하나마다 붙인다  → 추출 스키마(models.py)에 칸을 추가해야 함
#    - source_type: 문서 하나마다 붙인다                  → 문서 메타데이터에 칸을 추가해야 함
# ──────────────────────────────────────────────────────────────────────────
ASSERTION_STATUSES = {
    "confirmed": "Stated by the affected organization, an investigating authority or regulator, "
                 "or backed by published technical findings.",
    "claimed": "Asserted by the attacker or an interested party, or reported as 'according to X' "
               "without confirmation.",
    "inferred": "An analyst's or reporter's inference that is not attributed to an official finding.",
}

SOURCE_TYPES = [
    "official_government",      # 정부·규제기관 발표
    "affected_organization",    # 피해 조직 공지
    "security_vendor",          # 보안 업체 분석
    "media",                    # 언론 보도
    "attacker_claim",           # 공격자 게시·주장
    "researcher",               # 독립 연구자 보고
]


# ──────────────────────────────────────────────────────────────────────────
# 5-2. 사건 해소(같은 사건 합치기) [신규] — incident_resolution.py가 읽는다
#      원본은 새 노드를 이름 의미 유사도 0.8 이상이면 합친다. 사건에는 날짜와 조직을 보지 않아 오류가 난다.
#      결정: D1 조직 단위 Incident + 선택적 Campaign / D2 같은 조직 필수 + 공개 시점 기준 + 공유 신호 /
#            D3 애매하면 합치지 않고 사람 확인(정밀도 우선) / D4 같은 조직·90일 이내 연속 파동은 하나의 사건.
#      아래 숫자는 출발점이다. 다섯 사건으로는 보정할 수 없어 파일럿에서 조정한다.
# ──────────────────────────────────────────────────────────────────────────
INCIDENT_RESOLUTION = {
    "anchor": "headline_date",        # 공격 기간이 아니라 문서가 제시하는 사건 시점을 기준으로 한다
    "same_within_days": 90,           # 이 이내면 시간상 같은 사건 후보 (D4: 연속 파동 포함)
    "different_after_days": 365,      # 이보다 멀면 다른 사건
    "name_similarity_for_merge": 0.8, # 이름은 약한 신호다. 단독으로는 합치지 않고 시간이 가까울 때만 보조로 쓴다
    "review_policy": "precision_first",  # 애매하면 합치지 않고 확인 대기열로 보낸다(D3)
    "id_format": "INC-{org}-{yyyymm}",
}

# 조직 별칭 시드(초안). 같은 조직을 여러 이름으로 쓰는 문제는 한 단계 아래에도 있어서 사건 해소보다 먼저 합친다.
# 여기 없는 이름은 다른 조직으로 취급되어 사건이 쪼개질 수 있다. 실제 문서를 보며 늘려야 한다.
ORG_ALIAS_SEED = {
    "SK텔레콤": ["SKT", "SK Telecom", "에스케이텔레콤"],
    "쿠팡": ["Coupang", "쿠팡(주)"],
    "레벨인피니트": ["Level Infinite"],
    "Instructure": ["인스트럭처", "Instructure, Inc."],
    "신한은행": ["Shinhan Bank"],
    "KB국민은행": ["KB Kookmin Bank", "국민은행"],
    "하나은행": ["Hana Bank"],
}


# ──────────────────────────────────────────────────────────────────────────
# 6. 답의 집계 [신규] — '취약점 없음/미공개'를 다루는 최소안
#    원칙: 부재를 추측하지 않는다. 트리플렛이 없으면 "없음"이 아니라 "언급 없음(처리한 문서 n개 중)"이다.
#    새 개체 종류나 관계를 추가하지 않는다. aggregate.py가 이 설정으로 사건별 답을 만든다.
# ──────────────────────────────────────────────────────────────────────────

# 질문 틀의 칸 → 그 칸의 답이 되는 관계. 이 관계의 트리플렛이 하나라도 있으면 그 칸은 "있음"이다.
ANSWER_SLOTS = {
    "a_vulnerability": ["EXPLOITED_VULNERABILITY"],
    "b_weakness_or_failure": ["EXPLOITED_WEAKNESS", "HAS_ROOT_CAUSE"],
    "c_technique": ["USED_TECHNIQUE", "USED_MALWARE"],
}

# 질문의 칸은 아니지만 답과 함께 보여 줄 참고 정보 → 그 정보의 답이 되는 관계. 상태 규칙은 칸과 같다.
CONTEXT_FIELDS = {
    "actor_origin": ["HAS_ACTOR_ORIGIN"],
    "attribution": ["ATTRIBUTED_TO"],
}
# 값이 여러 개 나오면 사람이 확인하도록 표시할 참고 정보
# (문서들이 서로 다른 값을 말했거나 사건에 행위자가 둘 이상일 수 있다)
REVIEW_IF_MULTIPLE_VALUES = ["actor_origin"]

# 칸의 상태. 최소안에서는 두 가지뿐이다. (구분이 필요해지면 확장안: README 참고)
SLOT_STATES = {
    "found": "하나 이상의 문서가 답을 제시함",
    "not_mentioned": "처리한 문서 중 어느 것도 이 칸을 언급하지 않음(= '없음'이 아니라 '확인 안 됨')",
}
NOT_MENTIONED_TEXT = "확인되지 않음: 처리한 문서 {n}개 중 언급 없음"
NO_DOCUMENTS_TEXT = "확인되지 않음: 처리한 문서가 없음"

# 답을 보여 줄 때의 정렬 기준: 확정 > 주장 > 추정, 같으면 더 많은 문서가 말한 것을 먼저
ASSERTION_RANK = {"confirmed": 0, "claimed": 1, "inferred": 2}

# [신규] 문서 단위로 추가로 뽑아야 하는 필드. 사건당 처리한 문서 수와 시점을 세기 위해 필요하다.
NEW_DOCUMENT_LEVEL_FIELDS = {
    "incident_mentions": "이 문서가 다루는 사건의 목록. 항목 구조는 INCIDENT_MENTION_FIELDS (사건 해소와 문서 수 집계의 기준)",
    "document_date": "문서의 발행일 (확장안에서 '미공개'의 시점 비교에 필요)",
    "source_type": "SOURCE_TYPES 중 하나",
}

# 사건 언급 한 건의 구조. 날짜는 그래프의 트리플렛이 아니라 문서 단위 메타데이터로만 둔다(결정 D1~D4, 5번 문제의 날짜 결정).
INCIDENT_MENTION_FIELDS = {
    "name": "문서가 쓴 사건 이름 그대로",
    "breached_org": "침해된 조직의 이름 그대로. 사건 식별의 필수 조건",
    "headline_date": "문서가 그 사건의 시점으로 제시하는 날짜. 공개 시점이 있으면 그것, 없으면 문서가 사건 날짜로 쓴 것. "
                     "형식 YYYY, YYYY-MM, YYYY-MM-DD 중 하나. 불확실하면 비워 둔다",
    "attack_span": "문서에 명시된 공격(침입) 기간 {start, end}. 있을 때만. 서로 다른 시점을 쓴 문서를 잇는 데 쓴다",
    "signals": "이 사건에 대해 문서가 말한 CVE, 악성코드, 행위자 이름 목록(트리플렛에서 뽑음). 같은 사건의 강한 증거",
}


# ──────────────────────────────────────────────────────────────────────────
# 자체 검사: python consts.py
# ──────────────────────────────────────────────────────────────────────────
def validate() -> list[str]:
    problems = []
    types = set(ENTITY_TYPES)
    for s, t, r in ALL_RELATIONSHIP_SOURCE_TO_TARGET:
        for x in (s, t):
            if x not in types:
                problems.append(f"관계 {(s, t, r)}: 정의되지 않은 개체 종류 {x}")
    if len(set(ALL_RELATIONSHIP_SOURCE_TO_TARGET)) != len(ALL_RELATIONSHIP_SOURCE_TO_TARGET):
        problems.append("ALL 관계 목록에 중복이 있음")
    if not set(FILTERED_RELATIONSHIP_SOURCE_TO_TARGET) <= set(ALL_RELATIONSHIP_SOURCE_TO_TARGET):
        problems.append("FILTERED가 ALL의 부분 집합이 아님")
    for name, group in (("EMBEDDING_MATCH_ENTITIES", EMBEDDING_MATCH_ENTITIES),
                        ("EXACT_ID_ENTITIES", EXACT_ID_ENTITIES),
                        ("ID_PATTERNS", ID_PATTERNS)):
        for k in group:
            if k not in types:
                problems.append(f"{name}: 정의되지 않은 개체 종류 {k}")
    for k in ENTITY_TYPES_TO_ADD_INSTANCES:
        if k not in types:
            problems.append(f"ENTITY_TYPES_TO_ADD_INSTANCES: 정의되지 않은 개체 종류 {k}")
    used = {x for s, t, _ in ALL_RELATIONSHIP_SOURCE_TO_TARGET for x in (s, t)}
    for k in types - used:
        problems.append(f"어떤 관계에도 쓰이지 않는 개체 종류: {k}")
    # 닫힌 목록 종류는 '연결 방법'이 하나는 정해져 있어야 한다
    closed = {"Vulnerability", "Weakness", "Technique", "Tactic", "ActorOrigin"}
    for k in closed:
        if k not in EMBEDDING_MATCH_ENTITIES and k not in EXACT_ID_ENTITIES:
            problems.append(f"닫힌 목록 종류 {k}에 연결 방법이 없음")
        if k in ENTITY_TYPES_TO_ADD_INSTANCES:
            problems.append(f"닫힌 목록 종류 {k}가 추가 가능 목록에 있음")
    known_relations = {r for _, _, r in ALL_RELATIONSHIP_SOURCE_TO_TARGET}
    for slot, relations in ANSWER_SLOTS.items():
        for r in relations:
            if r not in known_relations:
                problems.append(f"ANSWER_SLOTS[{slot}]: 정의되지 않은 관계 {r}")
    asserted = {r for _, _, r in FILTERED_RELATIONSHIP_SOURCE_TO_TARGET}
    covered = {r for rels in ANSWER_SLOTS.values() for r in rels}
    for r in covered - asserted:
        problems.append(f"ANSWER_SLOTS가 문서에서 받지 않는 관계를 씀: {r}")
    for field, relations in CONTEXT_FIELDS.items():
        for r in relations:
            if r not in asserted:
                problems.append(f"CONTEXT_FIELDS[{field}]: 문서에서 받지 않는 관계 {r}")
    for field in REVIEW_IF_MULTIPLE_VALUES:
        if field not in CONTEXT_FIELDS:
            problems.append(f"REVIEW_IF_MULTIPLE_VALUES: 정의되지 않은 참고 정보 {field}")
    if covered & {r for rels in CONTEXT_FIELDS.values() for r in rels}:
        problems.append("같은 관계가 ANSWER_SLOTS와 CONTEXT_FIELDS에 모두 있음")
    r = INCIDENT_RESOLUTION
    if not (0 < r["same_within_days"] < r["different_after_days"]):
        problems.append("INCIDENT_RESOLUTION: same_within_days는 0보다 크고 different_after_days보다 작아야 함")
    if r["review_policy"] not in ("precision_first", "recall_first"):
        problems.append("INCIDENT_RESOLUTION: review_policy 값이 올바르지 않음")
    seen = {}
    for canon, aliases in ORG_ALIAS_SEED.items():
        for name in [canon] + aliases:
            key = name.casefold().replace(" ", "")
            if key in seen and seen[key] != canon:
                problems.append(f"ORG_ALIAS_SEED: '{name}'이 {seen[key]}와 {canon}에 모두 있음")
            seen[key] = canon
    if set(ACTOR_ORIGIN_TO_VERIS) != set(ACTOR_ORIGIN_SEED):
        problems.append("ACTOR_ORIGIN_TO_VERIS의 키가 ACTOR_ORIGIN_SEED와 다름")
    for text, expected in ACTOR_ORIGIN_BOUNDARY_EXAMPLES:
        if expected is not None and expected not in ACTOR_ORIGIN_SEED:
            problems.append(f"경계 사례의 기대값이 시드에 없음: {expected}")
    if ACTOR_PAIRING not in ("incident_level", "actor_level"):
        problems.append("ACTOR_PAIRING은 incident_level 또는 actor_level이어야 함")
    if sorted(ACTOR_ORIGIN_SEED) != sorted(["INTERNAL", "FORMER_INSIDER", "PARTNER", "EXTERNAL"]):
        problems.append("ACTOR_ORIGIN_SEED가 정의 문구의 값과 다름")
    if set(ASSERTION_RANK) != set(ASSERTION_STATUSES):
        problems.append("ASSERTION_RANK와 ASSERTION_STATUSES의 키가 다름")
    return problems


if __name__ == "__main__":
    issues = validate()
    print(f"개체 종류 {len(ENTITY_TYPES)}개, 관계 {len(ALL_RELATIONSHIP_SOURCE_TO_TARGET)}개 "
          f"(문서에서 받는 것 {len(FILTERED_RELATIONSHIP_SOURCE_TO_TARGET)}개, 뼈대 {len(BACKBONE_RELATIONSHIP_SOURCE_TO_TARGET)}개)")
    print("검사 결과:", "문제 없음" if not issues else "")
    for p in issues:
        print(" -", p)
