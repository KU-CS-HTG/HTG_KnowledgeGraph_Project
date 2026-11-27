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

import re

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
        "A technical control failure or an organizational/operational failure that made the incident possible or "
        "widened its impact, such as a missing patch, unrevoked credential, missing encryption, missing security "
        "logs, no staff monitoring alerts, or late incident response. Use ONLY a failure the text states; never "
        "infer the cause from the size of the damage. Each value needs its own evidence sentence. Not a software "
        "defect with a CVE identifier (that is a Vulnerability) and not an attacker action (that is a Technique)."
    ),
    "Asset": (
        "A named system, service or data store of the breached organization that the attacker accessed or whose "
        "data was affected (e.g. an employee mobile work-support system, a business-support system). Not the "
        "organization itself and not a software product in general."
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
        "Use ONLY when the text itself names the ATT&CK technique (by name or ID). Plain descriptions of what the "
        "attacker did are an AttackBehavior, not a Technique. Not a malware name, not a tool, not a vulnerability."
    ),
    "AttackBehavior": (
        "What the attacker did, described in plain language close to the source text (e.g. 'forged login tokens "
        "using a signing key that was never revoked', 'replaced CDN scripts so that the launcher downloaded a remote "
        "access agent'). One action per entity. Not a malware name, not a CVE, not a vulnerability, and not an "
        "attacker group. Do NOT force it into an ATT&CK technique; mapping is a separate step."
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
        "assertion as inferred. Never infer it from the attacker's nationality, location or skill. "
        "FORMER_INSIDER also requires that access, credentials or knowledge obtained from the past relationship "
        "were used in the attack; a former employee who attacked by unrelated means is EXTERNAL. "
        "The attacker's origin is NOT the account owner's: if an outsider used a partner employee's stolen "
        "account, the attacker is EXTERNAL and the account owner is recorded separately (ACCOUNT_OWNER_ORIGIN)."
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
    # 내려받은 날짜는 2026-11-25. backbone.py가 같은 값을 출력한다. 모두 raw.githubusercontent.com의 원문 파일이다.
    "cve": "전체 목록은 받지 못함(이 환경에서 cve.org와 저장소 전체 접근이 막힘). CVEProject/cvelistV5의 레코드를 번호로 하나씩 조회(backbone.lookup_cve)",
    "nvd": None,      # NVD API가 이 환경에서 막혀 받지 못함. CVE→CWE는 CVE 레코드의 problemTypes로, CPE 사전은 없음
    "cwe": "5.0 (2026-10-28), cwec_v5.0.xml. 사용자가 CWE 사이트에서 받은 공식 파일과 변환 결과가 같음을 2026-11-26에 확인(약점 984, 분류 431)",
    "attack": "Enterprise 20.1 (modified 2026-11-05), 기법 706, 소프트웨어 842, 그룹 178. ICS와 Mobile은 받지 않음. 번들 enterprise-attack-20.1.json은 버전이 파일 이름에 있고 sha256 539a843a7b53…(data/attack_catalog.json의 source)",
    "kev": "cisagov/kev-data develop 사본, catalogVersion 2026.11.25, 1,805건(2026-11-27 갱신), sha256 a76360009e4a…, develop 커밋 51e0a777743f…에서 내용이 같음. www.cisa.gov 원본은 이 환경에서 막혀 사본을 씀",
    "misp_galaxy": "threat-actor 갤럭시 version 360, 1,132개, sha256 5bffee604295…. 2026-11-25에 main에서 받았고 2026-11-27에 main 커밋 779b780a13f6…의 같은 파일과 내용이 같음을 확인(이 파일을 마지막으로 바꾼 커밋은 아님)",
    "veris": "vz-risk/veris master의 verisc-merged.json(JSON 스키마), 2026-11-27 받음, 104,764바이트, sha256 e43fbc1c3c1d…. 스키마에 버전 표기가 없고 커밋 해시는 기록하지 못함",
    "nist": "CSF 2.0과 SP 800-53 Rev. 5.2.0의 OSCAL 목록(usnistgov/oscal-content main), 2026-11-27 받음. 번호와 제목은 data/nist_catalog.json, 파일의 sha256은 그 안에 있음",
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
    "AttackBehavior",   # 열린 서술형. 사건 안에서만 의미가 있고, 사건 간 비교는 매핑된 전술·기법으로 한다
    "RootCause",        # 시드에 없는 원인은 일단 추가하되 사람이 정리한다
    "MalwareFamily",    # 새 악성코드 계열이 계속 생김
    "ThreatActor",      # 새 행위자와 별칭이 계속 생김
    "Product",
    "Asset",            # 침해된 시스템·서비스. 문서에서 이름 그대로 받는다
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
    ("Incident", "AttackBehavior", "USED_BEHAVIOR"),         # (c) 문서가 서술한 행동(평이한 말). 기법 매핑은 별도 단계
    ("Incident", "Technique", "USED_TECHNIQUE"),             # (c) 문서가 ATT&CK 기법 이름·ID를 직접 쓴 경우만
    ("Incident", "MalwareFamily", "USED_MALWARE"),           # (c) 악성코드·도구
    ("Incident", "ThreatActor", "ATTRIBUTED_TO"),            # 배후 지목(주장인 경우가 많음)
    ("Incident", "ActorOrigin", "HAS_ACTOR_ORIGIN"),         # 공격자와 피해 조직의 관계(내부자, 외부자 등)
    ("Incident", "ActorOrigin", "ACCOUNT_OWNER_ORIGIN"),     # 도용·악용된 계정 소유자와 피해 조직의 관계(공격자와 별개)
    ("Incident", "Asset", "AFFECTED_ASSET"),                 # 참고: 접근되었거나 영향을 받은 시스템. (a)(b)(c) 칸이 아니다
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
    "INSUFFICIENT_MONITORING_DETECTION",   # 모니터링·탐지 미흡 (상위). 탐지 실패는 확인되었으나 어느 통제의 실패인지 출처가 말하지 않을 때
    "INSUFFICIENT_LOGGING_AUDIT",          # (하위) 필요한 보안 이벤트의 생성·수집·기록·보존·감사 기능 부재. 출처가 직접 말할 때만
    "INSUFFICIENT_SECURITY_MONITORING_OPERATIONS",  # (하위) 관제 인력·모니터링 절차·경보 검토와 에스컬레이션 체계 부재. 출처가 직접 말할 때만
    "INADEQUATE_INCIDENT_RESPONSE",        # 과거 침해 대응 미흡
    "THIRD_PARTY_OR_SUPPLY_CHAIN_RISK",    # 서드파티·공급망 관리 미흡
    "MISCONFIGURATION",                    # 설정 오류
]


# 시드의 뜻(사람이 읽는 설명). 검토표와 전문가 자료에 쓴다.
ROOT_CAUSE_MEANING = {
    "UNPATCHED_KNOWN_VULNERABILITY": "알려진 취약점의 패치를 적용하지 않음",
    "CREDENTIAL_OR_KEY_MISMANAGEMENT": "자격 증명·키의 수명주기(발급, 보관, 교체, 폐기) 관리 실패. 예: 퇴사자 키 미폐기",
    "INSUFFICIENT_ENCRYPTION": "저장·전송 데이터가 암호화되지 않았거나 약하게 암호화됨",
    "WEAK_ACCESS_CONTROL": "권한의 범위·분리·인증 요구가 없거나 약함",
    "INSUFFICIENT_MONITORING_DETECTION": "(상위) 탐지 실패는 확인되었으나 어느 통제의 실패인지 출처가 말하지 않음",
    "INSUFFICIENT_LOGGING_AUDIT": "(하위) 필요한 보안 이벤트의 생성·수집·기록·보존·감사 기능이 없음",
    "INSUFFICIENT_SECURITY_MONITORING_OPERATIONS": "(하위) 관제 인력, 모니터링 절차, 경보 검토와 에스컬레이션 체계가 없음",
    "INADEQUATE_INCIDENT_RESPONSE": "경보나 과거 침해를 알고도 차단·정리·재발 방지를 하지 않음",
    "THIRD_PARTY_OR_SUPPLY_CHAIN_RISK": "외부 공급사·협력사·구성요소가 침해되었거나 그 신뢰가 악용됨",
    "MISCONFIGURATION": "잘못된 설정이나 기본값이 원인임",
}

# 시드의 계층: 상위 시드(모니터링)를 지우지 않고 하위 시드를 추가했다. 결과만 적힌 사례("장기간 탐지하지 못했다")를 받을 자리가
# 있어야 하기 때문이다(결과만으로 하위 시드를 고르면 출처에 없는 원인을 만들어 낸다). 하위는 출처가 직접 말할 때만 쓴다.
ROOT_CAUSE_PARENT = {
    "INSUFFICIENT_LOGGING_AUDIT": "INSUFFICIENT_MONITORING_DETECTION",
    "INSUFFICIENT_SECURITY_MONITORING_OPERATIONS": "INSUFFICIENT_MONITORING_DETECTION",
}

# 시드에서 파생되는 속성. 문서에서 따로 뽑지 않고 시드마다 정해 두며(추출 스키마를 바꾸지 않는다), 사람이 근거와 함께 사건 단위로
# 덮어쓸 때만 다른 값을 둔다. 세 가지 분류(RootCause, 성격, 영역)가 서로 모순되는 값을 갖는 것을 막기 위해서다.
#   failure_nature: 실패의 성격. 값이 None이면 "출처가 말하지 않아 미정"이다(추측하지 않는다).
FAILURE_NATURES = {
    "TECHNICAL_CONTROL_FAILURE": "기술적 보안 통제, 시스템 기능, 설정 또는 구현의 실패",
    "ORGANIZATIONAL_PROCESS_FAILURE": "조직의 정책, 절차, 인력, 책임체계 또는 운영상의 실패",
}
#   control_domain: 실패한 보안 통제의 업무 영역. 프로젝트 내부의 분석·집계 기준이며 NIST CSF 카테고리와 같은 개념이 아니다.
CONTROL_DOMAINS = [
    "VULNERABILITY_MANAGEMENT", "IDENTITY_AND_ACCESS_MANAGEMENT", "DATA_PROTECTION", "SECURITY_MONITORING",
    "INCIDENT_RESPONSE", "SUPPLY_CHAIN_SECURITY", "CONFIGURATION_MANAGEMENT",
]
#   display_group: 화면 표시용 묶음(전문가 검토 의견의 5개 상위 분류). 사건 간 비교 기준으로 쓰지 않는다.
ROOT_CAUSE_ATTRIBUTES = {
    "UNPATCHED_KNOWN_VULNERABILITY": {"failure_nature": "ORGANIZATIONAL_PROCESS_FAILURE", "control_domain": "VULNERABILITY_MANAGEMENT",
                                      "display_group": "취약점 관리 실패"},
    "CREDENTIAL_OR_KEY_MISMANAGEMENT": {"failure_nature": "ORGANIZATIONAL_PROCESS_FAILURE", "control_domain": "IDENTITY_AND_ACCESS_MANAGEMENT",
                                        "display_group": "자산·계정 관리 실패",
                                        "note": "기본값은 수명주기 관리(조직 절차). 하드코딩된 키처럼 기술적 결함이면 사람이 근거와 함께 사건 단위로 덮어쓴다"},
    "INSUFFICIENT_ENCRYPTION": {"failure_nature": "TECHNICAL_CONTROL_FAILURE", "control_domain": "DATA_PROTECTION",
                                "display_group": "기술적 통제 실패"},
    "WEAK_ACCESS_CONTROL": {"failure_nature": "TECHNICAL_CONTROL_FAILURE", "control_domain": "IDENTITY_AND_ACCESS_MANAGEMENT",
                            "display_group": "기술적 통제 실패"},
    "INSUFFICIENT_MONITORING_DETECTION": {"failure_nature": None, "control_domain": "SECURITY_MONITORING",
                                          "display_group": "보안 운영 실패",
                                          "note": "탐지 실패는 확인되었으나 로깅 기능 부재인지 관제 미운영인지 출처가 말하지 않아 성격은 미정"},
    "INSUFFICIENT_LOGGING_AUDIT": {"failure_nature": "TECHNICAL_CONTROL_FAILURE", "control_domain": "SECURITY_MONITORING",
                                   "display_group": "기술적 통제 실패"},
    "INSUFFICIENT_SECURITY_MONITORING_OPERATIONS": {"failure_nature": "ORGANIZATIONAL_PROCESS_FAILURE", "control_domain": "SECURITY_MONITORING",
                                                    "display_group": "보안 운영 실패"},
    "INADEQUATE_INCIDENT_RESPONSE": {"failure_nature": "ORGANIZATIONAL_PROCESS_FAILURE", "control_domain": "INCIDENT_RESPONSE",
                                     "display_group": "보안 운영 실패"},
    "THIRD_PARTY_OR_SUPPLY_CHAIN_RISK": {"failure_nature": "ORGANIZATIONAL_PROCESS_FAILURE", "control_domain": "SUPPLY_CHAIN_SECURITY",
                                         "display_group": "외부 의존성 관리 실패",
                                         "note": "공급자 쪽 실패라는 위치 정보는 시드 자체가 나타내므로 성격의 별도 값을 두지 않는다"},
    "MISCONFIGURATION": {"failure_nature": "TECHNICAL_CONTROL_FAILURE", "control_domain": "CONFIGURATION_MANAGEMENT",
                         "display_group": "기술적 통제 실패"},
}

# 시드를 값으로 부여할 때의 공통 규칙(경계 규칙과 함께 프롬프트와 사람 검토에 쓴다)
ROOT_CAUSE_ASSIGNMENT_RULES = [
    "문서가 말한 '실패한 통제'로 고르고 결과(피해 규모, 오래 탐지하지 못했다는 사실)로 고르지 않는다.",
    "시드마다 자신의 근거 문장이 있어야 부여한다. 한 문장에서 두 시드를 자동으로 만들지 않는다(중복 집계 방지).",
    "하위 시드(로깅, 관제 운영)는 출처가 그 원인을 직접 말할 때만 쓰고, 탐지 실패만 말하면 상위 시드를 쓴다.",
    "원인을 밝히지 않았거나 조사 중이면 값을 기록하지 않는다.",
]

# 표준 매핑 후보(NIST CSF 2.0, SP 800-53 Rev. 5). CWE는 위 ROOT_CAUSE_CWE_MAP이 따로 가진다(`root_cause_standard_view`가 합쳐 보여 준다).
# 전문가 검토 의견의 후보에서 범위 표기(GV.SC-01~10, RS.MA-01~05)는 구별하는 힘이 없어 카테고리 단위(GV.SC, RS.MA)만 두었다.
# ID가 공식 파일에 있는지는 nist_catalog.py가 확인한다(2026-11-26: CSF 2.0과 800-53 Rev. 5.2.0 OSCAL 목록에서 모두 존재 확인).
# **존재 확인은 적합성 확인이 아니다.** mapping_status는 후보(candidate) → 확정(confirmed) 또는 기각(rejected)이며, 확정은 사람이 검토해야 한다(검토자와 검토일 필수).
ROOT_CAUSE_STANDARD_MAP = {
    "UNPATCHED_KNOWN_VULNERABILITY": {"nist_csf": ["PR.PS-02"], "nist_800_53": ["SI-2", "CM-3"],
                                      "nist_partial": ["ID.RA-01", "ID.RA-05", "RA-5"],
                                      "note": "부분 적합 셋(ID.RA-01, ID.RA-05, RA-5)은 취약점 식별·우선순위·스캔으로 패치 내용을 구성하는 단계에 불과하다는 검토 의견"},
    "CREDENTIAL_OR_KEY_MISMANAGEMENT": {"nist_csf": ["PR.AA-01"], "nist_800_53": ["IA-5"], "nist_partial": [],
                                        "note": "PR.AA-03, PR.AA-05, AC-2, AC-6은 부적합: WEAK_ACCESS_CONTROL에 더 가깝다는 검토 의견(그쪽이 가짐)"},
    "INSUFFICIENT_ENCRYPTION": {"nist_csf": ["PR.DS-01", "PR.DS-02"], "nist_800_53": ["SC-8", "SC-13", "SC-28"], "nist_partial": []},
    "WEAK_ACCESS_CONTROL": {"nist_csf": ["PR.AA-03", "PR.AA-05", "PR.IR-01"], "nist_800_53": ["AC-2", "AC-3", "AC-6"], "nist_partial": []},
    "INSUFFICIENT_MONITORING_DETECTION": {"nist_csf": ["DE.CM", "DE.AE"], "nist_800_53": [], "nist_partial": [],
                                          "note": "상위 시드라 카테고리만 둔다. 결정(2026-11-27): DE.CM-01, DE.CM-03, DE.CM-09는 상위 시드의 후보로 옮기지 않는다. OPERATIONS에서 부적합으로 판정되었고(메모: 'Monitoring에 더 가까움') 상위 시드는 이미 DE.CM 카테고리 전체를 가지므로 세 항목을 포함한다. 세부 범주를 두면 이유를 말하지 않은 탐지 실패에 세부 원인을 암시하게 된다"},
    "INSUFFICIENT_LOGGING_AUDIT": {"nist_csf": ["PR.PS-04"], "nist_800_53": ["AU-2", "AU-3", "AU-12"], "nist_partial": []},
    "INSUFFICIENT_SECURITY_MONITORING_OPERATIONS": {"nist_csf": ["DE.AE-02", "DE.AE-03"], "nist_800_53": ["SI-4", "CA-7", "AU-6"], "nist_partial": [],
                                                    "note": "DE.CM-01, DE.CM-03, DE.CM-09는 부적합(Monitoring에 더 가까움). 상위 MONITORING 시드의 DE.CM 카테고리가 이미 포함하므로 옮기지 않기로 결정함(위 MONITORING 메모 참고)"},
    "INADEQUATE_INCIDENT_RESPONSE": {"nist_csf": ["RS.MA", "RS.MI-01", "RS.MI-02"], "nist_800_53": ["IR-4", "IR-6", "IR-8"], "nist_partial": ["IR-5"],
                                     "note": "RS.MA는 카테고리 단위(세부 범주는 좁힌 뒤에). IR-5는 부분 적합: 대응 관련 내용이 명시적으로 표현되어 있지 않다는 검토 의견"},
    "THIRD_PARTY_OR_SUPPLY_CHAIN_RISK": {"nist_csf": ["GV.SC"], "nist_800_53": ["SR-3", "SR-5", "SR-6", "SA-9"], "nist_partial": [],
                                         "note": "GV.SC는 카테고리 단위(세부 범주는 좁힌 뒤에)"},
    "MISCONFIGURATION": {"nist_csf": ["PR.PS-01"], "nist_800_53": ["CM-2", "CM-6", "CM-7"], "nist_partial": [],
                         "note": "PR.IR-01은 부적합(WEAK_ACCESS_CONTROL에 더 가까움), CM-3은 부적합(UNPATCHED_KNOWN_VULNERABILITY에 더 가까움)"},
}
# 2026-11-27 Taegyu가 후보 55개를 검토해 확정했다(`data/nist_candidate_review.csv`: 적합 42, 부분 적합 4, 부적합 9).
# 적합은 nist_csf, nist_800_53에, 부분 적합은 nist_partial에 두고 부적합은 뺐다. 대응표와 검토표가 어긋나지 않는지는 nist_catalog.py가 검사한다.
for _v in ROOT_CAUSE_STANDARD_MAP.values():
    _v.setdefault("mapping_status", "confirmed")
    _v.setdefault("reviewed_by", "Taegyu")
    _v.setdefault("reviewed_at", "2026-11-27")
MAPPING_STATUSES_STANDARD = ["candidate", "confirmed", "rejected"]


def root_cause_standard_view(seed: str) -> dict:
    """시드 하나의 표준 대응을 한곳에서 본다: CWE(기술적 약점), NIST CSF, NIST 800-53, 성격과 영역."""
    m = ROOT_CAUSE_STANDARD_MAP[seed]
    c = ROOT_CAUSE_CWE_MAP[seed]
    a = ROOT_CAUSE_ATTRIBUTES[seed]
    return {"seed": seed, "cwe": c["cwe_verified"] + c["cwe_unverified"], "cwe_fit": c["fit"],
            "nist_csf": list(m["nist_csf"]), "nist_800_53": list(m["nist_800_53"]), "nist_partial": list(m["nist_partial"]),
            "mapping_status": m["mapping_status"], "reviewed_by": m["reviewed_by"], "reviewed_at": m["reviewed_at"],
            "failure_nature": a["failure_nature"], "control_domain": a["control_domain"], "display_group": a["display_group"]}


# ──────────────────────────────────────────────────────────────────────────
# 4-1. RootCause 시드 검토 자료: CWE 대응표와 경계 규칙 [신규, 초안] — 열린 설계 문제 6번의 준비 작업
#      목적: 전문가 검토를 받기 전에 (1) 시드가 공개 표준(CWE)과 어디까지 맞는지, (2) 겹치는 항목의 선을 어디에 긋는지를
#      눈에 보이게 한다. 이것은 전문가 검토를 대신하지 않는다.
#      검증 정도: cwe_verified는 CWE 5.0 파일(2026-10-28, 사용자가 제공한 cwec_v5.0.xml)에서 이름·상태·매핑 사용 구분을 확인한 번호,
#                 cwe_unverified는 확인하지 못한 번호다(현재 없음).
#      fit: close(대응이 분명) / partial(일부만 맞음) / none(CWE에 대응이 없음).
#      핵심 관찰: CWE는 '제품의 약점'이라서, 조직의 절차·대응 실패(패치 운영, 침해 대응)는 맞지 않거나 일부만 맞는다.
#                 RootCause는 기술 약점과 조직 관리 실패를 한 목록에 섞고 있다.
# ──────────────────────────────────────────────────────────────────────────
ROOT_CAUSE_CWE_MAP = {
    "UNPATCHED_KNOWN_VULNERABILITY": {
        "fit": "partial", "cwe_verified": ["CWE-1395", "CWE-1104"], "cwe_unverified": [],
        "note": "CWE-1395/1104는 개발자가 취약하거나 관리되지 않는 외부 구성요소에 기대는 약점이다. "
                "운영 조직이 이미 공개된 패치를 적용하지 않은 것은 정확히 대응하는 CWE가 없다(패치 운영은 절차 문제).",
    },
    "CREDENTIAL_OR_KEY_MISMANAGEMENT": {
        "fit": "partial", "cwe_verified": ["CWE-798", "CWE-324"], "cwe_unverified": [],
        "note": "CWE-798은 코드에 박힌 자격 증명이라 '퇴사자 키 미폐기'와는 다르고, CWE-324(만료된 키 사용)가 키 수명주기에 더 가깝다. "
                "키 관리 그룹(CWE-320)은 폐기된 그룹이라 대응 대상이 아니다(멤버 약점인 324, 798을 쓴다).",
    },
    "INSUFFICIENT_ENCRYPTION": {
        "fit": "close", "cwe_verified": ["CWE-311", "CWE-327", "CWE-326"], "cwe_unverified": [],
        "note": "암호화 없음(311), 깨졌거나 위험한 알고리즘(327), 강도 부족(326). "
                "CWE-311은 MITRE가 매핑에 권하지 않는 항목(Discouraged)이고 저장(312)·전송(319)의 하위 항목을 쓰라고 제안한다.",
    },
    "WEAK_ACCESS_CONTROL": {
        "fit": "close", "cwe_verified": ["CWE-284", "CWE-862", "CWE-863", "CWE-306"], "cwe_unverified": [],
        "note": "CWE-284는 포괄 항목이라 MITRE가 매핑에 권하지 않는다(Discouraged). 더 구체적인 862(인가 없음), 863(잘못된 인가), "
                "306(중요 기능의 인증 없음)을 쓴다.",
    },
    "INSUFFICIENT_MONITORING_DETECTION": {
        "fit": "partial", "cwe_verified": ["CWE-778"], "cwe_unverified": [],
        "note": "상위 시드. CWE-778은 보안상 중요한 사건을 기록하지 않는 약점이라 하위 시드(로깅)와만 맞는다. "
                "'장기 잠복을 탐지하지 못함'은 기록 부재보다 넓은 개념이라 일부만 맞는다.",
    },
    "INSUFFICIENT_LOGGING_AUDIT": {
        "fit": "close", "cwe_verified": ["CWE-778"], "cwe_unverified": [],
        "note": "필요한 보안 이벤트를 기록하지 않는 약점(CWE-778)과 분명히 대응한다.",
    },
    "INSUFFICIENT_SECURITY_MONITORING_OPERATIONS": {
        "fit": "none", "cwe_verified": [], "cwe_unverified": [],
        "note": "관제 인력, 모니터링 절차, 경보 검토 체계는 제품의 약점이 아니라 조직의 운영 문제라서 CWE에 대응이 없다.",
    },
    "INADEQUATE_INCIDENT_RESPONSE": {
        "fit": "none", "cwe_verified": [], "cwe_unverified": [],
        "note": "과거 침해에 대한 대응 실패는 제품의 약점이 아니라 조직의 절차 문제라서 CWE에 대응이 없다. "
                "다른 표준(예: 침해 대응·보안 관리 프레임워크)을 대응 후보로 검토해야 하나 확인하지 않았다.",
    },
    "THIRD_PARTY_OR_SUPPLY_CHAIN_RISK": {
        "fit": "partial", "cwe_verified": ["CWE-1395", "CWE-1357"], "cwe_unverified": [],
        "note": "OWASP Top 10 2025에 'Software Supply Chain Failures'(A03)가 있어 개념은 표준에 있다. "
                "다만 CWE는 제품이 쓰는 구성요소의 약점이고, 협력사가 침해되어 그 접근 권한이 악용된 경우까지 덮지는 않는다.",
    },
    "MISCONFIGURATION": {
        "fit": "partial", "cwe_verified": ["CWE-1188"], "cwe_unverified": [],
        "note": "'설정(CWE-16)'은 폐기된 그룹이라 매핑이 금지되어 있다. CWE는 설정 오류를 독립된 약점이 아니라 "
                "그 설정이 만든 행동의 약점(접근 통제 계열 등)으로 매핑하라고 한다. CWE-1188(안전하지 않은 기본값)은 일부만 덮는다.",
    },
}

# CWE 5.0 파일(2026-10-28)에서 확인한 MITRE의 매핑 사용 구분. cwe_catalog.py가 같은 값을 파일에서 읽는다.
# Allowed / Allowed-with-Review / Discouraged(더 구체적인 하위 항목을 쓰라는 뜻) / Prohibited(그룹, 폐기 등)
ROOT_CAUSE_CWE_MAPPING_USAGE = {
    "CWE-1395": "Allowed-with-Review", "CWE-1104": "Allowed", "CWE-798": "Allowed-with-Review", "CWE-324": "Allowed",
    "CWE-311": "Discouraged", "CWE-326": "Allowed-with-Review", "CWE-327": "Allowed-with-Review",
    "CWE-284": "Discouraged", "CWE-862": "Allowed-with-Review", "CWE-863": "Allowed-with-Review", "CWE-306": "Allowed",
    "CWE-778": "Allowed", "CWE-1357": "Allowed-with-Review", "CWE-1188": "Allowed",
}

# 대응표에서 의도적으로 뺀 CWE와 이유(문서가 이 번호를 인용하면 연결하지 않고 사람 확인으로 보낸다)
ROOT_CAUSE_CWE_EXCLUDED = {
    "CWE-320": "Key Management Errors: 그룹이고 폐기(Obsolete), 매핑 금지. 멤버 약점 322, 323, 324, 798을 쓴다",
    "CWE-16": "Configuration: 그룹이고 폐기(Obsolete), 매핑 금지, 멤버 약점 없음. 설정이 만든 행동의 약점으로 매핑한다",
}


# 겹치는 항목의 선 긋기. 원칙: 문서가 말한 '실패한 통제'를 기준으로 하고 결과(피해)로 고르지 않는다.
# 문서가 서로 다른 실패를 둘 말하면 값도 둘이다(트리플렛 둘). 한 실패에 값을 둘 붙이지 않는다.
ROOT_CAUSE_BOUNDARY_RULES = {
    ("WEAK_ACCESS_CONTROL", "CREDENTIAL_OR_KEY_MISMANAGEMENT"):
        "자격 증명·키의 수명주기(발급, 보관, 교체, 폐기, 노출)가 실패했으면 CREDENTIAL. "
        "권한의 범위·분리·인증 요구(다중 인증, 망 분리, 최소 권한)가 없거나 약하면 WEAK_ACCESS_CONTROL.",
    ("UNPATCHED_KNOWN_VULNERABILITY", "THIRD_PARTY_OR_SUPPLY_CHAIN_RISK"):
        "피해 조직이 자기 시스템에서 공개된 패치를 적용하지 않았으면 UNPATCHED. "
        "외부 공급사·협력사·구성요소가 침해되었거나 그 신뢰가 악용되었으면 THIRD_PARTY.",
    ("INSUFFICIENT_MONITORING_DETECTION", "INADEQUATE_INCIDENT_RESPONSE"):
        "침입 자체를 알아채지 못했으면(체류 기간이 길었으면) MONITORING 계열. "
        "경보나 과거 침해를 알고도 차단·정리·재발 방지를 하지 않았으면 INCIDENT_RESPONSE.",
    ("INSUFFICIENT_MONITORING_DETECTION", "INSUFFICIENT_LOGGING_AUDIT"):
        "탐지 실패만 말하고 이유를 말하지 않으면 상위(MONITORING). 필요한 로그가 생성·수집·보존되지 않았다고 말할 때만 LOGGING_AUDIT.",
    ("INSUFFICIENT_MONITORING_DETECTION", "INSUFFICIENT_SECURITY_MONITORING_OPERATIONS"):
        "탐지 실패만 말하고 이유를 말하지 않으면 상위(MONITORING). 관제 인력·절차·경보 검토 체계가 없다고 말할 때만 OPERATIONS.",
    ("INSUFFICIENT_LOGGING_AUDIT", "INSUFFICIENT_SECURITY_MONITORING_OPERATIONS"):
        "로그 자체가 없거나 보존되지 않았으면 LOGGING_AUDIT, 로그는 있으나 보는 사람·절차가 없으면 OPERATIONS. 둘 다 말하면 값도 둘이고 각각 근거 문장이 있어야 한다.",
    ("INSUFFICIENT_SECURITY_MONITORING_OPERATIONS", "INADEQUATE_INCIDENT_RESPONSE"):
        "경보를 검토할 인력·절차·체계가 없어 알아채지 못했으면 OPERATIONS. 경보를 인지하고도 차단·격리를 하지 않았으면 INCIDENT_RESPONSE.",
    ("MISCONFIGURATION", "INSUFFICIENT_LOGGING_AUDIT"):
        "탐지 규칙이나 로그 설정이 잘못되어 있었다고 말하면 MISCONFIGURATION. 로그 기능 자체가 없었다고 말하면 LOGGING_AUDIT.",
    ("MISCONFIGURATION", "WEAK_ACCESS_CONTROL"):
        "문서가 '잘못된 설정·기본값'을 원인으로 말하면 MISCONFIGURATION. "
        "통제 자체가 설계에 없었거나 약했다고 말하면 WEAK_ACCESS_CONTROL.",
    ("INSUFFICIENT_ENCRYPTION", "WEAK_ACCESS_CONTROL"):
        "저장·전송 데이터가 암호화되지 않았거나 약하게 암호화되었다고 말할 때만 INSUFFICIENT_ENCRYPTION. "
        "암호화 이야기가 없으면 쓰지 않는다.",
}

# 경계 사례: (합성 문장, 기대하는 값 목록). 기대 목록이 빈 리스트면 어떤 값도 기록하지 않는다(추측 금지).
# 문장은 규칙을 시험하려고 만든 가상 문장이며 실제 사건의 사실이 아니다. 추출 프롬프트의 예시와 시험에 쓴다.
ROOT_CAUSE_BOUNDARY_EXAMPLES = [
    ("The company had not applied a patch for an operating system flaw that was publicly known for years.",
     ["UNPATCHED_KNOWN_VULNERABILITY"]),
    ("A signing key issued to a contractor was never revoked after the contractor left, and was later used to log in.",
     ["CREDENTIAL_OR_KEY_MISMANAGEMENT"]),
    ("Administrator accounts could reach every internal server because the network was not segmented and no second factor was required.",
     ["WEAK_ACCESS_CONTROL"]),
    ("The vendor's update server was compromised and a signed update carried the malware into customer networks.",
     ["THIRD_PARTY_OR_SUPPLY_CHAIN_RISK"]),
    ("Customer data was stored without encryption and a stolen backup was readable.",
     ["INSUFFICIENT_ENCRYPTION"]),
    ("The intruder stayed in the network for three years before anyone noticed.",
     ["INSUFFICIENT_MONITORING_DETECTION"]),
    ("The company had received an alert about the intrusion but did not isolate the server for weeks.",
     ["INADEQUATE_INCIDENT_RESPONSE"]),
    ("A storage bucket was left public because of a default setting nobody changed.",
     ["MISCONFIGURATION"]),
    # 한 문장에 서로 다른 실패가 둘 있으면 값도 둘이다
    ("Credentials were never rotated, and the intruder went unnoticed for months.",
     ["CREDENTIAL_OR_KEY_MISMANAGEMENT", "INSUFFICIENT_MONITORING_DETECTION"]),
    # 결과로 고르지 않는다: 피해가 크다는 말만으로는 원인을 정하지 않는다
    ("The breach exposed millions of customer records.", []),
    # 원인을 말하지 않은 문장
    ("The investigation is ongoing and the cause has not been disclosed.", []),
    # 모니터링: 하위 시드는 출처가 직접 말할 때만 쓴다
    ("Security audit logs were never generated for the authentication service, so the intrusion left no record.",
     ["INSUFFICIENT_LOGGING_AUDIT"]),
    ("Logs were collected, but nobody was assigned to review the alerts outside business hours.",
     ["INSUFFICIENT_SECURITY_MONITORING_OPERATIONS"]),
    ("A detection rule had been configured with the wrong pattern, so it never matched the attack.",
     ["MISCONFIGURATION"]),
    ("The company had no 24-hour monitoring team and no security audit logs for the service.",
     ["INSUFFICIENT_SECURITY_MONITORING_OPERATIONS", "INSUFFICIENT_LOGGING_AUDIT"]),
]


def render_root_cause_table() -> str:
    """CWE 대응표를 표로 출력한다(README와 전문가 검토용)."""
    lines = ["| RootCause | 대응 | CWE (MITRE 매핑 구분) |", "| --- | --- | --- |"]
    for k in ROOT_CAUSE_SEED:
        m = ROOT_CAUSE_CWE_MAP[k]
        cw = ", ".join(f"{c} ({ROOT_CAUSE_CWE_MAPPING_USAGE[c]})" for c in m["cwe_verified"] + m["cwe_unverified"]) or "-"
        lines.append(f"| `{k}` | {m['fit']} | {cw} |")
    return "\n".join(lines)


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
# 확인(2026-11-27): VERIS 공식 스키마(vz-risk/veris의 verisc-merged.json)의 행위자 최상위가 external, internal, partner, unknown이고
# 값 이름이 아래 대응과 맞는다. `python veris_check.py`가 같은 검사를 한다.
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
    ("외부 공격자가 협력사 직원의 계정을 탈취해 침입에 썼다", "EXTERNAL"),     # 공격자는 외부, 계정 소유자는 협력사(아래 ACCOUNT_OWNER_EXAMPLES)
    ("협력사 직원이 자신의 업무 접근 권한을 악용해 데이터를 빼냈다", "PARTNER"),
    ("퇴사한 직원이 과거 접근 권한이나 정보를 쓰지 않고 공개된 취약점을 외부에서 공격했다", "EXTERNAL"),   # 전직자라는 사실만으로 FORMER_INSIDER를 주지 않는다
    ("이름 있는 해킹 조직이 외부에서 침입했다", "EXTERNAL"),
    ("개발자가 가진 접근 권한으로 침해가 일어났다(고용 상태와 시점이 적혀 있지 않음)", None),
]

# 결정 기록(2-1): 공격자 유형과 계정 소유자는 별개다(전문가 검토 의견). (사례, 공격자 유형, 계정 소유자 유형).
# 값이 None이면 기록하지 않는다(추측 금지). 소유자는 ACCOUNT_OWNER_ORIGIN 관계로 따로 기록한다.
ACCOUNT_OWNER_EXAMPLES = [
    ("외부 공격자가 협력사 직원의 계정을 탈취해 침입에 썼다", "EXTERNAL", "PARTNER"),
    ("협력사 직원이 자기 계정으로 직접 데이터를 빼냈다", "PARTNER", "PARTNER"),
    ("퇴사자가 남아 있던 서명키로 인증 토큰을 위조했다", "FORMER_INSIDER", None),
    ("누군가의 계정이 쓰였으나 누구의 것인지, 누가 썼는지는 밝혀지지 않았다", None, None),
]

# VERIS와의 세부 대응(전문가 검토 의견): VERIS는 전직 직원을 External 행위자의 한 종류('Former employee')로 둔다고 알려져 있다.
# **확인됨(2026-11-27)**: VERIS 공식 스키마의 actor.external.variety에 'Former employee'가 있다(README 확인-A3). `python veris_check.py`로 다시 확인할 수 있다.
# 값을 VERIS로 내보낼 때 FORMER_INSIDER는 actor.external, variety 'Former employee'로 변환한다.
ACTOR_ORIGIN_VERIS_VARIETY = {"FORMER_INSIDER": "Former employee"}

# 결정 기록(3): 행위자가 둘 이상일 때 값과 이름의 짝 짓기는 파일럿에서 필요가 확인될 때까지 하지 않는다(옵션 i).
# 지금은 사건 단위로만 기록하고 값이 여러 개면 aggregate.py가 "사람이 확인 필요"로 표시한다.
ACTOR_PAIRING = "incident_level"   # 행위자별 기록("actor_level")은 보류

# 결정 기록(4): 행위자 이름 연결. ATT&CK 그룹은 정확히 일치하면 연결하고, MISP는 후보로만 제시하며 둘을 합치지 않는다(옵션 A).
# 근거: MISP에서 48개 별칭이 둘 이상의 항목에 나오고, ATT&CK과 MISP가 같은 이름을 다른 행위자 범위로 쓴다
# (예: ATT&CK은 Andariel을 Lazarus Group과 따로 두지만 MISP는 Lazarus Group의 별칭으로 둔다). actors.py가 이 규칙을 구현한다.
ACTOR_NAME_LINKING = {
    "attack_exact_unique": "link",     # ATT&CK 그룹 한 곳의 이름·별칭과 정확히 일치
    "attack_ambiguous": "review",      # 둘 이상의 그룹에 일치
    "misp_only": "review",             # MISP에만 일치: 후보로 제시하고 사람이 확인
    "not_found": "none",               # 어디에도 없음: 새 행위자일 수 있어 연결하지 않음
}
MISP_MERGE_WITH_ATTACK = False         # 두 출처를 같은 행위자로 합치지 않는다

# 결정 기록(5): ATT&CK과 MISP 어디에도 없는 이름(한국어 표기, 줄임말, 새 행위자 등)의 처리. actors.plan_actor가 구현한다.
# 별칭 사전: 사람이 확인한 별칭만 넣는다. 사전에 있으면 연결하고, 없으면 새 노드를 만들되 확인 대기로 표시한다.
# 아래 값은 제 일반 지식으로 만든 후보이고 이 세션에서 확인하지 않았다. 사용 전에 사람이 확인해야 한다.
# 키는 ATT&CK 그룹 ID이며, actors.validate_alias_seed가 실제 목록에 있는지 점검한다.
ACTOR_ALIAS_SEED = {
    "G0094": {"canonical": "Kimsuky", "aliases": ["김수키"]},
    "G0032": {"canonical": "Lazarus Group", "aliases": ["라자루스", "Lazarus"]},
    "G0138": {"canonical": "Andariel", "aliases": ["안다리엘"]},
}
ACTOR_NEW_NODE_POLICY = {
    "origin": "document_added",            # 표준(ATT&CK)에서 온 노드와 구분한다
    "status": "pending_review",            # 사람이 확인하기 전까지 확인 대기
    "auto_merge_by_similarity": False,     # 이름 유사도로 자동 합치지 않는다(원본의 합치기를 이 종류에는 쓰지 않음)
    "ai_english_name": "ai_suggested",     # AI가 제안한 영문명은 확정으로 세지 않고 후보로만 보여 준다
    "skip_if_software_name": True,         # 악성코드·도구 이름이면 행위자 노드를 만들지 않고 종류 확인으로 보낸다
}

# 행위자 이름 추출 프롬프트 초안(영문). 이 저장소에는 AI 호출 코드가 없고 이 프롬프트는 실제 모델로 시험하지 않았다.
# 응답 형식은 actor_review.parse_ai_name_response가 검증한다. english_name은 후보일 뿐 확정으로 세지 않는다(ACTOR_NEW_NODE_POLICY).
ACTOR_NAME_EXTRACTION_PROMPT = """You will read a security incident document and list every named attacker (threat actor) it mentions.

Return JSON only, in this shape:
{"names": [{"name_as_written": str, "english_name": str | null, "name_type": str, "confidence": str, "evidence": str}]}

Rules:
- name_as_written: copy the name exactly as it appears in the document, in the document's own language and spelling.
- english_name: ONLY if you are confident the same attacker is commonly known by an English or vendor name (for example the name MITRE ATT&CK or a major
  security vendor uses). If you are not sure, use null. Do NOT translate or transliterate by guessing, and do NOT invent a name.
- name_type: one of "threat_actor", "malware", "tool", "campaign", "organization", "person", "other".
  A malware or tool name (for example a backdoor name) is NOT a threat actor; label it "malware" or "tool".
  Unnamed attackers ("hackers", "the attacker") must not be listed.
- confidence: "high", "medium", or "low" for the english_name only.
- evidence: the exact sentence from the document in which the name appears.
- List each distinct name once. If the document names no attacker, return {"names": []}.
"""
ACTOR_NAME_TYPES = ["threat_actor", "malware", "tool", "campaign", "organization", "person", "other"]


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
# 5-1. 기법 층: 서술형 행동 → ATT&CK 매핑 → 뼈대 유도 [신규] — attack_mapping.py가 읽는다
#      결정: D5 2층(서술형을 먼저 기록, ATT&CK 매핑은 별도 단계, 악성코드는 뼈대에서 기법 유도) /
#            D6 AI가 후보를 제안하고 사람이 확인(파일럿) / D7 비교는 전술, 상세는 기법, 하위 기법은 문서가 구체적일 때만 /
#            D8 뼈대에서 유도한 기법은 답에 포함하되 "문서의 주장이 아니라 뼈대 유도"로 구분.
#      매핑 결과에는 신뢰도와 근거가 필요해서 트리플렛이 아니라 별도 기록으로 둔다:
#        {"behavior": 서술형 행동, "candidates": [{"technique_id", "confidence", "evidence"}], "status": ...}
# ──────────────────────────────────────────────────────────────────────────
ATTACK_MAPPING_STATUSES = {
    "documented": "문서가 ATT&CK 기법 이름·ID를 직접 씀 (USED_TECHNIQUE 트리플렛). 별도 매핑 불필요",
    "ai_suggested": "AI가 후보를 제안했으나 사람이 아직 확인하지 않음. 확정으로 세지 않는다",
    "human_confirmed": "사람이 후보를 확인함",
    "human_rejected": "사람이 후보를 기각함. 답에서 제외한다",
    "no_match": "ATT&CK에 맞는 기법이 없다고 판단함. 억지로 맞추지 않고 서술형으로 남긴다",
}
MAPPING_CONFIDENCE_LEVELS = ["high", "medium", "low"]
MAPPING_REQUIRES_HUMAN_CONFIRMATION = True      # D6: 파일럿에서는 사람이 확인해야 확정으로 센다
COMPARISON_LEVEL = "tactic"                      # D7: 사건 간 비교는 전술 수준
ALLOW_SUBTECHNIQUE_ONLY_IF_SPECIFIC = True       # D7: 문서가 구체적일 때만 하위 기법, 아니면 상위 기법으로 올린다
INCLUDE_BACKBONE_DERIVED_TECHNIQUES = True       # D8: 악성코드에서 유도한 기법을 답에 포함
BACKBONE_DERIVED_LABEL = "backbone_derived"      #     포함하되 이 이름표로 구분한다
MAPPING_EVIDENCE_STRENGTH = ["direct", "implied", "inferred"]   # 근거의 직접성(AI confidence와 별개). 모르는 값은 inferred로 낮춘다
# 같은 기법이 여러 출처에서 나올 때 전술 집계에는 가장 강한 하나만 센다(강한 순서). documented는 출처의 assertion_status가
# confirmed일 때만 확정으로 세고, 아니면 documented_unconfirmed로 따로 센다.
TECHNIQUE_LABEL_PRIORITY = ["confirmed", "documented", "documented_unconfirmed", "ai_suggested", BACKBONE_DERIVED_LABEL]

# 매핑 단계의 프롬프트 규칙(영문). 후보는 반드시 내려받은 ATT&CK 목록 안의 것이어야 하고, 목록에 없는 ID는 버린다.
ATTACK_MAPPING_RULES = [
    "Map an AttackBehavior to an ATT&CK technique only when the evidence span supports it.",
    "Prefer the technique level. Use a sub-technique only when the text is specific enough; otherwise use the parent.",
    "If only the attacker's goal is clear, say so and give the tactic; do not guess a technique.",
    "If ATT&CK has no matching technique, answer no_match. Never force a match.",
    "Candidates must come from the provided ATT&CK catalogue. Never invent an ID or a name.",
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
# 5-2. 수치(피해 규모, 금액) [신규] — measurements.py가 읽는다
#      결정: D9 트리플렛이 아니라 별도 기록(단위·정확도·시점·출처가 붙는 필드 묶음) /
#            D10 닫힌 소수 지표 + other(원문 표현 보존), 사람·건수·용량은 서로 다른 지표라 합치지 않음 /
#            D11 출처 간 차이는 자동으로 조정하지 않고 나란히 보여 줌(같은 지표 안에서만 범위 계산) /
#            D12 원문 수치 문자열과 근거 문장을 같이 기록하고, 정규화는 AI 없이 규칙 코드로 하며,
#                단위가 안 읽히면 버리지 않고 unit_unknown으로 사람 확인.
#      기록: {"incident", "metric", "raw", "evidence", "as_of", "doc_id", "source_type", "assertion_status"}
#            (+ 정규화 결과 value, value_high, unit_kind, currency, qualifier, review)
# ──────────────────────────────────────────────────────────────────────────
MEASUREMENT_METRICS = {
    "affected_people": {"unit_kind": "people", "description": "Number of people (individuals/customers/users) affected"},
    "affected_records": {"unit_kind": "records", "description": "Number of records/items exposed (a person can have several)"},
    "data_volume": {"unit_kind": "bytes", "description": "Volume of data exfiltrated or exposed"},
    "fine": {"unit_kind": "money", "description": "Penalty or fine imposed by an authority"},
    "loss_estimate": {"unit_kind": "money", "description": "Estimated financial loss, cost or damages (not a fine)"},
    "other": {"unit_kind": None, "description": "Any number not covered above; keep the document's own wording in 'raw'"},
}
MEASUREMENT_QUALIFIERS = ["exact", "approx", "lower_bound", "upper_bound", "range"]
# 같은 지표라도 단위 종류가 다르면(사람 vs 건수 등) 합치거나 비교하지 않는다
MEASUREMENT_COMPARE_ACROSS_METRICS = False
MEASUREMENT_CONVERT_CURRENCY = False             # 환율 시점 문제로 환산하지 않는다. 통화별로 따로 둔다
MEASUREMENT_REVIEW_REASONS = {
    "no_number": "숫자가 없는 표현(예: '수백만'). 값은 비워 두고 원문만 보존한다",
    "unit_unknown": "단위를 읽지 못함. 버리지 않고 사람이 확인한다",
    "unit_mismatch": "지표가 요구하는 단위 종류와 원문 단위가 다름(예: affected_people인데 '건')",
    "raw_not_in_evidence": "원문 수치 문자열이 근거 문장에 없음(추출 오류 가능성)",
    "unknown_metric": "정의되지 않은 지표 이름이라 other로 바꿈",
}
MEASUREMENT_NOT_MENTIONED_TEXT = "확인되지 않음: 처리한 문서 {n}개 중 수치 언급 없음"


# ──────────────────────────────────────────────────────────────────────────
# 6. 답의 집계 [신규] — '취약점 없음/미공개'를 다루는 최소안
#    원칙: 부재를 추측하지 않는다. 트리플렛이 없으면 "없음"이 아니라 "언급 없음(처리한 문서 n개 중)"이다.
#    새 개체 종류나 관계를 추가하지 않는다. aggregate.py가 이 설정으로 사건별 답을 만든다.
# ──────────────────────────────────────────────────────────────────────────

# 질문 틀의 칸 → 그 칸의 답이 되는 관계. 이 관계의 트리플렛이 하나라도 있으면 그 칸은 "있음"이다.
ANSWER_SLOTS = {
    "a_vulnerability": ["EXPLOITED_VULNERABILITY"],
    "b_weakness_or_failure": ["EXPLOITED_WEAKNESS", "HAS_ROOT_CAUSE"],
    "c_technique": ["USED_BEHAVIOR", "USED_TECHNIQUE", "USED_MALWARE"],
}

# 질문의 칸은 아니지만 답과 함께 보여 줄 참고 정보 → 그 정보의 답이 되는 관계. 상태 규칙은 칸과 같다.
CONTEXT_FIELDS = {
    "actor_origin": ["HAS_ACTOR_ORIGIN"],
    "account_owner_origin": ["ACCOUNT_OWNER_ORIGIN"],   # 공격자 유형과 섞지 않는다
    "attribution": ["ATTRIBUTED_TO"],
    "affected_asset": ["AFFECTED_ASSET"],
}
# 값이 여러 개 나오면 사람이 확인하도록 표시할 참고 정보
# (문서들이 서로 다른 값을 말했거나 사건에 행위자가 둘 이상일 수 있다)
REVIEW_IF_MULTIPLE_VALUES = ["actor_origin", "account_owner_origin"]

# 칸의 상태. 최소안에서는 두 가지뿐이다. (구분이 필요해지면 확장안: README 참고)
SLOT_STATES = {
    "found": "하나 이상의 문서가 답을 제시함",
    "not_mentioned": "처리한 문서 중 어느 것도 이 칸을 언급하지 않음(= '없음'이 아니라 '확인 안 됨')",
}
# 정답표(`fact_check/answer_key_draft.csv`)의 칸 상태(slot_state) 5가지의 정의와 사용 조건. 집계(aggregate.py)의 두 상태는
# 아래 SLOT_STATE_ALIASES로 대응시킨다. not_confirmed는 집계 코드가 아직 표현하지 못한다(README의 보류한 확장안과 함께 파일럿에서 도입).
ANSWER_KEY_SLOT_STATES = {
    "answered": "처리한 문서가 이 칸의 답을 제시함. assertion_status(confirmed, claimed, inferred)를 함께 붙인다",
    "not_confirmed": "관련 정보가 있으나 출처가 '조사 중', '확인하지 못함'이라고 말해 확정되지 않음",
    "not_mentioned_in_sources": "문서를 처리했으나 이 칸에 해당하는 언급이 없음. '없다'는 뜻이 아니다",
    "not_applicable": "출처가 이 질문이 이 사건에 해당하지 않는다고 직접 말함. 출처의 직접 진술이 있을 때만 쓴다",
    "not_assessed": "아직 이 칸을 평가하지 않았거나 문서를 처리하지 않음. 정답표를 만드는 도중의 상태",
}
SLOT_STATE_ALIASES = {"found": "answered", "not_mentioned": "not_mentioned_in_sources"}
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
    if "USED_BEHAVIOR" not in ANSWER_SLOTS["c_technique"]:
        problems.append("칸 (c)에 USED_BEHAVIOR가 없음")
    if "AttackBehavior" not in ENTITY_TYPES_TO_ADD_INSTANCES:
        problems.append("AttackBehavior가 추가 가능 목록에 없음")
    if "AttackBehavior" in EMBEDDING_MATCH_ENTITIES or "AttackBehavior" in EXACT_ID_ENTITIES:
        problems.append("AttackBehavior는 열린 서술형이라 뼈대 연결 대상이 아님")
    if COMPARISON_LEVEL not in ("tactic", "technique"):
        problems.append("COMPARISON_LEVEL은 tactic 또는 technique이어야 함")
    if set(MAPPING_CONFIDENCE_LEVELS) != {"high", "medium", "low"}:
        problems.append("MAPPING_CONFIDENCE_LEVELS가 올바르지 않음")
    if set(ACTOR_ORIGIN_TO_VERIS) != set(ACTOR_ORIGIN_SEED):
        problems.append("ACTOR_ORIGIN_TO_VERIS의 키가 ACTOR_ORIGIN_SEED와 다름")
    for text, expected in ACTOR_ORIGIN_BOUNDARY_EXAMPLES:
        if expected is not None and expected not in ACTOR_ORIGIN_SEED:
            problems.append(f"경계 사례의 기대값이 시드에 없음: {expected}")
    if ACTOR_PAIRING not in ("incident_level", "actor_level"):
        problems.append("ACTOR_PAIRING은 incident_level 또는 actor_level이어야 함")
    if sorted(ACTOR_ORIGIN_SEED) != sorted(["INTERNAL", "FORMER_INSIDER", "PARTNER", "EXTERNAL"]):
        problems.append("ACTOR_ORIGIN_SEED가 정의 문구의 값과 다름")
    if "other" not in MEASUREMENT_METRICS:
        problems.append("MEASUREMENT_METRICS에 other가 없음")
    for m, spec in MEASUREMENT_METRICS.items():
        if spec["unit_kind"] not in (None, "people", "records", "bytes", "money"):
            problems.append(f"MEASUREMENT_METRICS[{m}]: 알 수 없는 unit_kind")
    if "range" not in MEASUREMENT_QUALIFIERS:
        problems.append("MEASUREMENT_QUALIFIERS에 range가 없음")
    if MEASUREMENT_COMPARE_ACROSS_METRICS or MEASUREMENT_CONVERT_CURRENCY:
        problems.append("지표 간 비교와 통화 환산은 결정 D10/D12에서 하지 않기로 함")
    if set(ROOT_CAUSE_CWE_MAP) != set(ROOT_CAUSE_SEED):
        problems.append("ROOT_CAUSE_CWE_MAP의 키가 ROOT_CAUSE_SEED와 다름")
    for k, m in ROOT_CAUSE_CWE_MAP.items():
        if m["fit"] not in ("close", "partial", "none"):
            problems.append(f"ROOT_CAUSE_CWE_MAP[{k}]: fit 값이 올바르지 않음")
        if m["fit"] == "none" and (m["cwe_verified"] or m["cwe_unverified"]):
            problems.append(f"ROOT_CAUSE_CWE_MAP[{k}]: fit이 none인데 CWE가 있음")
        if m["fit"] != "none" and not (m["cwe_verified"] or m["cwe_unverified"]):
            problems.append(f"ROOT_CAUSE_CWE_MAP[{k}]: CWE가 하나도 없음")
        if set(m["cwe_verified"]) & set(m["cwe_unverified"]):
            problems.append(f"ROOT_CAUSE_CWE_MAP[{k}]: 확인한 것과 못 한 것이 겹침")
    for pair in ROOT_CAUSE_BOUNDARY_RULES:
        for x in pair:
            if x not in ROOT_CAUSE_SEED:
                problems.append(f"ROOT_CAUSE_BOUNDARY_RULES: 시드에 없는 값 {x}")
    for text, expected in ROOT_CAUSE_BOUNDARY_EXAMPLES:
        for x in expected:
            if x not in ROOT_CAUSE_SEED:
                problems.append(f"ROOT_CAUSE_BOUNDARY_EXAMPLES: 시드에 없는 값 {x}")
    for k, usage in ROOT_CAUSE_CWE_MAPPING_USAGE.items():
        if usage not in ("Allowed", "Allowed-with-Review", "Discouraged", "Prohibited"):
            problems.append(f"ROOT_CAUSE_CWE_MAPPING_USAGE[{k}]: 알 수 없는 값")
    in_map = {c for m in ROOT_CAUSE_CWE_MAP.values() for c in m["cwe_verified"] + m["cwe_unverified"]}
    if in_map != set(ROOT_CAUSE_CWE_MAPPING_USAGE):
        problems.append("ROOT_CAUSE_CWE_MAPPING_USAGE의 키가 대응표의 CWE와 다름")
    if in_map & set(ROOT_CAUSE_CWE_EXCLUDED):
        problems.append("제외한 CWE가 대응표에 있음")
    if any(u == "Prohibited" for c, u in ROOT_CAUSE_CWE_MAPPING_USAGE.items() if c in in_map):
        problems.append("매핑이 금지된(Prohibited) CWE가 대응표에 있음")
    covered_by_examples = {x for _, exp in ROOT_CAUSE_BOUNDARY_EXAMPLES for x in exp}
    for k in ROOT_CAUSE_SEED:
        if k not in covered_by_examples:
            problems.append(f"ROOT_CAUSE_BOUNDARY_EXAMPLES: 시드 {k}를 보여 주는 사례가 없음")
    # RootCause 계층과 속성, 표준 매핑
    seeds = set(ROOT_CAUSE_SEED)
    if len(ROOT_CAUSE_SEED) != len(seeds):
        problems.append("ROOT_CAUSE_SEED에 중복이 있음")
    for child, parent in ROOT_CAUSE_PARENT.items():
        if child not in seeds or parent not in seeds:
            problems.append(f"ROOT_CAUSE_PARENT: 시드에 없는 값 {child} → {parent}")
        elif ROOT_CAUSE_PARENT.get(parent):
            problems.append(f"ROOT_CAUSE_PARENT: 하위의 하위는 두지 않음 {child}")
        elif ROOT_CAUSE_ATTRIBUTES.get(child, {}).get("control_domain") != ROOT_CAUSE_ATTRIBUTES.get(parent, {}).get("control_domain"):
            problems.append(f"ROOT_CAUSE_ATTRIBUTES: {child}와 상위 {parent}의 control_domain이 다름")
    if set(ROOT_CAUSE_MEANING) != seeds:
        problems.append("ROOT_CAUSE_MEANING의 키가 ROOT_CAUSE_SEED와 다름")
    if set(ROOT_CAUSE_ATTRIBUTES) != seeds:
        problems.append("ROOT_CAUSE_ATTRIBUTES의 키가 ROOT_CAUSE_SEED와 다름")
    for k, a in ROOT_CAUSE_ATTRIBUTES.items():
        if a["failure_nature"] is not None and a["failure_nature"] not in FAILURE_NATURES:
            problems.append(f"ROOT_CAUSE_ATTRIBUTES[{k}]: failure_nature 값이 올바르지 않음")
        if a["failure_nature"] is None and k not in set(ROOT_CAUSE_PARENT.values()):
            problems.append(f"ROOT_CAUSE_ATTRIBUTES[{k}]: failure_nature가 미정(None)인 것은 하위가 있는 상위 시드뿐")
        if a["control_domain"] not in CONTROL_DOMAINS:
            problems.append(f"ROOT_CAUSE_ATTRIBUTES[{k}]: control_domain 값이 올바르지 않음")
    for child in ROOT_CAUSE_PARENT:
        if ROOT_CAUSE_ATTRIBUTES.get(child, {}).get("failure_nature") is None:
            problems.append(f"ROOT_CAUSE_ATTRIBUTES[{child}]: 하위 시드는 성격이 정해져 있어야 함")
    if set(ROOT_CAUSE_STANDARD_MAP) != seeds:
        problems.append("ROOT_CAUSE_STANDARD_MAP의 키가 ROOT_CAUSE_SEED와 다름")
    csf_re = re.compile(r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}(-\d{2})?$")
    r5_re = re.compile(r"^[A-Z]{2}-\d{1,2}$")
    for k, m in ROOT_CAUSE_STANDARD_MAP.items():
        for i in m["nist_csf"]:
            if not csf_re.match(i):
                problems.append(f"ROOT_CAUSE_STANDARD_MAP[{k}]: CSF ID 형식이 올바르지 않음 {i} (범위 표기는 쓰지 않음)")
        for i in m["nist_800_53"]:
            if not r5_re.match(i):
                problems.append(f"ROOT_CAUSE_STANDARD_MAP[{k}]: 800-53 통제 ID 형식이 올바르지 않음 {i} (패밀리가 아니라 개별 통제 ID)")
        for i in m["nist_partial"]:
            if not (csf_re.match(i) or r5_re.match(i)):
                problems.append(f"ROOT_CAUSE_STANDARD_MAP[{k}]: 부분 적합 ID 형식이 올바르지 않음 {i}")
        if set(m["nist_partial"]) & (set(m["nist_csf"]) | set(m["nist_800_53"])):
            problems.append(f"ROOT_CAUSE_STANDARD_MAP[{k}]: 적합과 부분 적합에 같은 ID가 있음")
        if m["mapping_status"] not in MAPPING_STATUSES_STANDARD:
            problems.append(f"ROOT_CAUSE_STANDARD_MAP[{k}]: mapping_status 값이 올바르지 않음")
        if (m["mapping_status"] == "confirmed") != bool(m["reviewed_by"]):
            problems.append(f"ROOT_CAUSE_STANDARD_MAP[{k}]: 확정(confirmed)과 검토자(reviewed_by)가 일치하지 않음")
    if not ROOT_CAUSE_ASSIGNMENT_RULES:
        problems.append("ROOT_CAUSE_ASSIGNMENT_RULES가 비어 있음")
    for text, attacker, owner in ACCOUNT_OWNER_EXAMPLES:
        for x in (attacker, owner):
            if x is not None and x not in ACTOR_ORIGIN_SEED:
                problems.append(f"ACCOUNT_OWNER_EXAMPLES: 시드에 없는 값 {x}")
    if set(ACTOR_ORIGIN_VERIS_VARIETY) - set(ACTOR_ORIGIN_SEED):
        problems.append("ACTOR_ORIGIN_VERIS_VARIETY의 키가 ACTOR_ORIGIN_SEED에 없음")
    if set(SLOT_STATE_ALIASES.values()) - set(ANSWER_KEY_SLOT_STATES):
        problems.append("SLOT_STATE_ALIASES가 ANSWER_KEY_SLOT_STATES에 없는 값을 가리킴")
    if MISP_MERGE_WITH_ATTACK:
        problems.append("MISP와 ATT&CK 행위자는 합치지 않기로 함(결정 4)")
    if set(ACTOR_NAME_LINKING.values()) - {"link", "review", "none"}:
        problems.append("ACTOR_NAME_LINKING 값이 올바르지 않음")
    if ACTOR_NEW_NODE_POLICY["auto_merge_by_similarity"]:
        problems.append("행위자는 이름 유사도로 자동 합치지 않기로 함(결정 5)")
    for gid, e in ACTOR_ALIAS_SEED.items():
        if not re.match(r"^G\d{4}$", gid) or not e.get("canonical") or not e.get("aliases"):
            problems.append(f"ACTOR_ALIAS_SEED[{gid}]: 형식이 올바르지 않음")
    if "threat_actor" not in ACTOR_NAME_TYPES or "{" not in ACTOR_NAME_EXTRACTION_PROMPT:
        problems.append("ACTOR_NAME_TYPES 또는 ACTOR_NAME_EXTRACTION_PROMPT가 올바르지 않음")
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
