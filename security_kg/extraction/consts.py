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
    "cwe": "5.0 (2026-10-28), cwec_v5.0.xml. 메인 페이지의 다른 버전 표기와 어긋나므로 최신 여부는 미확인",
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
    "AttackBehavior",   # 열린 서술형. 사건 안에서만 의미가 있고, 사건 간 비교는 매핑된 전술·기법으로 한다
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
    ("Incident", "AttackBehavior", "USED_BEHAVIOR"),         # (c) 문서가 서술한 행동(평이한 말). 기법 매핑은 별도 단계
    ("Incident", "Technique", "USED_TECHNIQUE"),             # (c) 문서가 ATT&CK 기법 이름·ID를 직접 쓴 경우만
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
        "fit": "close", "cwe_verified": ["CWE-778"], "cwe_unverified": [],
        "note": "CWE-778은 보안상 중요한 사건을 기록하지 않는 약점이다. '장기 잠복을 탐지하지 못함'은 기록 부재보다 넓은 개념이다.",
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
        "침입 자체를 알아채지 못했으면(체류 기간이 길었으면) MONITORING. "
        "경보나 과거 침해를 알고도 차단·정리·재발 방지를 하지 않았으면 INCIDENT_RESPONSE.",
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
