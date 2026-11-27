"""온톨로지 적합성 검사(원본 `ontology_conformance_agent.py`의 보안 분야판).
원본은 기후 어휘 집합(realm, experiment 등)으로 검사했다. 여기서는 consts의 규칙으로 검사한다:
관계와 개체 종류 조합, ID 형식, 닫힌 시드(RootCause, ActorOrigin), 근거 문장이 원문에 실제로 있는지."""
import re

from _paths import consts as C

ONTOLOGY = {(s, t, r) for s, t, r in C.FILTERED_RELATIONSHIP_SOURCE_TO_TARGET}
CLOSED_SEEDS = {"RootCause": set(C.ROOT_CAUSE_SEED), "ActorOrigin": set(C.ACTOR_ORIGIN_SEED)}


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s or "").lower()


def quote_in_document(quote: str, document: str) -> bool:
    """근거 문장이 원문에 있는가(공백과 대소문자는 무시). 모델이 문장을 지어내는지 막는 검사."""
    q = _norm(quote)
    return bool(q) and q in _norm(document)


def check_entity(entity_type: str, instance: str) -> list[str]:
    problems = []
    if entity_type not in C.ENTITY_TYPES:
        return [f"정의되지 않은 개체 종류 {entity_type}"]
    pat = C.ID_PATTERNS.get(entity_type)
    if pat and not re.match(pat, instance.strip()):
        problems.append(f"{entity_type} ID 형식이 아님: {instance}")
    seed = CLOSED_SEEDS.get(entity_type)
    if seed is not None and instance not in seed:
        problems.append(f"{entity_type}이 닫힌 시드에 없음: {instance}")
    return problems


def check_triplet(t: dict, document: str) -> dict:
    """트리플렛 하나를 검사해 `ontology_conformed`, `quote_verified`, `issues`를 붙여 돌려준다. 버리지 않고 표시만 한다."""
    issues = []
    if (t["source_entity_type"], t["target_entity_type"], t["relation"]) not in ONTOLOGY:
        issues.append(f"허용되지 않은 관계 조합 ({t['source_entity_type']}, {t['relation']}, {t['target_entity_type']})")
    issues += check_entity(t["source_entity_type"], t["source_entity_instance"])
    issues += check_entity(t["target_entity_type"], t["target_entity_instance"])
    verified = quote_in_document(t.get("evidence_quote", ""), document)
    if not verified:
        issues.append("근거 문장이 원문에서 발견되지 않음")
    return {**t, "ontology_conformed": not [i for i in issues if "근거" not in i], "quote_verified": verified, "issues": issues}
