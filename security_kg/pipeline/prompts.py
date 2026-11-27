"""프롬프트(원본 `prompts_deprecated.py`의 보안 분야판). 정의와 규칙은 `consts.py`에서 읽어 만든다.
정의를 여기에 다시 쓰지 않는다: consts가 바뀌면 프롬프트가 같이 바뀐다."""
from _paths import consts as C

# 문서가 채우는 관계에 나오는 개체 종류만 프롬프트에 보인다(표준 뼈대의 관계는 문서에서 받지 않는다).
DOC_ENTITY_TYPES = sorted({t for s, t2, _ in C.FILTERED_RELATIONSHIP_SOURCE_TO_TARGET for t in (s, t2)})

ENTITY_TYPE_DEFINITIONS = "\n".join(f"- {t}: {C.ENTITY_TYPE_DEFINITIONS[t]}" for t in DOC_ENTITY_TYPES)
RELATIONS = "\n".join(f"- ({s}) -[{r}]-> ({t})" for s, t, r in C.FILTERED_RELATIONSHIP_SOURCE_TO_TARGET)
ASSERTION_DEFINITIONS = "\n".join(f"- {k}: {v}" for k, v in C.ASSERTION_STATUSES.items())
ROOT_CAUSE_LIST = "\n".join(f"- {k}: {C.ROOT_CAUSE_MEANING.get(k, '')}" for k in C.ROOT_CAUSE_SEED)
ROOT_CAUSE_RULES = "\n".join(f"- {r}" for r in C.ROOT_CAUSE_ASSIGNMENT_RULES)
ID_RULE = ("CVE, CWE and ATT&CK IDs must be written exactly as in the document (CVE-YYYY-NNNN, CWE-N, TNNNN or TNNNN.NNN). "
           "If the document gives only a name such as 'DirtyCow' and no ID, write the name and never add an ID yourself.")

NO_EXPLANATION_PROMPT = "Do not put any additional comment or explanation."

DOCUMENT_META_PROMPT = f"""Read the security incident document and fill the response.

source_type: one of {', '.join(C.SOURCE_TYPES)}. Choose by WHO wrote the document (government or regulator, the breached organization itself, a security vendor, a news outlet, the attacker, an independent researcher).
document_date: the publication date of this document (YYYY, YYYY-MM or YYYY-MM-DD). Leave empty if the document does not show it.
incident_mentions: every incident the document discusses. One incident per BREACHED ORGANIZATION. For each:
{chr(10).join(f'- {k}: {v}' for k, v in C.INCIDENT_MENTION_FIELDS.items())}
(attack_span is given as attack_span_start and attack_span_end.)
{NO_EXPLANATION_PROMPT}"""

KG_EXTRACTION_PROMPT = f"""Extract relations about the security incident(s) in the document.

Entity types you may use:
{ENTITY_TYPE_DEFINITIONS}

Allowed relations (source type, relation, target type). Use only these:
{RELATIONS}

Answer frame: (a) which vulnerability was exploited (EXPLOITED_VULNERABILITY), (b) which weakness or management failure (EXPLOITED_WEAKNESS, HAS_ROOT_CAUSE), (c) which attack behavior or technique (USED_BEHAVIOR, USED_TECHNIQUE, USED_MALWARE). ATTRIBUTED_TO, HAS_ACTOR_ORIGIN, ACCOUNT_OWNER_ORIGIN and AFFECTED_ASSET are context, not part of the frame.

RootCause must be one of these exact names:
{ROOT_CAUSE_LIST}
Rules for choosing a RootCause:
{ROOT_CAUSE_RULES}

ActorOrigin must be one of: {', '.join(C.ACTOR_ORIGIN_SEED)}. The attacker's origin and the owner of an abused account are different facts: use HAS_ACTOR_ORIGIN for the attacker and ACCOUNT_OWNER_ORIGIN for the account owner.

assertion_status, for every relation:
{ASSERTION_DEFINITIONS}

{ID_RULE}
evidence_quote: copy the sentence from the document that supports the relation, word for word.
Write entity names as the document writes them. Do not extract a relation the document does not state.
{NO_EXPLANATION_PROMPT}"""

ENTITY_EXTRACTION_PROMPT = f"""List the entities the document mentions, whether or not they take part in a relation.

Entity types you may use:
{ENTITY_TYPE_DEFINITIONS}

{ID_RULE}
{NO_EXPLANATION_PROMPT}"""
