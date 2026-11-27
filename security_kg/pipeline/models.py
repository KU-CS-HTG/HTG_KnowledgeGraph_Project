"""추출 결과의 형식(원본 `models.py`의 보안 분야판). 허용값은 모두 `extraction/consts.py`에서 가져온다."""
from typing import Literal

from pydantic import BaseModel, Field

from _paths import consts

AssertionStatus = Literal[tuple(consts.ASSERTION_STATUSES)]
SourceType = Literal[tuple(consts.SOURCE_TYPES)]


class Kg_Extraction_Model(BaseModel):
    """관계 하나. 원본의 `paragraph`는 `evidence_quote`(문서 원문 그대로)로 바꿨고 `assertion_status`를 더했다."""
    source_entity_instance: str
    source_entity_type: str
    relation: str
    target_entity_instance: str
    target_entity_type: str
    assertion_status: AssertionStatus
    evidence_quote: str = Field(description="문서에서 이 관계를 뒷받침하는 문장을 그대로 옮긴 것")


class Entity_Extraction_Model(BaseModel):
    entity_instance: str
    entity_type: str


class Incident_Mention_Model(BaseModel):
    """`consts.INCIDENT_MENTION_FIELDS`의 구조. attack_span은 시작과 끝 두 칸으로 폈다."""
    name: str
    breached_org: str
    headline_date: str = ""
    attack_span_start: str = ""
    attack_span_end: str = ""
    signals: list[str] = []


class Document_Meta_Model(BaseModel):
    """`consts.NEW_DOCUMENT_LEVEL_FIELDS`: 문서 단위 메타데이터."""
    source_type: SourceType
    document_date: str = ""
    incident_mentions: list[Incident_Mention_Model]
