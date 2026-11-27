"""LLM 호출을 한곳에 모은 파일(원본의 `google.genai` 호출을 대체).

다른 모듈은 `client.structured(...)`만 부른다. 모델을 바꾸려면 이 파일만 고친다.
- `ClaudeClient`: Anthropic API. 구조화 출력은 '도구 호출 강제'로 받고, 문서는 프롬프트 캐시 블록으로 보낸다
  (같은 문서에 여러 질문을 할 때 문서 토큰을 매번 새로 읽지 않게 하려는 것. 원본의 Gemini 컨텍스트 캐시에 해당).
- `FakeClient`: 키 없이 구조를 시험하는 용도. 미리 정한 응답을 돌려준다.
키는 환경변수 `ANTHROPIC_API_KEY`(또는 환경이 주는 설정)로 읽는다. 코드와 저장소에 키를 쓰지 않는다.
"""
from __future__ import annotations

import time
from typing import TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

DEFAULT_MODEL = "claude-sonnet-5-5"            # 구조화 추출(관계, 개체)
DEFAULT_METADATA_MODEL = "claude-haiku-5-5"    # 문서 단위 메타데이터(날짜, 출처 유형, 사건 언급)
SYSTEM_INSTRUCTION = (
    "You are an expert in extracting information from security incident documents. "
    "Answer only from the document provided. Do not use outside knowledge. "
    "If the document does not say something, leave it out instead of guessing."
)
MAX_TOKENS = 8000


def _tool_schema(schema: type[BaseModel], as_list: bool) -> dict:
    s = schema.model_json_schema()
    if not as_list:
        return s
    defs = s.pop("$defs", {})
    out = {"type": "object", "properties": {"items": {"type": "array", "items": s}}, "required": ["items"]}
    if defs:
        out["$defs"] = defs
    return out


class ClaudeClient:
    def __init__(self, api=None, retries: int = 3):
        if api is None:
            import anthropic
            api = anthropic.Anthropic()
        self.api = api
        self.retries = retries

    def structured(self, prompt: str, document: str, schema: type[T], model: str = DEFAULT_MODEL, as_list: bool = False):
        """문서와 질문을 보내 pydantic 형식의 답을 받는다. as_list=True면 schema의 목록을 돌려준다."""
        tool = {"name": "record", "description": "Record the extracted result.", "input_schema": _tool_schema(schema, as_list)}
        messages = [{"role": "user", "content": [
            {"type": "text", "text": f"<document>\n{document}\n</document>", "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": prompt},
        ]}]
        last = None
        for attempt in range(self.retries):
            try:
                resp = self.api.messages.create(
                    model=model, max_tokens=MAX_TOKENS, system=SYSTEM_INSTRUCTION, messages=messages,
                    tools=[tool], tool_choice={"type": "tool", "name": "record"})
                block = next(b for b in resp.content if getattr(b, "type", "") == "tool_use")
                data = block.input
                if as_list:
                    return [schema.model_validate(x) for x in data["items"]]
                return schema.model_validate(data)
            except Exception as e:                      # 네트워크, 속도 제한, 형식 오류를 같이 다시 시도한다
                last = e
                time.sleep(2 ** attempt)
        raise RuntimeError(f"LLM 호출이 {self.retries}번 실패함: {last}")


class FakeClient:
    """`responses`: {schema 클래스 이름: 응답(모델 하나 또는 목록)}. 부른 기록이 `calls`에 남는다."""
    def __init__(self, responses: dict):
        self.responses = responses
        self.calls: list[tuple[str, str]] = []

    def structured(self, prompt: str, document: str, schema, model: str = DEFAULT_MODEL, as_list: bool = False):
        self.calls.append((schema.__name__, model))
        r = self.responses[schema.__name__]
        return [schema.model_validate(x) for x in r] if as_list else schema.model_validate(r)
