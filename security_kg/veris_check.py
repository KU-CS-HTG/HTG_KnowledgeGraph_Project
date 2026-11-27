"""VERIS 공식 스키마와 우리의 ActorOrigin 대응을 대조한다(README 확인-A3).

검사하는 것:
  1. 스키마의 actor 최상위가 external, internal, partner, unknown을 가지는가
  2. `consts.ACTOR_ORIGIN_TO_VERIS`의 값(Internal, External, Partner)이 그 최상위 이름과 맞는가
  3. `consts.ACTOR_ORIGIN_VERIS_VARIETY`의 값(예: Former employee)이 actor.external.variety에 실제로 있는가

사용: python veris_check.py                      # backbone/raw/veris/verisc-merged.json을 검사한다
      python veris_check.py --fetch              # vz-risk/veris master에서 받아 검사한다(받은 파일의 sha256을 출력)
      python veris_check.py 경로.json
      python veris_check.py --self-test

스키마 파일에는 버전 표기와 커밋 해시가 없어서 받은 날짜, 크기, sha256으로 재현한다(consts.BACKBONE_SNAPSHOTS["veris"]).
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "extraction"))
import consts  # noqa: E402

HERE = Path(__file__).resolve().parent
RAW = HERE / "backbone" / "raw" / "veris" / "verisc-merged.json"
URL = "https://raw.githubusercontent.com/vz-risk/veris/master/verisc-merged.json"


def check(doc: dict, to_veris=None, variety=None) -> list[str]:
    to_veris = consts.ACTOR_ORIGIN_TO_VERIS if to_veris is None else to_veris
    variety = consts.ACTOR_ORIGIN_VERIS_VARIETY if variety is None else variety
    problems = []
    actor = doc.get("properties", {}).get("actor", {}).get("properties", {})
    for k in ("external", "internal", "partner", "unknown"):
        if k not in actor:
            problems.append(f"스키마의 actor에 {k}가 없음")
    for ours, veris in to_veris.items():
        if veris.lower() not in actor:
            problems.append(f"ACTOR_ORIGIN_TO_VERIS[{ours}] = {veris}가 VERIS actor 최상위에 없음")
    ext = actor.get("external", {}).get("properties", {}).get("variety", {}).get("items", {}).get("enum", [])
    for ours, v in variety.items():
        if v not in ext:
            problems.append(f"ACTOR_ORIGIN_VERIS_VARIETY[{ours}] = {v}가 actor.external.variety에 없음")
        if to_veris.get(ours) != "External":
            problems.append(f"{ours}: variety는 External 행위자의 것인데 대응이 {to_veris.get(ours)}임")
    return problems


def fetch(dest: Path = RAW) -> Path:
    import os
    import ssl
    import urllib.request
    dest.parent.mkdir(parents=True, exist_ok=True)
    cafile = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    with urllib.request.urlopen(URL, timeout=60, context=ctx) as r:
        dest.write_bytes(r.read())
    return dest


def self_test():
    ok = {"properties": {"actor": {"properties": {
        "external": {"properties": {"variety": {"items": {"enum": ["Former employee", "Other"]}}}},
        "internal": {}, "partner": {}, "unknown": {}}}}}
    assert check(ok) == []
    assert check(ok, variety={"FORMER_INSIDER": "Ex-staff"})                       # 없는 세부 유형을 걸러냄
    assert check(ok, to_veris={"INTERNAL": "Insider"})                              # 없는 최상위 이름을 걸러냄
    assert check({"properties": {}})                                                 # 구조가 다르면 걸러냄
    assert check(ok, to_veris={**consts.ACTOR_ORIGIN_TO_VERIS, "FORMER_INSIDER": "Internal"})   # 전직자를 Internal로 두면 걸러냄
    print("자체 시험 통과")


def main():
    if "--self-test" in sys.argv:
        return self_test()
    if "--fetch" in sys.argv:
        path = fetch()
    elif len(sys.argv) > 1:
        path = Path(sys.argv[1])
    else:
        path = RAW
    raw = path.read_bytes()
    doc = json.loads(raw.decode("utf-8"))
    problems = check(doc)
    print(f"{path.name}: {len(raw):,}바이트, sha256 {hashlib.sha256(raw).hexdigest()[:12]}…")
    print("검사 결과:", "문제 없음(최상위 이름과 'Former employee' 확인)" if not problems else "")
    for p in problems:
        print(" -", p)
    if problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
