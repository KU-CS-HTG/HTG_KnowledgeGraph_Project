"""전문가 검토 자료 묶음(전문가-B1~B5)을 압축 파일로 만든다.

보안 전문가에게 보여 줄 자료만 모아서 한 개의 zip으로 만든다. 저장소 전체를 보여 줄 필요가 없도록
README와 설정 파일(consts.py)에서 필요한 부분을 뽑아 읽기 쉬운 문서로 다시 쓴다. 내용을 새로 만들지는 않는다.

사용: python expert_review_bundle.py                 # security_kg/expert_review/전문가검토자료.zip
      python expert_review_bundle.py --out 경로.zip
      python expert_review_bundle.py --self-test

zip은 만들어지는 결과물이라 저장소에 올리지 않는다(.gitignore).
"""
import re
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "extraction"))
import consts  # noqa: E402

README = HERE / "README.md"
DEFAULT_OUT = HERE / "expert_review" / "전문가검토자료.zip"
NOTICE = ("> 이 자료는 **초안**이며 전문가 검토를 받기 전의 것입니다. 번호 존재 여부 같은 기계적인 확인만 했고, "
          "분류가 적절한지는 아직 판단받지 않았습니다. 코드 이름(`consts.py` 등)은 프로젝트 내부 이름이니 몰라도 됩니다.\n")


def section(text: str, heading: str) -> str:
    """README에서 `heading`으로 시작하는 절을 같은 단계의 다음 제목 직전까지 뽑는다."""
    lines = text.split("\n")
    start = next(i for i, l in enumerate(lines) if l.startswith(heading))
    level = len(lines[start]) - len(lines[start].lstrip("#"))
    end = len(lines)
    for j in range(start + 1, len(lines)):
        m = re.match(r"^(#+) ", lines[j])
        if m and len(m.group(1)) <= level:
            end = j
            break
    return "\n".join(lines[start:end]).rstrip() + "\n"


def seed_table(var: str, source_name: str) -> str:
    """consts.py에서 시드 목록의 이름과 주석(뜻)을 표로 만든다."""
    src = (HERE / "extraction" / "consts.py").read_text(encoding="utf-8")
    block = re.search(rf"^{var} = \[\n(.*?)^\]", src, re.S | re.M).group(1)
    rows = []
    for line in block.split("\n"):
        m = re.match(r'\s*"([A-Z_]+)",\s*(?:#\s*(.*))?$', line)
        if m:
            rows.append(f"| `{m.group(1)}` | {m.group(2) or ''} |")
    return f"| {source_name} | 뜻 |\n| --- | --- |\n" + "\n".join(rows) + "\n"


def questions() -> dict:
    """README 체크리스트의 전문가 절에서 B1~B5 질문을 뽑는다."""
    sec = section(README.read_text(encoding="utf-8"), "### 전문가")
    out = {}
    for line in sec.split("\n"):
        m = re.match(r"\| 전문가-(B\d) \| (.*?) \|\s*$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def build_files() -> dict:
    text = README.read_text(encoding="utf-8")
    q = questions()
    assert len(q) == 5, "README에서 B1~B5 질문을 찾지 못함"
    f = {}
    f["00_읽어주세요.md"] = f"""# 보안 사건 지식 그래프 설계 검토 요청

{NOTICE}
## 무엇에 대한 자료인가

뉴스, 정부 발표, 피해 조직의 공지 같은 문서에서 **한 사건의 (a) 어떤 취약점 (b) 어떤 약점·관리 실패 (c) 어떤 기법**을
공격자가 이용했는지를 출처와 함께(확정, 주장, 추정 구분) 뽑아 사건끼리 비교하는 지식 그래프의 **설계 초안**입니다.
분류의 뼈대로 공개 표준(CWE, ATT&CK, KEV, VERIS)을 쓰고, 표준에 없는 부분은 직접 만든 목록(시드)으로 채웠습니다.

## 검토를 부탁드리는 질문

| 번호 | 질문 | 볼 파일 |
| --- | --- | --- |
| B1 | {q['B1']} | `B1_B2_RootCause_시드와_조직절차_실패.md` |
| B2 | {q['B2']} | `B1_B2_RootCause_시드와_조직절차_실패.md` (특히 "대응표에서 보이는 것") |
| B3 | {q['B3']} | `B3_공격자유형_ActorOrigin_경계.md` |
| B4 | {q['B4']} | `B4_질문틀과_설계_요약.md` |
| B5 | {q['B5']} | `B5_ATTCK_매핑과_확인_절차.md` |

**우선순위**: B1과 B2가 가장 중요합니다(나머지 설계가 이 분류에 기대고 있습니다).

## 답변 형식 (편한 대로)

항목마다 **그대로 좋다 / 수정 / 삭제 / 추가**와 한 줄 이유만 적어 주시면 됩니다. 예: "`MISCONFIGURATION`: 수정 - 설정 오류는 별도 원인이 아니라 접근 통제 결함의 하위로 본다."

## 실제 사건에 적용한 예 (`부록/`)

- `정답표_초안.csv`: 네 사건(레벨인피니트 CDN 변조, SK텔레콤 유심 정보 유출, 2026 금융권 동시다발 해킹, 쿠팡 개인정보 유출)에
  공식 발표를 근거로 (a)(b)(c)를 매겨 본 초안 28행입니다. 열: `slot`은 a(취약점) b(약점·관리 실패) c(기법) ref(참고) asset(침해된 시스템),
  `slot_state`는 답이 있음/확정 전/문서에 없음, `assertion_status`는 confirmed(확정) claimed(주장) inferred(추정),
  `standard_candidates`는 표준 번호 후보(적합한지는 검토 전)입니다.
- `attack_mapping.py`: B5의 규칙을 구현한 코드입니다(읽지 않으셔도 됩니다).

## 알아 두실 점

- 사건의 사실은 공식 발표로 확인했지만, 분류와 매핑은 검토 전입니다.
- 사건 중 Canvas(Instructure)는 공식 문서를 구하지 못해 사실 확인에서 제외했고, 설계 설명에는 예시로만 남아 있습니다.
"""
    # B1, B2
    f["B1_B2_RootCause_시드와_조직절차_실패.md"] = f"""# B1, B2: RootCause 시드와 조직 절차 실패

{NOTICE}
**질문 B1**: {q['B1']}

**질문 B2**: {q['B2']}

## 현재 시드 8개 (질문 틀의 (b) "약점·관리 실패"에 쓰는 목록)

{seed_table('ROOT_CAUSE_SEED', 'RootCause')}
5개 사건의 검색 요약에서 나온 원인을 일반화한 것이라 **빠진 원인이 있을 수 있습니다**(피싱 교육, 백업, 물리 보안 등은 아직 없음).

{re.sub(r'^## .*', '## CWE 대응표와 경계 규칙', section(text, '## RootCause 시드 검토 자료'), count=1)}
## 경계 규칙 원문 (겹치는 항목 쌍)

""" + "\n".join(f"- **{a} ↔ {b}**: {v}" for (a, b), v in consts.ROOT_CAUSE_BOUNDARY_RULES.items()) + """

## 경계 사례 11개 (가상 문장, 기대하는 값)

기대 값이 비어 있으면 "어떤 값도 기록하지 않는다"는 뜻입니다.

| 문장 | 기대하는 RootCause |
| --- | --- |
""" + "\n".join(f"| {s} | {', '.join('`'+x+'`' for x in v) if v else '(없음)'} |" for s, v in consts.ROOT_CAUSE_BOUNDARY_EXAMPLES) + "\n"
    # B3
    f["B3_공격자유형_ActorOrigin_경계.md"] = f"""# B3: 공격자 유형(ActorOrigin) 경계

{NOTICE}
**질문 B3**: {q['B3']}

## 시드 4개

{seed_table('ACTOR_ORIGIN_SEED', 'ActorOrigin')}
## VERIS와의 대응

세분한 값을 VERIS의 값으로 합치는 대응표입니다(VERIS 위키 사본으로 확인했고, 공식 스키마와의 대조는 하지 않았습니다).

| ActorOrigin | VERIS |
| --- | --- |
""" + "\n".join(f"| `{k}` | {v} |" for k, v in consts.ACTOR_ORIGIN_TO_VERIS.items()) + f"""

## 경계 사례 6개 (기준: "공격(접근)이 일어난 시점의 고용 상태")

기대 값이 `없음`이면 값을 기록하지 않습니다(추측 금지).

| 사례 | 기대하는 값 |
| --- | --- |
""" + "\n".join(f"| {s} | {('`'+v+'`') if v else '없음'} |" for s, v in consts.ACTOR_ORIGIN_BOUNDARY_EXAMPLES) + f"""

{section(text, '## 공격자 유형: 내부자 표현')}"""
    # B4
    f["B4_질문틀과_설계_요약.md"] = f"""# B4: 질문 틀과 설계 요약

{NOTICE}
**질문 B4**: {q['B4']}

{section(text, '## 질문 틀')}
{section(text, '## 설계 요약')}
{section(text, '## 확정/주장/추정 구분을 담는 방법')}
{section(text, '## 5개 사건으로 본 시험')}"""
    # B5
    f["B5_ATTCK_매핑과_확인_절차.md"] = f"""# B5: AI가 제안한 ATT&CK 매핑의 확인

{NOTICE}
**질문 B5**: {q['B5']}

{section(text, '## 기법 층')}
"""
    f["부록/attack_mapping.py"] = (HERE / "attack_mapping.py").read_text(encoding="utf-8")
    f["부록/정답표_초안.csv"] = (HERE / "fact_check" / "answer_key_draft.csv").read_text(encoding="utf-8-sig")
    return f


def build(out: Path = DEFAULT_OUT) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    files = build_files()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(f"전문가검토자료/{name}", content.encode("utf-8-sig") if name.endswith((".md", ".csv")) else content)
    return out


def self_test():
    files = build_files()
    for need in ("00_읽어주세요.md", "B1_B2_RootCause_시드와_조직절차_실패.md", "B3_공격자유형_ActorOrigin_경계.md",
                 "B4_질문틀과_설계_요약.md", "B5_ATTCK_매핑과_확인_절차.md", "부록/attack_mapping.py", "부록/정답표_초안.csv"):
        assert need in files and files[need].strip(), need
    allt = "\n".join(files.values())
    for bad in ("C:\\Users", "/root/", "@gmail", "/home/user"):
        assert bad not in allt, f"개인 경로나 주소가 들어 있음: {bad}"
    for k in consts.ROOT_CAUSE_SEED:
        assert k in files["B1_B2_RootCause_시드와_조직절차_실패.md"], k
    assert "FORMER_INSIDER" in files["B3_공격자유형_ActorOrigin_경계.md"]
    assert "(b) 어떤 약점·관리 실패" in files["B4_질문틀과_설계_요약.md"]
    assert "D6" in files["B5_ATTCK_매핑과_확인_절차.md"] or "사람이 확인" in files["B5_ATTCK_매핑과_확인_절차.md"]
    for i in range(1, 6):
        assert f"B{i}" in files["00_읽어주세요.md"]
    with tempfile.TemporaryDirectory() as d:
        p = build(Path(d) / "x.zip")
        with zipfile.ZipFile(p) as z:
            assert z.testzip() is None and len(z.namelist()) == len(files)
    print("자체 시험 통과")


def main():
    if "--self-test" in sys.argv:
        return self_test()
    out = Path(sys.argv[sys.argv.index("--out") + 1]) if "--out" in sys.argv else DEFAULT_OUT
    p = build(out)
    print(f"만들었습니다: {p} ({p.stat().st_size:,}바이트)")
    with zipfile.ZipFile(p) as z:
        for n in z.namelist():
            print("  ", n)


if __name__ == "__main__":
    main()
