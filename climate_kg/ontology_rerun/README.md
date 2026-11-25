# 온톨로지 적합성 단계(O) 재실행

> 이 폴더는 `climate_kg/` 아래에 있다. 이 문서의 명령은 `climate_kg/` 폴더를 작업 폴더로 해서 실행한다.

저장된 `ontology_conformed` 플래그를 그대로 집계하지 않고, `ontology_conformance_agent.py`를 `extracted_papers`에서 처음부터 다시 실행해 같은 플래그가 나오는지 확인한다.
이 단계는 LLM 호출 없이 규칙(온톨로지 조합 + 정규식)으로만 동작하므로 API 비용이 없다.

## 실행

```bash
# 입력: stats/ 에서 풀어 둔 extracted_papers (stats/data/*.tar.gz)
cd ontology_rerun/extraction
python -m unittest test_ontology_conformance_agent -v          # 단위 테스트 7개
for d in 2026-02-01 2026-04-24; do
  python ontology_conformance_agent.py --date $d \
    --input-dir ../../stats/output/extracted_papers/$d --output-dir ../output/$d
done
cd ..
python -I compare_flags.py ../stats/output/ontology_conformed_papers output ../stats/output/extracted_papers 2026-02-01 2026-04-24
python breakdown.py
```

원본 스크립트(`ontology_conformance_agent.py`, `consts.py`, 테스트)는 `aayushacharya/climatekg`의 `extraction/`에서 그대로 복사했다.

## 결과

- 단위 테스트 7개 통과.
- 재실행 결과가 저장된 플래그와 **39,964개 트리플렛 전부 일치** (불일치 0, 실패 파일 0, 길이 불일치 0).

| 파티션 | 트리플렛 | 적합 | 부적합 | 저장 플래그와 일치 |
| --- | --- | --- | --- | --- |
| 2026-02-01 | 21,506 | 15,710 | 5,796 | 21,506 / 21,506 |
| 2026-04-24 | 18,458 | 13,204 | 5,254 | 18,458 / 18,458 |
| 합계 | 39,964 | 28,914 | 11,050 | 39,964 / 39,964 |

- `extracted_papers` 입력에는 이 플래그가 처음부터 없었다(`extracted_already_had_flag` 없음). 따라서 같은 값을 읽어 온 것이 아니라 새로 계산한 값이다.

## 제거된 11,050개의 내용 (`breakdown_result.txt`)

| 제거 사유 | 개수 | 그중 C_triplet 판정자가 "맞다"고 본 비율 |
| --- | --- | --- |
| (출발 종류, 관계, 도착 종류) 조합이 온톨로지에 없음 | 9,810 | 94.5% |
| 조합은 맞지만 의미 경계 규칙 위반 | 1,240 | 84.9% |

가장 많이 제거된 조합: `Source-PRODUCES_VARIABLE->Variable` 2,763, `Source-USED_IN_EXPERIMENT->Experiment` 1,882, `Source-PRODUCED_BY_INSTITUTE->Institute` 674, `Source-PART_OF_PROJECT->Project` 590, `Source-HAS_SPATIAL_RESOLUTION->Resolution` 513.

해석(추정): O 단계는 틀린 사실을 거르는 단계가 아니라 스키마 필터에 가깝다. 제거된 것의 대부분(약 94%)이 판정자 기준으로는 맞는 사실이다.
상위 제거 조합이 모델-변수, 모델-실험, 모델-기관처럼 ESGF 메타데이터 백본이 이미 가진 관계와 겹치므로, 논문에서 다시 뽑은 사실을 버리는 설계로 보이지만 저자가 그렇게 밝힌 것은 아니며 확인하지 않았다.
