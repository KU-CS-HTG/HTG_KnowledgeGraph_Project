# CMIP Publication Hub 엔티티 재현율 재현

ClimateKG 논문의 "CMIP Publication Hub 대비 엔티티 수준 재현율" 실험을 재현한다.
정답은 CMIP Publication Hub의 More Info(활동, 실험, 모델, 빈도)이고, 비교 대상은 파이프라인이 추출해 엔티티 링크한 결과다.

## 실행 (2026-11-24)

```bash
cd cmip_recall/extraction
mkdir -p output/entity_linked_papers
gunzip -c ../data/entity_linked_papers_2000.json.gz > output/entity_linked_papers/v2_processed_papers_entity_linking_post_llm.json
cd experiments
python -I extract_cmip_publication_moreinfo_entities.py   # 사이트에서 정답 수집 (약 1.5분, 네트워크 필요)
python -I evaluate_cmip_moreinfo_entity_extraction.py       # 평가 (LLM 호출 없음, 약 1초)
```

필요 패키지: `requests`, `beautifulsoup4`.

## 결과

- 사이트와 매칭된 우리 CMIP 논문 174편 (DOI 10, DOI+제목 163, 제목 1), 이 중 More Info 정답이 있는 논문 139편이 평가 대상.
- 정답이 없는 35편은 평가에서 제외.

| 집계 방식 | Precision | Recall | F1 |
| --- | --- | --- | --- |
| 논문 단위 micro (TP 1,184 / FP 2,841 / FN 1,047) | 0.294 | 0.531 | 0.379 |
| 논문 단위 macro | 0.239 | 0.498 | 0.312 |
| 전체 고유 엔티티 (TP 175 / FP 1,251 / FN 41) | 0.123 | 0.810 | 0.213 |

종류별(논문 단위): activities R=0.492, experiments R=0.458, frequencies R=0.492, sources R=0.551.
종류별(전체 고유): activities R=1.000, experiments R=0.714, frequencies R=0.714, sources R=0.850.

## 주의

- 정답은 실시간 웹사이트에서 가져오므로 사이트 내용이 바뀌면 숫자가 달라진다. 이 실행의 스냅샷은
  `extraction/experiments/output/cmip_publication_moreinfo_entities/20261124_021500_dd97bf97/`에 저장했다.
- Precision이 낮은 것은 사이트의 More Info 목록에 없는 엔티티를 우리가 추출한 경우(FP)가 많기 때문이다. 목록이 불완전해서인지 추출이 과해서인지는 구분하지 않았다.
- 본문 필터와 놓친 엔티티 분석(`analyze_cmip_missing_entities_in_parsed_papers.py`)은 olmOCR 대신 PDF 텍스트 추출로 근사해 `../parsed_text/`에서 수행했다(아래 "본문 필터 재현"). PDF 보고서(`create_cmip_recall_report.py`)는 실행하지 않았다.

## 논문(AACL 2026, Table 8, 4.4절)과 비교

논문의 재현율 90.29%는 **정답 중 파싱된 논문 본문에 표면형이 실제로 나오는 엔티티만** 분모로 센 값이다
(저자가 체크박스로 태깅한 엔티티 중 본문에 없는 것이 많아서, 논문은 이를 제외한다). 이 필터에는 파싱된 본문이 필요하며, 아래 "본문 필터 재현"에서 olmOCR 대신 텍스트 추출로 근사해 재현했다.

| 확인 항목 | 논문 | 이 재현 | 판정 |
| --- | --- | --- | --- |
| 평가 논문 수 | 139 | 139 | 일치 |
| 정답 중 본문에 나오는 비율 | 50.78% | 1,133 / 2,231 = 50.78% (2,231 = TP 1,184 + FN 1,047) | 일치 |
| Activity 추출(맞힌 수) | 30 | 30 | 일치 |
| Experiment 추출 | 162 | 169 (필터 전) | 논문 ≤ 재현, 정합 |
| Frequency 추출 | 57 | 63 (필터 전) | 논문 ≤ 재현, 정합 |
| Source 추출 | 774 | 922 (필터 전) | 논문 ≤ 재현, 정합 |
| 전체 micro 재현율 | 1,023 / 1,133 = 90.29% | 1,184 / 2,231 = 53.07% (필터 전) | 필터 유무 차이 |

종류별 논문 값(Gold / Extracted / Recall): Source 797/774/97.11%, Experiment 196/162/82.65%, Frequency 85/57/67.06%, Activity 55/30/54.55%.
재현에서 나온 필터 전 종류별 정답 수: Source 1,673, Experiment 369, Frequency 128, Activity 61.

결론(필터 전): 논문과 같은 139편, 같은 정답 집합(분모 2,231로 50.78%가 정확히 일치)을 재현했다. 필터 전 값(53.07%)은 논문의 설명과 모순 없이 정합한다.

## 본문 필터 재현 (텍스트 추출 근사)

논문은 olmOCR로 파싱했고, 여기서는 PDF 텍스트를 PyMuPDF로 직접 추출했다(`../parsed_text/`). 139편 중 137편의 PDF를 확보했고 2편은 받지 못했다
(구독 또는 사이트 응답 문제). 실행은 2026-11-24, Windows 로컬 환경이며 아래 숫자는 `run_analysis.py`의 출력이다.

| 종류 | 논문 (정답 / 추출 / 재현율) | 이 재현 (정답 / 맞힘 / 재현율) | 재현율 차이 |
| --- | --- | --- | --- |
| Source | 797 / 774 / 97.11% | 818 / 795 / 97.19% | +0.08%p |
| Experiment | 196 / 162 / 82.65% | 192 / 158 / 82.29% | -0.36%p |
| Frequency | 85 / 57 / 67.06% | 83 / 55 / 66.27% | -0.79%p |
| Activity | 55 / 30 / 54.55% | 53 / 29 / 54.72% | +0.17%p |
| **전체** | **1,133 / 1,023 / 90.29%** | **1,146 / 1,037 / 90.49%** | **+0.20%p** |

- 정답 중 본문에 나오는 비율: 논문 50.78%, 이 재현 51.37% (분모 2,231, 본문 없는 2편 포함) / 51.76% (`--only-available`, 분모 2,214).
- 본문에 있는데 놓친 엔티티: 논문 110개, 이 재현 109개.
- 본문이 없는 2편은 "본문에 나오는 정답"이 0개로 계산되어 두 실행(기본, `--only-available`)의 재현율이 같다(90.49%). 분모(정답 총수)만 2,231과 2,214로 다르다.

결론: 파서가 달라도 종류별 순위와 크기가 모두 맞고(전부 0.8%p 이내), 전체 재현율이 논문의 90.29%와 0.2%p 차이로 재현됐다.
본문에서 찾은 정답이 13개 더 많고 Source에서 특히 그렇다(+21). 원인은 확인하지 않았으며, 텍스트 추출이 참고문헌, 표, 그림 설명까지 포함하기 때문일 수 있다는 추정이다.
논문의 정확한 숫자(1,133 / 1,023)를 재현한 것은 아니고, 근사 파서로 같은 결론이 나온 것이다.
이 필터는 "추출기가 본문에 있는 것을 얼마나 잘 찾는가"를 재며, 본문 파싱 실패는 필터에 드러나지 않는다.
