# 본문 필터를 건 CMIP 재현율 (텍스트 추출 근사)

논문(Table 8)의 CMIP 재현율 90.29%는 정답 중 **파싱된 논문 본문에 표면형이 나오는 엔티티만** 분모로 센 값이다.
논문은 olmOCR(GPU 필요)로 파싱했지만, 여기서는 PDF에서 텍스트를 직접 꺼내는 **근사 방법**(PyMuPDF)을 쓴다.
파싱 방식이 다르므로 수치가 논문과 정확히 같지 않고 근처에서 나올 수 있다. 결과를 적을 때 이 점을 함께 적을 것.

## 준비 (Windows PowerShell)

```powershell
git fetch origin
git checkout claude/confident-carson-3hv4ka     # PR이 main에 합쳐졌다면 main에서 git pull
git pull
.venv\Scripts\Activate.ps1
pip install requests pymupdf
```

`stats\output\<단계>\2026-02-01\` 폴더가 있어야 한다(없으면 `stats\data\*.tar.gz`를 `stats\output\<단계>\`에 푼다. `stats\README` 또는 이전 안내 참고).

## 실행

1. 시험으로 5편만 받아 본다. 실패 이유가 `failures.json`에 남는다.

```powershell
python parsed_text\download_pdfs.py --limit 5
```

2. 문제가 없으면 139편 전체를 받는다(이어받기 가능, 요청 사이 1.5초 대기, 약 4~5분).

```powershell
python parsed_text\download_pdfs.py
```

받지 못한 논문은 `cmip_recall\extraction\papers\pdfs\2026-02-01\failures.json`에 있다.
브라우저로 직접 받아 같은 폴더에 `<OpenAlexID>.pdf`(예: `W1966668438.pdf`)로 저장하면 된다.

3. 텍스트로 변환한다.

```powershell
python parsed_text\pdf_to_text.py
```

"짧음(스캔본 가능성)"으로 표시된 파일은 텍스트가 거의 없는 PDF(스캔본)이므로 확인이 필요하다.

4. 분석하고 논문 Table 8과 비교한다.

```powershell
python parsed_text\run_analysis.py
```

## 비교 기준 (논문 Table 8)

| 종류 | 정답 | 추출 | 재현율 |
| --- | --- | --- | --- |
| Source | 797 | 774 | 97.11% |
| Experiment | 196 | 162 | 82.65% |
| Frequency | 85 | 57 | 67.06% |
| Activity | 55 | 30 | 54.55% |
| 전체 | 1,133 | 1,023 | 90.29% |

정답 중 본문에 나오는 비율은 논문 50.78% (정답 총 2,231개 중 1,133개).

## 해석할 때

- `run_analysis.py`가 "본문에 나오는 정답" 수가 논문(1,133)과 크게 다르면 파싱 방식 차이가 원인일 가능성이 크다.
- 본문 파일이 없는 논문이 있으면 그 논문의 정답은 전부 "본문에 없음"으로 계산돼 재현율이 부풀 수 있다. 출력의 "본문 파일이 없는 항목" 줄을 확인한다.
