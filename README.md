## Files

- `run_assessment.py` — entry point.
- `report_data.py` — reads the workbook and creates `Report` and `SyntheticReport` objects.
- `evidence_assessment.py` — analyses each evidence excerpt and stores the result in its report.
- `claim_assessment.py` — combines the evidence results and gives each claim its final assessment.

## Requirements

- Python 3.9+
- `openpyxl`

```powershell
python -m pip install openpyxl
```

## Run

```powershell
python run_assessment.py `
  --input claim_evidence_input_manual.xlsx `
  --output claim_evidence_result_code.xlsx
```


