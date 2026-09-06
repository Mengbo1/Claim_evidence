# Rule-Based Claim--Evidence Assessment

Code accompanying the dissertation. It reproduces the rule-based assessment
reported in the thesis.

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
  --input ..\data\claim_evidence_input_manual.xlsx `
  --output ..\data\claim_evidence_result_code.xlsx
```

## Input and output

The input workbook must contain `Report Sources`, `Source Evidence Excerpts`,
and `Synthetic Claims`. The output workbook adds automatic assessments and an
`Assessment Summary` sheet.
