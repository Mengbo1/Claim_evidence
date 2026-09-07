"""Read excel rows and build original and synthetic report objects."""

from collections import defaultdict
from dataclasses import dataclass, field
import re
from typing import Iterable, Mapping, Union


VALID_CLAIM_TYPES = {"maliciousness", "malware_family"}
VALID_MALICIOUSNESS_VALUES = {"no_threat", "low_risk", "high_risk", "malicious"}
VALID_MANIPULATION_TYPES = {"claim_value_change", "remove_evidence"}
UNKNOWN_FAMILY_VALUES = {"", "n/a", "n_a", "na", "none", "unknown", "not_available"}

REPORT_COLUMNS = {"report_id", "claim_type", "platform_verdict", "normalized_verdict"}
SYNTHETIC_COLUMNS = {
    "synthetic_claim_id", "report_id", "claim_type", "claim_value", "manipulation_type",
}


@dataclass
class Report:
    """One original platform report with its claim, evidence, and assessment results."""

    case_id: str
    report_id: str
    claim: dict[str, str]
    evidence: dict[str, dict[str, str]]
    manual_assessment: str = ""
    evidence_analysis: dict[str, dict[str, str]] = field(default_factory=dict)
    automatic_assessment: str = ""
    assessment_rationale: str = ""


@dataclass
class SyntheticReport:
    """One synthetic report read directly from the synthetic-claims worksheet."""

    case_id: str
    report_id: str
    claim: dict[str, str]
    evidence: dict[str, dict[str, str]]
    manipulation_type: str
    removed_evidence_ids: set[str]
    manual_assessment: str = ""
    evidence_analysis: dict[str, dict[str, str]] = field(default_factory=dict)
    automatic_assessment: str = ""
    assessment_rationale: str = ""


AssessmentReport = Union[Report, SyntheticReport]


def text(value: object) -> str:
    """Convert a workbook value to trimmed text."""
    return str(value or "").strip()


def token(value: object) -> str:
    """Create a lower-case label with spaces and hyphens written as underscores."""
    return re.sub(r"[\s-]+", "_", text(value).casefold())


def normalise_report_id(value: object) -> str:
    """Use one report-ID format, so report31 and report031 refer to the same report."""
    report_id = text(value)
    match = re.fullmatch(r"report0*(\d+)", report_id, flags=re.IGNORECASE)
    if match:
        return f"report{int(match.group(1))}"
    return report_id


def require(value: object, label: str) -> str:
    """Return a required value or stop with a clear workbook error."""
    result = text(value)
    if not result:
        raise ValueError(f"{label} must not be blank.")
    return result


def require_columns(rows: list[Mapping[str, object]], required: set[str], sheet_name: str) -> None:
    """Check that a worksheet contains every column needed by this program."""
    present = {key for row in rows for key in row}
    missing = required - present
    if missing:
        raise ValueError(f"{sheet_name} is missing columns: {', '.join(sorted(missing))}")


def is_unknown_family(value: object) -> bool:
    """Return True when a family value means that no family has been named."""
    return token(value) in UNKNOWN_FAMILY_VALUES


def _copy_evidence(evidence: Mapping[str, Mapping[str, str]]) -> dict[str, dict[str, str]]:
    """Give each report its own evidence dictionary without changing the source data."""
    return {evidence_id: dict(item) for evidence_id, item in evidence.items()}


def group_evidence(source_rows: Iterable[Mapping[str, object]]) -> dict[str, dict[str, dict[str, str]]]:
    """Read source evidence once and group it by the report it belongs to."""
    grouped: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    seen_ids: dict[str, set[str]] = defaultdict(set)

    for row in source_rows:
        evidence_id = require(row.get("evidence_id"), "Source Evidence Excerpts.evidence_id")
        evidence_key = token(evidence_id)
        report_id = normalise_report_id(
            require(row.get("report_id"), f"Evidence {evidence_id}.report_id")
        )
        if evidence_key in seen_ids[report_id]:
            raise ValueError(f"Report {report_id} has duplicate evidence_id: {evidence_id}")
        seen_ids[report_id].add(evidence_key)
        grouped[report_id][evidence_id] = {
            "evidence_id": evidence_id,
            "raw_evidence": text(row.get("raw_evidence")),
        }
    return dict(grouped)


def load_reports(
    report_rows: Iterable[Mapping[str, object]],
    evidence_by_report: Mapping[str, Mapping[str, Mapping[str, str]]],
) -> tuple[list[Report], dict[str, dict[str, str]]]:
    """Create original Report objects directly from the Report Sources worksheet."""
    rows = list(report_rows)
    require_columns(rows, REPORT_COLUMNS, "Report Sources")

    reports: list[Report] = []
    source_claims: dict[str, dict[str, str]] = {}
    for row in rows:
        case_id = require(row.get("report_id"), "Report Sources.report_id")
        report_id = normalise_report_id(case_id)
        if report_id in source_claims:
            raise ValueError(f"Duplicate report_id: {report_id}")

        claim_type = token(require(row.get("claim_type"), f"Report {report_id}.claim_type"))
        if claim_type not in VALID_CLAIM_TYPES:
            raise ValueError(f"Report {report_id} has unknown claim_type: {claim_type}")

        if claim_type == "maliciousness":
            claim_value = token(
                require(row.get("normalized_verdict"), f"Report {report_id}.normalized_verdict")
            )
            if claim_value not in VALID_MALICIOUSNESS_VALUES:
                raise ValueError(f"Report {report_id} has invalid normalized_verdict: {claim_value}")
        else:
            claim_value = token(require(
                row.get("platform_verdict") or row.get("normalized_verdict"),
                f"Report {report_id}.platform_verdict",
            ))

        claim = {
            "claim_id": case_id,
            "claim_type": claim_type,
            "claim_value": claim_value,
        }
        source_claims[report_id] = claim
        reports.append(Report(
            case_id=case_id,
            report_id=report_id,
            claim=claim,
            evidence=_copy_evidence(evidence_by_report.get(report_id, {})),
            manual_assessment=text(row.get("manual_assessment")),
        ))
    return reports, source_claims


def _removed_evidence_ids(row: Mapping[str, object]) -> set[str]:
    """Read the semicolon-separated evidence IDs removed by one synthetic case."""
    return {
        token(value)
        for value in text(row.get("removed_evidence_ids")).split(";")
        if text(value)
    }


def _filtered_evidence(
    evidence: Mapping[str, Mapping[str, str]], removed_ids: set[str],
) -> dict[str, dict[str, str]]:
    """Copy the source evidence while leaving out IDs removed by a synthetic report."""
    return {
        evidence_id: dict(item)
        for evidence_id, item in evidence.items()
        if token(evidence_id) not in removed_ids
    }


def load_synthetic_reports(
    synthetic_rows: Iterable[Mapping[str, object]],
    source_claims: Mapping[str, Mapping[str, str]],
    evidence_by_report: Mapping[str, Mapping[str, Mapping[str, str]]],
) -> list[SyntheticReport]:
    """Create SyntheticReport objects directly from the Synthetic Claims worksheet."""
    rows = list(synthetic_rows)
    if not rows:
        return []
    require_columns(rows, SYNTHETIC_COLUMNS, "Synthetic Claims")

    synthetic_reports: list[SyntheticReport] = []
    seen_case_ids: set[str] = set()
    for row in rows:
        case_id = require(row.get("synthetic_claim_id"), "Synthetic Claims.synthetic_claim_id")
        if case_id in seen_case_ids or case_id in source_claims:
            raise ValueError(f"Duplicate claim identifier: {case_id}")
        seen_case_ids.add(case_id)

        report_id = normalise_report_id(
            require(row.get("report_id"), f"Synthetic claim {case_id}.report_id")
        )
        if report_id not in source_claims:
            raise ValueError(f"Synthetic claim {case_id} refers to missing report_id: {report_id}")
        source_claim = source_claims[report_id]

        claim_type = token(require(row.get("claim_type"), f"Synthetic claim {case_id}.claim_type"))
        if claim_type not in VALID_CLAIM_TYPES:
            raise ValueError(f"Synthetic claim {case_id} has unknown claim_type: {claim_type}")
        if claim_type != source_claim["claim_type"]:
            raise ValueError(
                f"Synthetic claim {case_id} has claim_type={claim_type}, but its source report "
                f"uses claim_type={source_claim['claim_type']}."
            )

        claim_value = token(require(row.get("claim_value"), f"Synthetic claim {case_id}.claim_value"))
        if claim_type == "maliciousness" and claim_value not in VALID_MALICIOUSNESS_VALUES:
            raise ValueError(f"Synthetic claim {case_id} has invalid claim_value: {claim_value}")
        if claim_type == "malware_family" and is_unknown_family(claim_value):
            raise ValueError(f"Synthetic claim {case_id} needs a named malware family.")

        manipulation_type = token(
            require(row.get("manipulation_type"), f"Synthetic claim {case_id}.manipulation_type")
        )
        if manipulation_type not in VALID_MANIPULATION_TYPES:
            raise ValueError(
                f"Synthetic claim {case_id} has invalid manipulation_type: {manipulation_type}"
            )

        removed_ids = _removed_evidence_ids(row)
        if manipulation_type == "remove_evidence" and not removed_ids:
            raise ValueError(
                f"Synthetic claim {case_id} uses remove_evidence but lists no removed_evidence_ids."
            )
        if manipulation_type != "remove_evidence" and removed_ids:
            raise ValueError(
                f"Synthetic claim {case_id} lists removed_evidence_ids without remove_evidence."
            )

        source_evidence = evidence_by_report.get(report_id, {})
        source_evidence_ids = {token(evidence_id) for evidence_id in source_evidence}
        unknown_removed_ids = removed_ids - source_evidence_ids
        if unknown_removed_ids:
            raise ValueError(
                f"Synthetic claim {case_id} removes evidence not found in report {report_id}: "
                f"{', '.join(sorted(unknown_removed_ids))}."
            )
        if manipulation_type == "claim_value_change" and claim_value == source_claim["claim_value"]:
            raise ValueError(
                f"Synthetic claim {case_id} uses claim_value_change but retains the source claim value: "
                f"{source_claim['claim_value']}."
            )
        if manipulation_type == "remove_evidence" and claim_value != source_claim["claim_value"]:
            raise ValueError(
                f"Synthetic claim {case_id} uses remove_evidence but changes the source claim value "
                f"from {source_claim['claim_value']} to {claim_value}."
            )

        evidence = _filtered_evidence(source_evidence, removed_ids)
        synthetic_reports.append(SyntheticReport(
            case_id=case_id,
            report_id=report_id,
            claim={
                "claim_id": case_id,
                "claim_type": claim_type,
                "claim_value": claim_value,
            },
            evidence=evidence,
            manipulation_type=manipulation_type,
            removed_evidence_ids=removed_ids,
            manual_assessment=text(row.get("manual_assessment")),
        ))
    return synthetic_reports


def load_all_reports(
    report_rows: Iterable[Mapping[str, object]],
    synthetic_rows: Iterable[Mapping[str, object]],
    source_rows: Iterable[Mapping[str, object]],
) -> tuple[list[Report], list[SyntheticReport]]:
    """Read all three input worksheets and return complete original and synthetic reports."""
    evidence_by_report = group_evidence(source_rows)
    reports, source_claims = load_reports(report_rows, evidence_by_report)
    synthetic_reports = load_synthetic_reports(synthetic_rows, source_claims, evidence_by_report)
    return reports, synthetic_reports
