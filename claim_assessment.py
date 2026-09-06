"""Turn evidence-analysis results into one final assessment for each report."""

from collections import Counter
from typing import Iterable, Optional

from report_data import AssessmentReport, SyntheticReport, is_unknown_family


STRENGTH_RANK = {"strong": 3, "moderate": 2, "weak": 1}
MALICIOUSNESS_LEVEL_RANK = {
    "no_threat": 0,
    "low_risk": 1,
    "high_risk": 2,
    "malicious": 3,
}


def _highest_strength(items: Iterable[dict[str, str]]) -> dict[str, str]:
    """Keep the strongest signal for each evidence ID."""
    strongest: dict[str, str] = {}
    for item in items:
        evidence_id = item["evidence_id"]
        old_strength = strongest.get(evidence_id)
        if old_strength is None or STRENGTH_RANK[item["evidence_strength"]] > STRENGTH_RANK[old_strength]:
            strongest[evidence_id] = item["evidence_strength"]
    return strongest


def _report_kind(report: AssessmentReport) -> str:
    """Return the workbook group used for output and agreement results."""
    return "synthetic" if isinstance(report, SyntheticReport) else "report"


def _result(
    report: AssessmentReport,
    supporting: Iterable[dict[str, str]],
    contradicting: Iterable[dict[str, str]],
    assessment: str,
    rationale: str,
) -> dict[str, object]:
    """Store one final result in the report and return the worksheet output row."""
    support_by_evidence = _highest_strength(supporting)
    contradiction_by_evidence = _highest_strength(contradicting)
    support_counts = Counter(support_by_evidence.values())
    contradiction_counts = Counter(contradiction_by_evidence.values())

    report.automatic_assessment = assessment
    report.assessment_rationale = rationale
    manipulation_type = report.manipulation_type if isinstance(report, SyntheticReport) else ""
    return {
        "claim_id": report.case_id,
        "report_id": report.report_id,
        "claim_source_type": _report_kind(report),
        "manipulation_type": manipulation_type,
        "claim_type": report.claim["claim_type"],
        "claim_value": report.claim["claim_value"],
        "strong_support_count": support_counts["strong"],
        "moderate_support_count": support_counts["moderate"],
        "weak_support_count": support_counts["weak"],
        "strong_contradiction_count": contradiction_counts["strong"],
        "moderate_contradiction_count": contradiction_counts["moderate"],
        "weak_contradiction_count": contradiction_counts["weak"],
        "supporting_evidence_ids": "; ".join(sorted(support_by_evidence)),
        "contradicting_evidence_ids": "; ".join(sorted(contradiction_by_evidence)),
        "assessment": assessment,
        "assessment_rationale": rationale,
    }


def _evidence_level(
    malicious_evidence: Counter[str], benign_evidence: Counter[str],
) -> tuple[Optional[str], Optional[str]]:
    """Convert the strongest malicious and benign signals into one maliciousness level."""
    malicious_rank = max(
        (STRENGTH_RANK[level] for level, count in malicious_evidence.items() if count), default=0,
    )
    benign_rank = max(
        (STRENGTH_RANK[level] for level, count in benign_evidence.items() if count), default=0,
    )
    if malicious_rank >= 2 and benign_rank >= 2:
        return None, "Moderate/strong malicious evidence and explicit benign evidence conflict."
    if malicious_evidence["strong"] >= 1 or malicious_evidence["moderate"] >= 2:
        return "malicious", None
    if malicious_evidence["moderate"] >= 1:
        return "high_risk", None
    if malicious_evidence["weak"] >= 1:
        return "low_risk", None
    return "no_threat", None


def _assess_maliciousness(report: AssessmentReport) -> dict[str, object]:
    """Compare a maliciousness claim with the evidence already stored in its report."""
    matched = [
        item for item in report.evidence_analysis.values()
        if item["match_status"] == "matched"
    ]
    malicious_evidence = [item for item in matched if item["direction"] == "toward_malicious"]
    benign_evidence = [item for item in matched if item["direction"] == "toward_benign"]
    malicious_strengths = Counter(_highest_strength(malicious_evidence).values())
    benign_strengths = Counter(_highest_strength(benign_evidence).values())
    evidence_level, conflict_reason = _evidence_level(malicious_strengths, benign_strengths)
    if conflict_reason:
        return _result(report, malicious_evidence, benign_evidence, "unclear", conflict_reason)

    assert evidence_level is not None
    claim_value = report.claim["claim_value"]
    difference = MALICIOUSNESS_LEVEL_RANK[evidence_level] - MALICIOUSNESS_LEVEL_RANK[claim_value]
    if difference == 0:
        if evidence_level == "no_threat":
            rationale = (
                "No malicious evidence signal was found in the selected evidence scope; "
                "this supports a no_threat claim within that scope, not a benign ground-truth conclusion."
            )
        elif evidence_level == "high_risk" and malicious_strengths["moderate"] < 2:
            return _result(
                report,
                malicious_evidence,
                benign_evidence,
                "weakly_supported",
                "One moderate threat signal indicates high risk, but does not fully substantiate a High Risk platform claim.",
            )
        else:
            rationale = f"The evidence-derived maliciousness level matches the platform claim: {evidence_level}."
        return _result(report, malicious_evidence, benign_evidence, "strongly_supported", rationale)
    if abs(difference) == 1:
        level_direction = "higher" if difference > 0 else "lower"
        return _result(
            report,
            malicious_evidence,
            benign_evidence,
            "weakly_supported",
            f"The evidence-derived maliciousness level is one step {level_direction} than the platform claim.",
        )
    if difference >= 2:
        return _result(
            report,
            malicious_evidence,
            benign_evidence,
            "contradicted",
            "The evidence-derived maliciousness level is materially higher than the platform claim.",
        )
    if benign_strengths["strong"] >= 1:
        return _result(
            report,
            malicious_evidence,
            benign_evidence,
            "contradicted",
            "Explicit benign/clean evidence materially conflicts with the platform claim.",
        )
    return _result(
        report,
        malicious_evidence,
        benign_evidence,
        "unsupported",
        "The evidence-derived maliciousness level is materially lower than the platform claim.",
    )


def _generic_assessment(
    supporting: Counter[str], contradicting: Counter[str],
) -> tuple[str, str]:
    """Use the shared strength threshold for malware-family assessments."""
    support_rank = max(
        (STRENGTH_RANK[level] for level, count in supporting.items() if count), default=0,
    )
    contradiction_rank = max(
        (STRENGTH_RANK[level] for level, count in contradicting.items() if count), default=0,
    )
    if support_rank >= 2 and contradiction_rank >= 2:
        return "unclear", "Moderate/strong evidence exists on both supporting and contradicting sides."
    if (contradicting["strong"] >= 1 or contradicting["moderate"] >= 2) and contradiction_rank >= support_rank:
        return "contradicted", "The claim has decisive contradiction evidence and no same-grade support."
    if supporting["strong"] >= 1 or supporting["moderate"] >= 2:
        return "strongly_supported", "The claim has one strong or at least two distinct moderate supporting evidence units."
    if sum(supporting.values()) > 0:
        return "weakly_supported", "The claim has some supporting evidence but does not meet the strong-support threshold."
    return "unsupported", "No matching evidence analysis supports or decisively contradicts the claim."


def _assess_family(report: AssessmentReport) -> dict[str, object]:
    """Compare a CAPE-derived named family with the report's malware-family claim."""
    named_family_evidence = [
        item for item in report.evidence_analysis.values()
        if item["match_status"] == "matched" and not is_unknown_family(item["family_name"])
    ]
    claim_value = report.claim["claim_value"]
    if is_unknown_family(claim_value):
        if named_family_evidence:
            return _result(
                report,
                [],
                named_family_evidence,
                "contradicted",
                "A named malware-family value appears in the selected evidence scope, which conflicts with an N/A family claim.",
            )
        return _result(
            report,
            [],
            [],
            "strongly_supported",
            "No named malware-family evidence was found in the selected evidence scope; this supports an N/A family claim within that scope.",
        )

    supporting = [
        item for item in named_family_evidence if item["family_name"] == claim_value
    ]
    support_counts = Counter(_highest_strength(supporting).values())
    assessment, rationale = _generic_assessment(support_counts, Counter())
    return _result(report, supporting, [], assessment, rationale)


def assess_report(report: AssessmentReport) -> dict[str, object]:
    """Give one complete report its final claim assessment after evidence analysis."""
    if set(report.evidence) != set(report.evidence_analysis):
        raise ValueError(
            f"Report {report.case_id} has not had all of its evidence analysed."
        )
    claim_type = report.claim["claim_type"]
    if claim_type == "maliciousness":
        return _assess_maliciousness(report)
    if claim_type == "malware_family":
        return _assess_family(report)
    return _result(
        report,
        [],
        [],
        "review_required",
        f"No analyser is implemented for claim_type={claim_type}.",
    )


def assess_reports(reports: Iterable[AssessmentReport]) -> list[dict[str, object]]:
    """Assess every original or synthetic report after its evidence has been analysed."""
    return [assess_report(report) for report in reports]
