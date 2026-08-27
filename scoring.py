from __future__ import annotations

from collections import defaultdict
import re

from .linker import profile_claim, requested_persistence_components
from .models import Claim, Link


PERSISTENCE_COMPONENT_BY_PREDICATE = {
    "creates_scheduled_task": "scheduled_task",
    "writes_run_key": "run_key",
    "creates_startup_entry": "startup_entry",
    "contains_startup_name": "startup_entry",
}


def _link_strength(link: Link) -> int:
    """Score link quality without treating platform labels as primary proof."""
    if link.match_auto == "contradiction":
        return -3
    high_quality = link.evidence_basis in {"direct_observation", "extracted_artifact"}
    detection_signal = link.evidence_basis == "detection_signal"
    if link.match_auto == "direct_match":
        return 3 if high_quality else 2 if detection_signal else 1
    if link.match_auto == "partial_match":
        return 2 if high_quality else 1
    return 1


def _vendor_ratio(link: Link) -> float | None:
    match = re.fullmatch(r"(\d+)_of_(\d+)_vendors", link.object)
    if not match:
        return None
    detected, total = (int(value) for value in match.groups())
    return detected / total if total else None


def aggregate_claim_assessments(claims: list[Claim], links: list[Link]) -> dict[str, str]:
    """Assign a conservative claim-level assessment.

    Levels use the same vocabulary as the human sheet: weak, moderate, support,
    and strong. Strong requires corroboration, not merely one direct label.
    """
    by_claim: dict[str, list[Link]] = defaultdict(list)
    for link in links:
        by_claim[link.claim_id].append(link)

    results: dict[str, str] = {}
    for claim in claims:
        claim_links = by_claim[claim.claim_id]
        positive_links = [link for link in claim_links if link.match_auto != "contradiction"]
        if not positive_links:
            results[claim.claim_id] = "contradicted" if claim_links else "not_verifiable"
            continue

        profile = profile_claim(claim)
        strengths = [_link_strength(link) for link in positive_links]
        high_links = [link for link in positive_links if _link_strength(link) == 3]
        medium_links = [link for link in positive_links if _link_strength(link) == 2]
        narrative = claim.text.lower()
        hedged_behavior = claim.claim_type == "execution_behavior" and bool(re.search(r"\blike\b|\blikely\b", narrative))
        required_behavior_topics = profile.topics & {
            "execution", "network", "defense_evasion", "persistence",
        }
        covered_behavior_topics = {link.topic for link in positive_links}

        requested_persistence = requested_persistence_components(claim)
        covered_persistence = {
            component
            for link in positive_links
            if (component := PERSISTENCE_COMPONENT_BY_PREDICATE.get(link.predicate))
        }

        # A persistence claim that names two or more distinct mechanisms is a
        # compound claim. One observed mechanism supports only that part of the
        # sentence; it must not make the complete claim strongly supported.
        # This cap is applied before the single-event persistence rule below.
        if (
            len(requested_persistence) > 1
            and covered_persistence
            and not requested_persistence.issubset(covered_persistence)
        ):
            results[claim.claim_id] = "weak_support"
            continue

        # A compound behaviour claim must not become strong merely because one
        # part has several facts. If at least one requested behaviour topic is
        # missing, the available evidence supports only part of the claim.
        if (
            claim.claim_type == "execution_behavior"
            and len(required_behavior_topics) > 1
            and not required_behavior_topics.issubset(covered_behavior_topics)
        ):
            results[claim.claim_id] = "weak_support"
            continue

        vendor_ratios = [
            ratio for link in positive_links if link.predicate == "detected_by_vendors"
            if (ratio := _vendor_ratio(link)) is not None
        ]
        has_verdict = any(
            link.predicate == "classified_as" and link.object in {"confirmed_threat", "high_risk"}
            for link in positive_links
        )
        has_conflicting_platform_outcomes = (
            any(link.object == "no_threats_detected" for link in claim_links)
            and any(link.object in {"confirmed_threat", "high_risk"} for link in positive_links)
        )

        if "comparison" in profile.topics and has_conflicting_platform_outcomes:
            results[claim.claim_id] = "strong_support"
        # A narrow persistence claim is directly demonstrated by one observed
        # registry Run-key, scheduled-task, or Startup-folder action; requiring
        # a second fact here would wrongly downgrade a concrete event.
        elif claim.claim_type == "persistence" and "persistence" in profile.topics and high_links:
            results[claim.claim_id] = "strong_support"
        elif "ioc" in profile.topics and len({link.fact_id for link in positive_links}) >= 2:
            results[claim.claim_id] = "strong_support"
        elif claim.claim_type == "maliciousness" and has_verdict and any(ratio >= 0.50 for ratio in vendor_ratios):
            results[claim.claim_id] = "strong_support"
        elif claim.claim_type in {"family_attribution", "configuration"} and any(
            link.topic == "family" and _link_strength(link) == 3 for link in positive_links
        ) and len(positive_links) >= 2:
            results[claim.claim_id] = "strong_support"
        # One platform family label is meaningful but remains an association,
        # not a settled family attribution.
        elif ("family" in profile.topics or "generic_family" in profile.topics) and all(
            link.predicate == "labelled_as" for link in positive_links
        ):
            results[claim.claim_id] = "moderate_support"
        elif not hedged_behavior and len({(link.topic, link.predicate) for link in high_links}) >= 2:
            results[claim.claim_id] = "strong_support"
        # A YARA hit plus one or more platform verdicts is relevant, but without
        # multi-vendor corroboration or a direct technical observation it stays
        # weak for a whole-sample maliciousness claim.
        elif "maliciousness" in profile.topics and not vendor_ratios and not high_links:
            results[claim.claim_id] = "weak_support"
        elif max(strengths) >= 2:
            results[claim.claim_id] = "support"
        elif len(positive_links) >= 2:
            results[claim.claim_id] = "moderate_support"
        else:
            results[claim.claim_id] = "weak_support"
    return results
