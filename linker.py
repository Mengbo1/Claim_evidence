from __future__ import annotations

import re
from dataclasses import dataclass

from .extractors import FAMILY_NAMES
from .models import Claim, Fact, Link
from .text_utils import normalize
from .yara_mappings import claim_terms_for_behavior


@dataclass(frozen=True)
class ClaimProfile:
    family_names: frozenset[str]
    topics: frozenset[str]
    asks_for_configuration: bool


FAMILY_ALIASES = {
    "quasar": ("quasar", "quasarrat"),
    "valleyrat": ("valleyrat", "valley rat"),
}


def _families_in_text(value: str) -> frozenset[str]:
    normalized = normalize(value)
    found: set[str] = set()
    for family in FAMILY_NAMES:
        aliases = FAMILY_ALIASES.get(family, (family,))
        if any(re.search(rf"\b{re.escape(alias)}\b", normalized) for alias in aliases):
            found.add(family)
    return frozenset(found)


def profile_claim(claim: Claim) -> ClaimProfile:
    structural = normalize(f"{claim.claim_type} {claim.predicate} {claim.object}")
    semantic = normalize(f"{structural} {claim.text}")
    family_names = _families_in_text(semantic)
    # A configuration/family claim can use words such as "execution contains"
    # in normal prose. For those claims, topic detection must rely on the
    # structured fields, otherwise generic process facts become false links.
    # claim_type=execution_behavior is a broad category, not proof that the
    # claim asks for process-execution facts. Topic detection therefore uses
    # the predicate/object/text and relies on explicit words such as process,
    # loader, HTTP, or persistence.
    topic_details = normalize(f"{claim.predicate} {claim.object} {claim.text}")
    topic_text = normalize(f"{claim.predicate} {claim.object}") if (
        "configuration" in structural or family_names
    ) else topic_details
    topics: set[str] = set()
    if re.search(r"persist|scheduled.?task|startup|run key|run-key|autorun", topic_text):
        topics.add("persistence")
    if re.search(r"network|http|c2|communicat|connect|download", topic_text):
        topics.add("network")
    if re.search(r"evasion|anti-analysis|anti analysis|injection|debug", topic_text):
        topics.add("defense_evasion")
    if re.search(
        r"dropper|loader|process chain|multi.?process|multi.?component execution|executes? (?:a )?process",
        topic_text,
    ):
        topics.add("execution")
    if claim.claim_type == "indicator_association" or re.search(r"ioc|url/ip infrastructure|indicator", structural):
        topics.add("ioc")
    # In an IOC claim, "malicious" describes the URL/IP, not the sample-wide
    # verdict. Verdict facts must not be linked as a substitute for IOC facts.
    if claim.claim_type == "maliciousness" or (
        "ioc" not in topics and re.search(r"malicious|high risk|confirmed threat|maliciousness|verdict", topic_text)
    ):
        topics.add("maliciousness")
    if re.search(r"cross.?platform|inconsistent platform|platform outcomes|disagreement", topic_text):
        topics.add("comparison")
    if family_names:
        topics.add("family")
    elif claim.claim_type in {"family_attribution", "malware_type"}:
        topics.add("generic_family")
    asks_for_configuration = bool(re.search(r"configuration|configured|config|c2 setting", semantic))
    return ClaimProfile(family_names, frozenset(topics), asks_for_configuration)


def _family_match(profile: ClaimProfile, fact: Fact) -> tuple[str, str] | None:
    """Link only facts that themselves name the claimed family.

    This prevents generic C2/version/mutex values from being attached to every
    family claim merely because the claim text contains a family name.
    """
    object_text = normalize(fact.object)
    named_families = {family for family in profile.family_names if re.search(rf"\b{family}\b", object_text)}
    if not named_families:
        return None
    if fact.predicate == "similar_to":
        return "weak_match", "family"
    if fact.predicate == "labelled_as":
        return "direct_match", "family"
    if fact.predicate == "contains_startup_name":
        return "direct_match", "family"
    return None


def _requested_persistence_predicates(claim_text: str) -> frozenset[str]:
    requested: set[str] = set()
    if re.search(r"scheduled.?task", claim_text):
        requested.add("creates_scheduled_task")
    if re.search(r"run.?key|autorun|registry modification", claim_text):
        requested.add("writes_run_key")
    if re.search(r"startup", claim_text):
        requested.update({"creates_startup_entry", "contains_startup_name"})
    return frozenset(requested)


def requested_persistence_components(claim: Claim) -> frozenset[str]:
    """Return the distinct persistence mechanisms requested by a claim.

    A Startup-folder observation can be represented by either an observed
    startup-entry fact or an extracted configured startup name. Treating both
    predicates as one semantic component lets claim-level scoring measure
    coverage without requiring duplicate evidence for the same mechanism.
    """
    claim_text = normalize(f"{claim.predicate} {claim.object} {claim.text}")
    requested: set[str] = set()
    if re.search(r"scheduled.?task", claim_text):
        requested.add("scheduled_task")
    if re.search(r"run.?key|autorun|registry modification", claim_text):
        requested.add("run_key")
    if re.search(r"startup", claim_text):
        requested.add("startup_entry")
    return frozenset(requested)


def _verdict_polarity(claim: Claim) -> str:
    claim_text = normalize(f"{claim.object} {claim.text}")
    if re.search(r"\bbenign\b|\bclean\b|no threats? detected|not malicious", claim_text):
        return "benign"
    return "malicious"


def classify_link(
    claim: Claim, fact: Fact, family_supported_in_scope: bool = True,
) -> tuple[str, str] | None:
    """Return (match label, claim topic) only for a substantively relevant fact."""
    profile = profile_claim(claim)
    claim_text = normalize(f"{claim.object} {claim.text}")

    # Semantic directness and evidence strength are separate: a mapped YARA
    # fact can exactly address a claim, but its detection-signal basis still
    # limits the final claim score in scoring.py.
    if fact.predicate == "indicates_behavior":
        if any(normalize(term) in claim_text for term in claim_terms_for_behavior(fact.object)):
            return "direct_match", "mapped_yara_behavior"

    if "family" in profile.topics:
        family_result = _family_match(profile, fact)
        if family_result:
            return family_result

    if "generic_family" in profile.topics and fact.predicate in {"labelled_as", "similar_to", "matched_yara_rule"}:
        return "weak_match", "generic_family"

    if "comparison" in profile.topics and fact.predicate in {
        "labelled_as", "similar_to", "classified_as", "detected_by_vendors",
    }:
        return "direct_match", "comparison"

    if "ioc" in profile.topics and fact.predicate in {
        "associated_with_malicious_url", "associated_with_malicious_ip",
    }:
        return "direct_match", "ioc"

    if "persistence" in profile.topics:
        requested = _requested_persistence_predicates(claim_text)
        if not requested or fact.predicate in requested:
            if fact.predicate in {"creates_scheduled_task", "writes_run_key", "creates_startup_entry"} and fact.event_status == "observed":
                return "direct_match", "persistence"
            if fact.predicate == "contains_startup_name" and fact.event_status == "configured":
                return "partial_match", "persistence"

    if "network" in profile.topics:
        asks_for_smtp = bool(re.search(r"\bsmtp\b", claim_text))
        asks_for_http_post = bool(re.search(r"http.?post|repeated.?post", claim_text))
        network_predicate_allowed = not (
            (asks_for_smtp and fact.predicate != "connects_to_smtp_port")
            or (
                asks_for_http_post
                and fact.predicate not in {"uses_http_post", "sends_http_request_to"}
            )
        )
        if network_predicate_allowed:
            if fact.predicate == "uses_http_post":
                return "direct_match", "network"
            if fact.predicate in {"sends_http_request_to", "connects_to", "connects_to_smtp_port", "downloads_executable"} and fact.event_status in {"observed", "reported"}:
                return "direct_match", "network"
            # A configured C2 may support only a claim explicitly about configuration;
            # it must not be linked to a claim about observed network traffic.
            if fact.predicate == "has_configured_c2" and profile.asks_for_configuration:
                return "partial_match", "network"

    if "defense_evasion" in profile.topics and fact.predicate in {
        "injects_code_into_process", "hides_from_debugger", "modifies_function_hooks",
    }:
        return "direct_match", "defense_evasion"

    if "execution" in profile.topics and fact.predicate in {
        "drops_file", "executes_process_chain", "loads_module",
    }:
        return "direct_match", "execution"

    if "maliciousness" in profile.topics:
        # For family claims such as "confirmed Phorpiex threat", a generic
        # verdict is relevant only after the claimed family is also named by a
        # fact in the same report scope. This prevents a confirmed verdict for
        # Phorpiex from supporting a synthetic Quasar claim.
        if profile.family_names and not family_supported_in_scope:
            return None
        polarity = _verdict_polarity(claim)
        if fact.predicate == "classified_as":
            fact_is_benign = fact.object in {"no_threats_detected", "benign", "clean"}
            if (polarity == "benign") != fact_is_benign:
                return "contradiction", "maliciousness"
            return "direct_match", "maliciousness"
        if fact.predicate == "detected_by_vendors":
            return ("contradiction", "maliciousness") if polarity == "benign" else ("direct_match", "maliciousness")
        if fact.predicate == "matched_yara_rule":
            return ("contradiction", "maliciousness") if polarity == "benign" else ("partial_match", "maliciousness")

    return None


def generate_links(claims: list[Claim], facts: list[Fact]) -> list[Link]:
    """Generate candidate links only inside the claim's sample and report scope."""
    links: list[Link] = []
    for claim in claims:
        scoped_facts = [
            fact for fact in facts
            if fact.sample_id == claim.sample_id and fact.report_id in claim.report_ids
        ]
        profile = profile_claim(claim)
        family_supported_in_scope = not profile.family_names or any(
            _family_match(profile, fact) is not None for fact in scoped_facts
        )
        for fact in scoped_facts:
            result = classify_link(claim, fact, family_supported_in_scope)
            if result is None:
                continue
            match_auto, topic = result
            links.append(Link(
                link_id=f"link{len(links) + 1:03d}", claim_id=claim.claim_id,
                fact_id=fact.fact_id, match_auto=match_auto, topic=topic,
                evidence_basis=fact.evidence_basis, predicate=fact.predicate,
                object=fact.object,
            ))
    return links
