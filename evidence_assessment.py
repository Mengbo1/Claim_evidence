"""Apply evidence rules and store the result inside each report."""

import re

from report_data import AssessmentReport, is_unknown_family, text, token


def _analysis(
    evidence_id: str,
    family_name: str = "",
    direction: str = "",
    evidence_strength: str = "",
    rule_id: str = "no_rule",
    rationale: str = "No reliable rule matched.",
) -> dict[str, str]:
    """Return one consistently shaped evidence-analysis record."""
    matched = bool(evidence_strength and (direction or family_name))
    return {
        "evidence_id": evidence_id,
        "family_name": family_name,
        "direction": direction,
        "evidence_strength": evidence_strength,
        "match_status": "matched" if matched else "unknown",
        "rule_id": rule_id,
        "rationale": rationale,
    }


def analyse_maliciousness_evidence(raw_evidence: object, evidence_id: str) -> dict[str, str]:
    """Classify one evidence excerpt as a maliciousness signal or an unknown signal."""
    lower = text(raw_evidence).casefold()
    if re.search(r"\b(classified as benign|known clean|explicitly non[- ]malicious|marked benign)\b", lower):
        return _analysis(
            evidence_id, direction="toward_benign", evidence_strength="strong",
            rule_id="explicit_benign_judgement",
            rationale="The evidence explicitly classifies the analysed object as benign/clean.",
        )
    if re.search(r"\bwas marked malicious\b", lower):
        return _analysis(
            evidence_id, direction="toward_malicious", evidence_strength="strong",
            rule_id="explicit_malicious_judgement",
            rationale="The report explicitly marked an analysed process or object malicious.",
        )

    named_reputation_provider = bool(
        re.search(r"\b(?:opswat(?:[_ -](?:metadefender|reputation))?|virus(?:[_ -]?total)?|metadefender)\b", lower)
    )
    exact_hash = re.search(r"\b(input[- ]file|file[_ -]?hash(?:[_ -]?sha256)?|sha[- ]?256)\b", lower)
    if exact_hash and "malicious" in lower and named_reputation_provider:
        if "likely_malicious" in lower:
            return _analysis(
                evidence_id, direction="toward_malicious", evidence_strength="moderate",
                rule_id="likely_malicious_reputation",
                rationale="A named reputation provider classified the analysed file/hash as likely malicious.",
            )
        return _analysis(
            evidence_id, direction="toward_malicious", evidence_strength="strong",
            rule_id="exact_object_reputation",
            rationale="A named reputation provider classified the analysed file/hash as malicious.",
        )

    av_match = re.search(r"detected (?:the sample )?by\s+(\d+)\s*/\s*(\d+)\s+av engines", lower)
    if av_match:
        detected, total = (int(av_match.group(1)), int(av_match.group(2)))
        if total > 0 and detected / total >= 0.5:
            return _analysis(
                evidence_id, direction="toward_malicious", evidence_strength="moderate",
                rule_id="av_detection_ratio_high",
                rationale="At least half of the reported AV engines detected the sample.",
            )
        if detected > 0:
            return _analysis(
                evidence_id, direction="toward_malicious", evidence_strength="weak",
                rule_id="av_detection_ratio_low",
                rationale="One or more AV engines detected the sample, but the detection ratio is below one half.",
            )

    if re.search(r"\bet malware\b", lower):
        return _analysis(
            evidence_id, direction="toward_malicious", evidence_strength="moderate",
            rule_id="malware_network_detection",
            rationale="A malware-specific network detection label was reported.",
        )
    yara_detection = "yara" in lower and bool(
        re.search(r"\b(detected|matched|has been detected|was detected|included)\b", lower)
    )
    suricata_detection = "suricata" in lower and (
        bool(re.search(r"\b(detected|matched|has been detected|was detected)\b", lower))
        or bool(re.search(r"\b(malware|rat|trojan|vidar|stealc|valleyrat|processkiller)\b", lower))
    )
    if yara_detection or suricata_detection:
        if re.search(r"\b(malware|credential|steal(?:er|ing)?|injection|processkiller|meterpreter|rat|trojan|ransomware|miner|formbook|vidar|stealc|valleyrat|njrat|quasarrat|xworm)\b", lower):
            return _analysis(
                evidence_id, direction="toward_malicious", evidence_strength="moderate",
                rule_id="specific_signature_detection",
                rationale="A malware-specific YARA or Suricata signature detection was reported.",
            )
        if re.search(r"\b(packer|entropy|obfuscat|anti[- ]?debug|evasion|generic suspicious)\b", lower):
            return _analysis(
                evidence_id, direction="toward_malicious", evidence_strength="weak",
                rule_id="generic_signature_detection",
                rationale="A generic YARA or Suricata signature detection was reported without malware-specific context.",
            )
    if re.search(r"\b(offline_reputation|opswat_reputation)\b", lower) and re.search(r"\burl\b", lower) and "malicious" in lower:
        return _analysis(
            evidence_id, direction="toward_malicious", evidence_strength="moderate",
            rule_id="malicious_url_reputation",
            rationale="A reputation provider classified a URL related to the sample as malicious.",
        )
    if re.search(r"\b(was injected by another process|runs injected code|process injection)\b", lower):
        return _analysis(
            evidence_id, direction="toward_malicious", evidence_strength="moderate",
            rule_id="process_injection_indicator",
            rationale="The evidence reports a process-injection indicator.",
        )
    if re.search(r"\b(vulnerable driver|steals? credentials|credential.?steal|c2-specific)\b", lower):
        return _analysis(
            evidence_id, direction="toward_malicious", evidence_strength="moderate",
            rule_id="specific_malicious_behaviour",
            rationale="The evidence reports a specific malicious detection or behaviour indicator.",
        )
    dep_disabled = bool(
        re.search(r"\b(?:data\s+execution\s+prevention(?:\s*\(\s*dep\s*\))?|dep)\s+(?:is\s+)?disabled\b", lower)
    )
    if dep_disabled or re.search(r"\b(high entropy|not digitally signed|unsigned|configured c2|suspicious packer|packer/protector)\b", lower):
        return _analysis(
            evidence_id, direction="toward_malicious", evidence_strength="weak",
            rule_id="generic_suspicious_indicator",
            rationale="The evidence reports a generic suspicious indicator but no direct malware-specific detection.",
        )
    if re.search(r"\b(threat reputation detected \d+ (?:confirmed threat )?iocs?|confirmed threat ioc)\b", lower):
        return _analysis(
            evidence_id, direction="toward_malicious", evidence_strength="weak",
            rule_id="ioc_summary_indicator",
            rationale="The evidence reports an IOC count without fully identifying the underlying IOC evidence.",
        )
    return _analysis(evidence_id)


def analyse_family_evidence(raw_evidence: object, evidence_id: str) -> dict[str, str]:
    """Extract a malware-family label from CAPE evidence without reading the claim value."""
    raw = text(raw_evidence)
    if "cape" not in raw.casefold():
        return _analysis(evidence_id)

    config_match = re.search(
        r'(?:extracted|displayed)\s+(?:an?\s+)?["“]?([A-Za-z][A-Za-z0-9._ -]{0,80}?)\s+Config(?=["”\s,.:;]|$)',
        raw,
        flags=re.IGNORECASE,
    )
    if config_match:
        family = token(config_match.group(1))
        if not is_unknown_family(family):
            partial_markers = (
                "partially extracted", "partially decoded", "garbled", "undecoded", "unreadable",
            )
            is_partial = any(marker in raw.casefold() for marker in partial_markers)
            return _analysis(
                evidence_id, family_name=family,
                evidence_strength="moderate" if is_partial else "strong",
                rule_id="cape_partial_configuration_family" if is_partial else "cape_configuration_family",
                rationale=(
                    "CAPE extracted or displayed a partially decoded named malware-family configuration."
                    if is_partial else "CAPE extracted or displayed a named malware-family configuration."
                ),
            )

    process_match = re.search(
        r'\b(?:labelled|labeled|tagged|classified)\b.{0,240}?\bas\s+["“]?([A-Za-z][A-Za-z0-9._ -]{0,80}?)(?=["”\s,.;:]|$)',
        raw,
        flags=re.IGNORECASE,
    )
    if process_match:
        family = token(process_match.group(1))
        if not is_unknown_family(family):
            return _analysis(
                evidence_id, family_name=family, evidence_strength="moderate",
                rule_id="cape_process_family_label",
                rationale="CAPE assigned a named malware-family label in the process tree.",
            )
    return _analysis(evidence_id)


def analyse_evidence(report: AssessmentReport) -> None:
    """Analyse every evidence excerpt in one complete report and store the results there."""
    claim_type = report.claim["claim_type"]
    report.evidence_analysis = {}
    for evidence_id, evidence in report.evidence.items():
        raw_evidence = evidence["raw_evidence"]
        if claim_type == "maliciousness":
            result = analyse_maliciousness_evidence(raw_evidence, evidence_id)
        elif claim_type == "malware_family":
            result = analyse_family_evidence(raw_evidence, evidence_id)
        else:
            result = _analysis(evidence_id)
        report.evidence_analysis[evidence_id] = result
