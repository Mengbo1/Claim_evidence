from __future__ import annotations

import re
from typing import Any

from .models import Fact
from .text_utils import normalize, text
from .yara_mappings import lookup_yara_rule


FAMILY_NAMES = (
    "quasar", "valleyrat", "prometei", "formbook", "stealc",
    "phorpiex", "mirai", "vidar", "xworm", "njrat",
)


def _yara_rule_names(raw: str) -> set[str]:
    """Return only rule names explicitly displayed beside a YARA hit."""
    patterns = (
        r"matched(?:\s+a)?\s+(?:malicious\s+|suspicious\s+)?YARA\s+rule\s*[: ]+([A-Za-z0-9_.-]+)",
        r"\b([A-Za-z0-9_.-]+)\s+(?:has been\s+)?detected\s*\(YARA\)",
    )
    return {match.group(1) for pattern in patterns for match in re.finditer(pattern, raw, re.I)}


def extract_facts(rows: list[list[Any]], index: dict[str, int]) -> list[Fact]:
    """Convert each raw evidence statement into small, machine-readable facts."""
    facts: list[Fact] = []
    seen: set[tuple[str, ...]] = set()

    def add(
        row: list[Any], predicate: str, object_value: str, object_type: str,
        event_status: str, specificity: str = "generic", basis: str | None = None,
        domain: str | None = None,
    ) -> None:
        object_value = text(object_value)
        if not object_value:
            return
        candidate = Fact(
            fact_id=f"fact{len(facts) + 1:03d}",
            evidence_id=text(row[index["evidence_id"]]),
            sample_id=text(row[index["sample_id"]]),
            report_id=text(row[index["report_id"]]),
            evidence_basis=basis or text(row[index["evidence_basis"]]),
            evidence_domain=domain or text(row[index["evidence_domain"]]),
            predicate=predicate,
            object=object_value,
            object_type=object_type,
            event_status=event_status,
            specificity=specificity,
        )
        key = tuple(normalize(value) for value in candidate.as_row()[1:])
        if key not in seen:
            seen.add(key)
            facts.append(candidate)

    for row in rows:
        raw = text(row[index["raw_evidence"]])

        c2 = re.search(r"\bC2\s*[:=]?\s*([A-Za-z0-9.-]+:\d+)", raw, re.I)
        if c2:
            add(row, "has_configured_c2", c2.group(1), "c2_endpoint", "configured", basis="extracted_artifact", domain="configuration")
        version = re.search(r"\bversion\s+([0-9]+(?:\.[0-9]+)+)", raw, re.I)
        if version:
            add(row, "has_configured_version", version.group(1), "software_version", "configured", basis="extracted_artifact", domain="configuration")
        mutex = re.search(r"\bmutex\s+([A-Za-z0-9-]{8,})", raw, re.I)
        if mutex:
            add(row, "contains_mutex_value", mutex.group(1), "mutex", "configured", "unknown", "extracted_artifact", "configuration")
        startup = re.search(r"\bstartup\s+([^;]+)", raw, re.I)
        if startup:
            add(row, "contains_startup_name", startup.group(1), "startup_entry", "configured", "unknown", "extracted_artifact", "configuration")

        if re.search(r"schtasks\s*/create|scheduled.?task", raw, re.I):
            add(row, "creates_scheduled_task", "scheduled_task", "scheduled_task", "observed", basis="direct_observation", domain="persistence_host_change")
        if re.search(r"HKCU\\.*\\Run|Run-key|autorun value in the registry|autorun registry", raw, re.I):
            add(row, "writes_run_key", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "registry_key", "observed", basis="direct_observation", domain="persistence_host_change")
        if re.search(r"startup.?folder|\\Startup\\|startup\\", raw, re.I):
            add(row, "creates_startup_entry", "startup_folder", "startup_entry", "observed", basis="direct_observation", domain="persistence_host_change")

        urls = re.findall(r"https?://[^\s;\"')]+", raw, re.I)
        endpoints = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", raw)
        if re.search(r"HTTP\s+POST|repeated\s+POST|HTTP\s+GET|network\s+threat", raw, re.I):
            for url in urls:
                add(row, "sends_http_request_to", url, "url", "observed", basis="direct_observation", domain="network")
            for endpoint in endpoints:
                add(row, "connects_to", endpoint, "network_endpoint", "observed", basis="direct_observation", domain="network")
        elif re.search(r"C2 network traffic|CnC|C&C|command and control", raw, re.I):
            for endpoint in endpoints:
                add(row, "connects_to", endpoint, "network_endpoint", "reported", "specific")
        if re.search(r"HTTP\s+POST|repeated\s+POST", raw, re.I):
            add(row, "uses_http_post", "http_post", "network_protocol_activity", "reported", "specific")
        if re.search(r"connects? to SMTP port|SMTP port", raw, re.I):
            add(row, "connects_to_smtp_port", "smtp_port", "network_service", "observed", basis="direct_observation", domain="network")
        if re.search(r"downloaded|executable.?download|payload delivery", raw, re.I):
            add(row, "downloads_executable", "executable_payload", "network_event", "observed", basis="detection_signal", domain="network")

        if re.search(r"injected code|application was injected|process injection", raw, re.I):
            add(row, "injects_code_into_process", "another_process", "process_injection", "reported", basis="detection_signal", domain="defense_evasion")
        if re.search(r"hide thread|anti-debug|debugger", raw, re.I):
            add(row, "hides_from_debugger", "debugger", "anti_analysis_event", "reported", basis="detection_signal", domain="defense_evasion")
        if re.search(r"unhook|modify Windows functions|function hooks", raw, re.I):
            add(row, "modifies_function_hooks", "Windows_functions", "anti_analysis_event", "reported", basis="detection_signal", domain="defense_evasion")
        if re.search(r"dropped?\s+[^;]*\.dll|dropped?\s+[^;]*\.exe|output_64\.bin|loader\.exe|persist\.dll|executable content was dropped or overwritten", raw, re.I):
            add(row, "drops_file", "dropped_component", "dropped_file", "observed", basis="direct_observation", domain="execution_process")
        if re.search(r"process chain|process tree|->.*\.exe", raw, re.I):
            add(row, "executes_process_chain", "multi_process_execution", "process_chain", "observed", basis="direct_observation", domain="execution_process")
        if re.search(r"loaded\s+[^;]*\.dll|module[s]? include", raw, re.I):
            add(row, "loads_module", "loaded_module", "module", "observed", basis="direct_observation", domain="execution_process")
        if re.search(r"steals? (?:credentials|login information) from (?:web )?browsers|browser credential theft", raw, re.I):
            add(
                row, "indicates_behavior", "browser_login_information_collection",
                "behavior_capability", "observed", "specific",
            )
        if re.search(r"YARA", raw, re.I):
            add(row, "matched_yara_rule", "malicious_or_suspicious_yara_rule", "yara_rule", "reported", basis="detection_signal", domain="static_file")
            for rule_name in _yara_rule_names(raw):
                mapping = lookup_yara_rule(rule_name)
                if mapping is None:
                    # Preserve an unknown rule name but never guess its meaning.
                    add(row, "matched_yara_rule", rule_name, "yara_rule", "reported", "unknown", "detection_signal", "static_file")
                    continue
                add(
                    row,
                    str(mapping["predicate"]),
                    str(mapping["canonical_id"]),
                    str(mapping["object_type"]),
                    "reported",
                    "specific",
                    "detection_signal",
                    str(mapping["evidence_domain"]),
                )
        api = re.search(r"\b(GetNativeSystemInfo|GetSystemInfo|NtSetInformationThread)\b", raw, re.I)
        if api:
            add(row, "contains_api_indicator", api.group(1), "api_string_or_call", "reported", basis="extracted_artifact", domain="static_file")

        if re.search(r"Confirmed Threat", raw, re.I):
            add(row, "classified_as", "confirmed_threat", "platform_verdict", "reported", basis="platform_assessment", domain="maliciousness")
        if re.search(r"Malicious activity|verdict\s*[:=]?\s*malicious\b", raw, re.I):
            add(row, "classified_as", "confirmed_threat", "platform_verdict", "reported", basis="platform_assessment", domain="maliciousness")
        if re.search(r"High Risk", raw, re.I):
            add(row, "classified_as", "high_risk", "platform_verdict", "reported", basis="platform_assessment", domain="maliciousness")
        if re.search(r"No threats detected", raw, re.I):
            add(row, "classified_as", "no_threats_detected", "platform_verdict", "reported", basis="platform_assessment", domain="maliciousness")
        vendor = re.search(r"\b(\d+)\s*/\s*(\d+)\s*(?:AV|vendors?|security vendors?)", raw, re.I)
        if vendor:
            add(row, "detected_by_vendors", f"{vendor.group(1)}_of_{vendor.group(2)}_vendors", "multi_vendor_verdict", "reported", basis="detection_signal", domain="maliciousness")

        for family in FAMILY_NAMES:
            if not re.search(rf"\b{family}\b", raw, re.I):
                continue
            if re.search(r"similar|imphash", raw, re.I):
                add(row, "similar_to", family, "malware_family", "reported", basis="reputation_context", domain="attribution_classification")
            if re.search(r"label|signature|family|tag|component", raw, re.I):
                add(row, "labelled_as", family, "malware_family", "reported", "unknown", "platform_assessment", "attribution_classification")

        if re.search(r"IOC|malicious URL|malicious resource", raw, re.I):
            for url in urls:
                add(row, "associated_with_malicious_url", url, "url", "reported", basis="reputation_context", domain="ioc_reputation")
            for endpoint in endpoints:
                add(row, "associated_with_malicious_ip", endpoint, "ip_address", "reported", basis="reputation_context", domain="ioc_reputation")

        if not any(fact.evidence_id == text(row[index["evidence_id"]]) for fact in facts):
            add(row, "reported_text", raw[:180], "text_excerpt", "reported", "unknown")

    return facts
