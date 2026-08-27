"""Load a small, editable vocabulary for YARA-rule meanings."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path


def normalize_rule_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


@lru_cache(maxsize=1)
def load_yara_mappings() -> dict[str, dict[str, object]]:
    path = Path(__file__).with_name("yara_rule_mappings.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    mappings: dict[str, dict[str, object]] = {}
    for behavior in document.get("behaviors", []):
        for alias in behavior.get("aliases", []):
            mappings[normalize_rule_name(str(alias))] = behavior
    return mappings


def lookup_yara_rule(rule_name: str) -> dict[str, object] | None:
    return load_yara_mappings().get(normalize_rule_name(rule_name))


def claim_terms_for_behavior(canonical_id: str) -> tuple[str, ...]:
    seen: set[str] = set()
    for behavior in load_yara_mappings().values():
        if behavior["canonical_id"] == canonical_id and canonical_id not in seen:
            seen.add(canonical_id)
            return tuple(str(term) for term in behavior.get("claim_terms", []))
    return ()
