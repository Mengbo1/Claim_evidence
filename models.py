from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Fact:
    fact_id: str
    evidence_id: str
    sample_id: str
    report_id: str
    evidence_basis: str
    evidence_domain: str
    predicate: str
    object: str
    object_type: str
    event_status: str
    specificity: str

    def as_row(self) -> list[str]:
        return [
            self.fact_id, self.evidence_id, self.sample_id, self.report_id,
            self.evidence_basis, self.evidence_domain, self.predicate,
            self.object, self.object_type, self.event_status, self.specificity,
        ]


@dataclass(frozen=True)
class Claim:
    claim_id: str
    sample_id: str
    report_ids: tuple[str, ...]
    claim_type: str
    predicate: str
    object: str
    text: str


@dataclass(frozen=True)
class Link:
    link_id: str
    claim_id: str
    fact_id: str
    match_auto: str
    topic: str
    evidence_basis: str
    predicate: str
    object: str

    def as_row(self) -> list[str]:
        return [self.link_id, self.claim_id, self.fact_id, self.match_auto]
