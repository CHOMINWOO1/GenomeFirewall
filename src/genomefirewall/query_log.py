"""Query transcript schema for GenomeFirewall experiments."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any


@dataclass(frozen=True)
class QueryLogRecord:
    """One attempted query in an experiment transcript.

    Evaluation-only fields are included so attack metrics can be computed
    deterministically, but those fields must not be shown to attackers or used
    by production policy logic.
    """

    run_id: str
    dataset_seed: int
    workload_seed: int
    attacker_seed: int
    attacker_type: str
    policy_type: str
    query_index: int
    operator: str
    variant_id: str | None
    predicate_json: str
    cohort_size: int
    cohort_hash: str
    accepted: bool
    rejection_reason_bucket: str | None = None
    result_value: int | None = None
    max_prior_overlap: int | None = None
    min_prior_difference: int | None = None
    min_prior_symmetric_difference: int | None = None
    target_in_cohort: bool | None = None
    target_variant_carrier: bool | None = None
    attack_enabling_pair_id: str | None = None
    attacker_guess: bool | None = None
    attacker_confidence: float | None = None
    workload_label: str | None = None
    workload_family: str | None = None
    attack_template: str | None = None

    @classmethod
    def fieldnames(cls) -> list[str]:
        return [field.name for field in fields(cls)]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
