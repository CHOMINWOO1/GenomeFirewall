"""Query release policies for GenomeFirewall experiments."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class PolicyEvaluation:
    """Policy input for one attempted aggregate query."""

    query_index: int
    operator: str
    variant_id: str | None
    cohort: frozenset[int]
    cohort_hash: str

    @property
    def cohort_size(self) -> int:
        return len(self.cohort)


@dataclass(frozen=True)
class PolicyDecision:
    accepted: bool
    reason_bucket: str | None = None
    max_prior_overlap: int | None = None
    min_prior_difference: int | None = None
    min_prior_symmetric_difference: int | None = None


class QueryPolicy(Protocol):
    name: str

    def decide(self, evaluation: PolicyEvaluation) -> PolicyDecision:
        """Return whether an aggregate result may be released."""


@dataclass(frozen=True)
class NoPrivacyPolicy:
    name: str = "no_privacy_policy"

    def decide(self, evaluation: PolicyEvaluation) -> PolicyDecision:
        return PolicyDecision(accepted=True)


@dataclass(frozen=True)
class MinimumCohortPolicy:
    k_min: int
    name: str = "minimum_cohort"

    def __post_init__(self) -> None:
        if self.k_min <= 0:
            raise ValueError("k_min must be positive")

    def decide(self, evaluation: PolicyEvaluation) -> PolicyDecision:
        if evaluation.cohort_size < self.k_min:
            return PolicyDecision(accepted=False, reason_bucket="small_cohort")
        return PolicyDecision(accepted=True)


@dataclass(frozen=True)
class AcceptedQueryRecord:
    query_index: int
    operator: str
    variant_id: str | None
    cohort: frozenset[int]
    cohort_hash: str
    result_value: int | None


@dataclass
class StatefulPrivacyLedgerPolicy:
    """Stateful policy that rejects risky overlaps with accepted prior queries."""

    k_min: int
    difference_min: int | None = None
    symmetric_difference_min: int | None = None
    same_variant_only: bool = True
    same_operator_only: bool = True
    name: str = "stateful_privacy_ledger"
    accepted_history: list[AcceptedQueryRecord] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.k_min <= 0:
            raise ValueError("k_min must be positive")
        if self.difference_min is not None and self.difference_min <= 0:
            raise ValueError("difference_min must be positive when set")
        if self.symmetric_difference_min is not None and self.symmetric_difference_min <= 0:
            raise ValueError("symmetric_difference_min must be positive when set")

    def decide(self, evaluation: PolicyEvaluation) -> PolicyDecision:
        if evaluation.cohort_size < self.k_min:
            return PolicyDecision(accepted=False, reason_bucket="small_cohort")

        comparable = [record for record in self.accepted_history if self._is_comparable(record, evaluation)]
        if not comparable:
            return PolicyDecision(accepted=True)

        overlaps: list[int] = []
        differences: list[int] = []
        symmetric_differences: list[int] = []

        for record in comparable:
            overlap = len(evaluation.cohort & record.cohort)
            forward_difference = len(evaluation.cohort - record.cohort)
            reverse_difference = len(record.cohort - evaluation.cohort)
            symmetric_difference = len(evaluation.cohort ^ record.cohort)

            overlaps.append(overlap)
            differences.append(min(forward_difference, reverse_difference))
            symmetric_differences.append(symmetric_difference)

        max_overlap = max(overlaps)
        min_difference = min(differences)
        min_symmetric_difference = min(symmetric_differences)

        if self.difference_min is not None and min_difference < self.difference_min:
            return PolicyDecision(
                accepted=False,
                reason_bucket="ledger_difference",
                max_prior_overlap=max_overlap,
                min_prior_difference=min_difference,
                min_prior_symmetric_difference=min_symmetric_difference,
            )

        if (
            self.symmetric_difference_min is not None
            and min_symmetric_difference < self.symmetric_difference_min
        ):
            return PolicyDecision(
                accepted=False,
                reason_bucket="ledger_symmetric_difference",
                max_prior_overlap=max_overlap,
                min_prior_difference=min_difference,
                min_prior_symmetric_difference=min_symmetric_difference,
            )

        return PolicyDecision(
            accepted=True,
            max_prior_overlap=max_overlap,
            min_prior_difference=min_difference,
            min_prior_symmetric_difference=min_symmetric_difference,
        )

    def record_accepted(self, evaluation: PolicyEvaluation, result_value: int | None) -> None:
        self.accepted_history.append(
            AcceptedQueryRecord(
                query_index=evaluation.query_index,
                operator=evaluation.operator,
                variant_id=evaluation.variant_id,
                cohort=evaluation.cohort,
                cohort_hash=evaluation.cohort_hash,
                result_value=result_value,
            )
        )

    def _is_comparable(self, record: AcceptedQueryRecord, evaluation: PolicyEvaluation) -> bool:
        if self.same_variant_only and record.variant_id != evaluation.variant_id:
            return False
        if self.same_operator_only and record.operator != evaluation.operator:
            return False
        return True
