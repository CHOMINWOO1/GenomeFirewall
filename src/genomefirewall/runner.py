"""Helpers for evaluating query attempts and producing transcript rows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .policies import PolicyEvaluation, QueryPolicy
from .query_log import QueryLogRecord
from .synthetic import GenomicQuery, SyntheticDataset, cohort_hash, evaluate_query, select_cohort
from .workloads import WorkloadItem


@dataclass(frozen=True)
class QueryAttemptContext:
    run_id: str
    workload_seed: int
    attacker_seed: int
    attacker_type: str
    query_index: int
    target_individual_index: int | None = None
    target_variant_id: str | None = None
    attack_enabling_pair_id: str | None = None
    workload_label: str | None = None
    workload_family: str | None = None
    attack_template: str | None = None


def evaluate_query_attempt(
    dataset: SyntheticDataset,
    query: GenomicQuery,
    policy: QueryPolicy,
    context: QueryAttemptContext,
) -> QueryLogRecord:
    """Evaluate one query attempt under a release policy."""

    query.validate()
    cohort = select_cohort(dataset, query.predicate)
    selected_cohort_hash = cohort_hash(cohort)
    evaluation = PolicyEvaluation(
        query_index=context.query_index,
        operator=query.operator,
        variant_id=query.variant_id,
        cohort=cohort,
        cohort_hash=selected_cohort_hash,
    )
    decision = policy.decide(evaluation)
    result_value = evaluate_query(dataset, query) if decision.accepted else None

    record_accepted = getattr(policy, "record_accepted", None)
    if decision.accepted and callable(record_accepted):
        record_accepted(evaluation, result_value)

    target_in_cohort = None
    if context.target_individual_index is not None:
        target_in_cohort = context.target_individual_index in cohort

    target_variant_carrier = None
    if context.target_individual_index is not None and context.target_variant_id is not None:
        variant_idx = dataset.variant_index(context.target_variant_id)
        target_variant_carrier = dataset.genotypes[context.target_individual_index][variant_idx] > 0

    return QueryLogRecord(
        run_id=context.run_id,
        dataset_seed=dataset.config.dataset_seed,
        workload_seed=context.workload_seed,
        attacker_seed=context.attacker_seed,
        attacker_type=context.attacker_type,
        policy_type=policy.name,
        query_index=context.query_index,
        operator=query.operator,
        variant_id=query.variant_id,
        predicate_json=query.canonical_predicate_json(),
        cohort_size=len(cohort),
        cohort_hash=selected_cohort_hash,
        accepted=decision.accepted,
        rejection_reason_bucket=decision.reason_bucket,
        result_value=result_value,
        max_prior_overlap=decision.max_prior_overlap,
        min_prior_difference=decision.min_prior_difference,
        min_prior_symmetric_difference=decision.min_prior_symmetric_difference,
        target_in_cohort=target_in_cohort,
        target_variant_carrier=target_variant_carrier,
        attack_enabling_pair_id=context.attack_enabling_pair_id,
        workload_label=context.workload_label,
        workload_family=context.workload_family,
        attack_template=context.attack_template,
    )


def run_workload(
    dataset: SyntheticDataset,
    workload: Sequence[WorkloadItem],
    policy: QueryPolicy,
    run_id: str,
    workload_seed: int,
    attacker_seed: int,
    attacker_type: str,
    target_individual_index: int | None = None,
    target_variant_id: str | None = None,
) -> tuple[QueryLogRecord, ...]:
    """Evaluate a generated workload and return transcript rows."""

    records: list[QueryLogRecord] = []
    for query_index, item in enumerate(workload):
        context = QueryAttemptContext(
            run_id=run_id,
            workload_seed=workload_seed,
            attacker_seed=attacker_seed,
            attacker_type=attacker_type,
            query_index=query_index,
            target_individual_index=target_individual_index,
            target_variant_id=target_variant_id,
            attack_enabling_pair_id=item.attack_enabling_pair_id,
            workload_label=item.label,
            workload_family=item.workload_family,
            attack_template=item.attack_template,
        )
        records.append(evaluate_query_attempt(dataset, item.query, policy, context))
    return tuple(records)
