"""Scripted attacker loops for GenomeFirewall experiments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .policies import QueryPolicy
from .query_log import QueryLogRecord
from .runner import QueryAttemptContext, evaluate_query_attempt
from .synthetic import SyntheticDataset
from .workloads import (
    AttackTarget,
    generate_differencing_attack_workload,
    generate_subgroup_slicing_attack_workload,
)


DEFAULT_SLICE_FIELDS: tuple[str, ...] = ("study_site", "region", "batch", "age_bin", "sex")


@dataclass(frozen=True)
class ScriptedAttackResult:
    transcript: tuple[QueryLogRecord, ...]
    outcome: str
    attempted_slice_fields: tuple[str, ...]
    stopped_pair_id: str | None = None


def run_adaptive_differencing_attack(
    dataset: SyntheticDataset,
    target: AttackTarget,
    policy: QueryPolicy,
    run_id: str,
    workload_seed: int,
    attacker_seed: int,
    slice_fields: Sequence[str] = DEFAULT_SLICE_FIELDS,
) -> ScriptedAttackResult:
    """Run a small feedback-driven scripted differencing attacker.

    The attacker tries one differencing pair per slice field. It stops when a
    pair is fully accepted, when the ledger blocks a pair, or when all slice
    fields are exhausted by non-ledger rejections.
    """

    transcript: list[QueryLogRecord] = []
    attempted_slice_fields: list[str] = []

    for slice_field in slice_fields:
        attempted_slice_fields.append(slice_field)
        workload = generate_differencing_attack_workload(dataset, target, slice_field=slice_field)
        pair_records: list[QueryLogRecord] = []

        for item in workload:
            context = QueryAttemptContext(
                run_id=run_id,
                workload_seed=workload_seed,
                attacker_seed=attacker_seed,
                attacker_type="scripted_adaptive",
                query_index=len(transcript),
                target_individual_index=target.individual_index,
                target_variant_id=target.variant_id,
                attack_enabling_pair_id=item.attack_enabling_pair_id,
                workload_label=item.label,
                attack_template=item.attack_template,
            )
            record = evaluate_query_attempt(dataset, item.query, policy, context)
            transcript.append(record)
            pair_records.append(record)

            if _is_ledger_rejection(record):
                return ScriptedAttackResult(
                    transcript=tuple(transcript),
                    outcome="ledger_blocked",
                    attempted_slice_fields=tuple(attempted_slice_fields),
                    stopped_pair_id=item.attack_enabling_pair_id,
                )

            if not record.accepted:
                break

        if len(pair_records) == len(workload) and all(record.accepted for record in pair_records):
            return ScriptedAttackResult(
                transcript=tuple(transcript),
                outcome="attack_enabling",
                attempted_slice_fields=tuple(attempted_slice_fields),
                stopped_pair_id=workload[0].attack_enabling_pair_id,
            )

    return ScriptedAttackResult(
        transcript=tuple(transcript),
        outcome="exhausted",
        attempted_slice_fields=tuple(attempted_slice_fields),
    )


def run_subgroup_slicing_attack(
    dataset: SyntheticDataset,
    target: AttackTarget,
    policy: QueryPolicy,
    run_id: str,
    workload_seed: int,
    attacker_seed: int,
    slice_fields: Sequence[str] = ("region", "study_site", "batch"),
) -> ScriptedAttackResult:
    """Run a deterministic progressive subgroup-slicing attacker."""

    transcript: list[QueryLogRecord] = []
    workload = generate_subgroup_slicing_attack_workload(
        dataset,
        target,
        slice_fields=slice_fields,
    )

    for item in workload:
        context = QueryAttemptContext(
            run_id=run_id,
            workload_seed=workload_seed,
            attacker_seed=attacker_seed,
            attacker_type="scripted_adaptive",
            query_index=len(transcript),
            target_individual_index=target.individual_index,
            target_variant_id=target.variant_id,
            workload_label=item.label,
            attack_template=item.attack_template,
        )
        record = evaluate_query_attempt(dataset, item.query, policy, context)
        transcript.append(record)
        if _is_ledger_rejection(record):
            return ScriptedAttackResult(
                transcript=tuple(transcript),
                outcome="ledger_blocked",
                attempted_slice_fields=tuple(slice_fields),
            )
        if not record.accepted:
            return ScriptedAttackResult(
                transcript=tuple(transcript),
                outcome="other_rejected",
                attempted_slice_fields=tuple(slice_fields),
            )

    return ScriptedAttackResult(
        transcript=tuple(transcript),
        outcome="attack_enabling",
        attempted_slice_fields=tuple(slice_fields),
    )


def _is_ledger_rejection(record: QueryLogRecord) -> bool:
    reason = record.rejection_reason_bucket
    return reason is not None and reason.startswith("ledger_")
