"""Transcript-level metrics for GenomeFirewall experiments."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class TranscriptSummary:
    total_rows: int
    accepted_rows: int
    rejected_rows: int
    acceptance_rate: float
    benign_rows: int
    attack_rows: int
    benign_accepted_rows: int
    attack_accepted_rows: int
    attack_rejected_rows: int
    ledger_rejection_rows: int
    attack_run_count: int
    attack_enabling_run_count: int
    ledger_blocked_attack_run_count: int
    attack_run_outcomes: dict[str, str]
    attack_pair_count: int
    attack_enabling_pair_count: int
    ledger_blocked_attack_pair_count: int
    attack_pair_outcomes: dict[str, str]
    attack_guess_count: int
    attack_correct_guess_count: int
    attack_guess_success_rate: float
    attack_guess_outcomes: dict[str, str]
    attack_breakdown_by_type: dict[str, dict[str, int | float]]
    attack_breakdown_by_template: dict[str, dict[str, int | float]]
    attack_breakdown_by_policy: dict[str, dict[str, int | float]]
    benign_breakdown_by_policy: dict[str, dict[str, int | float]]
    benign_breakdown_by_policy_family: dict[str, dict[str, dict[str, int | float]]]
    attacker_type_counts: dict[str, int]
    attack_template_counts: dict[str, int]
    policy_type_counts: dict[str, int]
    rejection_reason_counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def summarize_transcript(rows: list[Mapping[str, Any]]) -> TranscriptSummary:
    total_rows = len(rows)
    accepted_rows = sum(1 for row in rows if row.get("accepted") is True)
    rejected_rows = total_rows - accepted_rows
    benign_rows = sum(1 for row in rows if row.get("attacker_type") == "benign")
    attack_rows = total_rows - benign_rows
    benign_accepted_rows = sum(
        1 for row in rows if row.get("attacker_type") == "benign" and row.get("accepted") is True
    )
    attack_accepted_rows = sum(
        1 for row in rows if row.get("attacker_type") != "benign" and row.get("accepted") is True
    )
    attack_rejected_rows = sum(
        1 for row in rows if row.get("attacker_type") != "benign" and row.get("accepted") is not True
    )

    rejection_reasons = Counter(
        row.get("rejection_reason_bucket")
        for row in rows
        if row.get("rejection_reason_bucket") is not None
    )
    ledger_rejection_rows = sum(
        count for reason, count in rejection_reasons.items() if str(reason).startswith("ledger_")
    )
    attack_run_outcomes = _attack_run_outcomes(rows)
    attack_pair_outcomes = _attack_pair_outcomes(rows)
    attack_guess_outcomes = _attack_guess_outcomes(rows)
    attack_guess_count = len(attack_guess_outcomes)
    attack_correct_guess_count = sum(
        1 for outcome in attack_guess_outcomes.values() if outcome == "correct"
    )

    return TranscriptSummary(
        total_rows=total_rows,
        accepted_rows=accepted_rows,
        rejected_rows=rejected_rows,
        acceptance_rate=accepted_rows / total_rows if total_rows else 0.0,
        benign_rows=benign_rows,
        attack_rows=attack_rows,
        benign_accepted_rows=benign_accepted_rows,
        attack_accepted_rows=attack_accepted_rows,
        attack_rejected_rows=attack_rejected_rows,
        ledger_rejection_rows=ledger_rejection_rows,
        attack_run_count=len(attack_run_outcomes),
        attack_enabling_run_count=sum(
            1 for outcome in attack_run_outcomes.values() if outcome == "all_accepted"
        ),
        ledger_blocked_attack_run_count=sum(
            1 for outcome in attack_run_outcomes.values() if outcome == "ledger_blocked"
        ),
        attack_run_outcomes=attack_run_outcomes,
        attack_pair_count=len(attack_pair_outcomes),
        attack_enabling_pair_count=sum(
            1 for outcome in attack_pair_outcomes.values() if outcome == "all_accepted"
        ),
        ledger_blocked_attack_pair_count=sum(
            1 for outcome in attack_pair_outcomes.values() if outcome == "ledger_blocked"
        ),
        attack_pair_outcomes=attack_pair_outcomes,
        attack_guess_count=attack_guess_count,
        attack_correct_guess_count=attack_correct_guess_count,
        attack_guess_success_rate=(
            attack_correct_guess_count / attack_guess_count if attack_guess_count else 0.0
        ),
        attack_guess_outcomes=attack_guess_outcomes,
        attack_breakdown_by_type=_attack_breakdown_by_type(rows),
        attack_breakdown_by_template=_attack_breakdown_by_template(rows),
        attack_breakdown_by_policy=_attack_breakdown_by_policy(rows),
        benign_breakdown_by_policy=_benign_breakdown_by_policy(rows),
        benign_breakdown_by_policy_family=_benign_breakdown_by_policy_family(rows),
        attacker_type_counts=dict(Counter(str(row.get("attacker_type")) for row in rows)),
        attack_template_counts=dict(
            Counter(_attack_template(row) for row in rows if row.get("attacker_type") != "benign")
        ),
        policy_type_counts=dict(Counter(str(row.get("policy_type")) for row in rows)),
        rejection_reason_counts={str(key): value for key, value in rejection_reasons.items()},
    )


def _attack_run_outcomes(rows: list[Mapping[str, Any]]) -> dict[str, str]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        if row.get("attacker_type") == "benign":
            continue
        run_id = str(row.get("run_id"))
        grouped.setdefault(run_id, []).append(row)

    outcomes: dict[str, str] = {}
    for run_id, run_rows in sorted(grouped.items()):
        if run_rows and all(row.get("accepted") is True for row in run_rows):
            outcomes[run_id] = "all_accepted"
            continue
        if any(str(row.get("rejection_reason_bucket")).startswith("ledger_") for row in run_rows):
            outcomes[run_id] = "ledger_blocked"
            continue
        outcomes[run_id] = "other_rejected"
    return outcomes


def _attack_breakdown_by_type(rows: list[Mapping[str, Any]]) -> dict[str, dict[str, int | float]]:
    attack_types = sorted(
        {str(row.get("attacker_type")) for row in rows if row.get("attacker_type") != "benign"}
    )
    breakdown: dict[str, dict[str, int | float]] = {}
    for attacker_type in attack_types:
        typed_rows = [row for row in rows if row.get("attacker_type") == attacker_type]
        breakdown[attacker_type] = _attack_breakdown_for_rows(typed_rows)
    return breakdown


def _attack_breakdown_by_template(rows: list[Mapping[str, Any]]) -> dict[str, dict[str, int | float]]:
    attack_templates = sorted(
        {
            _attack_template(row)
            for row in rows
            if row.get("attacker_type") != "benign"
        }
    )
    breakdown: dict[str, dict[str, int | float]] = {}
    for attack_template in attack_templates:
        template_rows = [
            row
            for row in rows
            if row.get("attacker_type") != "benign" and _attack_template(row) == attack_template
        ]
        breakdown[attack_template] = _attack_breakdown_for_rows(template_rows)
    return breakdown


def _attack_breakdown_by_policy(rows: list[Mapping[str, Any]]) -> dict[str, dict[str, int | float]]:
    policy_types = sorted(
        {str(row.get("policy_type")) for row in rows if row.get("attacker_type") != "benign"}
    )
    breakdown: dict[str, dict[str, int | float]] = {}
    for policy_type in policy_types:
        policy_rows = [
            row
            for row in rows
            if row.get("attacker_type") != "benign" and str(row.get("policy_type")) == policy_type
        ]
        breakdown[policy_type] = _attack_breakdown_for_rows(policy_rows)
    return breakdown


def _benign_breakdown_by_policy(rows: list[Mapping[str, Any]]) -> dict[str, dict[str, int | float]]:
    policy_types = sorted(
        {str(row.get("policy_type")) for row in rows if row.get("attacker_type") == "benign"}
    )
    breakdown: dict[str, dict[str, int | float]] = {}
    for policy_type in policy_types:
        policy_rows = [
            row
            for row in rows
            if row.get("attacker_type") == "benign" and str(row.get("policy_type")) == policy_type
        ]
        accepted_rows = sum(1 for row in policy_rows if row.get("accepted") is True)
        row_count = len(policy_rows)
        breakdown[policy_type] = {
            "rows": row_count,
            "accepted_rows": accepted_rows,
            "rejected_rows": row_count - accepted_rows,
            "acceptance_rate": accepted_rows / row_count if row_count else 0.0,
        }
    return breakdown


def _benign_breakdown_by_policy_family(
    rows: list[Mapping[str, Any]],
) -> dict[str, dict[str, dict[str, int | float]]]:
    policy_types = sorted(
        {str(row.get("policy_type")) for row in rows if row.get("attacker_type") == "benign"}
    )
    breakdown: dict[str, dict[str, dict[str, int | float]]] = {}
    for policy_type in policy_types:
        policy_rows = [
            row
            for row in rows
            if row.get("attacker_type") == "benign" and str(row.get("policy_type")) == policy_type
        ]
        families = sorted({_workload_family(row) for row in policy_rows})
        breakdown[policy_type] = {}
        for family in families:
            family_rows = [row for row in policy_rows if _workload_family(row) == family]
            breakdown[policy_type][family] = _benign_stats_for_rows(family_rows)
    return breakdown


def _benign_stats_for_rows(rows: list[Mapping[str, Any]]) -> dict[str, int | float]:
    accepted_rows = sum(1 for row in rows if row.get("accepted") is True)
    row_count = len(rows)
    return {
        "rows": row_count,
        "accepted_rows": accepted_rows,
        "rejected_rows": row_count - accepted_rows,
        "acceptance_rate": accepted_rows / row_count if row_count else 0.0,
    }


def _workload_family(row: Mapping[str, Any]) -> str:
    value = row.get("workload_family")
    return str(value) if value else "unspecified"


def _attack_breakdown_for_rows(rows: list[Mapping[str, Any]]) -> dict[str, int | float]:
    run_outcomes = _attack_run_outcomes(rows)
    pair_outcomes = _attack_pair_outcomes(rows)
    guess_outcomes = _attack_guess_outcomes(rows)
    correct_guess_count = sum(1 for outcome in guess_outcomes.values() if outcome == "correct")
    return {
        "rows": len(rows),
        "accepted_rows": sum(1 for row in rows if row.get("accepted") is True),
        "rejected_rows": sum(1 for row in rows if row.get("accepted") is not True),
        "run_count": len(run_outcomes),
        "attack_enabling_run_count": sum(
            1 for outcome in run_outcomes.values() if outcome == "all_accepted"
        ),
        "ledger_blocked_run_count": sum(
            1 for outcome in run_outcomes.values() if outcome == "ledger_blocked"
        ),
        "pair_count": len(pair_outcomes),
        "attack_enabling_pair_count": sum(
            1 for outcome in pair_outcomes.values() if outcome == "all_accepted"
        ),
        "ledger_blocked_pair_count": sum(
            1 for outcome in pair_outcomes.values() if outcome == "ledger_blocked"
        ),
        "guess_count": len(guess_outcomes),
        "correct_guess_count": correct_guess_count,
        "guess_success_rate": correct_guess_count / len(guess_outcomes) if guess_outcomes else 0.0,
    }


def _attack_template(row: Mapping[str, Any]) -> str:
    template = row.get("attack_template")
    return str(template) if template else "unspecified"


def _attack_guess_outcomes(rows: list[Mapping[str, Any]]) -> dict[str, str]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        pair_id = row.get("attack_enabling_pair_id")
        if pair_id is None:
            continue
        run_id = str(row.get("run_id"))
        grouped.setdefault(f"{run_id}:{pair_id}", []).append(row)

    outcomes: dict[str, str] = {}
    for pair_key, pair_rows in sorted(grouped.items()):
        if len(pair_rows) != 2 or not all(row.get("accepted") is True for row in pair_rows):
            continue
        if any(row.get("result_value") is None for row in pair_rows):
            continue

        result_values = [int(row["result_value"]) for row in pair_rows]
        carrier_truth_values = {
            row.get("target_variant_carrier")
            for row in pair_rows
            if row.get("target_variant_carrier") is not None
        }
        if len(carrier_truth_values) != 1:
            continue

        guessed_carrier = abs(result_values[0] - result_values[1]) > 0
        true_carrier = bool(next(iter(carrier_truth_values)))
        outcomes[pair_key] = "correct" if guessed_carrier == true_carrier else "incorrect"
    return outcomes


def _attack_pair_outcomes(rows: list[Mapping[str, Any]]) -> dict[str, str]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        pair_id = row.get("attack_enabling_pair_id")
        if pair_id is None:
            continue
        run_id = str(row.get("run_id"))
        grouped.setdefault(f"{run_id}:{pair_id}", []).append(row)

    outcomes: dict[str, str] = {}
    for pair_key, pair_rows in sorted(grouped.items()):
        if pair_rows and all(row.get("accepted") is True for row in pair_rows):
            outcomes[pair_key] = "all_accepted"
            continue
        if any(str(row.get("rejection_reason_bucket")).startswith("ledger_") for row in pair_rows):
            outcomes[pair_key] = "ledger_blocked"
            continue
        outcomes[pair_key] = "other_rejected"
    return outcomes
