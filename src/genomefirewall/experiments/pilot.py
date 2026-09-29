"""Pilot experiment CLI for GenomeFirewall synthetic transcripts."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from genomefirewall.attackers import run_adaptive_differencing_attack, run_subgroup_slicing_attack
from genomefirewall.io import write_jsonl
from genomefirewall.policies import MinimumCohortPolicy, StatefulPrivacyLedgerPolicy
from genomefirewall.runner import run_workload
from genomefirewall.synthetic import SyntheticConfig, generate_synthetic_dataset
from genomefirewall.workloads import (
    generate_benign_operator_metadata_workload,
    generate_benign_workload,
    generate_benign_near_overlap_workload,
    generate_differencing_attack_workload,
    select_attack_target,
)

POLICY_VARIANT_SETS: dict[str, tuple[str, ...]] = {
    "core": ("stateful_privacy_ledger",),
    "e3": (
        "stateful_privacy_ledger",
        "stateful_privacy_ledger_difference_only",
        "stateful_privacy_ledger_symmetric_only",
        "stateful_privacy_ledger_session_scope",
        "stateful_privacy_ledger_user_scope",
    ),
}


@dataclass(frozen=True)
class PilotResult:
    output_path: Path
    row_count: int
    benign_rows: int
    attack_rows: int
    policy_variant_set: str = "core"
    target_count: int = 1


def run_pilot_experiment(
    output_path: str | Path,
    individuals: int = 1_000,
    variants: int = 500,
    dataset_seed: int = 1729,
    metadata_seed: int = 1730,
    workload_seed: int = 1731,
    attacker_seed: int = 1732,
    k_min: int = 20,
    difference_min: int | None = 10,
    symmetric_difference_min: int = 20,
    benign_variant_count: int = 3,
    policy_variant_set: str = "core",
    target_count: int = 1,
) -> PilotResult:
    """Run a deterministic pilot and write one JSONL transcript."""

    if target_count <= 0:
        raise ValueError("target_count must be positive")
    ledger_policy_variants = get_policy_variant_names(policy_variant_set)
    dataset = generate_synthetic_dataset(
        SyntheticConfig(
            individuals=individuals,
            variants=variants,
            dataset_seed=dataset_seed,
            metadata_seed=metadata_seed,
        )
    )

    benign_workload = generate_benign_workload(
        dataset,
        workload_seed=workload_seed,
        variant_count=benign_variant_count,
    )
    benign_near_overlap_workload = generate_benign_near_overlap_workload(
        dataset,
        workload_seed=workload_seed,
    )
    benign_operator_metadata_workload = generate_benign_operator_metadata_workload(
        dataset,
        workload_seed=workload_seed,
        variant_count=max(1, min(benign_variant_count, 2)),
    )
    benign_workload_families = (
        ("broad-summary", benign_workload),
        ("near-overlap", benign_near_overlap_workload),
        ("operator-metadata", benign_operator_metadata_workload),
    )

    benign_transcript_rows = []
    for family_suffix, workload in benign_workload_families:
        benign_transcript_rows.extend(
            run_workload(
                dataset=dataset,
                workload=workload,
                policy=MinimumCohortPolicy(k_min=k_min),
                run_id=f"pilot-benign-minimum-cohort-{family_suffix}",
                workload_seed=workload_seed,
                attacker_seed=0,
                attacker_type="benign",
            )
        )

    for policy_variant in ledger_policy_variants:
        for family_suffix, workload in benign_workload_families:
            benign_transcript_rows.extend(
                run_workload(
                    dataset=dataset,
                    workload=workload,
                    policy=_build_ledger_policy(
                        policy_variant,
                        k_min,
                        difference_min,
                        symmetric_difference_min,
                    ),
                    run_id=f"pilot-benign-{_policy_run_id_suffix(policy_variant)}-{family_suffix}",
                    workload_seed=workload_seed,
                    attacker_seed=0,
                    attacker_type="benign",
                )
            )

    attack_transcript_rows = []
    for target_index in range(target_count):
        target_attacker_seed = attacker_seed + target_index
        target = select_attack_target(dataset, target_seed=target_attacker_seed)
        fixed_attack_workload = generate_differencing_attack_workload(dataset, target)
        non_adaptive_attack_transcript = run_workload(
            dataset=dataset,
            workload=fixed_attack_workload,
            policy=MinimumCohortPolicy(k_min=k_min),
            run_id=_target_run_id(
                "pilot-attack-non-adaptive-minimum-cohort",
                target_index,
                target_count,
            ),
            workload_seed=workload_seed,
            attacker_seed=target_attacker_seed,
            attacker_type="non_adaptive",
            target_individual_index=target.individual_index,
            target_variant_id=target.variant_id,
        )
        minimum_attack = run_adaptive_differencing_attack(
            dataset=dataset,
            target=target,
            policy=MinimumCohortPolicy(k_min=k_min),
            run_id=_target_run_id("pilot-attack-minimum-cohort", target_index, target_count),
            workload_seed=workload_seed,
            attacker_seed=target_attacker_seed,
        )
        minimum_subgroup_attack = run_subgroup_slicing_attack(
            dataset=dataset,
            target=target,
            policy=MinimumCohortPolicy(k_min=k_min),
            run_id=_target_run_id(
                "pilot-attack-subgroup-slicing-minimum-cohort",
                target_index,
                target_count,
            ),
            workload_seed=workload_seed,
            attacker_seed=target_attacker_seed,
        )
        attack_transcript_rows.extend(non_adaptive_attack_transcript)
        attack_transcript_rows.extend(minimum_attack.transcript)
        attack_transcript_rows.extend(minimum_subgroup_attack.transcript)

        for policy_variant in ledger_policy_variants:
            policy_suffix = _policy_run_id_suffix(policy_variant)
            shared_policy = (
                _build_ledger_policy(
                    policy_variant,
                    k_min,
                    difference_min,
                    symmetric_difference_min,
                )
                if _policy_reuse_scope(policy_variant) == "user"
                else None
            )
            ledger_attack = run_adaptive_differencing_attack(
                dataset=dataset,
                target=target,
                policy=shared_policy
                or _build_ledger_policy(
                    policy_variant,
                    k_min,
                    difference_min,
                    symmetric_difference_min,
                ),
                run_id=_target_run_id(
                    f"pilot-attack-{policy_suffix}",
                    target_index,
                    target_count,
                ),
                workload_seed=workload_seed,
                attacker_seed=target_attacker_seed,
            )
            ledger_subgroup_attack = run_subgroup_slicing_attack(
                dataset=dataset,
                target=target,
                policy=shared_policy
                or _build_ledger_policy(
                    policy_variant,
                    k_min,
                    difference_min,
                    symmetric_difference_min,
                ),
                run_id=_target_run_id(
                    f"pilot-attack-subgroup-slicing-{policy_suffix}",
                    target_index,
                    target_count,
                ),
                workload_seed=workload_seed,
                attacker_seed=target_attacker_seed,
            )
            attack_transcript_rows.extend(ledger_attack.transcript)
            attack_transcript_rows.extend(ledger_subgroup_attack.transcript)

    attack_transcript = tuple(attack_transcript_rows)
    benign_transcript = tuple(benign_transcript_rows)
    rows = [record.to_dict() for record in (*benign_transcript, *attack_transcript)]
    row_count = write_jsonl(output_path, rows)

    return PilotResult(
        output_path=Path(output_path),
        row_count=row_count,
        benign_rows=len(benign_transcript),
        attack_rows=len(attack_transcript),
        policy_variant_set=policy_variant_set,
        target_count=target_count,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="outputs/pilot_transcript.jsonl")
    parser.add_argument("--individuals", type=int, default=1_000)
    parser.add_argument("--variants", type=int, default=500)
    parser.add_argument("--dataset-seed", type=int, default=1729)
    parser.add_argument("--metadata-seed", type=int, default=1730)
    parser.add_argument("--workload-seed", type=int, default=1731)
    parser.add_argument("--attacker-seed", type=int, default=1732)
    parser.add_argument("--k-min", type=int, default=20)
    parser.add_argument("--difference-min", type=int, default=10)
    parser.add_argument("--disable-difference-rule", action="store_true")
    parser.add_argument("--symmetric-difference-min", type=int, default=20)
    parser.add_argument("--benign-variant-count", type=int, default=3)
    parser.add_argument("--policy-variant-set", choices=sorted(POLICY_VARIANT_SETS), default="core")
    parser.add_argument("--target-count", type=int, default=1)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_pilot_experiment(
        output_path=args.output,
        individuals=args.individuals,
        variants=args.variants,
        dataset_seed=args.dataset_seed,
        metadata_seed=args.metadata_seed,
        workload_seed=args.workload_seed,
        attacker_seed=args.attacker_seed,
        k_min=args.k_min,
        difference_min=None if args.disable_difference_rule else args.difference_min,
        symmetric_difference_min=args.symmetric_difference_min,
        benign_variant_count=args.benign_variant_count,
        policy_variant_set=args.policy_variant_set,
        target_count=args.target_count,
    )
    print(
        f"Wrote {result.row_count} transcript rows "
        f"({result.benign_rows} benign, {result.attack_rows} attack) to {result.output_path}"
    )
    return 0


def get_policy_variant_names(policy_variant_set: str) -> tuple[str, ...]:
    try:
        return POLICY_VARIANT_SETS[policy_variant_set]
    except KeyError as exc:
        valid = ", ".join(sorted(POLICY_VARIANT_SETS))
        raise ValueError(f"unknown policy_variant_set {policy_variant_set!r}; expected one of: {valid}") from exc


def _build_ledger_policy(
    policy_variant: str,
    k_min: int,
    difference_min: int | None,
    symmetric_difference_min: int,
) -> StatefulPrivacyLedgerPolicy:
    if policy_variant == "stateful_privacy_ledger":
        variant_difference_min = difference_min
        variant_symmetric_difference_min = symmetric_difference_min
    elif policy_variant == "stateful_privacy_ledger_session_scope":
        variant_difference_min = difference_min
        variant_symmetric_difference_min = symmetric_difference_min
    elif policy_variant == "stateful_privacy_ledger_user_scope":
        variant_difference_min = difference_min
        variant_symmetric_difference_min = symmetric_difference_min
    elif policy_variant == "stateful_privacy_ledger_difference_only":
        variant_difference_min = difference_min if difference_min is not None else symmetric_difference_min
        variant_symmetric_difference_min = None
    elif policy_variant == "stateful_privacy_ledger_symmetric_only":
        variant_difference_min = None
        variant_symmetric_difference_min = symmetric_difference_min
    else:
        raise ValueError(f"unknown policy variant {policy_variant!r}")
    return StatefulPrivacyLedgerPolicy(
        k_min=k_min,
        difference_min=variant_difference_min,
        symmetric_difference_min=variant_symmetric_difference_min,
        name=policy_variant,
    )


def _policy_run_id_suffix(policy_variant: str) -> str:
    if policy_variant == "stateful_privacy_ledger":
        return "ledger"
    if policy_variant == "stateful_privacy_ledger_difference_only":
        return "ledger-difference-only"
    if policy_variant == "stateful_privacy_ledger_symmetric_only":
        return "ledger-symmetric-only"
    if policy_variant == "stateful_privacy_ledger_session_scope":
        return "ledger-session-scope"
    if policy_variant == "stateful_privacy_ledger_user_scope":
        return "ledger-user-scope"
    raise ValueError(f"unknown policy variant {policy_variant!r}")


def _policy_reuse_scope(policy_variant: str) -> str:
    if policy_variant == "stateful_privacy_ledger_user_scope":
        return "user"
    return "session"


def _target_run_id(base_run_id: str, target_index: int, target_count: int) -> str:
    if target_count == 1:
        return base_run_id
    return f"{base_run_id}-target-{target_index:03d}"


if __name__ == "__main__":
    raise SystemExit(main())
