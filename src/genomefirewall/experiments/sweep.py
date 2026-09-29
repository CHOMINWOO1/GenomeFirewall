"""Run simple ledger-threshold sweeps for GenomeFirewall pilots."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path
from typing import Any, Sequence

from genomefirewall.experiments.matrix import run_pilot_matrix
from genomefirewall.experiments.pilot import POLICY_VARIANT_SETS
from genomefirewall.io import write_json


def run_difference_threshold_sweep(
    output_path: str | Path,
    difference_min_values: Sequence[int],
    seed_count: int = 5,
    individuals: int = 1_000,
    variants: int = 500,
    k_min: int = 20,
    symmetric_difference_min: int = 20,
    benign_variant_count: int = 3,
    base_dataset_seed: int = 1729,
    base_metadata_seed: int = 1730,
    base_workload_seed: int = 1731,
    base_attacker_seed: int = 1732,
    policy_variant_set: str = "core",
    target_count: int = 1,
) -> dict[str, Any]:
    """Run a multi-seed matrix for each difference threshold."""

    thresholds = tuple(difference_min_values)
    if not thresholds:
        raise ValueError("difference_min_values must not be empty")
    if any(value <= 0 for value in thresholds):
        raise ValueError("difference_min_values must be positive")

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        for difference_min in thresholds:
            matrix_summary = run_pilot_matrix(
                output_path=temp_root / f"matrix_difference_{difference_min}.json",
                transcript_dir=temp_root / f"transcripts_difference_{difference_min}",
                seed_count=seed_count,
                base_dataset_seed=base_dataset_seed,
                base_metadata_seed=base_metadata_seed,
                base_workload_seed=base_workload_seed,
                base_attacker_seed=base_attacker_seed,
                individuals=individuals,
                variants=variants,
                k_min=k_min,
                difference_min=difference_min,
                symmetric_difference_min=symmetric_difference_min,
                benign_variant_count=benign_variant_count,
                policy_variant_set=policy_variant_set,
                target_count=target_count,
            )
            _clear_transcript_paths(matrix_summary)
            results.append({"difference_min": difference_min, "matrix_summary": matrix_summary})

    summary = {
        "sweep_type": "difference_min",
        "difference_min_values": list(thresholds),
        "seed_count": seed_count,
        "policy_variant_set": policy_variant_set,
        "target_count": target_count,
        "results": results,
    }
    write_json(output_path, summary)
    return summary


def run_symmetric_difference_threshold_sweep(
    output_path: str | Path,
    symmetric_difference_min_values: Sequence[int],
    seed_count: int = 5,
    individuals: int = 1_000,
    variants: int = 500,
    k_min: int = 20,
    benign_variant_count: int = 3,
    base_dataset_seed: int = 1729,
    base_metadata_seed: int = 1730,
    base_workload_seed: int = 1731,
    base_attacker_seed: int = 1732,
    policy_variant_set: str = "core",
    target_count: int = 1,
) -> dict[str, Any]:
    """Run a symmetric-difference sweep with the difference rule disabled."""

    thresholds = tuple(symmetric_difference_min_values)
    if not thresholds:
        raise ValueError("symmetric_difference_min_values must not be empty")
    if any(value <= 0 for value in thresholds):
        raise ValueError("symmetric_difference_min_values must be positive")

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        for symmetric_difference_min in thresholds:
            matrix_summary = run_pilot_matrix(
                output_path=temp_root / f"matrix_symmetric_{symmetric_difference_min}.json",
                transcript_dir=temp_root / f"transcripts_symmetric_{symmetric_difference_min}",
                seed_count=seed_count,
                base_dataset_seed=base_dataset_seed,
                base_metadata_seed=base_metadata_seed,
                base_workload_seed=base_workload_seed,
                base_attacker_seed=base_attacker_seed,
                individuals=individuals,
                variants=variants,
                k_min=k_min,
                difference_min=None,
                symmetric_difference_min=symmetric_difference_min,
                benign_variant_count=benign_variant_count,
                policy_variant_set=policy_variant_set,
                target_count=target_count,
            )
            _clear_transcript_paths(matrix_summary)
            results.append(
                {
                    "symmetric_difference_min": symmetric_difference_min,
                    "matrix_summary": matrix_summary,
                }
            )

    summary = {
        "sweep_type": "symmetric_difference_min",
        "symmetric_difference_min_values": list(thresholds),
        "seed_count": seed_count,
        "policy_variant_set": policy_variant_set,
        "target_count": target_count,
        "results": results,
    }
    write_json(output_path, summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="outputs/difference_threshold_sweep.json")
    parser.add_argument("--sweep-type", choices=("difference", "symmetric"), default="difference")
    parser.add_argument("--threshold-values", help="Comma-separated threshold values.")
    parser.add_argument("--difference-min-values", default="1,5,10,20,50")
    parser.add_argument("--seed-count", type=int, default=5)
    parser.add_argument("--individuals", type=int, default=1_000)
    parser.add_argument("--variants", type=int, default=500)
    parser.add_argument("--k-min", type=int, default=20)
    parser.add_argument("--symmetric-difference-min", type=int, default=20)
    parser.add_argument("--benign-variant-count", type=int, default=3)
    parser.add_argument("--base-dataset-seed", type=int, default=1729)
    parser.add_argument("--base-metadata-seed", type=int, default=1730)
    parser.add_argument("--base-workload-seed", type=int, default=1731)
    parser.add_argument("--base-attacker-seed", type=int, default=1732)
    parser.add_argument("--policy-variant-set", choices=sorted(POLICY_VARIANT_SETS), default="core")
    parser.add_argument("--target-count", type=int, default=1)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    thresholds = _parse_int_list(args.threshold_values or args.difference_min_values)
    if args.sweep_type == "difference":
        summary = run_difference_threshold_sweep(
            output_path=args.output,
            difference_min_values=thresholds,
            seed_count=args.seed_count,
            individuals=args.individuals,
            variants=args.variants,
            k_min=args.k_min,
            symmetric_difference_min=args.symmetric_difference_min,
            benign_variant_count=args.benign_variant_count,
            base_dataset_seed=args.base_dataset_seed,
            base_metadata_seed=args.base_metadata_seed,
            base_workload_seed=args.base_workload_seed,
            base_attacker_seed=args.base_attacker_seed,
            policy_variant_set=args.policy_variant_set,
            target_count=args.target_count,
        )
        threshold_key = "difference_min"
    else:
        summary = run_symmetric_difference_threshold_sweep(
            output_path=args.output,
            symmetric_difference_min_values=thresholds,
            seed_count=args.seed_count,
            individuals=args.individuals,
            variants=args.variants,
            k_min=args.k_min,
            benign_variant_count=args.benign_variant_count,
            base_dataset_seed=args.base_dataset_seed,
            base_metadata_seed=args.base_metadata_seed,
            base_workload_seed=args.base_workload_seed,
            base_attacker_seed=args.base_attacker_seed,
            policy_variant_set=args.policy_variant_set,
            target_count=args.target_count,
        )
        threshold_key = "symmetric_difference_min"
    compact = [
        (
            result[threshold_key],
            result["matrix_summary"]["attack_enabling_run_count"],
            result["matrix_summary"]["ledger_blocked_attack_run_count"],
        )
        for result in summary["results"]
    ]
    print(f"Wrote {args.sweep_type}-threshold sweep to {Path(args.output)}: {compact}")
    return 0


def _parse_int_list(value: str) -> tuple[int, ...]:
    return tuple(int(item.strip()) for item in value.split(",") if item.strip())


def _clear_transcript_paths(matrix_summary: dict[str, Any]) -> None:
    for entry in matrix_summary["per_seed"]:
        entry["transcript_path"] = None


if __name__ == "__main__":
    raise SystemExit(main())
