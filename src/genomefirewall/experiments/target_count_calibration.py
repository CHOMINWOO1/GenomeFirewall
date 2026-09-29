"""Run target-count calibration matrices for GenomeFirewall E1/E3."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path
from typing import Any, Sequence

from genomefirewall.experiments.matrix import run_pilot_matrix
from genomefirewall.experiments.pilot import POLICY_VARIANT_SETS
from genomefirewall.io import write_json


def run_target_count_calibration(
    output_path: str | Path,
    target_count_values: Sequence[int],
    seed_count: int = 10,
    individuals: int = 5_000,
    variants: int = 2_000,
    k_min: int = 20,
    difference_min: int = 20,
    symmetric_difference_min: int = 50,
    benign_variant_count: int = 5,
    base_dataset_seed: int = 1729,
    base_metadata_seed: int = 1730,
    base_workload_seed: int = 1731,
    base_attacker_seed: int = 1732,
    policy_variant_set: str = "e3",
) -> dict[str, Any]:
    """Run matched matrices while varying attack target count."""

    target_counts = tuple(target_count_values)
    if not target_counts:
        raise ValueError("target_count_values must not be empty")
    if any(value <= 0 for value in target_counts):
        raise ValueError("target_count_values must be positive")

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        for target_count in target_counts:
            matrix_summary = run_pilot_matrix(
                output_path=temp_root / f"matrix_target_count_{target_count}.json",
                transcript_dir=temp_root / f"transcripts_target_count_{target_count}",
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
            results.append({"target_count": target_count, "matrix_summary": matrix_summary})

    summary = {
        "sweep_type": "target_count",
        "target_count_values": list(target_counts),
        "seed_count": seed_count,
        "individuals": individuals,
        "variants": variants,
        "k_min": k_min,
        "difference_min": difference_min,
        "symmetric_difference_min": symmetric_difference_min,
        "benign_variant_count": benign_variant_count,
        "policy_variant_set": policy_variant_set,
        "results": results,
    }
    write_json(output_path, summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="outputs/dev_target_count_calibration.json")
    parser.add_argument("--target-count-values", default="1,2,5,10")
    parser.add_argument("--seed-count", type=int, default=10)
    parser.add_argument("--individuals", type=int, default=5_000)
    parser.add_argument("--variants", type=int, default=2_000)
    parser.add_argument("--k-min", type=int, default=20)
    parser.add_argument("--difference-min", type=int, default=20)
    parser.add_argument("--symmetric-difference-min", type=int, default=50)
    parser.add_argument("--benign-variant-count", type=int, default=5)
    parser.add_argument("--base-dataset-seed", type=int, default=1729)
    parser.add_argument("--base-metadata-seed", type=int, default=1730)
    parser.add_argument("--base-workload-seed", type=int, default=1731)
    parser.add_argument("--base-attacker-seed", type=int, default=1732)
    parser.add_argument("--policy-variant-set", choices=sorted(POLICY_VARIANT_SETS), default="e3")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = run_target_count_calibration(
        output_path=args.output,
        target_count_values=_parse_int_list(args.target_count_values),
        seed_count=args.seed_count,
        individuals=args.individuals,
        variants=args.variants,
        k_min=args.k_min,
        difference_min=args.difference_min,
        symmetric_difference_min=args.symmetric_difference_min,
        benign_variant_count=args.benign_variant_count,
        base_dataset_seed=args.base_dataset_seed,
        base_metadata_seed=args.base_metadata_seed,
        base_workload_seed=args.base_workload_seed,
        base_attacker_seed=args.base_attacker_seed,
        policy_variant_set=args.policy_variant_set,
    )
    compact = [
        (
            result["target_count"],
            result["matrix_summary"]["attack_pair_count"],
            result["matrix_summary"]["ledger_blocked_attack_pair_count"],
            result["matrix_summary"]["paired_policy_delta"]["e4_utility_band"],
        )
        for result in summary["results"]
    ]
    print(f"Wrote target-count calibration to {Path(args.output)}: {compact}")
    return 0


def _parse_int_list(value: str) -> tuple[int, ...]:
    return tuple(int(item.strip()) for item in value.split(",") if item.strip())


def _clear_transcript_paths(matrix_summary: dict[str, Any]) -> None:
    for entry in matrix_summary["per_seed"]:
        entry["transcript_path"] = None


if __name__ == "__main__":
    raise SystemExit(main())
