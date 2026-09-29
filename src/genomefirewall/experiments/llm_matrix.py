"""Run a multi-seed fake-provider A2 LLM pilot matrix."""

from __future__ import annotations

import argparse
import tempfile
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any, Sequence

from genomefirewall.experiments.llm_pilot import run_fake_llm_pilot_experiment
from genomefirewall.io import write_json


@dataclass(frozen=True)
class FakeLLMMatrixResult:
    output_path: Path
    seed_count: int
    transcript_dir: Path | None
    summary: dict[str, Any]


def run_fake_llm_pilot_matrix(
    output_path: str | Path,
    seed_count: int = 3,
    base_dataset_seed: int = 1729,
    base_metadata_seed: int = 1730,
    base_workload_seed: int = 1731,
    base_attacker_seed: int = 1732,
    individuals: int = 80,
    variants: int = 20,
    k_min: int = 1,
    difference_min: int = 1000,
    symmetric_difference_min: int = 20,
    transcript_dir: str | Path | None = None,
) -> FakeLLMMatrixResult:
    if seed_count <= 0:
        raise ValueError("seed_count must be positive")

    if transcript_dir is None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = _run_matrix_with_transcript_dir(
                transcript_dir=Path(temp_dir),
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
            )
            _clear_per_seed_paths(summary)
            write_json(output_path, summary)
            return FakeLLMMatrixResult(
                output_path=Path(output_path),
                seed_count=seed_count,
                transcript_dir=None,
                summary=summary,
            )

    transcript_path = Path(transcript_dir)
    summary = _run_matrix_with_transcript_dir(
        transcript_dir=transcript_path,
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
    )
    write_json(output_path, summary)
    return FakeLLMMatrixResult(
        output_path=Path(output_path),
        seed_count=seed_count,
        transcript_dir=transcript_path,
        summary=summary,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="outputs/a2_fake_llm_matrix_summary.json")
    parser.add_argument("--transcript-dir", default="outputs/a2_fake_llm_matrix_transcripts")
    parser.add_argument("--seed-count", type=int, default=3)
    parser.add_argument("--base-dataset-seed", type=int, default=1729)
    parser.add_argument("--base-metadata-seed", type=int, default=1730)
    parser.add_argument("--base-workload-seed", type=int, default=1731)
    parser.add_argument("--base-attacker-seed", type=int, default=1732)
    parser.add_argument("--individuals", type=int, default=80)
    parser.add_argument("--variants", type=int, default=20)
    parser.add_argument("--k-min", type=int, default=1)
    parser.add_argument("--difference-min", type=int, default=1000)
    parser.add_argument("--symmetric-difference-min", type=int, default=20)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_fake_llm_pilot_matrix(
        output_path=args.output,
        transcript_dir=args.transcript_dir,
        seed_count=args.seed_count,
        base_dataset_seed=args.base_dataset_seed,
        base_metadata_seed=args.base_metadata_seed,
        base_workload_seed=args.base_workload_seed,
        base_attacker_seed=args.base_attacker_seed,
        individuals=args.individuals,
        variants=args.variants,
        k_min=args.k_min,
        difference_min=args.difference_min,
        symmetric_difference_min=args.symmetric_difference_min,
    )
    print(
        f"Wrote fake A2 LLM matrix summary for {result.seed_count} seeds to {result.output_path}"
    )
    return 0


def _run_matrix_with_transcript_dir(
    transcript_dir: Path,
    seed_count: int,
    base_dataset_seed: int,
    base_metadata_seed: int,
    base_workload_seed: int,
    base_attacker_seed: int,
    individuals: int,
    variants: int,
    k_min: int,
    difference_min: int,
    symmetric_difference_min: int,
) -> dict[str, Any]:
    transcript_dir.mkdir(parents=True, exist_ok=True)
    per_seed: list[dict[str, Any]] = []

    for seed_index in range(seed_count):
        transcript_path = transcript_dir / f"a2_fake_seed_{seed_index:03d}.jsonl"
        summary_path = transcript_dir / f"a2_fake_seed_{seed_index:03d}_summary.json"
        result = run_fake_llm_pilot_experiment(
            output_path=transcript_path,
            summary_output_path=summary_path,
            individuals=individuals,
            variants=variants,
            dataset_seed=base_dataset_seed + seed_index,
            metadata_seed=base_metadata_seed + seed_index,
            workload_seed=base_workload_seed + seed_index,
            attacker_seed=base_attacker_seed + seed_index,
            k_min=k_min,
            difference_min=difference_min,
            symmetric_difference_min=symmetric_difference_min,
        )
        per_seed.append(
            {
                "seed_index": seed_index,
                "comparison_key": f"seed:{seed_index:03d}",
                "dataset_seed": base_dataset_seed + seed_index,
                "metadata_seed": base_metadata_seed + seed_index,
                "workload_seed": base_workload_seed + seed_index,
                "attacker_seed": base_attacker_seed + seed_index,
                "transcript_path": str(transcript_path),
                "summary_path": str(summary_path),
                "summary": result.summary,
            }
        )

    return _aggregate_matrix_summary(per_seed)


def _aggregate_matrix_summary(per_seed: list[dict[str, Any]]) -> dict[str, Any]:
    summaries = [entry["summary"] for entry in per_seed]
    attack_guess_count = sum(int(summary["attack_guess_count"]) for summary in summaries)
    attack_correct_guess_count = sum(
        int(summary["attack_correct_guess_count"]) for summary in summaries
    )
    benign_rows = sum(int(summary["benign_rows"]) for summary in summaries)
    benign_accepted_rows = sum(int(summary["benign_accepted_rows"]) for summary in summaries)

    return {
        "seed_count": len(per_seed),
        "policy_variant_set": "core",
        "target_count": 1,
        "planner_mode": "fake",
        "status": "completed",
        "network_call_attempted": False,
        "llm_client_config": summaries[0]["llm_client_config"] if summaries else {},
        "paired_seed_metadata": {
            "paired_unit": "seed_index",
            "comparison_keys": [entry["comparison_key"] for entry in per_seed],
            "aligned_seed_fields": [
                "dataset_seed",
                "metadata_seed",
                "workload_seed",
                "attacker_seed",
            ],
            "note": "Fake A2 matrix uses the same deterministic seed schedule as the A0/A1 pilot matrix.",
        },
        "total_rows": sum(int(summary["total_rows"]) for summary in summaries),
        "accepted_rows": sum(int(summary["accepted_rows"]) for summary in summaries),
        "rejected_rows": sum(int(summary["rejected_rows"]) for summary in summaries),
        "acceptance_rate": mean(float(summary["acceptance_rate"]) for summary in summaries),
        "benign_rows": benign_rows,
        "benign_accepted_rows": benign_accepted_rows,
        "benign_rejected_rows": benign_rows - benign_accepted_rows,
        "benign_acceptance_rate": benign_accepted_rows / benign_rows if benign_rows else 0.0,
        "attack_rows": sum(int(summary["attack_rows"]) for summary in summaries),
        "attack_accepted_rows": sum(int(summary["attack_accepted_rows"]) for summary in summaries),
        "attack_rejected_rows": sum(int(summary["attack_rejected_rows"]) for summary in summaries),
        "ledger_rejection_rows": sum(int(summary["ledger_rejection_rows"]) for summary in summaries),
        "attack_run_count": sum(int(summary["attack_run_count"]) for summary in summaries),
        "attack_enabling_run_count": sum(
            int(summary["attack_enabling_run_count"]) for summary in summaries
        ),
        "ledger_blocked_attack_run_count": sum(
            int(summary["ledger_blocked_attack_run_count"]) for summary in summaries
        ),
        "attack_pair_count": sum(int(summary["attack_pair_count"]) for summary in summaries),
        "attack_enabling_pair_count": sum(
            int(summary["attack_enabling_pair_count"]) for summary in summaries
        ),
        "ledger_blocked_attack_pair_count": sum(
            int(summary["ledger_blocked_attack_pair_count"]) for summary in summaries
        ),
        "attack_guess_count": attack_guess_count,
        "attack_correct_guess_count": attack_correct_guess_count,
        "attack_guess_success_rate": (
            attack_correct_guess_count / attack_guess_count if attack_guess_count else 0.0
        ),
        "attack_breakdown_by_type": _aggregate_breakdown(summaries, "attack_breakdown_by_type"),
        "attack_breakdown_by_template": _aggregate_breakdown(
            summaries,
            "attack_breakdown_by_template",
        ),
        "attack_breakdown_by_policy": _aggregate_breakdown(summaries, "attack_breakdown_by_policy"),
        "per_seed": per_seed,
    }


def _aggregate_breakdown(
    summaries: list[dict[str, Any]],
    breakdown_key: str,
) -> dict[str, dict[str, int | float]]:
    names = sorted(
        {
            name
            for summary in summaries
            for name in summary.get(breakdown_key, {}).keys()
        }
    )
    additive_fields = (
        "rows",
        "accepted_rows",
        "rejected_rows",
        "run_count",
        "attack_enabling_run_count",
        "ledger_blocked_run_count",
        "pair_count",
        "attack_enabling_pair_count",
        "ledger_blocked_pair_count",
        "guess_count",
        "correct_guess_count",
    )
    aggregate: dict[str, dict[str, int | float]] = {}
    for name in names:
        row: dict[str, int | float] = {}
        for field_name in additive_fields:
            row[field_name] = sum(
                int(summary.get(breakdown_key, {}).get(name, {}).get(field_name, 0))
                for summary in summaries
            )
        guess_count = int(row["guess_count"])
        row["guess_success_rate"] = (
            int(row["correct_guess_count"]) / guess_count if guess_count else 0.0
        )
        aggregate[name] = row
    return aggregate


def _clear_per_seed_paths(summary: dict[str, Any]) -> None:
    for entry in summary["per_seed"]:
        entry["transcript_path"] = None
        entry["summary_path"] = None


if __name__ == "__main__":
    raise SystemExit(main())
