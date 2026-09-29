"""Run a multi-seed GenomeFirewall pilot matrix."""

from __future__ import annotations

import argparse
import tempfile
from math import sqrt
from pathlib import Path
from statistics import mean, stdev
from typing import Any, Sequence

from genomefirewall.experiments.pilot import POLICY_VARIANT_SETS, run_pilot_experiment
from genomefirewall.io import read_jsonl, write_json
from genomefirewall.metrics import summarize_transcript


def run_pilot_matrix(
    output_path: str | Path,
    seed_count: int = 5,
    base_dataset_seed: int = 1729,
    base_metadata_seed: int = 1730,
    base_workload_seed: int = 1731,
    base_attacker_seed: int = 1732,
    individuals: int = 1_000,
    variants: int = 500,
    k_min: int = 20,
    difference_min: int | None = 10,
    symmetric_difference_min: int = 20,
    benign_variant_count: int = 3,
    transcript_dir: str | Path | None = None,
    policy_variant_set: str = "core",
    target_count: int = 1,
) -> dict[str, Any]:
    """Run repeated deterministic pilots and write an aggregate summary JSON."""

    if seed_count <= 0:
        raise ValueError("seed_count must be positive")

    if transcript_dir is None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = _run_matrix_with_transcript_dir(
                Path(temp_dir),
                seed_count,
                base_dataset_seed,
                base_metadata_seed,
                base_workload_seed,
                base_attacker_seed,
                individuals,
                variants,
                k_min,
                difference_min,
                symmetric_difference_min,
                benign_variant_count,
                policy_variant_set,
                target_count,
            )
            _clear_transcript_paths(summary)
    else:
        summary = _run_matrix_with_transcript_dir(
            Path(transcript_dir),
            seed_count,
            base_dataset_seed,
            base_metadata_seed,
            base_workload_seed,
            base_attacker_seed,
            individuals,
            variants,
            k_min,
            difference_min,
            symmetric_difference_min,
            benign_variant_count,
            policy_variant_set,
            target_count,
        )

    write_json(output_path, summary)
    return summary


def _clear_transcript_paths(summary: dict[str, Any]) -> None:
    for entry in summary["per_seed"]:
        entry["transcript_path"] = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="outputs/pilot_matrix_summary.json")
    parser.add_argument("--transcript-dir", help="Optional directory for per-seed JSONL transcripts.")
    parser.add_argument("--seed-count", type=int, default=5)
    parser.add_argument("--base-dataset-seed", type=int, default=1729)
    parser.add_argument("--base-metadata-seed", type=int, default=1730)
    parser.add_argument("--base-workload-seed", type=int, default=1731)
    parser.add_argument("--base-attacker-seed", type=int, default=1732)
    parser.add_argument("--individuals", type=int, default=1_000)
    parser.add_argument("--variants", type=int, default=500)
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
    summary = run_pilot_matrix(
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
        difference_min=None if args.disable_difference_rule else args.difference_min,
        symmetric_difference_min=args.symmetric_difference_min,
        benign_variant_count=args.benign_variant_count,
        policy_variant_set=args.policy_variant_set,
        target_count=args.target_count,
    )
    print(
        f"Wrote matrix summary for {summary['seed_count']} seeds to {Path(args.output)} "
        f"({summary['attack_enabling_run_count']} attack-enabling runs, "
        f"{summary['ledger_blocked_attack_run_count']} ledger-blocked runs)"
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
    difference_min: int | None,
    symmetric_difference_min: int,
    benign_variant_count: int,
    policy_variant_set: str,
    target_count: int,
) -> dict[str, Any]:
    transcript_dir.mkdir(parents=True, exist_ok=True)
    per_seed: list[dict[str, Any]] = []

    for seed_index in range(seed_count):
        transcript_path = transcript_dir / f"pilot_seed_{seed_index:03d}.jsonl"
        run_pilot_experiment(
            output_path=transcript_path,
            individuals=individuals,
            variants=variants,
            dataset_seed=base_dataset_seed + seed_index,
            metadata_seed=base_metadata_seed + seed_index,
            workload_seed=base_workload_seed + seed_index,
            attacker_seed=base_attacker_seed + seed_index,
            k_min=k_min,
            difference_min=difference_min,
            symmetric_difference_min=symmetric_difference_min,
            benign_variant_count=benign_variant_count,
            policy_variant_set=policy_variant_set,
            target_count=target_count,
        )
        transcript_summary = summarize_transcript(read_jsonl(transcript_path)).to_dict()
        per_seed.append(
            {
                "seed_index": seed_index,
                "comparison_key": f"seed:{seed_index:03d}",
                "dataset_seed": base_dataset_seed + seed_index,
                "metadata_seed": base_metadata_seed + seed_index,
                "workload_seed": base_workload_seed + seed_index,
                "attacker_seed": base_attacker_seed + seed_index,
                "transcript_path": str(transcript_path),
                "summary": transcript_summary,
            }
        )

    summaries = [entry["summary"] for entry in per_seed]
    benign_rows = sum(summary["benign_rows"] for summary in summaries)
    benign_accepted_rows = sum(summary["benign_accepted_rows"] for summary in summaries)
    attack_breakdown_by_type = _aggregate_attack_breakdowns(summaries, "attack_breakdown_by_type")
    attack_breakdown_by_template = _aggregate_attack_breakdowns(
        summaries,
        "attack_breakdown_by_template",
    )
    attack_breakdown_by_policy = _aggregate_attack_breakdowns(
        summaries,
        "attack_breakdown_by_policy",
    )
    benign_breakdown_by_policy = _aggregate_benign_breakdowns(summaries)
    benign_breakdown_by_policy_family = _aggregate_benign_family_breakdowns(summaries)
    return {
        "seed_count": seed_count,
        "policy_variant_set": policy_variant_set,
        "target_count": target_count,
        "total_rows": sum(summary["total_rows"] for summary in summaries),
        "accepted_rows": sum(summary["accepted_rows"] for summary in summaries),
        "rejected_rows": sum(summary["rejected_rows"] for summary in summaries),
        "benign_rows": benign_rows,
        "benign_accepted_rows": benign_accepted_rows,
        "benign_rejected_rows": sum(
            summary["benign_rows"] - summary["benign_accepted_rows"] for summary in summaries
        ),
        "attack_run_count": sum(summary["attack_run_count"] for summary in summaries),
        "attack_enabling_run_count": sum(
            summary["attack_enabling_run_count"] for summary in summaries
        ),
        "ledger_blocked_attack_run_count": sum(
            summary["ledger_blocked_attack_run_count"] for summary in summaries
        ),
        "attack_pair_count": sum(summary["attack_pair_count"] for summary in summaries),
        "attack_enabling_pair_count": sum(
            summary["attack_enabling_pair_count"] for summary in summaries
        ),
        "ledger_blocked_attack_pair_count": sum(
            summary["ledger_blocked_attack_pair_count"] for summary in summaries
        ),
        "attack_guess_count": sum(summary["attack_guess_count"] for summary in summaries),
        "attack_correct_guess_count": sum(
            summary["attack_correct_guess_count"] for summary in summaries
        ),
        "attack_guess_success_rate": (
            sum(summary["attack_correct_guess_count"] for summary in summaries)
            / sum(summary["attack_guess_count"] for summary in summaries)
            if sum(summary["attack_guess_count"] for summary in summaries)
            else 0.0
        ),
        "attack_breakdown_by_type": attack_breakdown_by_type,
        "attack_breakdown_by_template": attack_breakdown_by_template,
        "attack_breakdown_by_policy": attack_breakdown_by_policy,
        "benign_breakdown_by_policy": benign_breakdown_by_policy,
        "benign_breakdown_by_policy_family": benign_breakdown_by_policy_family,
        "confidence_intervals_95": _confidence_intervals_95(summaries),
        "paired_policy_comparison": _paired_policy_comparison(per_seed),
        "paired_policy_delta": _paired_policy_delta(
            attack_breakdown_by_policy,
            benign_breakdown_by_policy,
            benign_breakdown_by_policy_family,
            per_seed,
        ),
        "mean_acceptance_rate": mean(summary["acceptance_rate"] for summary in summaries),
        "benign_acceptance_rate": benign_accepted_rows / benign_rows if benign_rows else 0.0,
        "per_seed": per_seed,
    }


def _aggregate_attack_breakdowns(
    summaries: list[dict[str, Any]],
    breakdown_key: str,
) -> dict[str, dict[str, int | float]]:
    breakdown_names = sorted(
        {
            breakdown_name
            for summary in summaries
            for breakdown_name in summary.get(breakdown_key, {}).keys()
        }
    )
    aggregate: dict[str, dict[str, int | float]] = {}
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
    for breakdown_name in breakdown_names:
        entry: dict[str, int | float] = {}
        for field_name in additive_fields:
            entry[field_name] = sum(
                int(summary.get(breakdown_key, {}).get(breakdown_name, {}).get(field_name, 0))
                for summary in summaries
            )
        guess_count = int(entry["guess_count"])
        entry["guess_success_rate"] = (
            int(entry["correct_guess_count"]) / guess_count if guess_count else 0.0
        )
        aggregate[breakdown_name] = entry
    return aggregate


def _aggregate_benign_breakdowns(
    summaries: list[dict[str, Any]],
) -> dict[str, dict[str, int | float]]:
    policy_types = sorted(
        {
            policy_type
            for summary in summaries
            for policy_type in summary.get("benign_breakdown_by_policy", {}).keys()
        }
    )
    aggregate: dict[str, dict[str, int | float]] = {}
    for policy_type in policy_types:
        rows = sum(
            int(summary.get("benign_breakdown_by_policy", {}).get(policy_type, {}).get("rows", 0))
            for summary in summaries
        )
        accepted_rows = sum(
            int(
                summary.get("benign_breakdown_by_policy", {})
                .get(policy_type, {})
                .get("accepted_rows", 0)
            )
            for summary in summaries
        )
        aggregate[policy_type] = {
            "rows": rows,
            "accepted_rows": accepted_rows,
            "rejected_rows": rows - accepted_rows,
            "acceptance_rate": accepted_rows / rows if rows else 0.0,
        }
    return aggregate


def _aggregate_benign_family_breakdowns(
    summaries: list[dict[str, Any]],
) -> dict[str, dict[str, dict[str, int | float]]]:
    policy_types = sorted(
        {
            policy_type
            for summary in summaries
            for policy_type in summary.get("benign_breakdown_by_policy_family", {}).keys()
        }
    )
    aggregate: dict[str, dict[str, dict[str, int | float]]] = {}
    for policy_type in policy_types:
        families = sorted(
            {
                family
                for summary in summaries
                for family in summary.get("benign_breakdown_by_policy_family", {})
                .get(policy_type, {})
                .keys()
            }
        )
        aggregate[policy_type] = {}
        for family in families:
            rows = sum(
                int(
                    summary.get("benign_breakdown_by_policy_family", {})
                    .get(policy_type, {})
                    .get(family, {})
                    .get("rows", 0)
                )
                for summary in summaries
            )
            accepted_rows = sum(
                int(
                    summary.get("benign_breakdown_by_policy_family", {})
                    .get(policy_type, {})
                    .get(family, {})
                    .get("accepted_rows", 0)
                )
                for summary in summaries
            )
            aggregate[policy_type][family] = {
                "rows": rows,
                "accepted_rows": accepted_rows,
                "rejected_rows": rows - accepted_rows,
                "acceptance_rate": accepted_rows / rows if rows else 0.0,
            }
    return aggregate


def _confidence_intervals_95(summaries: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    return {
        "mean_acceptance_rate": _mean_ci(
            [float(summary["acceptance_rate"]) for summary in summaries],
            clamp_rate=True,
        ),
        "benign_acceptance_rate": _mean_ci(
            [
                _rate(summary["benign_accepted_rows"], summary["benign_rows"])
                for summary in summaries
            ],
            clamp_rate=True,
        ),
        "attack_pair_block_rate": _mean_ci(
            [
                _rate(summary["ledger_blocked_attack_pair_count"], summary["attack_pair_count"])
                for summary in summaries
            ],
            clamp_rate=True,
        ),
        "attack_run_block_rate": _mean_ci(
            [
                _rate(summary["ledger_blocked_attack_run_count"], summary["attack_run_count"])
                for summary in summaries
            ],
            clamp_rate=True,
        ),
    }


def _mean_ci(values: Sequence[float], clamp_rate: bool = False) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "lower": 0.0, "upper": 0.0}
    center = mean(values)
    if len(values) < 2:
        lower = upper = center
    else:
        margin = 1.96 * stdev(values) / sqrt(len(values))
        lower = center - margin
        upper = center + margin
    if clamp_rate:
        lower = max(0.0, lower)
        upper = min(1.0, upper)
    return {"mean": center, "lower": lower, "upper": upper}


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _paired_policy_comparison(per_seed: list[dict[str, Any]]) -> dict[str, Any]:
    policy_types = sorted(
        {
            policy_type
            for entry in per_seed
            for policy_type in entry["summary"].get("policy_type_counts", {}).keys()
        }
    )
    attack_templates = sorted(
        {
            attack_template
            for entry in per_seed
            for attack_template in entry["summary"].get("attack_template_counts", {}).keys()
        }
    )
    return {
        "paired_unit": "seed_index",
        "comparison_keys": [entry["comparison_key"] for entry in per_seed],
        "aligned_seed_fields": [
            "dataset_seed",
            "metadata_seed",
            "workload_seed",
            "attacker_seed",
        ],
        "policy_types": policy_types,
        "attack_templates": attack_templates,
        "note": "Pilot scaffold aligns policy comparisons within each deterministic seed/target workload.",
    }


def _paired_policy_delta(
    policy_breakdown: dict[str, dict[str, int | float]],
    benign_breakdown: dict[str, dict[str, int | float]],
    benign_family_breakdown: dict[str, dict[str, dict[str, int | float]]],
    per_seed: list[dict[str, Any]],
) -> dict[str, Any]:
    baseline_policy = "minimum_cohort"
    comparison_policy = "stateful_privacy_ledger"
    baseline = policy_breakdown.get(baseline_policy, {})
    comparison = policy_breakdown.get(comparison_policy, {})
    additional_policies = sorted(
        policy
        for policy in policy_breakdown
        if policy not in {baseline_policy, comparison_policy}
    )
    additional_policy_deltas = {
        policy: _with_e4_utility_classification(
            {
                **_policy_delta_fields(baseline, policy_breakdown.get(policy, {})),
                **_benign_delta_fields(
                    benign_breakdown.get(baseline_policy, {}),
                    benign_breakdown.get(policy, {}),
                ),
                **_seed_utility_loss_fields(per_seed, baseline_policy, policy),
                "benign_utility_loss_by_family": _benign_family_delta_fields(
                    baseline_policy,
                    policy,
                    benign_family_breakdown,
                ),
            }
        )
        for policy in additional_policies
    }
    deltas = _policy_delta_fields(baseline, comparison)
    benign_deltas = _benign_delta_fields(
        benign_breakdown.get(baseline_policy, {}),
        benign_breakdown.get(comparison_policy, {}),
    )
    seed_utility_loss_fields = _seed_utility_loss_fields(
        per_seed,
        baseline_policy,
        comparison_policy,
    )
    benign_family_deltas = _benign_family_delta_fields(
        baseline_policy,
        comparison_policy,
        benign_family_breakdown,
    )
    return _with_e4_utility_classification(
        {
            "baseline_policy": baseline_policy,
            "comparison_policy": comparison_policy,
            **deltas,
            **benign_deltas,
            **seed_utility_loss_fields,
            "benign_utility_loss_by_family": benign_family_deltas,
            "available_comparison_policies": [
                policy for policy in sorted(policy_breakdown) if policy != baseline_policy
            ],
            "additional_policy_deltas": additional_policy_deltas,
            "note": "Aggregate scaffold delta; final E3 should compute paired deltas on matched policy variants.",
        }
    )


def _policy_delta_fields(
    baseline: dict[str, int | float],
    comparison: dict[str, int | float],
) -> dict[str, int]:
    delta_fields = (
        "attack_enabling_run_count",
        "ledger_blocked_run_count",
        "attack_enabling_pair_count",
        "ledger_blocked_pair_count",
    )
    return {
        f"{field_name}_delta": int(comparison.get(field_name, 0)) - int(baseline.get(field_name, 0))
        for field_name in delta_fields
    }


def _benign_delta_fields(
    baseline: dict[str, int | float],
    comparison: dict[str, int | float],
) -> dict[str, int | float]:
    baseline_acceptance = float(baseline.get("acceptance_rate", 0.0))
    comparison_acceptance = float(comparison.get("acceptance_rate", 0.0))
    return {
        "baseline_benign_acceptance_rate": baseline_acceptance,
        "comparison_benign_acceptance_rate": comparison_acceptance,
        "benign_utility_loss": baseline_acceptance - comparison_acceptance,
        "comparison_benign_rows": int(comparison.get("rows", 0)),
        "comparison_benign_rejected_rows": int(comparison.get("rejected_rows", 0)),
    }


def _seed_utility_loss_fields(
    per_seed: list[dict[str, Any]],
    baseline_policy: str,
    comparison_policy: str,
) -> dict[str, Any]:
    values: list[float] = []
    for entry in per_seed:
        summary = entry["summary"]
        benign_breakdown = summary.get("benign_breakdown_by_policy", {})
        baseline = benign_breakdown.get(baseline_policy, {})
        comparison = benign_breakdown.get(comparison_policy, {})
        baseline_acceptance = float(baseline.get("acceptance_rate", 0.0))
        comparison_acceptance = float(comparison.get("acceptance_rate", 0.0))
        values.append(baseline_acceptance - comparison_acceptance)
    return {
        "benign_utility_loss_seed_values": values,
        "benign_utility_loss_one_sided_95_upper": _one_sided_upper_bound(values),
        "benign_utility_loss_ci_method": "normal_approximation_one_sided_95",
    }


def _one_sided_upper_bound(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    center = mean(values)
    if len(values) < 2:
        return center
    return center + 1.645 * stdev(values) / sqrt(len(values))


def _with_e4_utility_classification(delta: dict[str, Any]) -> dict[str, Any]:
    utility_loss = float(delta.get("benign_utility_loss", 0.0))
    upper = float(delta.get("benign_utility_loss_one_sided_95_upper", utility_loss))
    comparison_acceptance = float(delta.get("comparison_benign_acceptance_rate", 0.0))
    if upper <= 0.025:
        band = "strong_utility_preservation"
        passes = True
    elif upper <= 0.05:
        band = "primary_acceptable_utility"
        passes = True
    elif comparison_acceptance < 0.90 or utility_loss > 0.10:
        band = "utility_failure"
        passes = False
    else:
        band = "marginal_utility"
        passes = False
    delta["e4_utility_band"] = band
    delta["e4_utility_pass"] = passes
    delta["e4_utility_primary_margin"] = 0.05
    delta["e4_utility_strong_margin"] = 0.025
    return delta


def _benign_family_delta_fields(
    baseline_policy: str,
    comparison_policy: str,
    benign_family_breakdown: dict[str, dict[str, dict[str, int | float]]],
) -> dict[str, dict[str, int | float]]:
    baseline_families = benign_family_breakdown.get(baseline_policy, {})
    comparison_families = benign_family_breakdown.get(comparison_policy, {})
    families = sorted(set(baseline_families) | set(comparison_families))
    deltas: dict[str, dict[str, int | float]] = {}
    for family in families:
        baseline = baseline_families.get(family, {})
        comparison = comparison_families.get(family, {})
        baseline_acceptance = float(baseline.get("acceptance_rate", 0.0))
        comparison_acceptance = float(comparison.get("acceptance_rate", 0.0))
        deltas[family] = {
            "baseline_benign_acceptance_rate": baseline_acceptance,
            "comparison_benign_acceptance_rate": comparison_acceptance,
            "benign_utility_loss": baseline_acceptance - comparison_acceptance,
            "baseline_benign_rows": int(baseline.get("rows", 0)),
            "comparison_benign_rows": int(comparison.get("rows", 0)),
            "comparison_benign_rejected_rows": int(comparison.get("rejected_rows", 0)),
        }
    return deltas


if __name__ == "__main__":
    raise SystemExit(main())
