"""Render experiment JSON summaries as Markdown reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Sequence


def render_difference_threshold_report(sweep_summary: dict[str, Any]) -> str:
    """Render a threshold sweep summary as a compact Markdown table."""

    threshold_key = _axis_key(sweep_summary)
    title = _axis_title(threshold_key)

    lines = [
        f"# {title}",
        "",
        "## Summary Table",
        "",
        f"| {threshold_key} | seeds | attack pairs | attack-enabling pairs | ledger-blocked pairs | pair block rate | correct guesses | guess success rate | attack runs | attack-enabling runs | ledger-blocked runs | benign acceptance rate | utility loss | utility upper 95% | E4 utility band | benign rejected | mean acceptance rate |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |",
    ]

    for result in sweep_summary["results"]:
        matrix = result["matrix_summary"]
        lines.append(
            "| "
            f"{result[threshold_key]} | "
            f"{matrix['seed_count']} | "
            f"{matrix['attack_pair_count']} | "
            f"{matrix['attack_enabling_pair_count']} | "
            f"{matrix['ledger_blocked_attack_pair_count']} | "
            f"{_rate(matrix['ledger_blocked_attack_pair_count'], matrix['attack_pair_count']):.4f} | "
            f"{matrix['attack_correct_guess_count']} / {matrix['attack_guess_count']} | "
            f"{matrix['attack_guess_success_rate']:.4f} | "
            f"{matrix['attack_run_count']} | "
            f"{matrix['attack_enabling_run_count']} | "
            f"{matrix['ledger_blocked_attack_run_count']} | "
            f"{matrix['benign_acceptance_rate']:.4f} | "
            f"{_benign_utility_loss(matrix):.4f} | "
            f"{_benign_utility_loss_upper(matrix):.4f} | "
            f"{_e4_utility_band(matrix)} | "
            f"{matrix['benign_rejected_rows']} | "
            f"{matrix['mean_acceptance_rate']:.4f} |"
        )

    lines.extend(
        [
            "",
            "## Confidence Intervals",
            "",
            f"| {threshold_key} | pair block rate 95% CI | attack run block rate 95% CI | benign acceptance 95% CI | utility loss one-sided 95% upper | mean acceptance 95% CI |",
            "| ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for result in sweep_summary["results"]:
        matrix = result["matrix_summary"]
        intervals = matrix.get("confidence_intervals_95", {})
        lines.append(
            "| "
            f"{result[threshold_key]} | "
            f"{_format_ci(intervals.get('attack_pair_block_rate'))} | "
            f"{_format_ci(intervals.get('attack_run_block_rate'))} | "
            f"{_format_ci(intervals.get('benign_acceptance_rate'))} | "
            f"{_benign_utility_loss_upper(matrix):.4f} | "
            f"{_format_ci(intervals.get('mean_acceptance_rate'))} |"
        )

    lines.extend(
        [
            "",
            "## Attacker Type Breakdown",
            "",
            f"| {threshold_key} | attacker type | attack pairs | attack-enabling pairs | ledger-blocked pairs | correct guesses | guess success rate | attack runs | attack-enabling runs | ledger-blocked runs |",
            "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for result in sweep_summary["results"]:
        threshold = result[threshold_key]
        breakdown = result["matrix_summary"].get("attack_breakdown_by_type", {})
        for attacker_type, stats in sorted(breakdown.items()):
            lines.append(
                "| "
                f"{threshold} | "
                f"{attacker_type} | "
                f"{stats['pair_count']} | "
                f"{stats['attack_enabling_pair_count']} | "
                f"{stats['ledger_blocked_pair_count']} | "
                f"{stats['correct_guess_count']} / {stats['guess_count']} | "
                f"{stats['guess_success_rate']:.4f} | "
                f"{stats['run_count']} | "
                f"{stats['attack_enabling_run_count']} | "
                f"{stats['ledger_blocked_run_count']} |"
            )

    lines.extend(
        [
            "",
            "## Attack Template Breakdown",
            "",
            f"| {threshold_key} | attack template | attack rows | accepted rows | rejected rows | attack pairs | ledger-blocked pairs | attack runs | ledger-blocked runs |",
            "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for result in sweep_summary["results"]:
        threshold = result[threshold_key]
        breakdown = result["matrix_summary"].get("attack_breakdown_by_template", {})
        for attack_template, stats in sorted(breakdown.items()):
            lines.append(
                "| "
                f"{threshold} | "
                f"{attack_template} | "
                f"{stats['rows']} | "
                f"{stats['accepted_rows']} | "
                f"{stats['rejected_rows']} | "
                f"{stats['pair_count']} | "
                f"{stats['ledger_blocked_pair_count']} | "
                f"{stats['run_count']} | "
                f"{stats['ledger_blocked_run_count']} |"
            )

    policy_delta_rows = _policy_delta_rows(sweep_summary)
    if policy_delta_rows:
        lines.extend(
            [
                "",
                "## Policy Delta Breakdown",
                "",
                f"| {threshold_key} | policy variant set | baseline policy | comparison policy | attack-enabling run delta | ledger-blocked run delta | attack-enabling pair delta | ledger-blocked pair delta | utility loss | utility upper 95% | E4 utility band | comparison benign acceptance | comparison attack runs | comparison ledger-blocked runs |",
                "| ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |",
            ]
        )
        for row in policy_delta_rows:
            lines.append(
                "| "
                f"{row['threshold_value']} | "
                f"{row['policy_variant_set']} | "
                f"{row['baseline_policy']} | "
                f"{row['comparison_policy']} | "
                f"{row['attack_enabling_run_count_delta']} | "
                f"{row['ledger_blocked_run_count_delta']} | "
                f"{row['attack_enabling_pair_count_delta']} | "
                f"{row['ledger_blocked_pair_count_delta']} | "
                f"{row['benign_utility_loss']:.4f} | "
                f"{row['benign_utility_loss_one_sided_95_upper']:.4f} | "
                f"{row['e4_utility_band']} | "
                f"{row['comparison_benign_acceptance_rate']:.4f} | "
                f"{row['comparison_attack_run_count']} | "
                f"{row['comparison_ledger_blocked_run_count']} |"
            )

    benign_family_rows = _benign_family_rows(sweep_summary)
    if benign_family_rows:
        lines.extend(
            [
                "",
                "## Benign Utility Family Breakdown",
                "",
                f"| {threshold_key} | policy | workload family | benign rows | accepted rows | rejected rows | acceptance rate |",
                "| ---: | --- | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in benign_family_rows:
            lines.append(
                "| "
                f"{row['threshold_value']} | "
                f"{row['policy']} | "
                f"{row['workload_family']} | "
                f"{row['rows']} | "
                f"{row['accepted_rows']} | "
                f"{row['rejected_rows']} | "
                f"{row['acceptance_rate']:.4f} |"
            )

    lines.extend(
        [
            "",
            "## Interpretation Notes",
            "",
            "- `attack-enabling runs` counts attack runs where all generated attack queries were accepted.",
            "- `ledger-blocked runs` counts attack runs with at least one ledger-based rejection.",
            "- `pair block rate` is ledger-blocked attack pairs divided by generated attack pairs.",
            "- `guess success rate` is computed only for accepted differencing pairs with released count results.",
            "- Attack rows include a fixed non-adaptive differencing baseline plus scripted differencing and subgroup-slicing attack runs.",
            "- Attack template rows separate differencing from progressive subgroup slicing where available.",
            "- `benign acceptance rate` is the current pilot proxy for utility retention.",
            "- `utility loss` follows `docs/experiments/utility_threshold.md`: minimum-cohort benign acceptance minus ledger benign acceptance.",
            "- `utility upper 95%` is a seed-level normal-approximation one-sided upper bound for the same utility loss; E4 utility bands follow the threshold document.",
            "- `target_count` reports repeat target selection within each seed when present.",
            "- This report is a pilot scaffold, not final empirical evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def render_policy_delta_matrix_report(matrix_summary: dict[str, Any]) -> str:
    """Render policy deltas from a single matrix summary."""

    rows = _policy_delta_rows_for_matrix(matrix_summary, "matrix", "summary")
    lines = [
        "# Policy Delta Matrix Report",
        "",
        f"- seeds: {matrix_summary.get('seed_count', 0)}",
        f"- policy variant set: {matrix_summary.get('policy_variant_set', 'core')}",
        "",
        "## Policy Delta Breakdown",
        "",
        "| baseline policy | comparison policy | attack-enabling run delta | ledger-blocked run delta | attack-enabling pair delta | ledger-blocked pair delta | utility loss | utility upper 95% | E4 utility band | comparison benign acceptance | comparison attack runs | comparison ledger-blocked runs |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            "| "
            f"{row['baseline_policy']} | "
            f"{row['comparison_policy']} | "
            f"{row['attack_enabling_run_count_delta']} | "
            f"{row['ledger_blocked_run_count_delta']} | "
            f"{row['attack_enabling_pair_count_delta']} | "
            f"{row['ledger_blocked_pair_count_delta']} | "
            f"{row['benign_utility_loss']:.4f} | "
            f"{row['benign_utility_loss_one_sided_95_upper']:.4f} | "
            f"{row['e4_utility_band']} | "
            f"{row['comparison_benign_acceptance_rate']:.4f} | "
            f"{row['comparison_attack_run_count']} | "
            f"{row['comparison_ledger_blocked_run_count']} |"
        )
    family_rows = _benign_family_rows_for_matrix(matrix_summary, "matrix", "summary")
    if family_rows:
        lines.extend(
            [
                "",
                "## Benign Utility Family Breakdown",
                "",
                "| policy | workload family | benign rows | accepted rows | rejected rows | acceptance rate |",
                "| --- | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in family_rows:
            lines.append(
                "| "
                f"{row['policy']} | "
                f"{row['workload_family']} | "
                f"{row['rows']} | "
                f"{row['accepted_rows']} | "
                f"{row['rejected_rows']} | "
                f"{row['acceptance_rate']:.4f} |"
            )
    return "\n".join(lines)


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _benign_utility_loss(matrix_summary: dict[str, Any]) -> float:
    return float(matrix_summary.get("paired_policy_delta", {}).get("benign_utility_loss", 0.0))


def _benign_utility_loss_upper(matrix_summary: dict[str, Any]) -> float:
    return float(
        matrix_summary.get("paired_policy_delta", {}).get(
            "benign_utility_loss_one_sided_95_upper",
            _benign_utility_loss(matrix_summary),
        )
    )


def _e4_utility_band(matrix_summary: dict[str, Any]) -> str:
    return str(matrix_summary.get("paired_policy_delta", {}).get("e4_utility_band", "unknown"))


def _e4_utility_pass(matrix_summary: dict[str, Any]) -> bool:
    return bool(matrix_summary.get("paired_policy_delta", {}).get("e4_utility_pass", False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Path to threshold sweep JSON.")
    parser.add_argument(
        "--output",
        default="docs/experiments/difference_threshold_sweep_report.md",
        help="Path to write Markdown report.",
    )
    parser.add_argument("--csv-output", help="Optional path to write a CSV table.")
    parser.add_argument(
        "--attacker-csv-output",
        help="Optional path to write a long-form attacker-type breakdown CSV.",
    )
    parser.add_argument(
        "--attack-template-csv-output",
        help="Optional path to write a long-form attack-template breakdown CSV.",
    )
    parser.add_argument(
        "--policy-delta-csv-output",
        help="Optional path to write a long-form policy-delta CSV.",
    )
    parser.add_argument(
        "--benign-family-csv-output",
        help="Optional path to write a long-form benign workload-family CSV.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    input_path = Path(args.input)
    output_path = Path(args.output)
    summary = json.loads(input_path.read_text(encoding="utf-8"))
    report = (
        render_difference_threshold_report(summary)
        if "results" in summary
        else render_policy_delta_matrix_report(summary)
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    if args.csv_output:
        write_sweep_csv(summary, args.csv_output)
    if args.attacker_csv_output:
        write_attacker_breakdown_csv(summary, args.attacker_csv_output)
    if args.attack_template_csv_output:
        write_attack_template_breakdown_csv(summary, args.attack_template_csv_output)
    if args.policy_delta_csv_output:
        write_policy_delta_csv(summary, args.policy_delta_csv_output)
    if args.benign_family_csv_output:
        write_benign_family_breakdown_csv(summary, args.benign_family_csv_output)
    print(f"Wrote Markdown report to {output_path}")
    return 0


def write_sweep_csv(sweep_summary: dict[str, Any], output_path: str | Path) -> None:
    threshold_key = _axis_key(sweep_summary)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        threshold_key,
        "seed_count",
        "attack_pair_count",
        "attack_enabling_pair_count",
        "ledger_blocked_attack_pair_count",
        "pair_block_rate",
        "attack_guess_count",
        "attack_correct_guess_count",
        "attack_guess_success_rate",
        "pair_block_rate_ci_lower",
        "pair_block_rate_ci_upper",
        "attack_run_block_rate_ci_lower",
        "attack_run_block_rate_ci_upper",
        "benign_acceptance_rate_ci_lower",
        "benign_acceptance_rate_ci_upper",
        "attack_run_count",
        "attack_enabling_run_count",
        "ledger_blocked_attack_run_count",
        "benign_acceptance_rate",
        "benign_utility_loss",
        "benign_utility_loss_one_sided_95_upper",
        "e4_utility_band",
        "e4_utility_pass",
        "benign_rejected_rows",
        "mean_acceptance_rate",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in sweep_summary["results"]:
            matrix = result["matrix_summary"]
            intervals = matrix.get("confidence_intervals_95", {})
            pair_ci = _ci(intervals.get("attack_pair_block_rate"))
            run_ci = _ci(intervals.get("attack_run_block_rate"))
            benign_ci = _ci(intervals.get("benign_acceptance_rate"))
            writer.writerow(
                {
                    threshold_key: result[threshold_key],
                    "seed_count": matrix["seed_count"],
                    "attack_pair_count": matrix["attack_pair_count"],
                    "attack_enabling_pair_count": matrix["attack_enabling_pair_count"],
                    "ledger_blocked_attack_pair_count": matrix["ledger_blocked_attack_pair_count"],
                    "pair_block_rate": f"{_rate(matrix['ledger_blocked_attack_pair_count'], matrix['attack_pair_count']):.4f}",
                    "attack_guess_count": matrix["attack_guess_count"],
                    "attack_correct_guess_count": matrix["attack_correct_guess_count"],
                    "attack_guess_success_rate": f"{matrix['attack_guess_success_rate']:.4f}",
                    "pair_block_rate_ci_lower": f"{pair_ci['lower']:.4f}",
                    "pair_block_rate_ci_upper": f"{pair_ci['upper']:.4f}",
                    "attack_run_block_rate_ci_lower": f"{run_ci['lower']:.4f}",
                    "attack_run_block_rate_ci_upper": f"{run_ci['upper']:.4f}",
                    "benign_acceptance_rate_ci_lower": f"{benign_ci['lower']:.4f}",
                    "benign_acceptance_rate_ci_upper": f"{benign_ci['upper']:.4f}",
                    "attack_run_count": matrix["attack_run_count"],
                    "attack_enabling_run_count": matrix["attack_enabling_run_count"],
                    "ledger_blocked_attack_run_count": matrix["ledger_blocked_attack_run_count"],
                    "benign_acceptance_rate": f"{matrix['benign_acceptance_rate']:.4f}",
                    "benign_utility_loss": f"{_benign_utility_loss(matrix):.4f}",
                    "benign_utility_loss_one_sided_95_upper": f"{_benign_utility_loss_upper(matrix):.4f}",
                    "e4_utility_band": _e4_utility_band(matrix),
                    "e4_utility_pass": str(_e4_utility_pass(matrix)).lower(),
                    "benign_rejected_rows": matrix["benign_rejected_rows"],
                    "mean_acceptance_rate": f"{matrix['mean_acceptance_rate']:.4f}",
                }
            )


def write_attacker_breakdown_csv(sweep_summary: dict[str, Any], output_path: str | Path) -> None:
    threshold_key = _axis_key(sweep_summary)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        threshold_key,
        "attacker_type",
        "seed_count",
        "attack_row_count",
        "attack_accepted_rows",
        "attack_rejected_rows",
        "attack_pair_count",
        "attack_enabling_pair_count",
        "ledger_blocked_attack_pair_count",
        "pair_block_rate",
        "attack_guess_count",
        "attack_correct_guess_count",
        "attack_guess_success_rate",
        "attack_run_count",
        "attack_enabling_run_count",
        "ledger_blocked_attack_run_count",
        "run_block_rate",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in sweep_summary["results"]:
            matrix = result["matrix_summary"]
            breakdown = matrix.get("attack_breakdown_by_type", {})
            for attacker_type, stats in sorted(breakdown.items()):
                attack_pair_count = _stat_int(stats, "pair_count")
                ledger_blocked_pair_count = _stat_int(stats, "ledger_blocked_pair_count")
                attack_run_count = _stat_int(stats, "run_count")
                ledger_blocked_run_count = _stat_int(stats, "ledger_blocked_run_count")
                writer.writerow(
                    {
                        threshold_key: result[threshold_key],
                        "attacker_type": attacker_type,
                        "seed_count": matrix["seed_count"],
                        "attack_row_count": _stat_int(stats, "rows"),
                        "attack_accepted_rows": _stat_int(stats, "accepted_rows"),
                        "attack_rejected_rows": _stat_int(stats, "rejected_rows"),
                        "attack_pair_count": attack_pair_count,
                        "attack_enabling_pair_count": _stat_int(
                            stats, "attack_enabling_pair_count"
                        ),
                        "ledger_blocked_attack_pair_count": ledger_blocked_pair_count,
                        "pair_block_rate": f"{_rate(ledger_blocked_pair_count, attack_pair_count):.4f}",
                        "attack_guess_count": _stat_int(stats, "guess_count"),
                        "attack_correct_guess_count": _stat_int(stats, "correct_guess_count"),
                        "attack_guess_success_rate": f"{float(stats.get('guess_success_rate', 0.0)):.4f}",
                        "attack_run_count": attack_run_count,
                        "attack_enabling_run_count": _stat_int(
                            stats, "attack_enabling_run_count"
                        ),
                        "ledger_blocked_attack_run_count": ledger_blocked_run_count,
                        "run_block_rate": f"{_rate(ledger_blocked_run_count, attack_run_count):.4f}",
                    }
                )


def write_attack_template_breakdown_csv(
    sweep_summary: dict[str, Any],
    output_path: str | Path,
) -> None:
    threshold_key = _axis_key(sweep_summary)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        threshold_key,
        "attack_template",
        "seed_count",
        "attack_row_count",
        "attack_accepted_rows",
        "attack_rejected_rows",
        "attack_pair_count",
        "attack_enabling_pair_count",
        "ledger_blocked_attack_pair_count",
        "pair_block_rate",
        "attack_guess_count",
        "attack_correct_guess_count",
        "attack_guess_success_rate",
        "attack_run_count",
        "attack_enabling_run_count",
        "ledger_blocked_attack_run_count",
        "run_block_rate",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in sweep_summary["results"]:
            matrix = result["matrix_summary"]
            breakdown = matrix.get("attack_breakdown_by_template", {})
            for attack_template, stats in sorted(breakdown.items()):
                attack_pair_count = _stat_int(stats, "pair_count")
                ledger_blocked_pair_count = _stat_int(stats, "ledger_blocked_pair_count")
                attack_run_count = _stat_int(stats, "run_count")
                ledger_blocked_run_count = _stat_int(stats, "ledger_blocked_run_count")
                writer.writerow(
                    {
                        threshold_key: result[threshold_key],
                        "attack_template": attack_template,
                        "seed_count": matrix["seed_count"],
                        "attack_row_count": _stat_int(stats, "rows"),
                        "attack_accepted_rows": _stat_int(stats, "accepted_rows"),
                        "attack_rejected_rows": _stat_int(stats, "rejected_rows"),
                        "attack_pair_count": attack_pair_count,
                        "attack_enabling_pair_count": _stat_int(
                            stats, "attack_enabling_pair_count"
                        ),
                        "ledger_blocked_attack_pair_count": ledger_blocked_pair_count,
                        "pair_block_rate": f"{_rate(ledger_blocked_pair_count, attack_pair_count):.4f}",
                        "attack_guess_count": _stat_int(stats, "guess_count"),
                        "attack_correct_guess_count": _stat_int(stats, "correct_guess_count"),
                        "attack_guess_success_rate": f"{float(stats.get('guess_success_rate', 0.0)):.4f}",
                        "attack_run_count": attack_run_count,
                        "attack_enabling_run_count": _stat_int(
                            stats, "attack_enabling_run_count"
                        ),
                        "ledger_blocked_attack_run_count": ledger_blocked_run_count,
                        "run_block_rate": f"{_rate(ledger_blocked_run_count, attack_run_count):.4f}",
                    }
                )


def write_policy_delta_csv(summary: dict[str, Any], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "threshold_name",
        "threshold_value",
        "seed_count",
        "policy_variant_set",
        "baseline_policy",
        "comparison_policy",
        "attack_enabling_run_count_delta",
        "ledger_blocked_run_count_delta",
        "attack_enabling_pair_count_delta",
        "ledger_blocked_pair_count_delta",
        "baseline_benign_acceptance_rate",
        "comparison_benign_acceptance_rate",
        "benign_utility_loss",
        "benign_utility_loss_one_sided_95_upper",
        "e4_utility_band",
        "e4_utility_pass",
        "comparison_benign_rows",
        "comparison_benign_rejected_rows",
        "comparison_attack_run_count",
        "comparison_attack_enabling_run_count",
        "comparison_ledger_blocked_run_count",
        "comparison_attack_pair_count",
        "comparison_attack_enabling_pair_count",
        "comparison_ledger_blocked_pair_count",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in _policy_delta_rows(summary):
            writer.writerow({field_name: row.get(field_name, "") for field_name in fieldnames})


def write_benign_family_breakdown_csv(summary: dict[str, Any], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "threshold_name",
        "threshold_value",
        "seed_count",
        "policy_variant_set",
        "policy",
        "workload_family",
        "benign_rows",
        "accepted_rows",
        "rejected_rows",
        "acceptance_rate",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in _benign_family_csv_rows(summary):
            writer.writerow({field_name: row.get(field_name, "") for field_name in fieldnames})


def _stat_int(stats: dict[str, Any], field_name: str) -> int:
    return int(stats.get(field_name, 0))


def _policy_delta_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    if "results" not in summary:
        return _policy_delta_rows_for_matrix(summary, "matrix", "summary")

    threshold_key = _axis_key(summary)
    rows: list[dict[str, Any]] = []
    for result in summary["results"]:
        rows.extend(
            _policy_delta_rows_for_matrix(
                result["matrix_summary"],
                threshold_key,
                result[threshold_key],
            )
        )
    return rows


def _benign_family_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    if "results" not in summary:
        return _benign_family_rows_for_matrix(summary, "matrix", "summary")

    threshold_key = _axis_key(summary)
    rows: list[dict[str, Any]] = []
    for result in summary["results"]:
        rows.extend(
            _benign_family_rows_for_matrix(
                result["matrix_summary"],
                threshold_key,
                result[threshold_key],
            )
        )
    return rows


def _benign_family_csv_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    if "results" not in summary:
        return _benign_family_csv_rows_for_matrix(summary, "matrix", "summary")

    threshold_key = _axis_key(summary)
    rows: list[dict[str, Any]] = []
    for result in summary["results"]:
        rows.extend(
            _benign_family_csv_rows_for_matrix(
                result["matrix_summary"],
                threshold_key,
                result[threshold_key],
            )
        )
    return rows


def _benign_family_csv_rows_for_matrix(
    matrix_summary: dict[str, Any],
    threshold_name: str,
    threshold_value: Any,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _benign_family_rows_for_matrix(matrix_summary, threshold_name, threshold_value):
        rows.append(
            {
                **row,
                "seed_count": matrix_summary.get("seed_count", 0),
                "policy_variant_set": matrix_summary.get("policy_variant_set", "core"),
                "benign_rows": row["rows"],
            }
        )
    return rows


def _benign_family_rows_for_matrix(
    matrix_summary: dict[str, Any],
    threshold_name: str,
    threshold_value: Any,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    breakdown = matrix_summary.get("benign_breakdown_by_policy_family", {})
    for policy, families in sorted(breakdown.items()):
        for family, stats in sorted(families.items()):
            rows.append(
                {
                    "threshold_name": threshold_name,
                    "threshold_value": threshold_value,
                    "policy": policy,
                    "workload_family": family,
                    "rows": _stat_int(stats, "rows"),
                    "accepted_rows": _stat_int(stats, "accepted_rows"),
                    "rejected_rows": _stat_int(stats, "rejected_rows"),
                    "acceptance_rate": float(stats.get("acceptance_rate", 0.0)),
                }
            )
    return rows


def _policy_delta_rows_for_matrix(
    matrix_summary: dict[str, Any],
    threshold_name: str,
    threshold_value: Any,
) -> list[dict[str, Any]]:
    policy_delta = matrix_summary.get("paired_policy_delta", {})
    policy_breakdown = matrix_summary.get("attack_breakdown_by_policy", {})
    baseline_policy = policy_delta.get("baseline_policy", "minimum_cohort")
    primary_policy = policy_delta.get("comparison_policy")
    comparison_policies = list(policy_delta.get("available_comparison_policies", ()))
    if primary_policy and primary_policy not in comparison_policies:
        comparison_policies.append(primary_policy)
    additional_deltas = policy_delta.get("additional_policy_deltas", {})

    rows: list[dict[str, Any]] = []
    for comparison_policy in sorted(comparison_policies):
        if comparison_policy == baseline_policy:
            continue
        deltas = (
            policy_delta
            if comparison_policy == primary_policy
            else additional_deltas.get(comparison_policy, {})
        )
        comparison_stats = policy_breakdown.get(comparison_policy, {})
        rows.append(
            {
                "threshold_name": threshold_name,
                "threshold_value": threshold_value,
                "seed_count": matrix_summary.get("seed_count", 0),
                "policy_variant_set": matrix_summary.get("policy_variant_set", "core"),
                "baseline_policy": baseline_policy,
                "comparison_policy": comparison_policy,
                "attack_enabling_run_count_delta": int(
                    deltas.get("attack_enabling_run_count_delta", 0)
                ),
                "ledger_blocked_run_count_delta": int(
                    deltas.get("ledger_blocked_run_count_delta", 0)
                ),
                "attack_enabling_pair_count_delta": int(
                    deltas.get("attack_enabling_pair_count_delta", 0)
                ),
                "ledger_blocked_pair_count_delta": int(
                    deltas.get("ledger_blocked_pair_count_delta", 0)
                ),
                "baseline_benign_acceptance_rate": float(
                    deltas.get("baseline_benign_acceptance_rate", 0.0)
                ),
                "comparison_benign_acceptance_rate": float(
                    deltas.get("comparison_benign_acceptance_rate", 0.0)
                ),
                "benign_utility_loss": float(deltas.get("benign_utility_loss", 0.0)),
                "benign_utility_loss_one_sided_95_upper": float(
                    deltas.get(
                        "benign_utility_loss_one_sided_95_upper",
                        deltas.get("benign_utility_loss", 0.0),
                    )
                ),
                "e4_utility_band": str(deltas.get("e4_utility_band", "unknown")),
                "e4_utility_pass": bool(deltas.get("e4_utility_pass", False)),
                "comparison_benign_rows": int(deltas.get("comparison_benign_rows", 0)),
                "comparison_benign_rejected_rows": int(
                    deltas.get("comparison_benign_rejected_rows", 0)
                ),
                "comparison_attack_run_count": _stat_int(comparison_stats, "run_count"),
                "comparison_attack_enabling_run_count": _stat_int(
                    comparison_stats,
                    "attack_enabling_run_count",
                ),
                "comparison_ledger_blocked_run_count": _stat_int(
                    comparison_stats,
                    "ledger_blocked_run_count",
                ),
                "comparison_attack_pair_count": _stat_int(comparison_stats, "pair_count"),
                "comparison_attack_enabling_pair_count": _stat_int(
                    comparison_stats,
                    "attack_enabling_pair_count",
                ),
                "comparison_ledger_blocked_pair_count": _stat_int(
                    comparison_stats,
                    "ledger_blocked_pair_count",
                ),
            }
        )
    return rows


def _format_ci(interval: Any) -> str:
    ci = _ci(interval)
    return f"[{ci['lower']:.4f}, {ci['upper']:.4f}]"


def _ci(interval: Any) -> dict[str, float]:
    if isinstance(interval, dict):
        return {
            "lower": float(interval.get("lower", 0.0)),
            "upper": float(interval.get("upper", 0.0)),
        }
    return {"lower": 0.0, "upper": 0.0}


def _axis_key(summary: dict[str, Any]) -> str:
    sweep_type = summary.get("sweep_type", "difference_min")
    if sweep_type == "symmetric_difference_min":
        return "symmetric_difference_min"
    if sweep_type == "target_count":
        return "target_count"
    return "difference_min"


def _axis_title(axis_key: str) -> str:
    if axis_key == "symmetric_difference_min":
        return "Symmetric Difference Threshold Sweep Report"
    if axis_key == "target_count":
        return "Target Count Calibration Report"
    return "Difference Threshold Sweep Report"


if __name__ == "__main__":
    raise SystemExit(main())
