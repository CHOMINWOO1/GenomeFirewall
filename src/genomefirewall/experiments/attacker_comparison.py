"""Render an A0/A1/A2 attacker comparison scaffold."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Sequence


ATTACKER_LABELS = {
    "non_adaptive": "A0 non-adaptive",
    "scripted_adaptive": "A1 scripted adaptive",
    "llm_adaptive": "A2 fake/local LLM adaptive",
    "llm_adaptive_real_status": "A2 guarded OpenAI-compatible",
}


def build_attacker_comparison_rows(
    scripted_summary: dict[str, Any],
    llm_summary: dict[str, Any],
    llm_status_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rows.extend(_rows_from_breakdown(scripted_summary, "pilot_matrix"))
    rows.extend(_rows_from_breakdown(llm_summary, _llm_source_label(llm_summary)))
    if llm_status_summary is not None:
        rows.append(_status_row_from_llm_summary(llm_status_summary, "a2_real_llm_blocked"))
    order = {
        "non_adaptive": 0,
        "scripted_adaptive": 1,
        "llm_adaptive": 2,
        "llm_adaptive_real_status": 3,
    }
    return sorted(rows, key=lambda row: order.get(str(row["attacker_type"]), 99))


def render_attacker_comparison_markdown(rows: Sequence[dict[str, Any]]) -> str:
    lines = [
        "# A0/A1/A2 Attacker Comparison Scaffold",
        "",
        "| attacker | source | seeds | targets | provider | status | network | attack runs | attack-enabling runs | ledger-blocked runs | attack pairs | ledger-blocked pairs | correct guesses | guess success rate |",
        "| --- | --- | ---: | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            "| "
            f"{row['attacker_label']} | "
            f"{row['source']} | "
            f"{row['seed_count']} | "
            f"{row['target_count']} | "
            f"{row['provider']} | "
            f"{row['planner_status']} | "
            f"{row['network_call_attempted']} | "
            f"{row['attack_run_count']} | "
            f"{row['attack_enabling_run_count']} | "
            f"{row['ledger_blocked_run_count']} | "
            f"{row['attack_pair_count']} | "
            f"{row['ledger_blocked_pair_count']} | "
            f"{row['attack_correct_guess_count']} / {row['attack_guess_count']} | "
            f"{row['attack_guess_success_rate']:.4f} |"
        )
    lines.extend(
        [
            "",
            "This scaffold uses current pilot/matrix summaries, a matched fake-provider A2 matrix when available, and the guarded real-provider status artifact. It is not final real-provider A2 evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def write_attacker_comparison_csv(rows: Sequence[dict[str, Any]], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "attacker_type",
        "attacker_label",
        "source",
        "seed_count",
        "policy_variant_set",
        "target_count",
        "planner_mode",
        "planner_status",
        "provider",
        "model",
        "network_call_attempted",
        "attack_run_count",
        "attack_enabling_run_count",
        "ledger_blocked_run_count",
        "attack_pair_count",
        "attack_enabling_pair_count",
        "ledger_blocked_pair_count",
        "attack_guess_count",
        "attack_correct_guess_count",
        "attack_guess_success_rate",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field_name: row[field_name] for field_name in fieldnames})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scripted-input", default="outputs/pilot_matrix_summary.json")
    parser.add_argument("--llm-input", default="outputs/a2_fake_llm_matrix_summary.json")
    parser.add_argument(
        "--llm-status-input",
        help="Optional guarded real-provider A2 status summary, such as a blocked run artifact.",
    )
    parser.add_argument("--output", default="docs/experiments/a0_a1_a2_comparison_report.md")
    parser.add_argument("--csv-output", default="docs/experiments/a0_a1_a2_comparison_report.csv")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    scripted_summary = json.loads(Path(args.scripted_input).read_text(encoding="utf-8"))
    llm_summary = json.loads(Path(args.llm_input).read_text(encoding="utf-8"))
    llm_status_summary = (
        json.loads(Path(args.llm_status_input).read_text(encoding="utf-8"))
        if args.llm_status_input
        else None
    )
    rows = build_attacker_comparison_rows(scripted_summary, llm_summary, llm_status_summary)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_attacker_comparison_markdown(rows), encoding="utf-8")
    write_attacker_comparison_csv(rows, args.csv_output)
    print(f"Wrote A0/A1/A2 comparison scaffold to {output_path}")
    return 0


def _rows_from_breakdown(summary: dict[str, Any], source: str) -> list[dict[str, Any]]:
    breakdown = summary.get("attack_breakdown_by_type", {})
    metadata = _summary_metadata(summary)
    rows: list[dict[str, Any]] = []
    for attacker_type, stats in breakdown.items():
        if attacker_type not in ATTACKER_LABELS:
            continue
        rows.append(
            {
                "attacker_type": attacker_type,
                "attacker_label": ATTACKER_LABELS[attacker_type],
                "source": source,
                **metadata,
                "attack_run_count": _stat_int(stats, "run_count"),
                "attack_enabling_run_count": _stat_int(stats, "attack_enabling_run_count"),
                "ledger_blocked_run_count": _stat_int(stats, "ledger_blocked_run_count"),
                "attack_pair_count": _stat_int(stats, "pair_count"),
                "attack_enabling_pair_count": _stat_int(stats, "attack_enabling_pair_count"),
                "ledger_blocked_pair_count": _stat_int(stats, "ledger_blocked_pair_count"),
                "attack_guess_count": _stat_int(stats, "guess_count"),
                "attack_correct_guess_count": _stat_int(stats, "correct_guess_count"),
                "attack_guess_success_rate": float(stats.get("guess_success_rate", 0.0)),
            }
        )
    return rows


def _status_row_from_llm_summary(summary: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "attacker_type": "llm_adaptive_real_status",
        "attacker_label": ATTACKER_LABELS["llm_adaptive_real_status"],
        "source": source,
        **_summary_metadata(summary),
        "attack_run_count": 0,
        "attack_enabling_run_count": 0,
        "ledger_blocked_run_count": 0,
        "attack_pair_count": 0,
        "attack_enabling_pair_count": 0,
        "ledger_blocked_pair_count": 0,
        "attack_guess_count": 0,
        "attack_correct_guess_count": 0,
        "attack_guess_success_rate": 0.0,
    }


def _summary_metadata(summary: dict[str, Any]) -> dict[str, Any]:
    config = summary.get("llm_client_config", {})
    if not isinstance(config, dict):
        config = {}
    return {
        "seed_count": _summary_int(summary, "seed_count"),
        "policy_variant_set": str(summary.get("policy_variant_set", "unknown")),
        "target_count": _summary_int(summary, "target_count"),
        "planner_mode": _planner_mode(summary, config),
        "planner_status": str(summary.get("status", "completed")),
        "provider": str(config.get("provider", "n/a")),
        "model": str(config.get("model", "n/a")),
        "network_call_attempted": _network_call_label(summary),
    }


def _planner_mode(summary: dict[str, Any], config: dict[str, Any]) -> str:
    value = summary.get("planner_mode")
    if value is not None:
        return str(value)
    if config:
        return str(config.get("provider", "llm_client"))
    return "deterministic"


def _network_call_label(summary: dict[str, Any]) -> str:
    value = summary.get("network_call_attempted")
    if value is None:
        return "n/a"
    return str(bool(value)).lower()


def _summary_int(summary: dict[str, Any], field_name: str) -> int:
    value = summary.get(field_name, 0)
    return int(value) if value is not None else 0


def _llm_source_label(summary: dict[str, Any]) -> str:
    return "a2_fake_llm_matrix" if _summary_int(summary, "seed_count") > 1 else "a2_fake_llm"


def _stat_int(stats: dict[str, Any], field_name: str) -> int:
    return int(stats.get(field_name, 0))


if __name__ == "__main__":
    raise SystemExit(main())
