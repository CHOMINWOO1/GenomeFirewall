from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.attacker_comparison import (
    build_attacker_comparison_rows,
    main as attacker_comparison_main,
    render_attacker_comparison_markdown,
    write_attacker_comparison_csv,
)


class AttackerComparisonTests(unittest.TestCase):
    def test_build_attacker_comparison_rows_orders_a0_a1_a2(self) -> None:
        rows = build_attacker_comparison_rows(_scripted_summary(), _llm_summary())

        self.assertEqual([row["attacker_type"] for row in rows], ["non_adaptive", "scripted_adaptive", "llm_adaptive"])
        self.assertEqual(rows[2]["source"], "a2_fake_llm_matrix")
        self.assertEqual(rows[2]["seed_count"], 3)

    def test_render_attacker_comparison_markdown_contains_all_rows(self) -> None:
        rows = build_attacker_comparison_rows(_scripted_summary(), _llm_summary())

        report = render_attacker_comparison_markdown(rows)

        self.assertIn("# A0/A1/A2 Attacker Comparison Scaffold", report)
        self.assertIn("A0 non-adaptive", report)
        self.assertIn("A1 scripted adaptive", report)
        self.assertIn("A2 fake/local LLM adaptive", report)
        self.assertIn("provider", report)

    def test_write_attacker_comparison_csv_writes_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "comparison.csv"
            rows = build_attacker_comparison_rows(_scripted_summary(), _llm_summary())

            write_attacker_comparison_csv(rows, csv_path)

            content = csv_path.read_text(encoding="utf-8")
            self.assertIn("attacker_type,attacker_label,source,seed_count", content)
            self.assertIn("llm_adaptive,A2 fake/local LLM adaptive,a2_fake_llm_matrix,3", content)

    def test_build_attacker_comparison_rows_includes_guarded_real_status(self) -> None:
        rows = build_attacker_comparison_rows(
            _scripted_summary(),
            _llm_summary(),
            _blocked_llm_status_summary(),
        )

        self.assertEqual(rows[-1]["attacker_type"], "llm_adaptive_real_status")
        self.assertEqual(rows[-1]["planner_status"], "network_not_allowed")
        self.assertEqual(rows[-1]["provider"], "local")
        self.assertEqual(rows[-1]["network_call_attempted"], "false")

    def test_attacker_comparison_cli_writes_markdown_and_csv(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            scripted_path = Path(temp_dir) / "scripted.json"
            llm_path = Path(temp_dir) / "llm.json"
            output_path = Path(temp_dir) / "comparison.md"
            csv_path = Path(temp_dir) / "comparison.csv"
            scripted_path.write_text(json.dumps(_scripted_summary()), encoding="utf-8")
            llm_path.write_text(json.dumps(_llm_summary()), encoding="utf-8")

            exit_code = attacker_comparison_main(
                [
                    "--scripted-input",
                    str(scripted_path),
                    "--llm-input",
                    str(llm_path),
                    "--output",
                    str(output_path),
                    "--csv-output",
                    str(csv_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())
            self.assertTrue(csv_path.exists())


def _scripted_summary() -> dict[str, object]:
    return {
        "seed_count": 3,
        "policy_variant_set": "core",
        "target_count": 1,
        "attack_breakdown_by_type": {
            "non_adaptive": {
                "run_count": 3,
                "attack_enabling_run_count": 3,
                "ledger_blocked_run_count": 0,
                "pair_count": 3,
                "attack_enabling_pair_count": 3,
                "ledger_blocked_pair_count": 0,
                "guess_count": 3,
                "correct_guess_count": 3,
                "guess_success_rate": 1.0,
            },
            "scripted_adaptive": {
                "run_count": 12,
                "attack_enabling_run_count": 6,
                "ledger_blocked_run_count": 6,
                "pair_count": 6,
                "attack_enabling_pair_count": 3,
                "ledger_blocked_pair_count": 3,
                "guess_count": 3,
                "correct_guess_count": 3,
                "guess_success_rate": 1.0,
            },
        }
    }


def _llm_summary() -> dict[str, object]:
    return {
        "seed_count": 3,
        "policy_variant_set": "core",
        "target_count": 1,
        "planner_mode": "fake",
        "status": "completed",
        "network_call_attempted": False,
        "llm_client_config": {
            "provider": "fake",
            "model": "fake-json-model",
            "api_key_configured": False,
        },
        "attack_breakdown_by_type": {
            "llm_adaptive": {
                "run_count": 2,
                "attack_enabling_run_count": 1,
                "ledger_blocked_run_count": 1,
                "pair_count": 2,
                "attack_enabling_pair_count": 1,
                "ledger_blocked_pair_count": 1,
                "guess_count": 1,
                "correct_guess_count": 1,
                "guess_success_rate": 1.0,
            }
        }
    }


def _blocked_llm_status_summary() -> dict[str, object]:
    return {
        "planner_mode": "openai-compatible",
        "status": "network_not_allowed",
        "network_call_attempted": False,
        "llm_client_config": {
            "provider": "local",
            "model": "local-json-model",
            "api_key_configured": False,
        },
    }


if __name__ == "__main__":
    unittest.main()
