from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.pilot import run_pilot_experiment
from genomefirewall.experiments.summarize import main as summarize_main
from genomefirewall.io import read_jsonl
from genomefirewall.metrics import summarize_transcript


class TranscriptMetricsTests(unittest.TestCase):
    def test_summarize_transcript_counts_rows(self) -> None:
        rows = [
            {
                "attacker_type": "benign",
                "run_id": "benign-run",
                "policy_type": "minimum_cohort",
                "accepted": True,
                "rejection_reason_bucket": None,
            },
            {
                "attacker_type": "scripted_adaptive",
                "run_id": "attack-run",
                "policy_type": "stateful_privacy_ledger",
                "accepted": False,
                "rejection_reason_bucket": "ledger_difference",
                "attack_enabling_pair_id": "pair-1",
                "attack_template": "differencing",
                "result_value": None,
                "target_variant_carrier": True,
            },
        ]

        summary = summarize_transcript(rows)

        self.assertEqual(summary.total_rows, 2)
        self.assertEqual(summary.accepted_rows, 1)
        self.assertEqual(summary.rejected_rows, 1)
        self.assertEqual(summary.benign_rows, 1)
        self.assertEqual(summary.attack_rows, 1)
        self.assertEqual(summary.ledger_rejection_rows, 1)
        self.assertEqual(summary.attack_run_count, 1)
        self.assertEqual(summary.attack_enabling_run_count, 0)
        self.assertEqual(summary.ledger_blocked_attack_run_count, 1)
        self.assertEqual(summary.attack_run_outcomes["attack-run"], "ledger_blocked")
        self.assertEqual(summary.attack_pair_count, 1)
        self.assertEqual(summary.attack_enabling_pair_count, 0)
        self.assertEqual(summary.ledger_blocked_attack_pair_count, 1)
        self.assertEqual(summary.attack_guess_count, 0)
        self.assertEqual(summary.attack_breakdown_by_type["scripted_adaptive"]["rows"], 1)
        self.assertEqual(
            summary.attack_breakdown_by_type["scripted_adaptive"]["ledger_blocked_pair_count"], 1
        )
        self.assertEqual(summary.attack_breakdown_by_template["differencing"]["rows"], 1)
        self.assertEqual(summary.attack_breakdown_by_policy["stateful_privacy_ledger"]["rows"], 1)
        self.assertEqual(summary.benign_breakdown_by_policy["minimum_cohort"]["rows"], 1)
        self.assertEqual(
            summary.benign_breakdown_by_policy["minimum_cohort"]["acceptance_rate"],
            1.0,
        )
        self.assertEqual(
            summary.benign_breakdown_by_policy_family["minimum_cohort"]["unspecified"]["rows"],
            1,
        )
        self.assertEqual(summary.attack_template_counts["differencing"], 1)
        self.assertEqual(summary.rejection_reason_counts["ledger_difference"], 1)

    def test_summarize_cli_writes_summary_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            transcript_path = Path(temp_dir) / "pilot.jsonl"
            summary_path = Path(temp_dir) / "summary.json"
            run_pilot_experiment(
                output_path=transcript_path,
                individuals=80,
                variants=20,
                dataset_seed=601,
                metadata_seed=602,
                workload_seed=603,
                attacker_seed=604,
                k_min=1,
                difference_min=1000,
                benign_variant_count=1,
            )

            exit_code = summarize_main(["--input", str(transcript_path), "--output", str(summary_path)])

            self.assertEqual(exit_code, 0)
            self.assertTrue(summary_path.exists())
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            rows = read_jsonl(transcript_path)
            self.assertEqual(summary["total_rows"], len(rows))
            self.assertEqual(summary["ledger_rejection_rows"], 20)
            self.assertEqual(summary["attack_rows"], 12)
            self.assertEqual(summary["attack_run_count"], 5)
            self.assertEqual(summary["attack_enabling_run_count"], 3)
            self.assertEqual(summary["ledger_blocked_attack_run_count"], 2)
            self.assertEqual(summary["attack_pair_count"], 3)
            self.assertEqual(summary["attack_enabling_pair_count"], 2)
            self.assertEqual(summary["ledger_blocked_attack_pair_count"], 1)
            self.assertEqual(summary["attack_breakdown_by_type"]["non_adaptive"]["run_count"], 1)
            self.assertEqual(summary["attack_breakdown_by_type"]["scripted_adaptive"]["run_count"], 4)
            self.assertEqual(
                summary["attack_breakdown_by_type"]["scripted_adaptive"]["ledger_blocked_run_count"],
                2,
            )
            self.assertEqual(summary["attack_breakdown_by_template"]["differencing"]["run_count"], 3)
            self.assertEqual(summary["attack_breakdown_by_template"]["subgroup_slicing"]["run_count"], 2)
            self.assertEqual(
                summary["attack_breakdown_by_template"]["subgroup_slicing"]["ledger_blocked_run_count"],
                1,
            )
            self.assertEqual(summary["attack_breakdown_by_policy"]["minimum_cohort"]["run_count"], 3)
            self.assertEqual(summary["attack_breakdown_by_policy"]["stateful_privacy_ledger"]["run_count"], 2)
            self.assertIn("minimum_cohort", summary["benign_breakdown_by_policy"])
            self.assertIn("stateful_privacy_ledger", summary["benign_breakdown_by_policy"])
            self.assertIn("benign_broad_summary", summary["benign_breakdown_by_policy_family"]["minimum_cohort"])
            self.assertIn("benign_near_overlap", summary["benign_breakdown_by_policy_family"]["minimum_cohort"])
            self.assertIn(
                "benign_operator_metadata_summary",
                summary["benign_breakdown_by_policy_family"]["minimum_cohort"],
            )
            self.assertIn(
                "benign_broad_summary",
                summary["benign_breakdown_by_policy_family"]["stateful_privacy_ledger"],
            )
            self.assertIn(
                "benign_operator_metadata_summary",
                summary["benign_breakdown_by_policy_family"]["stateful_privacy_ledger"],
            )
            self.assertGreaterEqual(summary["attack_guess_count"], 2)
            self.assertGreaterEqual(summary["attack_correct_guess_count"], 2)
            self.assertEqual(
                summary["attack_run_outcomes"]["pilot-attack-non-adaptive-minimum-cohort"],
                "all_accepted",
            )
            self.assertEqual(summary["attack_run_outcomes"]["pilot-attack-minimum-cohort"], "all_accepted")
            self.assertEqual(summary["attack_run_outcomes"]["pilot-attack-ledger"], "ledger_blocked")
            self.assertEqual(
                summary["attack_run_outcomes"]["pilot-attack-subgroup-slicing-minimum-cohort"],
                "all_accepted",
            )
            self.assertEqual(
                summary["attack_run_outcomes"]["pilot-attack-subgroup-slicing-ledger"],
                "ledger_blocked",
            )

    def test_summarize_transcript_scores_accepted_pair_guess(self) -> None:
        rows = [
            {
                "run_id": "attack-run",
                "attacker_type": "scripted_adaptive",
                "policy_type": "minimum_cohort",
                "accepted": True,
                "rejection_reason_bucket": None,
                "attack_enabling_pair_id": "pair-1",
                "attack_template": "differencing",
                "result_value": 3,
                "target_variant_carrier": True,
            },
            {
                "run_id": "attack-run",
                "attacker_type": "scripted_adaptive",
                "policy_type": "minimum_cohort",
                "accepted": True,
                "rejection_reason_bucket": None,
                "attack_enabling_pair_id": "pair-1",
                "attack_template": "differencing",
                "result_value": 2,
                "target_variant_carrier": True,
            },
        ]

        summary = summarize_transcript(rows)

        self.assertEqual(summary.attack_guess_count, 1)
        self.assertEqual(summary.attack_correct_guess_count, 1)
        self.assertEqual(summary.attack_guess_success_rate, 1.0)


if __name__ == "__main__":
    unittest.main()
