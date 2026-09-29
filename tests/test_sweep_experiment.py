from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.sweep import (
    run_difference_threshold_sweep,
    run_symmetric_difference_threshold_sweep,
)


class ThresholdSweepExperimentTests(unittest.TestCase):
    def test_run_difference_threshold_sweep_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "sweep.json"

            summary = run_difference_threshold_sweep(
                output_path=output_path,
                difference_min_values=(1, 1000),
                seed_count=2,
                individuals=80,
                variants=20,
                k_min=1,
                benign_variant_count=1,
            )

            self.assertTrue(output_path.exists())
            written = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(written, summary)
            self.assertEqual(summary["difference_min_values"], [1, 1000])
            self.assertEqual(len(summary["results"]), 2)
            for result in summary["results"]:
                matrix_summary = result["matrix_summary"]
                self.assertEqual(matrix_summary["seed_count"], 2)
                self.assertEqual(matrix_summary["attack_run_count"], 10)
                self.assertEqual(matrix_summary["attack_enabling_run_count"], 6)
                self.assertEqual(matrix_summary["ledger_blocked_attack_run_count"], 4)
                self.assertEqual(matrix_summary["attack_pair_count"], 6)
                self.assertEqual(matrix_summary["attack_enabling_pair_count"], 4)
                self.assertEqual(matrix_summary["ledger_blocked_attack_pair_count"], 2)
                self.assertEqual(
                    matrix_summary["attack_breakdown_by_template"]["subgroup_slicing"]["run_count"],
                    4,
                )
                self.assertLess(matrix_summary["benign_acceptance_rate"], 1.0)
                expected_benign_rejections = 11 if result["difference_min"] == 1 else 36
                self.assertEqual(matrix_summary["benign_rejected_rows"], expected_benign_rejections)
                self.assertIn("benign_broad_summary", matrix_summary["benign_breakdown_by_policy_family"]["minimum_cohort"])
                self.assertIn(
                    "benign_operator_metadata_summary",
                    matrix_summary["benign_breakdown_by_policy_family"]["minimum_cohort"],
                )
                self.assertIn(
                    "benign_near_overlap",
                    matrix_summary["paired_policy_delta"]["benign_utility_loss_by_family"],
                )
                self.assertIn(
                    "benign_operator_metadata_summary",
                    matrix_summary["paired_policy_delta"]["benign_utility_loss_by_family"],
                )
                self.assertTrue(
                    all(entry["transcript_path"] is None for entry in matrix_summary["per_seed"])
                )

    def test_run_difference_threshold_sweep_can_use_e3_policy_variant_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "sweep_e3.json"

            summary = run_difference_threshold_sweep(
                output_path=output_path,
                difference_min_values=(1000,),
                seed_count=1,
                individuals=80,
                variants=20,
                k_min=1,
                benign_variant_count=1,
                policy_variant_set="e3",
            )

            matrix_summary = summary["results"][0]["matrix_summary"]
            self.assertEqual(summary["policy_variant_set"], "e3")
            self.assertEqual(matrix_summary["policy_variant_set"], "e3")
            self.assertIn(
                "stateful_privacy_ledger_difference_only",
                matrix_summary["attack_breakdown_by_policy"],
            )
            self.assertIn(
                "stateful_privacy_ledger_symmetric_only",
                matrix_summary["attack_breakdown_by_policy"],
            )

    def test_run_symmetric_difference_threshold_sweep_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "symmetric_sweep.json"

            summary = run_symmetric_difference_threshold_sweep(
                output_path=output_path,
                symmetric_difference_min_values=(1, 1000),
                seed_count=2,
                individuals=80,
                variants=20,
                k_min=1,
                benign_variant_count=1,
            )

            self.assertTrue(output_path.exists())
            self.assertEqual(summary["sweep_type"], "symmetric_difference_min")
            self.assertEqual(summary["symmetric_difference_min_values"], [1, 1000])
            self.assertEqual(len(summary["results"]), 2)
            self.assertEqual(summary["results"][0]["symmetric_difference_min"], 1)


if __name__ == "__main__":
    unittest.main()
