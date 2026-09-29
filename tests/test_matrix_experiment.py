from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.matrix import run_pilot_matrix


class PilotMatrixExperimentTests(unittest.TestCase):
    def test_run_pilot_matrix_writes_aggregate_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "matrix_summary.json"
            transcript_dir = Path(temp_dir) / "transcripts"

            summary = run_pilot_matrix(
                output_path=output_path,
                transcript_dir=transcript_dir,
                seed_count=3,
                base_dataset_seed=701,
                base_metadata_seed=801,
                base_workload_seed=901,
                base_attacker_seed=1001,
                individuals=80,
                variants=20,
                k_min=1,
                difference_min=1000,
                benign_variant_count=1,
            )

            self.assertTrue(output_path.exists())
            written = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(written, summary)
            self.assertEqual(summary["seed_count"], 3)
            self.assertEqual(len(summary["per_seed"]), 3)
            self.assertEqual(summary["per_seed"][0]["comparison_key"], "seed:000")
            self.assertEqual(summary["attack_run_count"], 15)
            self.assertEqual(summary["attack_enabling_run_count"], 9)
            self.assertEqual(summary["ledger_blocked_attack_run_count"], 6)
            self.assertEqual(summary["attack_pair_count"], 9)
            self.assertEqual(summary["attack_enabling_pair_count"], 6)
            self.assertEqual(summary["ledger_blocked_attack_pair_count"], 3)
            self.assertGreaterEqual(summary["attack_guess_count"], 6)
            self.assertGreaterEqual(summary["attack_correct_guess_count"], 6)
            self.assertEqual(summary["attack_breakdown_by_type"]["non_adaptive"]["run_count"], 3)
            self.assertEqual(summary["attack_breakdown_by_type"]["scripted_adaptive"]["run_count"], 12)
            self.assertEqual(summary["attack_breakdown_by_type"]["non_adaptive"]["pair_count"], 3)
            self.assertEqual(summary["attack_breakdown_by_type"]["scripted_adaptive"]["pair_count"], 6)
            self.assertEqual(
                summary["attack_breakdown_by_type"]["scripted_adaptive"]["ledger_blocked_pair_count"],
                3,
            )
            self.assertEqual(summary["attack_breakdown_by_template"]["differencing"]["run_count"], 9)
            self.assertEqual(summary["attack_breakdown_by_template"]["subgroup_slicing"]["run_count"], 6)
            self.assertEqual(
                summary["attack_breakdown_by_template"]["subgroup_slicing"]["ledger_blocked_run_count"],
                3,
            )
            intervals = summary["confidence_intervals_95"]
            self.assertIn("attack_pair_block_rate", intervals)
            self.assertIn("benign_acceptance_rate", intervals)
            self.assertLessEqual(intervals["attack_pair_block_rate"]["lower"], intervals["attack_pair_block_rate"]["mean"])
            self.assertGreaterEqual(intervals["attack_pair_block_rate"]["upper"], intervals["attack_pair_block_rate"]["mean"])
            paired = summary["paired_policy_comparison"]
            self.assertEqual(paired["paired_unit"], "seed_index")
            self.assertEqual(paired["comparison_keys"], ["seed:000", "seed:001", "seed:002"])
            self.assertIn("minimum_cohort", paired["policy_types"])
            self.assertIn("stateful_privacy_ledger", paired["policy_types"])
            self.assertIn("differencing", paired["attack_templates"])
            self.assertIn("subgroup_slicing", paired["attack_templates"])
            self.assertEqual(summary["attack_breakdown_by_policy"]["minimum_cohort"]["run_count"], 9)
            self.assertEqual(
                summary["attack_breakdown_by_policy"]["stateful_privacy_ledger"]["run_count"],
                6,
            )
            delta = summary["paired_policy_delta"]
            self.assertEqual(delta["baseline_policy"], "minimum_cohort")
            self.assertEqual(delta["comparison_policy"], "stateful_privacy_ledger")
            self.assertEqual(delta["ledger_blocked_run_count_delta"], 6)
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
            self.assertIn("benign_utility_loss", delta)
            self.assertIn("benign_utility_loss_seed_values", delta)
            self.assertEqual(len(delta["benign_utility_loss_seed_values"]), 3)
            self.assertIn("benign_utility_loss_one_sided_95_upper", delta)
            self.assertIn("e4_utility_band", delta)
            self.assertIn("e4_utility_pass", delta)
            self.assertIn("benign_utility_loss_by_family", delta)
            self.assertIn("benign_broad_summary", delta["benign_utility_loss_by_family"])
            self.assertIn("benign_operator_metadata_summary", delta["benign_utility_loss_by_family"])
            self.assertGreaterEqual(delta["comparison_benign_rows"], 0)
            self.assertGreater(summary["benign_rows"], 0)
            self.assertEqual(summary["benign_rejected_rows"], 54)
            self.assertLess(summary["benign_acceptance_rate"], 1.0)
            self.assertEqual(len(list(transcript_dir.glob("*.jsonl"))), 3)

    def test_run_pilot_matrix_can_split_e3_policy_variants(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "matrix_summary.json"

            summary = run_pilot_matrix(
                output_path=output_path,
                seed_count=1,
                base_dataset_seed=701,
                base_metadata_seed=801,
                base_workload_seed=901,
                base_attacker_seed=1001,
                individuals=80,
                variants=20,
                k_min=1,
                difference_min=1000,
                benign_variant_count=1,
                policy_variant_set="e3",
            )

            self.assertEqual(summary["policy_variant_set"], "e3")
            self.assertEqual(summary["attack_run_count"], 13)
            self.assertEqual(summary["ledger_blocked_attack_run_count"], 10)
            policy_breakdown = summary["attack_breakdown_by_policy"]
            self.assertEqual(policy_breakdown["minimum_cohort"]["run_count"], 3)
            self.assertEqual(policy_breakdown["stateful_privacy_ledger"]["run_count"], 2)
            self.assertEqual(
                policy_breakdown["stateful_privacy_ledger_difference_only"]["run_count"],
                2,
            )
            self.assertEqual(
                policy_breakdown["stateful_privacy_ledger_symmetric_only"]["run_count"],
                2,
            )
            self.assertEqual(
                policy_breakdown["stateful_privacy_ledger_session_scope"]["run_count"],
                2,
            )
            self.assertEqual(
                policy_breakdown["stateful_privacy_ledger_user_scope"]["run_count"],
                2,
            )
            paired = summary["paired_policy_comparison"]
            self.assertIn("stateful_privacy_ledger_difference_only", paired["policy_types"])
            self.assertIn("stateful_privacy_ledger_symmetric_only", paired["policy_types"])
            self.assertIn("stateful_privacy_ledger_session_scope", paired["policy_types"])
            self.assertIn("stateful_privacy_ledger_user_scope", paired["policy_types"])
            delta = summary["paired_policy_delta"]
            self.assertIn("stateful_privacy_ledger_difference_only", delta["available_comparison_policies"])
            self.assertIn("stateful_privacy_ledger_user_scope", delta["available_comparison_policies"])
            self.assertEqual(
                delta["additional_policy_deltas"]["stateful_privacy_ledger_difference_only"][
                    "ledger_blocked_run_count_delta"
                ],
                2,
            )
            self.assertEqual(
                delta["additional_policy_deltas"]["stateful_privacy_ledger_user_scope"][
                    "ledger_blocked_run_count_delta"
                ],
                2,
            )
            self.assertIn(
                "benign_utility_loss",
                delta["additional_policy_deltas"]["stateful_privacy_ledger_user_scope"],
            )
            self.assertIn(
                "benign_utility_loss_one_sided_95_upper",
                delta["additional_policy_deltas"]["stateful_privacy_ledger_user_scope"],
            )
            self.assertIn(
                "e4_utility_band",
                delta["additional_policy_deltas"]["stateful_privacy_ledger_user_scope"],
            )
            self.assertIn(
                "benign_broad_summary",
                delta["additional_policy_deltas"]["stateful_privacy_ledger_user_scope"][
                    "benign_utility_loss_by_family"
                ],
            )

    def test_run_pilot_matrix_without_transcript_dir_does_not_return_temp_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "matrix_summary.json"

            summary = run_pilot_matrix(
                output_path=output_path,
                seed_count=1,
                base_dataset_seed=711,
                base_metadata_seed=811,
                base_workload_seed=911,
                base_attacker_seed=1011,
                individuals=80,
                variants=20,
                k_min=1,
                difference_min=1000,
                benign_variant_count=1,
            )

            self.assertIsNone(summary["per_seed"][0]["transcript_path"])

    def test_run_pilot_matrix_can_scale_attack_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "matrix_summary.json"

            summary = run_pilot_matrix(
                output_path=output_path,
                seed_count=1,
                base_dataset_seed=701,
                base_metadata_seed=801,
                base_workload_seed=901,
                base_attacker_seed=1001,
                individuals=80,
                variants=20,
                k_min=1,
                difference_min=1000,
                benign_variant_count=1,
                target_count=2,
            )

            self.assertEqual(summary["target_count"], 2)
            self.assertEqual(summary["attack_run_count"], 10)
            self.assertEqual(summary["attack_enabling_run_count"], 6)
            self.assertEqual(summary["ledger_blocked_attack_run_count"], 4)
            run_outcomes = summary["per_seed"][0]["summary"]["attack_run_outcomes"]
            self.assertIn("pilot-attack-minimum-cohort-target-000", run_outcomes)
            self.assertIn("pilot-attack-minimum-cohort-target-001", run_outcomes)


if __name__ == "__main__":
    unittest.main()
