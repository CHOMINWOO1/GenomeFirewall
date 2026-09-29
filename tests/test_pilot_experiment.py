from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.pilot import run_pilot_experiment


class PilotExperimentTests(unittest.TestCase):
    def test_run_pilot_writes_jsonl_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "pilot.jsonl"

            result = run_pilot_experiment(
                output_path=output_path,
                individuals=80,
                variants=20,
                dataset_seed=501,
                metadata_seed=502,
                workload_seed=503,
                attacker_seed=504,
                k_min=1,
                difference_min=1000,
                benign_variant_count=2,
            )

            self.assertTrue(output_path.exists())
            self.assertEqual(result.row_count, result.benign_rows + result.attack_rows)
            self.assertGreater(result.benign_rows, 0)
            self.assertEqual(result.attack_rows, 12)

            rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), result.row_count)
            self.assertTrue(any(row["attacker_type"] == "benign" for row in rows))
            self.assertTrue(any(row["attacker_type"] == "scripted_adaptive" for row in rows))
            self.assertTrue(any(row["rejection_reason_bucket"] == "ledger_difference" for row in rows))
            minimum_attack_rows = [
                row for row in rows if row["run_id"] == "pilot-attack-minimum-cohort"
            ]
            ledger_attack_rows = [row for row in rows if row["run_id"] == "pilot-attack-ledger"]
            subgroup_minimum_rows = [
                row for row in rows if row["run_id"] == "pilot-attack-subgroup-slicing-minimum-cohort"
            ]
            subgroup_ledger_rows = [
                row for row in rows if row["run_id"] == "pilot-attack-subgroup-slicing-ledger"
            ]
            non_adaptive_rows = [
                row for row in rows if row["run_id"] == "pilot-attack-non-adaptive-minimum-cohort"
            ]
            self.assertEqual(len(non_adaptive_rows), 2)
            self.assertEqual(len(minimum_attack_rows), 2)
            self.assertEqual(len(ledger_attack_rows), 2)
            self.assertEqual(len(subgroup_minimum_rows), 4)
            self.assertEqual(len(subgroup_ledger_rows), 2)
            self.assertTrue(all(row["attacker_type"] == "non_adaptive" for row in non_adaptive_rows))
            self.assertTrue(all(row["accepted"] for row in minimum_attack_rows))
            self.assertTrue(all(row["attack_template"] == "subgroup_slicing" for row in subgroup_minimum_rows))
            self.assertEqual(subgroup_ledger_rows[1]["rejection_reason_bucket"], "ledger_difference")
            self.assertTrue(all(row["attack_enabling_pair_id"] for row in minimum_attack_rows))
            self.assertEqual(
                minimum_attack_rows[0]["attack_enabling_pair_id"],
                minimum_attack_rows[1]["attack_enabling_pair_id"],
            )

    def test_run_pilot_can_emit_e3_policy_variants(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "pilot_e3.jsonl"

            result = run_pilot_experiment(
                output_path=output_path,
                individuals=80,
                variants=20,
                dataset_seed=501,
                metadata_seed=502,
                workload_seed=503,
                attacker_seed=504,
                k_min=1,
                difference_min=1000,
                benign_variant_count=1,
                policy_variant_set="e3",
            )

            rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
            policy_types = {row["policy_type"] for row in rows}
            self.assertEqual(result.policy_variant_set, "e3")
            self.assertGreater(result.attack_rows, 12)
            self.assertIn("stateful_privacy_ledger_difference_only", policy_types)
            self.assertIn("stateful_privacy_ledger_symmetric_only", policy_types)
            self.assertIn("stateful_privacy_ledger_session_scope", policy_types)
            self.assertIn("stateful_privacy_ledger_user_scope", policy_types)
            self.assertTrue(
                any(row["run_id"] == "pilot-attack-ledger-difference-only" for row in rows)
            )
            self.assertTrue(
                any(row["run_id"] == "pilot-attack-ledger-symmetric-only" for row in rows)
            )
            self.assertTrue(
                any(row["run_id"] == "pilot-attack-ledger-session-scope" for row in rows)
            )
            self.assertTrue(any(row["run_id"] == "pilot-attack-ledger-user-scope" for row in rows))

    def test_run_pilot_can_scale_attack_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "pilot_multi_target.jsonl"

            result = run_pilot_experiment(
                output_path=output_path,
                individuals=80,
                variants=20,
                dataset_seed=501,
                metadata_seed=502,
                workload_seed=503,
                attacker_seed=504,
                k_min=1,
                difference_min=1000,
                benign_variant_count=1,
                target_count=2,
            )

            rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
            attack_run_ids = {row["run_id"] for row in rows if row["attacker_type"] != "benign"}
            self.assertEqual(result.target_count, 2)
            self.assertEqual(result.attack_rows, 24)
            self.assertIn("pilot-attack-minimum-cohort-target-000", attack_run_ids)
            self.assertIn("pilot-attack-minimum-cohort-target-001", attack_run_ids)


if __name__ == "__main__":
    unittest.main()
