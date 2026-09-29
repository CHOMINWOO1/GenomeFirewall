from __future__ import annotations

import unittest

from genomefirewall import (
    MinimumCohortPolicy,
    StatefulPrivacyLedgerPolicy,
    SyntheticConfig,
    generate_synthetic_dataset,
    run_adaptive_differencing_attack,
    run_subgroup_slicing_attack,
    select_attack_target,
)


class AdaptiveScriptedAttackerTests(unittest.TestCase):
    def test_minimum_policy_allows_first_differencing_pair(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=1101))
        target = select_attack_target(dataset, target_seed=1102)

        result = run_adaptive_differencing_attack(
            dataset=dataset,
            target=target,
            policy=MinimumCohortPolicy(k_min=1),
            run_id="attack-minimum",
            workload_seed=1,
            attacker_seed=2,
            slice_fields=("study_site", "region"),
        )

        self.assertEqual(result.outcome, "attack_enabling")
        self.assertEqual(result.attempted_slice_fields, ("study_site",))
        self.assertEqual(len(result.transcript), 2)
        self.assertTrue(all(record.accepted for record in result.transcript))
        self.assertIsNotNone(result.stopped_pair_id)

    def test_ledger_policy_blocks_first_differencing_pair(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=1201))
        target = select_attack_target(dataset, target_seed=1202)

        result = run_adaptive_differencing_attack(
            dataset=dataset,
            target=target,
            policy=StatefulPrivacyLedgerPolicy(k_min=1, difference_min=1000),
            run_id="attack-ledger",
            workload_seed=1,
            attacker_seed=2,
            slice_fields=("study_site", "region"),
        )

        self.assertEqual(result.outcome, "ledger_blocked")
        self.assertEqual(result.attempted_slice_fields, ("study_site",))
        self.assertEqual(len(result.transcript), 2)
        self.assertTrue(result.transcript[0].accepted)
        self.assertFalse(result.transcript[1].accepted)
        self.assertEqual(result.transcript[1].rejection_reason_bucket, "ledger_difference")

    def test_attacker_continues_after_non_ledger_rejection(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=1301))
        target = select_attack_target(dataset, target_seed=1302)

        result = run_adaptive_differencing_attack(
            dataset=dataset,
            target=target,
            policy=MinimumCohortPolicy(k_min=10_000),
            run_id="attack-exhausted",
            workload_seed=1,
            attacker_seed=2,
            slice_fields=("study_site", "region"),
        )

        self.assertEqual(result.outcome, "exhausted")
        self.assertEqual(result.attempted_slice_fields, ("study_site", "region"))
        self.assertEqual(len(result.transcript), 2)
        self.assertTrue(all(record.rejection_reason_bucket == "small_cohort" for record in result.transcript))

    def test_subgroup_slicing_minimum_policy_completes_sequence(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=1401))
        target = select_attack_target(dataset, target_seed=1402)

        result = run_subgroup_slicing_attack(
            dataset=dataset,
            target=target,
            policy=MinimumCohortPolicy(k_min=1),
            run_id="attack-subgroup-minimum",
            workload_seed=1,
            attacker_seed=2,
            slice_fields=("region", "study_site", "batch"),
        )

        self.assertEqual(result.outcome, "attack_enabling")
        self.assertEqual(len(result.transcript), 4)
        self.assertTrue(all(record.accepted for record in result.transcript))
        self.assertTrue(all(record.attack_template == "subgroup_slicing" for record in result.transcript))

    def test_subgroup_slicing_ledger_policy_stops_on_history_rejection(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=1501))
        target = select_attack_target(dataset, target_seed=1502)

        result = run_subgroup_slicing_attack(
            dataset=dataset,
            target=target,
            policy=StatefulPrivacyLedgerPolicy(k_min=1, difference_min=1000),
            run_id="attack-subgroup-ledger",
            workload_seed=1,
            attacker_seed=2,
            slice_fields=("region", "study_site", "batch"),
        )

        self.assertEqual(result.outcome, "ledger_blocked")
        self.assertEqual(len(result.transcript), 2)
        self.assertTrue(result.transcript[0].accepted)
        self.assertFalse(result.transcript[1].accepted)
        self.assertEqual(result.transcript[1].rejection_reason_bucket, "ledger_difference")


if __name__ == "__main__":
    unittest.main()
