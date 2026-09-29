from __future__ import annotations

import unittest

from genomefirewall import (
    MinimumCohortPolicy,
    StatefulPrivacyLedgerPolicy,
    generate_benign_operator_metadata_workload,
    SyntheticConfig,
    generate_benign_workload,
    generate_benign_near_overlap_workload,
    generate_differencing_attack_workload,
    generate_subgroup_slicing_attack_workload,
    generate_synthetic_dataset,
    run_workload,
    select_cohort,
    select_attack_target,
)


class WorkloadGeneratorTests(unittest.TestCase):
    def test_benign_workload_is_deterministic(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=12, dataset_seed=401))

        first = generate_benign_workload(dataset, workload_seed=7, variant_count=2)
        second = generate_benign_workload(dataset, workload_seed=7, variant_count=2)

        self.assertEqual(first, second)
        self.assertTrue(any(item.label == "benign_cohort_size_by_sex" for item in first))
        self.assertTrue(any(item.query.operator == "CARRIER_COUNT" for item in first))
        self.assertTrue(all(item.workload_family == "benign_broad_summary" for item in first))

    def test_differencing_workload_targets_same_variant(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=100, variants=20, dataset_seed=402))
        target = select_attack_target(dataset, target_seed=17)

        workload = generate_differencing_attack_workload(dataset, target)

        self.assertEqual(len(workload), 2)
        self.assertEqual(workload[0].query.variant_id, target.variant_id)
        self.assertEqual(workload[1].query.variant_id, target.variant_id)
        self.assertEqual(workload[0].query.operator, "CARRIER_COUNT")
        self.assertEqual(workload[1].query.operator, "CARRIER_COUNT")
        self.assertIsNotNone(workload[0].attack_enabling_pair_id)
        self.assertEqual(workload[0].attack_enabling_pair_id, workload[1].attack_enabling_pair_id)
        self.assertEqual(workload[0].attack_template, "differencing")
        self.assertEqual(workload[1].attack_template, "differencing")

    def test_subgroup_slicing_workload_progressively_adds_target_fields(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=100, variants=20, dataset_seed=406))
        target = select_attack_target(dataset, target_seed=29)

        workload = generate_subgroup_slicing_attack_workload(
            dataset,
            target,
            slice_fields=("region", "study_site", "batch"),
        )

        self.assertEqual(len(workload), 4)
        self.assertTrue(all(item.attack_template == "subgroup_slicing" for item in workload))
        self.assertEqual(workload[0].label, "attack_subgroup_slicing_base")
        self.assertEqual(workload[-1].query.predicate["batch"], target.visible_profile["batch"])
        self.assertTrue(
            all(target.individual_index in select_cohort(dataset, item.query.predicate) for item in workload)
        )

    def test_benign_near_overlap_workload_has_no_attack_pair_id(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=100, variants=20, dataset_seed=405))

        workload = generate_benign_near_overlap_workload(dataset, workload_seed=23)

        self.assertEqual(len(workload), 2)
        self.assertEqual(workload[0].query.operator, "CARRIER_COUNT")
        self.assertEqual(workload[1].query.operator, "CARRIER_COUNT")
        self.assertIsNone(workload[0].attack_enabling_pair_id)
        self.assertIsNone(workload[1].attack_enabling_pair_id)
        self.assertTrue(all(item.workload_family == "benign_near_overlap" for item in workload))

    def test_benign_operator_metadata_workload_covers_core_operators(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=100, variants=20, dataset_seed=407))

        workload = generate_benign_operator_metadata_workload(dataset, workload_seed=31, variant_count=1)

        operators = {item.query.operator for item in workload}
        labels = {item.label for item in workload}
        self.assertEqual(operators, {"ALLELE_COUNT", "CARRIER_COUNT", "COHORT_COUNT"})
        self.assertIn("benign_cohort_count_by_age_bin", labels)
        self.assertIn("benign_cohort_count_by_batch", labels)
        self.assertIn("benign_cohort_count_by_study_site", labels)
        self.assertIn("benign_allele_count_by_ancestry", labels)
        self.assertIn("benign_carrier_count_by_region", labels)
        self.assertTrue(
            all(item.workload_family == "benign_operator_metadata_summary" for item in workload)
        )
        self.assertTrue(all(item.attack_enabling_pair_id is None for item in workload))

    def test_run_benign_workload_produces_transcript(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=12, dataset_seed=403))
        workload = generate_benign_workload(dataset, workload_seed=9, variant_count=1)

        transcript = run_workload(
            dataset=dataset,
            workload=workload,
            policy=MinimumCohortPolicy(k_min=1),
            run_id="benign-v0",
            workload_seed=9,
            attacker_seed=0,
            attacker_type="benign",
        )

        self.assertEqual(len(transcript), len(workload))
        self.assertTrue(all(record.accepted for record in transcript))
        self.assertEqual(transcript[0].query_index, 0)
        self.assertEqual(transcript[0].workload_label, workload[0].label)
        self.assertEqual(transcript[0].workload_family, "benign_broad_summary")

    def test_differencing_workload_interacts_with_ledger(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=100, variants=20, dataset_seed=404))
        target = select_attack_target(dataset, target_seed=19)
        workload = generate_differencing_attack_workload(dataset, target)
        policy = StatefulPrivacyLedgerPolicy(
            k_min=1,
            difference_min=1000,
            same_variant_only=True,
            same_operator_only=True,
        )

        transcript = run_workload(
            dataset=dataset,
            workload=workload,
            policy=policy,
            run_id="attack-v0",
            workload_seed=19,
            attacker_seed=19,
            attacker_type="scripted_adaptive",
            target_individual_index=target.individual_index,
            target_variant_id=target.variant_id,
        )

        self.assertTrue(transcript[0].accepted)
        self.assertFalse(transcript[1].accepted)
        self.assertEqual(transcript[1].rejection_reason_bucket, "ledger_difference")
        self.assertIsNotNone(transcript[1].min_prior_difference)
        self.assertIsNotNone(transcript[0].attack_enabling_pair_id)
        self.assertEqual(transcript[0].attack_enabling_pair_id, transcript[1].attack_enabling_pair_id)
        self.assertEqual(transcript[0].attack_template, "differencing")
        self.assertEqual(transcript[1].target_variant_carrier, target.carrier)


if __name__ == "__main__":
    unittest.main()
