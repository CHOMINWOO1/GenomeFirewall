from __future__ import annotations

import unittest

from genomefirewall import (
    GenomicQuery,
    MinimumCohortPolicy,
    QueryAttemptContext,
    SyntheticConfig,
    evaluate_query_attempt,
    generate_synthetic_dataset,
)


class QueryAttemptRunnerTests(unittest.TestCase):
    def test_accepted_query_attempt_records_result(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=30, variants=4, dataset_seed=201))
        query = GenomicQuery(
            operator="COHORT_COUNT",
            predicate={"ancestry_group": ["A", "B", "C", "D", "E"]},
        )
        context = QueryAttemptContext(
            run_id="run-1",
            workload_seed=10,
            attacker_seed=20,
            attacker_type="benign",
            query_index=0,
        )

        record = evaluate_query_attempt(dataset, query, MinimumCohortPolicy(k_min=5), context)

        self.assertTrue(record.accepted)
        self.assertIsNone(record.rejection_reason_bucket)
        self.assertEqual(record.result_value, 30)
        self.assertEqual(record.policy_type, "minimum_cohort")

    def test_rejected_query_attempt_hides_result(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=30, variants=4, dataset_seed=202))
        query = GenomicQuery(operator="COHORT_COUNT", predicate={"sex": "F"})
        context = QueryAttemptContext(
            run_id="run-1",
            workload_seed=10,
            attacker_seed=20,
            attacker_type="scripted_adaptive",
            query_index=1,
        )

        record = evaluate_query_attempt(dataset, query, MinimumCohortPolicy(k_min=31), context)

        self.assertFalse(record.accepted)
        self.assertEqual(record.rejection_reason_bucket, "small_cohort")
        self.assertIsNone(record.result_value)

    def test_target_evaluation_fields_are_filled_when_requested(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=12, variants=3, dataset_seed=203))
        target_variant_id = dataset.variant_ids[0]
        query = GenomicQuery(
            operator="CARRIER_COUNT",
            predicate={"ancestry_group": ["A", "B", "C", "D", "E"]},
            variant_id=target_variant_id,
        )
        context = QueryAttemptContext(
            run_id="run-2",
            workload_seed=11,
            attacker_seed=21,
            attacker_type="non_adaptive",
            query_index=0,
            target_individual_index=0,
            target_variant_id=target_variant_id,
        )

        record = evaluate_query_attempt(dataset, query, MinimumCohortPolicy(k_min=1), context)

        self.assertTrue(record.target_in_cohort)
        self.assertEqual(record.target_variant_carrier, dataset.genotypes[0][0] > 0)


if __name__ == "__main__":
    unittest.main()
