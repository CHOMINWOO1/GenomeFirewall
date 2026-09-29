from __future__ import annotations

import unittest

from genomefirewall import (
    GenomicQuery,
    QueryAttemptContext,
    StatefulPrivacyLedgerPolicy,
    SyntheticConfig,
    evaluate_query_attempt,
    generate_synthetic_dataset,
)


class StatefulPrivacyLedgerPolicyTests(unittest.TestCase):
    def test_records_accepted_history(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=30, variants=4, dataset_seed=301))
        policy = StatefulPrivacyLedgerPolicy(k_min=1, difference_min=1)
        query = GenomicQuery(
            operator="CARRIER_COUNT",
            predicate={"ancestry_group": ["A", "B", "C", "D", "E"]},
            variant_id=dataset.variant_ids[0],
        )

        record = evaluate_query_attempt(dataset, query, policy, _context(0))

        self.assertTrue(record.accepted)
        self.assertEqual(len(policy.accepted_history), 1)
        self.assertEqual(policy.accepted_history[0].query_index, 0)
        self.assertEqual(policy.accepted_history[0].result_value, record.result_value)

    def test_rejects_repeated_same_variant_query_by_difference_threshold(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=30, variants=4, dataset_seed=302))
        policy = StatefulPrivacyLedgerPolicy(k_min=1, difference_min=1)
        query = GenomicQuery(
            operator="CARRIER_COUNT",
            predicate={"ancestry_group": ["A", "B", "C", "D", "E"]},
            variant_id=dataset.variant_ids[0],
        )

        first = evaluate_query_attempt(dataset, query, policy, _context(0))
        second = evaluate_query_attempt(dataset, query, policy, _context(1))

        self.assertTrue(first.accepted)
        self.assertFalse(second.accepted)
        self.assertEqual(second.rejection_reason_bucket, "ledger_difference")
        self.assertEqual(second.max_prior_overlap, 30)
        self.assertEqual(second.min_prior_difference, 0)
        self.assertEqual(second.min_prior_symmetric_difference, 0)
        self.assertEqual(len(policy.accepted_history), 1)

    def test_accepts_different_variant_when_same_variant_only(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=30, variants=4, dataset_seed=303))
        policy = StatefulPrivacyLedgerPolicy(k_min=1, difference_min=1, same_variant_only=True)
        first_query = GenomicQuery(
            operator="CARRIER_COUNT",
            predicate={"ancestry_group": ["A", "B", "C", "D", "E"]},
            variant_id=dataset.variant_ids[0],
        )
        second_query = GenomicQuery(
            operator="CARRIER_COUNT",
            predicate={"ancestry_group": ["A", "B", "C", "D", "E"]},
            variant_id=dataset.variant_ids[1],
        )

        first = evaluate_query_attempt(dataset, first_query, policy, _context(0))
        second = evaluate_query_attempt(dataset, second_query, policy, _context(1))

        self.assertTrue(first.accepted)
        self.assertTrue(second.accepted)
        self.assertIsNone(second.max_prior_overlap)
        self.assertEqual(len(policy.accepted_history), 2)

    def test_rejects_by_symmetric_difference_threshold(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=30, variants=4, dataset_seed=304))
        policy = StatefulPrivacyLedgerPolicy(k_min=1, symmetric_difference_min=1)
        query = GenomicQuery(
            operator="COHORT_COUNT",
            predicate={"sex": ["F", "M"]},
        )

        first = evaluate_query_attempt(dataset, query, policy, _context(0))
        second = evaluate_query_attempt(dataset, query, policy, _context(1))

        self.assertTrue(first.accepted)
        self.assertFalse(second.accepted)
        self.assertEqual(second.rejection_reason_bucket, "ledger_symmetric_difference")


def _context(query_index: int) -> QueryAttemptContext:
    return QueryAttemptContext(
        run_id="ledger-test",
        workload_seed=10,
        attacker_seed=20,
        attacker_type="scripted_adaptive",
        query_index=query_index,
    )


if __name__ == "__main__":
    unittest.main()
