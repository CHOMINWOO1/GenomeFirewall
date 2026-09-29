from __future__ import annotations

import unittest

from genomefirewall import QueryLogRecord


class QueryLogRecordTests(unittest.TestCase):
    def test_fieldnames_are_stable(self) -> None:
        self.assertEqual(
            QueryLogRecord.fieldnames(),
            [
                "run_id",
                "dataset_seed",
                "workload_seed",
                "attacker_seed",
                "attacker_type",
                "policy_type",
                "query_index",
                "operator",
                "variant_id",
                "predicate_json",
                "cohort_size",
                "cohort_hash",
                "accepted",
                "rejection_reason_bucket",
                "result_value",
                "max_prior_overlap",
                "min_prior_difference",
                "min_prior_symmetric_difference",
                "target_in_cohort",
                "target_variant_carrier",
                "attack_enabling_pair_id",
                "attacker_guess",
                "attacker_confidence",
                "workload_label",
                "workload_family",
                "attack_template",
            ],
        )

    def test_to_dict_contains_required_values(self) -> None:
        record = QueryLogRecord(
            run_id="pilot",
            dataset_seed=1,
            workload_seed=2,
            attacker_seed=3,
            attacker_type="benign",
            policy_type="minimum_cohort",
            query_index=0,
            operator="COHORT_COUNT",
            variant_id=None,
            predicate_json='{"sex":"F"}',
            cohort_size=42,
            cohort_hash="abc",
            accepted=True,
            result_value=42,
        )

        self.assertEqual(record.to_dict()["run_id"], "pilot")
        self.assertEqual(record.to_dict()["result_value"], 42)
        self.assertIsNone(record.to_dict()["workload_family"])


if __name__ == "__main__":
    unittest.main()
