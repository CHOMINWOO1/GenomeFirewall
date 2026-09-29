from __future__ import annotations

import unittest

from genomefirewall import GenomicQuery, SyntheticConfig, evaluate_query, generate_synthetic_dataset, select_cohort
from genomefirewall.synthetic import cohort_hash


class SyntheticDatasetTests(unittest.TestCase):
    def test_generation_is_deterministic(self) -> None:
        config = SyntheticConfig(individuals=25, variants=12, dataset_seed=11, metadata_seed=12)

        first = generate_synthetic_dataset(config)
        second = generate_synthetic_dataset(config)

        self.assertEqual(first.variant_mafs, second.variant_mafs)
        self.assertEqual(first.genotypes, second.genotypes)
        self.assertEqual(first.metadata, second.metadata)

    def test_generated_shapes_and_values(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=10, variants=7))

        self.assertEqual(len(dataset.individual_ids), 10)
        self.assertEqual(len(dataset.variant_ids), 7)
        self.assertEqual(len(dataset.genotypes), 10)
        self.assertTrue(all(len(row) == 7 for row in dataset.genotypes))
        self.assertTrue(all(dosage in {0, 1, 2} for row in dataset.genotypes for dosage in row))
        self.assertTrue(all(0.005 <= maf <= 0.50 for maf in dataset.variant_mafs))

    def test_query_evaluation_matches_selected_cohort(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=40, variants=5, dataset_seed=101))
        predicate = {"sex": "F"}
        cohort = select_cohort(dataset, predicate)

        query = GenomicQuery(operator="COHORT_COUNT", predicate=predicate)

        self.assertEqual(evaluate_query(dataset, query), len(cohort))
        self.assertEqual(len(cohort_hash(cohort)), 64)

    def test_carrier_count_uses_dosage_greater_than_zero(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=40, variants=5, dataset_seed=102))
        predicate = {"ancestry_group": ["A", "B", "C", "D", "E"]}
        variant_id = dataset.variant_ids[0]
        variant_idx = dataset.variant_index(variant_id)

        expected = sum(1 for row in dataset.genotypes if row[variant_idx] > 0)
        query = GenomicQuery(operator="CARRIER_COUNT", predicate=predicate, variant_id=variant_id)

        self.assertEqual(evaluate_query(dataset, query), expected)

    def test_invalid_query_rejected(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=5, variants=2))
        query = GenomicQuery(operator="ALLELE_COUNT", predicate={"sex": "F"})

        with self.assertRaises(ValueError):
            evaluate_query(dataset, query)


if __name__ == "__main__":
    unittest.main()
