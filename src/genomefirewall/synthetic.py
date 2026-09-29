"""Synthetic genotype, metadata, and aggregate-query utilities."""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from typing import Mapping, Sequence


DEFAULT_MAF_BANDS: tuple[tuple[str, float, float, float], ...] = (
    ("rare", 0.005, 0.01, 0.15),
    ("low_frequency", 0.01, 0.05, 0.25),
    ("common", 0.05, 0.30, 0.50),
    ("high_common", 0.30, 0.50, 0.10),
)


@dataclass(frozen=True)
class SyntheticConfig:
    """Configuration for deterministic synthetic dataset generation."""

    individuals: int = 1_000
    variants: int = 500
    dataset_seed: int = 1729
    metadata_seed: int = 1730
    metadata_correlation: str = "independent"
    marker_variant_count: int = 8

    def validate(self) -> None:
        if self.individuals <= 0:
            raise ValueError("individuals must be positive")
        if self.variants <= 0:
            raise ValueError("variants must be positive")
        if self.metadata_correlation not in {"independent", "weak", "moderate"}:
            raise ValueError("metadata_correlation must be independent, weak, or moderate")
        if self.marker_variant_count <= 0:
            raise ValueError("marker_variant_count must be positive")


@dataclass(frozen=True)
class SyntheticDataset:
    """In-memory pilot dataset for GenomeFirewall experiments."""

    config: SyntheticConfig
    individual_ids: tuple[str, ...]
    variant_ids: tuple[str, ...]
    variant_mafs: tuple[float, ...]
    variant_bands: tuple[str, ...]
    genotypes: tuple[tuple[int, ...], ...]
    metadata: tuple[Mapping[str, str], ...]

    def variant_index(self, variant_id: str) -> int:
        try:
            return self.variant_ids.index(variant_id)
        except ValueError as exc:
            raise KeyError(f"unknown variant_id: {variant_id}") from exc


@dataclass(frozen=True)
class GenomicQuery:
    """Constrained aggregate query used by the synthetic evaluator."""

    operator: str
    predicate: Mapping[str, str | Sequence[str]]
    variant_id: str | None = None

    def validate(self) -> None:
        allowed_operators = {"COHORT_COUNT", "ALLELE_COUNT", "CARRIER_COUNT"}
        if self.operator not in allowed_operators:
            raise ValueError(f"unsupported operator: {self.operator}")
        if self.operator == "COHORT_COUNT" and self.variant_id is not None:
            raise ValueError("COHORT_COUNT must not specify variant_id")
        if self.operator in {"ALLELE_COUNT", "CARRIER_COUNT"} and self.variant_id is None:
            raise ValueError(f"{self.operator} requires variant_id")

    def canonical_predicate_json(self) -> str:
        return json.dumps(self.predicate, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def generate_synthetic_dataset(config: SyntheticConfig | None = None) -> SyntheticDataset:
    """Generate a deterministic pilot-scale synthetic genotype dataset."""

    config = config or SyntheticConfig()
    config.validate()

    genotype_rng = random.Random(config.dataset_seed)
    metadata_rng = random.Random(config.metadata_seed)

    variant_mafs: list[float] = []
    variant_bands: list[str] = []
    for _ in range(config.variants):
        band_name, lower, upper = _sample_maf_band(genotype_rng)
        variant_bands.append(band_name)
        variant_mafs.append(genotype_rng.uniform(lower, upper))

    genotypes: list[tuple[int, ...]] = []
    for _ in range(config.individuals):
        row = tuple(_sample_dosage(genotype_rng, maf) for maf in variant_mafs)
        genotypes.append(row)

    metadata = _generate_metadata(config, metadata_rng, genotypes)

    return SyntheticDataset(
        config=config,
        individual_ids=tuple(f"ind_{idx:06d}" for idx in range(config.individuals)),
        variant_ids=tuple(f"var_{idx:06d}" for idx in range(config.variants)),
        variant_mafs=tuple(variant_mafs),
        variant_bands=tuple(variant_bands),
        genotypes=tuple(genotypes),
        metadata=tuple(metadata),
    )


def select_cohort(dataset: SyntheticDataset, predicate: Mapping[str, str | Sequence[str]]) -> frozenset[int]:
    """Return row indexes selected by an allowed metadata predicate."""

    selected: set[int] = set()
    for idx, metadata in enumerate(dataset.metadata):
        if _metadata_matches(metadata, predicate):
            selected.add(idx)
    return frozenset(selected)


def evaluate_query(dataset: SyntheticDataset, query: GenomicQuery) -> int:
    """Evaluate a constrained aggregate query in plaintext."""

    query.validate()
    cohort = select_cohort(dataset, query.predicate)

    if query.operator == "COHORT_COUNT":
        return len(cohort)

    assert query.variant_id is not None
    variant_idx = dataset.variant_index(query.variant_id)

    if query.operator == "ALLELE_COUNT":
        return sum(dataset.genotypes[row_idx][variant_idx] for row_idx in cohort)

    if query.operator == "CARRIER_COUNT":
        return sum(1 for row_idx in cohort if dataset.genotypes[row_idx][variant_idx] > 0)

    raise ValueError(f"unsupported operator: {query.operator}")


def cohort_hash(cohort: Sequence[int] | frozenset[int]) -> str:
    canonical = ",".join(str(idx) for idx in sorted(cohort))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sample_maf_band(rng: random.Random) -> tuple[str, float, float]:
    draw = rng.random()
    cumulative = 0.0
    for band_name, lower, upper, weight in DEFAULT_MAF_BANDS:
        cumulative += weight
        if draw <= cumulative:
            return band_name, lower, upper
    band_name, lower, upper, _ = DEFAULT_MAF_BANDS[-1]
    return band_name, lower, upper


def _sample_dosage(rng: random.Random, maf: float) -> int:
    homo_ref = (1.0 - maf) ** 2
    hetero = 2.0 * maf * (1.0 - maf)
    draw = rng.random()
    if draw < homo_ref:
        return 0
    if draw < homo_ref + hetero:
        return 1
    return 2


def _generate_metadata(
    config: SyntheticConfig,
    rng: random.Random,
    genotypes: Sequence[Sequence[int]],
) -> list[Mapping[str, str]]:
    age_bins = ("20-29", "30-39", "40-49", "50-59", "60-69", "70-79")
    ancestry_groups = ("A", "B", "C", "D", "E")
    regions = tuple(f"R{idx}" for idx in range(1, 11))
    study_sites = tuple(f"S{idx}" for idx in range(1, 21))
    batches = tuple(f"B{idx}" for idx in range(1, 11))

    marker_count = min(config.marker_variant_count, config.variants)
    metadata_rows: list[Mapping[str, str]] = []

    for row in genotypes:
        marker_carriers = sum(1 for dosage in row[:marker_count] if dosage > 0)
        marker_fraction = marker_carriers / marker_count
        case_probability = _case_probability(config.metadata_correlation, marker_fraction)

        metadata_rows.append(
            {
                "sex": rng.choice(("F", "M")),
                "age_bin": rng.choice(age_bins),
                "ancestry_group": rng.choice(ancestry_groups),
                "region": rng.choice(regions),
                "study_site": rng.choice(study_sites),
                "phenotype_proxy": "case" if rng.random() < case_probability else "control",
                "batch": rng.choice(batches),
            }
        )

    return metadata_rows


def _case_probability(metadata_correlation: str, marker_fraction: float) -> float:
    if metadata_correlation == "independent":
        return 0.5
    if metadata_correlation == "weak":
        return min(0.85, max(0.15, 0.35 + 0.20 * marker_fraction))
    if metadata_correlation == "moderate":
        return min(0.90, max(0.10, 0.25 + 0.50 * marker_fraction))
    raise ValueError(f"unknown metadata_correlation: {metadata_correlation}")


def _metadata_matches(metadata: Mapping[str, str], predicate: Mapping[str, str | Sequence[str]]) -> bool:
    for field_name, expected in predicate.items():
        if field_name not in metadata:
            raise KeyError(f"unknown metadata field: {field_name}")
        observed = metadata[field_name]
        if isinstance(expected, str):
            if observed != expected:
                return False
        else:
            if observed not in set(expected):
                return False
    return True
