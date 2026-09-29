"""Synthetic benign and malicious query workload generators."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Mapping, Sequence

from .synthetic import GenomicQuery, SyntheticDataset


@dataclass(frozen=True)
class WorkloadItem:
    """A generated query plus experiment-facing metadata."""

    query: GenomicQuery
    label: str
    description: str
    attack_enabling_pair_id: str | None = None
    attack_template: str | None = None
    workload_family: str | None = None


@dataclass(frozen=True)
class AttackTarget:
    individual_index: int
    variant_id: str
    carrier: bool
    visible_profile: Mapping[str, str]


def generate_benign_workload(
    dataset: SyntheticDataset,
    workload_seed: int,
    variant_count: int = 3,
) -> tuple[WorkloadItem, ...]:
    """Generate broad, non-targeted aggregate queries for utility testing."""

    rng = random.Random(workload_seed)
    variants = _select_common_variants(dataset, rng, variant_count)
    items: list[WorkloadItem] = []

    for sex in _field_values(dataset, "sex"):
        items.append(
            WorkloadItem(
                query=GenomicQuery(operator="COHORT_COUNT", predicate={"sex": sex}),
                label="benign_cohort_size_by_sex",
                description=f"COHORT_COUNT for sex={sex}",
                workload_family="benign_broad_summary",
            )
        )

    for ancestry in _field_values(dataset, "ancestry_group"):
        items.append(
            WorkloadItem(
                query=GenomicQuery(operator="COHORT_COUNT", predicate={"ancestry_group": ancestry}),
                label="benign_cohort_size_by_ancestry",
                description=f"COHORT_COUNT for ancestry_group={ancestry}",
                workload_family="benign_broad_summary",
            )
        )

    for variant_id in variants:
        for ancestry in _field_values(dataset, "ancestry_group"):
            items.append(
                WorkloadItem(
                    query=GenomicQuery(
                        operator="CARRIER_COUNT",
                        predicate={"ancestry_group": ancestry},
                        variant_id=variant_id,
                    ),
                    label="benign_carrier_count_by_ancestry",
                    description=f"CARRIER_COUNT for {variant_id} in ancestry_group={ancestry}",
                    workload_family="benign_broad_summary",
                )
            )

    return tuple(items)


def generate_benign_near_overlap_workload(
    dataset: SyntheticDataset,
    workload_seed: int,
    slice_field: str = "study_site",
) -> tuple[WorkloadItem, ...]:
    """Generate a legitimate stratum-comparison workload with overlapping cohorts."""

    rng = random.Random(workload_seed)
    variant_id = _select_common_variants(dataset, rng, 1)[0]
    ancestry = rng.choice(_field_values(dataset, "ancestry_group"))
    all_slice_values = _field_values(dataset, slice_field)
    held_out_value = rng.choice(all_slice_values)
    complement_values = tuple(value for value in all_slice_values if value != held_out_value)
    if not complement_values:
        raise ValueError(f"cannot build near-overlap workload with a single {slice_field} value")

    return (
        WorkloadItem(
            query=GenomicQuery(
                operator="CARRIER_COUNT",
                predicate={"ancestry_group": ancestry, slice_field: all_slice_values},
                variant_id=variant_id,
            ),
            label="benign_near_overlap_broad",
            description=f"Legitimate broad stratum comparison for ancestry_group={ancestry}.",
            workload_family="benign_near_overlap",
        ),
        WorkloadItem(
            query=GenomicQuery(
                operator="CARRIER_COUNT",
                predicate={"ancestry_group": ancestry, slice_field: complement_values},
                variant_id=variant_id,
            ),
            label="benign_near_overlap_complement",
            description=f"Legitimate complement stratum comparison excluding {slice_field}={held_out_value}.",
            workload_family="benign_near_overlap",
        ),
    )


def generate_benign_operator_metadata_workload(
    dataset: SyntheticDataset,
    workload_seed: int,
    variant_count: int = 1,
    values_per_field: int = 2,
) -> tuple[WorkloadItem, ...]:
    """Generate benign utility queries spanning operators and metadata axes."""

    if values_per_field <= 0:
        raise ValueError("values_per_field must be positive")

    rng = random.Random(workload_seed)
    variants = _select_common_variants(dataset, rng, variant_count)
    items: list[WorkloadItem] = []

    for field_name in ("age_bin", "batch", "study_site"):
        for field_value in _select_field_values(dataset, field_name, rng, values_per_field):
            items.append(
                WorkloadItem(
                    query=GenomicQuery(operator="COHORT_COUNT", predicate={field_name: field_value}),
                    label=f"benign_cohort_count_by_{field_name}",
                    description=f"COHORT_COUNT for {field_name}={field_value}",
                    workload_family="benign_operator_metadata_summary",
                )
            )

    for variant_id in variants:
        for ancestry in _select_field_values(dataset, "ancestry_group", rng, values_per_field):
            items.append(
                WorkloadItem(
                    query=GenomicQuery(
                        operator="ALLELE_COUNT",
                        predicate={"ancestry_group": ancestry},
                        variant_id=variant_id,
                    ),
                    label="benign_allele_count_by_ancestry",
                    description=f"ALLELE_COUNT for {variant_id} in ancestry_group={ancestry}",
                    workload_family="benign_operator_metadata_summary",
                )
            )

        for region in _select_field_values(dataset, "region", rng, values_per_field):
            items.append(
                WorkloadItem(
                    query=GenomicQuery(
                        operator="CARRIER_COUNT",
                        predicate={"region": region},
                        variant_id=variant_id,
                    ),
                    label="benign_carrier_count_by_region",
                    description=f"CARRIER_COUNT for {variant_id} in region={region}",
                    workload_family="benign_operator_metadata_summary",
                )
            )

    return tuple(items)


def select_attack_target(
    dataset: SyntheticDataset,
    target_seed: int,
    prefer_carrier: bool = True,
) -> AttackTarget:
    """Select a deterministic target individual and variant for attack workloads."""

    rng = random.Random(target_seed)
    candidate_variants = list(range(len(dataset.variant_ids)))
    rng.shuffle(candidate_variants)
    candidate_individuals = list(range(len(dataset.individual_ids)))
    rng.shuffle(candidate_individuals)

    for variant_idx in candidate_variants:
        variant_id = dataset.variant_ids[variant_idx]
        for individual_idx in candidate_individuals:
            carrier = dataset.genotypes[individual_idx][variant_idx] > 0
            if not prefer_carrier or carrier:
                return AttackTarget(
                    individual_index=individual_idx,
                    variant_id=variant_id,
                    carrier=carrier,
                    visible_profile=_visible_profile(dataset.metadata[individual_idx]),
                )

    individual_idx = candidate_individuals[0]
    variant_idx = candidate_variants[0]
    return AttackTarget(
        individual_index=individual_idx,
        variant_id=dataset.variant_ids[variant_idx],
        carrier=dataset.genotypes[individual_idx][variant_idx] > 0,
        visible_profile=_visible_profile(dataset.metadata[individual_idx]),
    )


def generate_differencing_attack_workload(
    dataset: SyntheticDataset,
    target: AttackTarget,
    slice_field: str = "study_site",
) -> tuple[WorkloadItem, ...]:
    """Generate a simple two-query differencing attack template.

    The first query asks for the carrier count over the target's visible broad
    profile. The second asks for the same profile while excluding the target's
    value for `slice_field` by using an explicit IN-list complement.
    """

    if slice_field not in target.visible_profile:
        raise KeyError(f"target visible profile does not include {slice_field}")

    all_slice_values = _field_values(dataset, slice_field)
    target_slice_value = target.visible_profile[slice_field]
    complement_values = tuple(value for value in all_slice_values if value != target_slice_value)
    if not complement_values:
        raise ValueError(f"cannot build differencing workload with a single {slice_field} value")

    broad_predicate = {
        "ancestry_group": target.visible_profile["ancestry_group"],
        slice_field: all_slice_values,
    }
    without_target_slice_predicate = {
        "ancestry_group": target.visible_profile["ancestry_group"],
        slice_field: complement_values,
    }

    pair_id = f"differencing:{target.individual_index}:{target.variant_id}:{slice_field}"
    return (
            WorkloadItem(
                query=GenomicQuery(
                    operator="CARRIER_COUNT",
                    predicate=broad_predicate,
                    variant_id=target.variant_id,
                ),
                label="attack_differencing_broad",
                description="Carrier count for target ancestry across all slice values.",
                attack_enabling_pair_id=pair_id,
                attack_template="differencing",
                workload_family="attack_differencing",
            ),
        WorkloadItem(
            query=GenomicQuery(
                operator="CARRIER_COUNT",
                predicate=without_target_slice_predicate,
                variant_id=target.variant_id,
            ),
            label="attack_differencing_without_target_slice",
            description="Carrier count for target ancestry excluding the target slice value.",
            attack_enabling_pair_id=pair_id,
            attack_template="differencing",
            workload_family="attack_differencing",
        ),
    )


def generate_subgroup_slicing_attack_workload(
    dataset: SyntheticDataset,
    target: AttackTarget,
    slice_fields: Sequence[str] = ("region", "study_site", "batch"),
) -> tuple[WorkloadItem, ...]:
    """Generate a progressive subgroup-slicing attack template.

    The sequence starts from a target-ancestry carrier count and then adds
    target-visible metadata predicates. It is intentionally deterministic so
    ledger effects can be compared across policies.
    """

    predicate: dict[str, str | Sequence[str]] = {
        "ancestry_group": target.visible_profile["ancestry_group"]
    }
    items = [
        WorkloadItem(
            query=GenomicQuery(
                operator="CARRIER_COUNT",
                predicate=dict(predicate),
                variant_id=target.variant_id,
            ),
            label="attack_subgroup_slicing_base",
            description="Carrier count for target ancestry before progressive slicing.",
            attack_template="subgroup_slicing",
            workload_family="attack_subgroup_slicing",
        )
    ]

    for slice_field in slice_fields:
        if slice_field == "ancestry_group":
            continue
        if slice_field not in target.visible_profile:
            raise KeyError(f"target visible profile does not include {slice_field}")
        predicate[slice_field] = target.visible_profile[slice_field]
        items.append(
            WorkloadItem(
                query=GenomicQuery(
                    operator="CARRIER_COUNT",
                    predicate=dict(predicate),
                    variant_id=target.variant_id,
                ),
                label=f"attack_subgroup_slicing_add_{slice_field}",
                description=f"Carrier count after adding target {slice_field}.",
                attack_template="subgroup_slicing",
                workload_family="attack_subgroup_slicing",
            )
        )

    return tuple(items)


def _select_common_variants(dataset: SyntheticDataset, rng: random.Random, variant_count: int) -> tuple[str, ...]:
    if variant_count <= 0:
        raise ValueError("variant_count must be positive")

    common_indexes = [
        idx
        for idx, band in enumerate(dataset.variant_bands)
        if band in {"common", "high_common"}
    ]
    if len(common_indexes) < variant_count:
        common_indexes = list(range(len(dataset.variant_ids)))
    rng.shuffle(common_indexes)
    return tuple(dataset.variant_ids[idx] for idx in common_indexes[:variant_count])


def _field_values(dataset: SyntheticDataset, field_name: str) -> tuple[str, ...]:
    values = sorted({metadata[field_name] for metadata in dataset.metadata})
    return tuple(values)


def _select_field_values(
    dataset: SyntheticDataset,
    field_name: str,
    rng: random.Random,
    value_count: int,
) -> tuple[str, ...]:
    values = list(_field_values(dataset, field_name))
    if len(values) <= value_count:
        return tuple(values)
    rng.shuffle(values)
    return tuple(sorted(values[:value_count]))


def _visible_profile(metadata: Mapping[str, str]) -> Mapping[str, str]:
    return {
        "sex": metadata["sex"],
        "age_bin": metadata["age_bin"],
        "ancestry_group": metadata["ancestry_group"],
        "region": metadata["region"],
        "study_site": metadata["study_site"],
        "phenotype_proxy": metadata["phenotype_proxy"],
        "batch": metadata["batch"],
    }
