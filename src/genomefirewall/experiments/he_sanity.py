"""HE execution sanity status and plaintext fallback checks."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from typing import Any, Sequence

from genomefirewall.io import write_json
from genomefirewall.synthetic import GenomicQuery, SyntheticConfig, evaluate_query, generate_synthetic_dataset


HE_BACKEND_CANDIDATES: tuple[str, ...] = ("tenseal", "seal", "Pyfhel", "openfhe", "concrete")
FIRST_BACKEND_TARGET = "tenseal"
FIRST_SCHEME_TARGET = "BFV"


def build_readiness_plan(backend_available: bool) -> dict[str, Any]:
    next_action = (
        "Wire encrypted evaluation for the detected backend and populate encrypted_result/agreement fields."
        if backend_available
        else "Install or vendor a BFV/BGV-capable Python-accessible backend, then rerun this command."
    )
    blocked_reason = None if backend_available else "No candidate HE backend is importable in the current Python environment."
    return {
        "first_backend_candidate": FIRST_BACKEND_TARGET,
        "first_scheme_target": FIRST_SCHEME_TARGET,
        "accepted_scheme_targets": ["BFV", "BGV"],
        "first_circuit_scope": [
            {
                "operator": "COHORT_COUNT",
                "encrypted_operation": "sum encrypted cohort-membership indicator bits",
            },
            {
                "operator": "ALLELE_COUNT",
                "encrypted_operation": "sum encrypted genotype allele counts over an approved cohort mask",
            },
            {
                "operator": "CARRIER_COUNT",
                "encrypted_operation": "sum encrypted carrier indicator bits over an approved cohort mask",
            },
        ],
        "success_criteria": [
            "selected backend import is detected in checked_backends",
            "encrypted_result is populated for every query_result row",
            "agreement is true for every query_result row",
            "encrypted_runtime_ms is populated for every query_result row",
        ],
        "blocked_reason": blocked_reason,
        "next_action": next_action,
    }


def check_he_backends(candidates: Sequence[str] = HE_BACKEND_CANDIDATES) -> dict[str, bool]:
    return {candidate: importlib.util.find_spec(candidate) is not None for candidate in candidates}


def build_plaintext_fallback_summary(
    individuals: int = 32,
    variants: int = 8,
    dataset_seed: int = 9101,
    metadata_seed: int = 9102,
    backend_candidates: Sequence[str] = HE_BACKEND_CANDIDATES,
) -> dict[str, Any]:
    dataset = generate_synthetic_dataset(
        SyntheticConfig(
            individuals=individuals,
            variants=variants,
            dataset_seed=dataset_seed,
            metadata_seed=metadata_seed,
        )
    )
    all_ancestry = sorted({metadata["ancestry_group"] for metadata in dataset.metadata})
    variant_id = dataset.variant_ids[0]
    queries = [
        GenomicQuery(
            operator="COHORT_COUNT",
            predicate={"ancestry_group": all_ancestry},
        ),
        GenomicQuery(
            operator="ALLELE_COUNT",
            predicate={"ancestry_group": all_ancestry},
            variant_id=variant_id,
        ),
        GenomicQuery(
            operator="CARRIER_COUNT",
            predicate={"ancestry_group": all_ancestry},
            variant_id=variant_id,
        ),
    ]
    query_results = [
        {
            "operator": query.operator,
            "variant_id": query.variant_id,
            "predicate_json": query.canonical_predicate_json(),
            "plaintext_result": evaluate_query(dataset, query),
            "encrypted_result": None,
            "encrypted_runtime_ms": None,
            "agreement": None,
        }
        for query in queries
    ]
    backends = check_he_backends(backend_candidates)
    backend_available = any(backends.values())
    return {
        "status": "he_backend_available" if backend_available else "blocked_no_he_backend",
        "he_backend_available": backend_available,
        "checked_backends": backends,
        "fallback": "plaintext_semantics_only",
        "dataset": {
            "individuals": individuals,
            "variants": variants,
            "dataset_seed": dataset_seed,
            "metadata_seed": metadata_seed,
        },
        "query_results": query_results,
        "agreement_scope": (
            "plaintext_only_backend_missing"
            if not backend_available
            else "backend_detected_but_encrypted_execution_not_wired"
        ),
        "readiness_plan": build_readiness_plan(backend_available),
    }


def run_he_sanity_status(output_path: str | Path, **kwargs: Any) -> dict[str, Any]:
    summary = build_plaintext_fallback_summary(**kwargs)
    write_json(output_path, summary)
    return summary


def render_he_sanity_markdown(summary: dict[str, Any]) -> str:
    backend_rows = [
        f"| `{backend}` | {'yes' if available else 'no'} |"
        for backend, available in sorted(summary["checked_backends"].items())
    ]
    query_rows = [
        "| `{operator}` | {plaintext} | {encrypted} | {agreement} | {runtime} | {variant} |".format(
            operator=row["operator"],
            plaintext=row["plaintext_result"],
            encrypted="n/a" if row["encrypted_result"] is None else row["encrypted_result"],
            agreement="n/a" if row["agreement"] is None else str(row["agreement"]).lower(),
            runtime="n/a" if row["encrypted_runtime_ms"] is None else row["encrypted_runtime_ms"],
            variant=row["variant_id"] or "",
        )
        for row in summary["query_results"]
    ]
    plan = summary["readiness_plan"]
    circuit_rows = [
        f"| `{row['operator']}` | {row['encrypted_operation']} |" for row in plan["first_circuit_scope"]
    ]
    criteria = "\n".join(f"- {criterion}" for criterion in plan["success_criteria"])
    blocked_reason = plan["blocked_reason"] or "Not blocked by backend detection; encrypted execution still must be wired."
    return "\n".join(
        [
            "# HE Sanity Status v1",
            "",
            "## Current Status",
            "",
            f"- Status: `{summary['status']}`",
            f"- HE backend available: `{str(summary['he_backend_available']).lower()}`",
            f"- Agreement scope: `{summary['agreement_scope']}`",
            f"- Blocked reason: {blocked_reason}",
            "",
            "## Checked Backends",
            "",
            "| Backend import | Detected |",
            "| --- | --- |",
            *backend_rows,
            "",
            "## First Implementation Target",
            "",
            f"- First backend candidate: `{plan['first_backend_candidate']}`",
            f"- First scheme target: `{plan['first_scheme_target']}`",
            f"- Accepted scheme targets: {', '.join(f'`{scheme}`' for scheme in plan['accepted_scheme_targets'])}",
            f"- Next action: {plan['next_action']}",
            "",
            "| Operator | Encrypted operation target |",
            "| --- | --- |",
            *circuit_rows,
            "",
            "## Success Criteria",
            "",
            criteria,
            "",
            "## Latest Fallback Results",
            "",
            "| Operator | Plaintext Result | Encrypted Result | Agreement | Encrypted Runtime ms | Variant |",
            "| --- | ---: | ---: | --- | ---: | --- |",
            *query_rows,
            "",
            "## Command",
            "",
            "```powershell",
            "$env:PYTHONPATH='src'",
            "& 'C:\\Users\\public-user\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe' -m genomefirewall.experiments.he_sanity `",
            "  --output outputs\\he_sanity_status.json `",
            "  --markdown-output docs\\experiments\\he_sanity_status.md `",
            "  --individuals 32 `",
            "  --variants 8",
            "```",
            "",
        ]
    )


def write_he_sanity_markdown(output_path: str | Path, summary: dict[str, Any]) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_he_sanity_markdown(summary), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="outputs/he_sanity_status.json")
    parser.add_argument("--markdown-output")
    parser.add_argument("--individuals", type=int, default=32)
    parser.add_argument("--variants", type=int, default=8)
    parser.add_argument("--dataset-seed", type=int, default=9101)
    parser.add_argument("--metadata-seed", type=int, default=9102)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = run_he_sanity_status(
        output_path=args.output,
        individuals=args.individuals,
        variants=args.variants,
        dataset_seed=args.dataset_seed,
        metadata_seed=args.metadata_seed,
    )
    if args.markdown_output:
        write_he_sanity_markdown(args.markdown_output, summary)
    print(f"Wrote HE sanity status to {Path(args.output)} ({summary['status']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
