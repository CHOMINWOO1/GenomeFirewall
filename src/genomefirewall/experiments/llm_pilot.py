"""Run a network-free fake-provider A2 LLM adaptive pilot artifact."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from genomefirewall.io import write_json, write_jsonl
from genomefirewall.llm_attackers import (
    ClientBackedLLMPlanner,
    FakeLLMJSONClient,
    LLMClientConfig,
    LLMClientDryRunStatus,
    LLMTransportFunction,
    OpenAICompatibleHTTPTransport,
    OpenAICompatibleLLMJSONClient,
    dry_run_llm_client_config,
    load_llm_client_config_from_env,
    run_llm_adaptive_attack,
)
from genomefirewall.metrics import summarize_transcript
from genomefirewall.policies import MinimumCohortPolicy, StatefulPrivacyLedgerPolicy
from genomefirewall.synthetic import SyntheticConfig, generate_synthetic_dataset
from genomefirewall.workloads import WorkloadItem, generate_differencing_attack_workload, select_attack_target


@dataclass(frozen=True)
class FakeLLMPilotResult:
    output_path: Path
    summary_output_path: Path
    row_count: int
    summary: dict[str, Any]


@dataclass(frozen=True)
class OpenAICompatibleLLMPilotResult:
    output_path: Path
    summary_output_path: Path
    row_count: int
    status: str
    summary: dict[str, Any]


def run_fake_llm_pilot_experiment(
    output_path: str | Path,
    summary_output_path: str | Path,
    individuals: int = 80,
    variants: int = 20,
    dataset_seed: int = 3101,
    metadata_seed: int = 3102,
    workload_seed: int = 3103,
    attacker_seed: int = 3104,
    k_min: int = 1,
    difference_min: int = 1000,
    symmetric_difference_min: int = 20,
) -> FakeLLMPilotResult:
    dataset = generate_synthetic_dataset(
        SyntheticConfig(
            individuals=individuals,
            variants=variants,
            dataset_seed=dataset_seed,
            metadata_seed=metadata_seed,
        )
    )
    target = select_attack_target(dataset, target_seed=attacker_seed)
    workload = generate_differencing_attack_workload(dataset, target)
    responses = tuple(_payload_from_workload_item(item) for item in workload)
    config = LLMClientConfig(provider="fake", model="fake-json-model")

    minimum_result = run_llm_adaptive_attack(
        dataset=dataset,
        target=target,
        policy=MinimumCohortPolicy(k_min=k_min),
        run_id="a2-fake-minimum-cohort",
        workload_seed=workload_seed,
        attacker_seed=attacker_seed,
        planner=ClientBackedLLMPlanner(
            client=FakeLLMJSONClient(responses),
            config=config,
        ),
    )
    ledger_result = run_llm_adaptive_attack(
        dataset=dataset,
        target=target,
        policy=StatefulPrivacyLedgerPolicy(
            k_min=k_min,
            difference_min=difference_min,
            symmetric_difference_min=symmetric_difference_min,
        ),
        run_id="a2-fake-ledger",
        workload_seed=workload_seed,
        attacker_seed=attacker_seed,
        planner=ClientBackedLLMPlanner(
            client=FakeLLMJSONClient(responses),
            config=config,
        ),
    )

    rows = [record.to_dict() for record in (*minimum_result.transcript, *ledger_result.transcript)]
    row_count = write_jsonl(output_path, rows)
    summary = summarize_transcript(rows).to_dict()
    summary["llm_client_config"] = config.to_log_dict()
    summary["network_call_attempted"] = False
    write_json(summary_output_path, summary)

    return FakeLLMPilotResult(
        output_path=Path(output_path),
        summary_output_path=Path(summary_output_path),
        row_count=row_count,
        summary=summary,
    )


def run_openai_compatible_llm_pilot_experiment(
    output_path: str | Path,
    summary_output_path: str | Path,
    allow_network: bool = False,
    env: Mapping[str, str] | None = None,
    transport: LLMTransportFunction | None = None,
    individuals: int = 80,
    variants: int = 20,
    dataset_seed: int = 3101,
    metadata_seed: int = 3102,
    workload_seed: int = 3103,
    attacker_seed: int = 3104,
    k_min: int = 1,
    difference_min: int = 1000,
    symmetric_difference_min: int = 20,
) -> OpenAICompatibleLLMPilotResult:
    dry_run_status = dry_run_llm_client_config(env)
    if not dry_run_status.ready:
        return _write_blocked_openai_compatible_result(
            output_path=output_path,
            summary_output_path=summary_output_path,
            status="missing_or_invalid_configuration",
            dry_run_status=dry_run_status,
        )

    if not allow_network:
        return _write_blocked_openai_compatible_result(
            output_path=output_path,
            summary_output_path=summary_output_path,
            status="network_not_allowed",
            dry_run_status=dry_run_status,
        )

    config = load_llm_client_config_from_env(env)
    if config.base_url is None:
        return _write_blocked_openai_compatible_result(
            output_path=output_path,
            summary_output_path=summary_output_path,
            status="missing_base_url",
            dry_run_status=dry_run_status,
        )

    client = OpenAICompatibleLLMJSONClient(
        transport=transport or OpenAICompatibleHTTPTransport(),
    )
    planner = ClientBackedLLMPlanner(client=client, config=config)
    dataset = generate_synthetic_dataset(
        SyntheticConfig(
            individuals=individuals,
            variants=variants,
            dataset_seed=dataset_seed,
            metadata_seed=metadata_seed,
        )
    )
    target = select_attack_target(dataset, target_seed=attacker_seed)

    minimum_result = run_llm_adaptive_attack(
        dataset=dataset,
        target=target,
        policy=MinimumCohortPolicy(k_min=k_min),
        run_id="a2-openai-compatible-minimum-cohort",
        workload_seed=workload_seed,
        attacker_seed=attacker_seed,
        planner=planner,
    )
    ledger_result = run_llm_adaptive_attack(
        dataset=dataset,
        target=target,
        policy=StatefulPrivacyLedgerPolicy(
            k_min=k_min,
            difference_min=difference_min,
            symmetric_difference_min=symmetric_difference_min,
        ),
        run_id="a2-openai-compatible-ledger",
        workload_seed=workload_seed,
        attacker_seed=attacker_seed,
        planner=planner,
    )

    rows = [record.to_dict() for record in (*minimum_result.transcript, *ledger_result.transcript)]
    row_count = write_jsonl(output_path, rows)
    summary = summarize_transcript(rows).to_dict()
    summary["planner_mode"] = "openai-compatible"
    summary["status"] = "completed"
    summary["llm_client_config"] = config.to_log_dict()
    summary["dry_run_status"] = dry_run_status.to_dict()
    summary["network_call_attempted"] = True
    write_json(summary_output_path, summary)

    return OpenAICompatibleLLMPilotResult(
        output_path=Path(output_path),
        summary_output_path=Path(summary_output_path),
        row_count=row_count,
        status="completed",
        summary=summary,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--planner-mode",
        choices=("fake", "openai-compatible"),
        default="fake",
        help="Select fake local planner or opt-in OpenAI-compatible provider path.",
    )
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Permit the OpenAI-compatible provider path to make HTTP requests.",
    )
    parser.add_argument("--output", default="outputs/a2_fake_llm_transcript.jsonl")
    parser.add_argument("--summary-output", default="outputs/a2_fake_llm_summary.json")
    parser.add_argument("--individuals", type=int, default=80)
    parser.add_argument("--variants", type=int, default=20)
    parser.add_argument("--dataset-seed", type=int, default=3101)
    parser.add_argument("--metadata-seed", type=int, default=3102)
    parser.add_argument("--workload-seed", type=int, default=3103)
    parser.add_argument("--attacker-seed", type=int, default=3104)
    parser.add_argument("--k-min", type=int, default=1)
    parser.add_argument("--difference-min", type=int, default=1000)
    parser.add_argument("--symmetric-difference-min", type=int, default=20)
    parser.add_argument("--provider", help="Override GENOMEFIREWALL_LLM_PROVIDER.")
    parser.add_argument("--model", help="Override GENOMEFIREWALL_LLM_MODEL.")
    parser.add_argument("--base-url", help="Override GENOMEFIREWALL_LLM_BASE_URL.")
    parser.add_argument(
        "--prompt-template-id",
        help="Override GENOMEFIREWALL_LLM_PROMPT_TEMPLATE_ID.",
    )
    parser.add_argument("--timeout-seconds", type=int, help="Override request timeout.")
    parser.add_argument(
        "--ignore-process-env",
        action="store_true",
        help="Use only explicit CLI overrides for provider configuration.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.planner_mode == "openai-compatible":
        env = _build_llm_env_from_args(args)
        result = run_openai_compatible_llm_pilot_experiment(
            output_path=args.output,
            summary_output_path=args.summary_output,
            allow_network=args.allow_network,
            env=env,
            individuals=args.individuals,
            variants=args.variants,
            dataset_seed=args.dataset_seed,
            metadata_seed=args.metadata_seed,
            workload_seed=args.workload_seed,
            attacker_seed=args.attacker_seed,
            k_min=args.k_min,
            difference_min=args.difference_min,
            symmetric_difference_min=args.symmetric_difference_min,
        )
        print(
            "Wrote "
            f"{result.status} A2 OpenAI-compatible summary to {result.summary_output_path}"
        )
        return 0

    result = run_fake_llm_pilot_experiment(
        output_path=args.output,
        summary_output_path=args.summary_output,
        individuals=args.individuals,
        variants=args.variants,
        dataset_seed=args.dataset_seed,
        metadata_seed=args.metadata_seed,
        workload_seed=args.workload_seed,
        attacker_seed=args.attacker_seed,
        k_min=args.k_min,
        difference_min=args.difference_min,
        symmetric_difference_min=args.symmetric_difference_min,
    )
    print(f"Wrote {result.row_count} fake A2 LLM rows to {result.output_path}")
    return 0


def _write_blocked_openai_compatible_result(
    output_path: str | Path,
    summary_output_path: str | Path,
    status: str,
    dry_run_status: LLMClientDryRunStatus,
) -> OpenAICompatibleLLMPilotResult:
    row_count = write_jsonl(output_path, [])
    summary = {
        "planner_mode": "openai-compatible",
        "status": status,
        "row_count": row_count,
        "llm_client_config": dry_run_status.config_log,
        "dry_run_status": dry_run_status.to_dict(),
        "network_call_attempted": False,
    }
    write_json(summary_output_path, summary)
    return OpenAICompatibleLLMPilotResult(
        output_path=Path(output_path),
        summary_output_path=Path(summary_output_path),
        row_count=row_count,
        status=status,
        summary=summary,
    )


def _build_llm_env_from_args(args: argparse.Namespace) -> dict[str, str]:
    env = {} if args.ignore_process_env else dict(os.environ)
    _set_if_present(env, "GENOMEFIREWALL_LLM_PROVIDER", args.provider)
    _set_if_present(env, "GENOMEFIREWALL_LLM_MODEL", args.model)
    _set_if_present(env, "GENOMEFIREWALL_LLM_BASE_URL", args.base_url)
    _set_if_present(env, "GENOMEFIREWALL_LLM_PROMPT_TEMPLATE_ID", args.prompt_template_id)
    if args.timeout_seconds is not None:
        env["GENOMEFIREWALL_LLM_TIMEOUT_SECONDS"] = str(args.timeout_seconds)
    return env


def _set_if_present(env: dict[str, str], field_name: str, value: str | None) -> None:
    if value is not None:
        env[field_name] = value


def _payload_from_workload_item(item: WorkloadItem) -> dict[str, Any]:
    return {
        "operator": item.query.operator,
        "predicate": item.query.predicate,
        "variant_id": item.query.variant_id,
        "label": item.label,
        "description": item.description,
        "attack_enabling_pair_id": item.attack_enabling_pair_id,
        "attack_template": item.attack_template,
        "workload_family": item.workload_family,
    }


if __name__ == "__main__":
    raise SystemExit(main())
