"""Write a secret-redacted dry-run status for the A2 LLM client config."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from genomefirewall.io import write_json
from genomefirewall.llm_attackers import dry_run_llm_client_config


def build_llm_client_status_payload(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    status = dry_run_llm_client_config(env)
    payload = status.to_dict()
    payload["network_call_attempted"] = False
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="outputs/llm_client_status.json")
    parser.add_argument("--provider", help="Override GENOMEFIREWALL_LLM_PROVIDER for dry-run.")
    parser.add_argument("--model", help="Override GENOMEFIREWALL_LLM_MODEL for dry-run.")
    parser.add_argument("--base-url", help="Override GENOMEFIREWALL_LLM_BASE_URL for dry-run.")
    parser.add_argument(
        "--prompt-template-id",
        help="Override GENOMEFIREWALL_LLM_PROMPT_TEMPLATE_ID for dry-run.",
    )
    parser.add_argument("--timeout-seconds", type=int, help="Override request timeout.")
    parser.add_argument(
        "--ignore-process-env",
        action="store_true",
        help="Use only explicit CLI overrides; useful for deterministic dry-run checks.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    env = {} if args.ignore_process_env else dict(os.environ)
    _set_if_present(env, "GENOMEFIREWALL_LLM_PROVIDER", args.provider)
    _set_if_present(env, "GENOMEFIREWALL_LLM_MODEL", args.model)
    _set_if_present(env, "GENOMEFIREWALL_LLM_BASE_URL", args.base_url)
    _set_if_present(env, "GENOMEFIREWALL_LLM_PROMPT_TEMPLATE_ID", args.prompt_template_id)
    if args.timeout_seconds is not None:
        env["GENOMEFIREWALL_LLM_TIMEOUT_SECONDS"] = str(args.timeout_seconds)

    payload = build_llm_client_status_payload(env)
    output_path = Path(args.output)
    write_json(output_path, payload)
    print(f"Wrote LLM client dry-run status to {output_path} ({payload['status']})")
    return 0


def _set_if_present(env: dict[str, str], field_name: str, value: str | None) -> None:
    if value is not None:
        env[field_name] = value


if __name__ == "__main__":
    raise SystemExit(main())
