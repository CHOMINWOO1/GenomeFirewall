"""Render a secret-redacted A2 provider readiness report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


def build_a2_readiness_rows(
    status_payloads: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for artifact, payload in status_payloads.items():
        rows.append(
            {
                "artifact": artifact,
                "ready": _ready_label(payload),
                "status": str(payload.get("status", "unknown")),
                "provider": _config_value(payload, "provider"),
                "model": _config_value(payload, "model"),
                "base_url": _config_value(payload, "base_url"),
                "api_key_configured": _config_value(payload, "api_key_configured"),
                "network_call_attempted": str(bool(payload.get("network_call_attempted", False))).lower(),
                "next_step": _next_step(payload),
            }
        )
    return rows


def render_a2_readiness_report(rows: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        "# A2 Provider Readiness Report",
        "",
        "| artifact | ready | status | provider | model | base URL | API key configured | network attempted | next step |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            "| "
            f"{row['artifact']} | "
            f"{row['ready']} | "
            f"{row['status']} | "
            f"{row['provider']} | "
            f"{row['model']} | "
            f"{row['base_url']} | "
            f"{row['api_key_configured']} | "
            f"{row['network_call_attempted']} | "
            f"{row['next_step']} |"
        )
    lines.extend(
        [
            "",
            "This report is secret-redacted. It records whether the A2 configured-provider path is ready, blocked by missing configuration, or blocked by the explicit `--allow-network` guard. It is not evidence of a completed real-provider A2 attack unless a row reports `status=completed` and `network attempted=true`.",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status-input", default="outputs/llm_client_status.json")
    parser.add_argument("--local-status-input", default="outputs/llm_client_status_local.json")
    parser.add_argument("--blocked-summary-input", default="outputs/a2_real_llm_blocked_summary.json")
    parser.add_argument("--output", default="docs/experiments/a2_provider_readiness_report.md")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payloads = {
        "default dry-run": _read_payload(args.status_input),
        "local dry-run": _read_payload(args.local_status_input),
        "guarded provider path": _read_payload(args.blocked_summary_input),
    }
    rows = build_a2_readiness_rows(payloads)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_a2_readiness_report(rows), encoding="utf-8")
    print(f"Wrote A2 provider readiness report to {output_path}")
    return 0


def _read_payload(path: str | Path) -> dict[str, Any]:
    input_path = Path(path)
    if not input_path.exists():
        return {"status": "missing_artifact", "network_call_attempted": False}
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {"status": "invalid_artifact"}


def _ready_label(payload: Mapping[str, Any]) -> str:
    if "ready" in payload:
        return str(bool(payload["ready"])).lower()
    dry_run = payload.get("dry_run_status")
    if isinstance(dry_run, Mapping) and "ready" in dry_run:
        return str(bool(dry_run["ready"])).lower()
    return "unknown"


def _config_value(payload: Mapping[str, Any], field_name: str) -> str:
    config = payload.get("config_log")
    if not isinstance(config, Mapping):
        config = payload.get("llm_client_config")
    if not isinstance(config, Mapping):
        return "n/a"
    value = config.get(field_name)
    if value is None:
        return "n/a"
    return str(value)


def _next_step(payload: Mapping[str, Any]) -> str:
    status = str(payload.get("status", "unknown"))
    if status == "completed":
        return "Use this as configured-provider evidence only after reviewing transcript quality."
    if status == "network_not_allowed":
        return "Run again with `--allow-network` only when the configured gateway is intentionally available."
    if status == "ready_no_network_call":
        return "Configuration is ready; use the guarded pilot path for an opt-in provider run."
    if status in {"missing_configuration", "missing_or_invalid_configuration"}:
        missing = payload.get("missing_fields")
        if not missing and isinstance(payload.get("dry_run_status"), Mapping):
            missing = payload["dry_run_status"].get("missing_fields")
        missing_text = ", ".join(str(field) for field in missing) if missing else "provider/model/base URL"
        return f"Configure required fields: {missing_text}."
    if status == "missing_artifact":
        return "Regenerate the dry-run or blocked-path artifact."
    return "Review provider configuration before any A2 claim."


if __name__ == "__main__":
    raise SystemExit(main())
