from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.a2_readiness_report import (
    build_a2_readiness_rows,
    main as a2_readiness_report_main,
    render_a2_readiness_report,
)


class A2ReadinessReportTests(unittest.TestCase):
    def test_render_a2_readiness_report_redacts_secret_values(self) -> None:
        rows = build_a2_readiness_rows(
            {
                "hosted dry-run": {
                    "ready": True,
                    "status": "ready_no_network_call",
                    "network_call_attempted": False,
                    "config_log": {
                        "provider": "openai",
                        "model": "gpt-test",
                        "api_key_configured": True,
                    },
                },
                "blocked path": {
                    "status": "network_not_allowed",
                    "network_call_attempted": False,
                    "llm_client_config": {
                        "provider": "local",
                        "model": "local-json-model",
                        "api_key_configured": False,
                    },
                    "dry_run_status": {"ready": True},
                },
            }
        )

        report = render_a2_readiness_report(rows)

        self.assertIn("# A2 Provider Readiness Report", report)
        self.assertIn("hosted dry-run", report)
        self.assertIn("network_not_allowed", report)
        self.assertIn("`--allow-network`", report)
        self.assertNotIn("secret-token", report)

    def test_cli_writes_report_from_status_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            default_status = root / "missing.json"
            local_status = root / "local.json"
            blocked_summary = root / "blocked.json"
            output_path = root / "readiness.md"
            default_status.write_text(
                json.dumps(
                    {
                        "ready": False,
                        "status": "missing_configuration",
                        "missing_fields": ["GENOMEFIREWALL_LLM_PROVIDER"],
                        "network_call_attempted": False,
                    }
                ),
                encoding="utf-8",
            )
            local_status.write_text(
                json.dumps(
                    {
                        "ready": True,
                        "status": "ready_no_network_call",
                        "network_call_attempted": False,
                        "config_log": {
                            "provider": "local",
                            "model": "local-json-model",
                        },
                    }
                ),
                encoding="utf-8",
            )
            blocked_summary.write_text(
                json.dumps(
                    {
                        "status": "network_not_allowed",
                        "network_call_attempted": False,
                        "llm_client_config": {
                            "provider": "local",
                            "model": "local-json-model",
                        },
                        "dry_run_status": {"ready": True},
                    }
                ),
                encoding="utf-8",
            )

            exit_code = a2_readiness_report_main(
                [
                    "--status-input",
                    str(default_status),
                    "--local-status-input",
                    str(local_status),
                    "--blocked-summary-input",
                    str(blocked_summary),
                    "--output",
                    str(output_path),
                ]
            )

            content = output_path.read_text(encoding="utf-8")
            self.assertEqual(exit_code, 0)
            self.assertIn("missing_configuration", content)
            self.assertIn("ready_no_network_call", content)
            self.assertIn("network_not_allowed", content)


if __name__ == "__main__":
    unittest.main()
