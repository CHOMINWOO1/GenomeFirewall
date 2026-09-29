from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.llm_pilot import (
    main as llm_pilot_main,
    run_fake_llm_pilot_experiment,
    run_openai_compatible_llm_pilot_experiment,
)


class FakeLLMPilotExperimentTests(unittest.TestCase):
    def test_run_fake_llm_pilot_writes_transcript_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "a2_fake.jsonl"
            summary_path = Path(temp_dir) / "a2_fake_summary.json"

            result = run_fake_llm_pilot_experiment(
                output_path=output_path,
                summary_output_path=summary_path,
                individuals=80,
                variants=20,
                k_min=1,
                difference_min=1000,
            )

            rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(result.row_count, 4)
            self.assertEqual(len(rows), 4)
            self.assertTrue(all(row["attacker_type"] == "llm_adaptive" for row in rows))
            self.assertEqual(summary["attacker_type_counts"]["llm_adaptive"], 4)
            self.assertEqual(summary["llm_client_config"]["provider"], "fake")
            self.assertFalse(summary["network_call_attempted"])
            self.assertNotIn("api_key", summary["llm_client_config"])

    def test_fake_llm_pilot_cli_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "a2_fake.jsonl"
            summary_path = Path(temp_dir) / "a2_fake_summary.json"

            exit_code = llm_pilot_main(
                [
                    "--output",
                    str(output_path),
                    "--summary-output",
                    str(summary_path),
                    "--individuals",
                    "80",
                    "--variants",
                    "20",
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())
            self.assertTrue(summary_path.exists())

    def test_openai_compatible_cli_blocks_without_allow_network(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "a2_real.jsonl"
            summary_path = Path(temp_dir) / "a2_real_summary.json"

            exit_code = llm_pilot_main(
                [
                    "--planner-mode",
                    "openai-compatible",
                    "--output",
                    str(output_path),
                    "--summary-output",
                    str(summary_path),
                    "--ignore-process-env",
                    "--provider",
                    "local",
                    "--model",
                    "local-json-model",
                    "--base-url",
                    "http://localhost:11434/v1",
                ]
            )

            rows = output_path.read_text(encoding="utf-8").splitlines()
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertEqual(rows, [])
            self.assertEqual(summary["status"], "network_not_allowed")
            self.assertFalse(summary["network_call_attempted"])
            self.assertEqual(summary["llm_client_config"]["provider"], "local")

    def test_openai_compatible_run_uses_injected_transport_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "a2_real.jsonl"
            summary_path = Path(temp_dir) / "a2_real_summary.json"
            captured_payloads = []

            def transport(payload, config):
                captured_payloads.append(payload)
                return {"choices": [{"message": {"content": "null"}}]}

            result = run_openai_compatible_llm_pilot_experiment(
                output_path=output_path,
                summary_output_path=summary_path,
                allow_network=True,
                env={
                    "GENOMEFIREWALL_LLM_PROVIDER": "openai",
                    "GENOMEFIREWALL_LLM_MODEL": "gpt-test",
                    "GENOMEFIREWALL_LLM_API_KEY": "secret-token",
                    "GENOMEFIREWALL_LLM_BASE_URL": "https://api.example.test/v1",
                },
                transport=transport,
            )

            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.row_count, 0)
            self.assertEqual(len(captured_payloads), 2)
            self.assertTrue(summary["network_call_attempted"])
            self.assertTrue(summary["llm_client_config"]["api_key_configured"])
            self.assertNotIn("secret-token", str(summary))
            self.assertNotIn("secret-token", str(captured_payloads))


if __name__ == "__main__":
    unittest.main()
