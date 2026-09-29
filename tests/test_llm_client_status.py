from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.llm_client_status import (
    build_llm_client_status_payload,
    main as llm_client_status_main,
)


class LLMClientStatusTests(unittest.TestCase):
    def test_status_payload_redacts_api_key(self) -> None:
        payload = build_llm_client_status_payload(
            {
                "GENOMEFIREWALL_LLM_PROVIDER": "openai",
                "GENOMEFIREWALL_LLM_MODEL": "gpt-test",
                "GENOMEFIREWALL_LLM_API_KEY": "secret-token",
            }
        )

        self.assertTrue(payload["ready"])
        self.assertFalse(payload["network_call_attempted"])
        self.assertTrue(payload["config_log"]["api_key_configured"])
        self.assertNotIn("secret-token", json.dumps(payload))

    def test_cli_writes_missing_key_status_without_process_env(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "llm_status.json"

            exit_code = llm_client_status_main(
                [
                    "--output",
                    str(output_path),
                    "--ignore-process-env",
                    "--provider",
                    "openai",
                    "--model",
                    "gpt-test",
                ]
            )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertFalse(payload["ready"])
            self.assertEqual(payload["status"], "missing_configuration")
            self.assertIn("GENOMEFIREWALL_LLM_API_KEY", payload["missing_fields"])
            self.assertNotIn("api_key", payload["config_log"])

    def test_cli_writes_local_ready_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "llm_status.json"

            exit_code = llm_client_status_main(
                [
                    "--output",
                    str(output_path),
                    "--ignore-process-env",
                    "--provider",
                    "local",
                    "--model",
                    "local-json-model",
                ]
            )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertTrue(payload["ready"])
            self.assertEqual(payload["status"], "ready_no_network_call")


if __name__ == "__main__":
    unittest.main()
