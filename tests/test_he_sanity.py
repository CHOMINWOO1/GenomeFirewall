from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.he_sanity import (
    build_plaintext_fallback_summary,
    main as he_sanity_main,
)


class HeSanityTests(unittest.TestCase):
    def test_plaintext_fallback_reports_blocked_backend(self) -> None:
        summary = build_plaintext_fallback_summary(
            individuals=16,
            variants=4,
            backend_candidates=("definitely_missing_he_backend",),
        )

        self.assertEqual(summary["status"], "blocked_no_he_backend")
        self.assertFalse(summary["he_backend_available"])
        self.assertEqual(len(summary["query_results"]), 3)
        self.assertEqual(
            {entry["operator"] for entry in summary["query_results"]},
            {"COHORT_COUNT", "ALLELE_COUNT", "CARRIER_COUNT"},
        )
        self.assertEqual(summary["readiness_plan"]["first_backend_candidate"], "tenseal")
        self.assertEqual(summary["readiness_plan"]["first_scheme_target"], "BFV")
        self.assertEqual(
            {entry["agreement"] for entry in summary["query_results"]},
            {None},
        )
        self.assertEqual(
            {entry["encrypted_result"] for entry in summary["query_results"]},
            {None},
        )

    def test_he_sanity_cli_writes_status_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "he_sanity.json"
            markdown_path = Path(temp_dir) / "he_sanity.md"

            exit_code = he_sanity_main(
                [
                    "--output",
                    str(output_path),
                    "--markdown-output",
                    str(markdown_path),
                    "--individuals",
                    "16",
                    "--variants",
                    "4",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertIn("checked_backends", payload)
            self.assertEqual(len(payload["query_results"]), 3)
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("HE Sanity Status v1", markdown)
            self.assertIn("First backend candidate: `tenseal`", markdown)


if __name__ == "__main__":
    unittest.main()
