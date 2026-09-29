from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.llm_matrix import (
    main as llm_matrix_main,
    run_fake_llm_pilot_matrix,
)


class FakeLLMMatrixExperimentTests(unittest.TestCase):
    def test_run_fake_llm_pilot_matrix_writes_matched_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "a2_matrix.json"
            transcript_dir = Path(temp_dir) / "transcripts"

            result = run_fake_llm_pilot_matrix(
                output_path=output_path,
                transcript_dir=transcript_dir,
                seed_count=2,
                individuals=80,
                variants=20,
                k_min=1,
                difference_min=1000,
            )

            summary = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(result.seed_count, 2)
            self.assertEqual(summary["seed_count"], 2)
            self.assertEqual(summary["policy_variant_set"], "core")
            self.assertEqual(summary["target_count"], 1)
            self.assertEqual(summary["planner_mode"], "fake")
            self.assertFalse(summary["network_call_attempted"])
            self.assertEqual(summary["attack_breakdown_by_type"]["llm_adaptive"]["run_count"], 4)
            self.assertEqual(len(summary["per_seed"]), 2)
            self.assertTrue((transcript_dir / "a2_fake_seed_000.jsonl").exists())

    def test_llm_matrix_cli_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "a2_matrix.json"
            transcript_dir = Path(temp_dir) / "transcripts"

            exit_code = llm_matrix_main(
                [
                    "--output",
                    str(output_path),
                    "--transcript-dir",
                    str(transcript_dir),
                    "--seed-count",
                    "2",
                    "--individuals",
                    "80",
                    "--variants",
                    "20",
                    "--k-min",
                    "1",
                    "--difference-min",
                    "1000",
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())


if __name__ == "__main__":
    unittest.main()
