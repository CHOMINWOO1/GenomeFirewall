from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.target_count_calibration import run_target_count_calibration


class TargetCountCalibrationTests(unittest.TestCase):
    def test_run_target_count_calibration_writes_matched_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "target_count.json"

            summary = run_target_count_calibration(
                output_path=output_path,
                target_count_values=(1, 2),
                seed_count=1,
                individuals=80,
                variants=20,
                k_min=1,
                difference_min=10,
                symmetric_difference_min=20,
                benign_variant_count=1,
                policy_variant_set="e3",
            )

            self.assertTrue(output_path.exists())
            self.assertEqual(summary["sweep_type"], "target_count")
            self.assertEqual(summary["target_count_values"], [1, 2])
            self.assertEqual([result["target_count"] for result in summary["results"]], [1, 2])
            self.assertEqual(summary["results"][1]["matrix_summary"]["target_count"], 2)
            self.assertTrue(
                all(
                    entry["transcript_path"] is None
                    for result in summary["results"]
                    for entry in result["matrix_summary"]["per_seed"]
                )
            )


if __name__ == "__main__":
    unittest.main()
