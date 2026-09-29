from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from genomefirewall.experiments.report import (
    main as report_main,
    render_difference_threshold_report,
    render_policy_delta_matrix_report,
    write_attack_template_breakdown_csv,
    write_attacker_breakdown_csv,
    write_benign_family_breakdown_csv,
    write_policy_delta_csv,
    write_sweep_csv,
)


class ExperimentReportTests(unittest.TestCase):
    def test_render_difference_threshold_report_contains_table(self) -> None:
        report = render_difference_threshold_report(_sample_sweep_summary())

        self.assertIn("# Difference Threshold Sweep Report", report)
        self.assertIn("| difference_min | seeds | attack pairs |", report)
        self.assertIn(
            "| 10 | 3 | 6 | 3 | 3 | 0.5000 | 3 / 3 | 1.0000 | 6 | 3 | 3 | 1.0000 | 0.1000 | 0.1200 | marginal_utility | 0 | 0.9500 |",
            report,
        )
        self.assertIn("## Attacker Type Breakdown", report)
        self.assertIn("## Confidence Intervals", report)
        self.assertIn("| 10 | [0.4000, 0.6000] | [0.4000, 0.6000] | [0.9000, 1.0000] | 0.1200 | [0.9000, 1.0000] |", report)
        self.assertIn("| 10 | non_adaptive | 3 | 3 | 0 | 3 / 3 | 1.0000 | 3 | 3 | 0 |", report)
        self.assertIn("| 10 | scripted_adaptive | 3 | 0 | 3 | 0 / 0 | 0.0000 | 3 | 0 | 3 |", report)
        self.assertIn("## Attack Template Breakdown", report)
        self.assertIn("| 10 | differencing | 6 | 3 | 3 | 6 | 3 | 6 | 3 |", report)
        self.assertIn("## Policy Delta Breakdown", report)
        self.assertIn(
            "| 10 | e3 | minimum_cohort | stateful_privacy_ledger | -3 | 3 | -3 | 3 | 0.1000 | 0.1200 | marginal_utility | 0.9000 | 3 | 3 |",
            report,
        )
        self.assertIn(
            "| 10 | e3 | minimum_cohort | stateful_privacy_ledger_difference_only | -2 | 2 | -2 | 2 | 0.0500 | 0.0500 | primary_acceptable_utility | 0.9500 | 3 | 2 |",
            report,
        )
        self.assertIn("docs/experiments/utility_threshold.md", report)
        self.assertIn("## Benign Utility Family Breakdown", report)
        self.assertIn("| 10 | minimum_cohort | benign_broad_summary | 10 | 10 | 0 | 1.0000 |", report)
        self.assertIn("| 10 | stateful_privacy_ledger | benign_near_overlap | 2 | 1 | 1 | 0.5000 |", report)
        self.assertIn("fixed non-adaptive differencing baseline", report)

    def test_render_symmetric_threshold_report_uses_symmetric_label(self) -> None:
        summary = _sample_sweep_summary()
        summary["sweep_type"] = "symmetric_difference_min"
        summary["symmetric_difference_min_values"] = [10]
        summary["results"][0]["symmetric_difference_min"] = 10
        del summary["results"][0]["difference_min"]

        report = render_difference_threshold_report(summary)

        self.assertIn("# Symmetric Difference Threshold Sweep Report", report)
        self.assertIn("| symmetric_difference_min | seeds | attack pairs |", report)

    def test_render_target_count_report_uses_target_count_axis(self) -> None:
        summary = _sample_sweep_summary()
        summary["sweep_type"] = "target_count"
        summary["target_count_values"] = [2]
        summary["results"][0]["target_count"] = 2
        del summary["results"][0]["difference_min"]

        report = render_difference_threshold_report(summary)

        self.assertIn("# Target Count Calibration Report", report)
        self.assertIn("| target_count | seeds | attack pairs |", report)
        self.assertIn("| 2 | 3 | 6 | 3 | 3 |", report)

    def test_report_cli_writes_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "sweep.json"
            output_path = Path(temp_dir) / "report.md"
            csv_path = Path(temp_dir) / "report.csv"
            attacker_csv_path = Path(temp_dir) / "attacker_report.csv"
            attack_template_csv_path = Path(temp_dir) / "attack_template_report.csv"
            policy_delta_csv_path = Path(temp_dir) / "policy_delta_report.csv"
            benign_family_csv_path = Path(temp_dir) / "benign_family_report.csv"
            input_path.write_text(json.dumps(_sample_sweep_summary()), encoding="utf-8")

            exit_code = report_main(
                [
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--csv-output",
                    str(csv_path),
                    "--attacker-csv-output",
                    str(attacker_csv_path),
                    "--attack-template-csv-output",
                    str(attack_template_csv_path),
                    "--policy-delta-csv-output",
                    str(policy_delta_csv_path),
                    "--benign-family-csv-output",
                    str(benign_family_csv_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())
            self.assertIn("ledger-blocked runs", output_path.read_text(encoding="utf-8"))
            self.assertTrue(csv_path.exists())
            self.assertTrue(attacker_csv_path.exists())
            self.assertTrue(attack_template_csv_path.exists())
            self.assertTrue(policy_delta_csv_path.exists())
            self.assertTrue(benign_family_csv_path.exists())

    def test_write_sweep_csv_writes_table_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "sweep.csv"

            write_sweep_csv(_sample_sweep_summary(), csv_path)

            content = csv_path.read_text(encoding="utf-8")
            self.assertIn("difference_min,seed_count,attack_pair_count", content)
            self.assertIn("benign_utility_loss", content)
            self.assertIn("pair_block_rate_ci_lower,pair_block_rate_ci_upper", content)
            self.assertIn("10,3,6,3,3,0.5000,3,3,1.0000", content)
        self.assertIn("1.0000,0.1000,0.1200,marginal_utility,false,0,0.9500", content)

    def test_write_attacker_breakdown_csv_writes_long_form_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "attacker_breakdown.csv"

            write_attacker_breakdown_csv(_sample_sweep_summary(), csv_path)

            content = csv_path.read_text(encoding="utf-8")
            self.assertIn("difference_min,attacker_type,seed_count,attack_row_count", content)
            self.assertIn("10,non_adaptive,3,3,3,0,3,3,0,0.0000,3,3,1.0000,3,3,0,0.0000", content)
            self.assertIn("10,scripted_adaptive,3,3,0,3,3,0,3,1.0000,0,0,0.0000,3,0,3,1.0000", content)

    def test_write_attack_template_breakdown_csv_writes_long_form_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "attack_template_breakdown.csv"

            write_attack_template_breakdown_csv(_sample_sweep_summary(), csv_path)

            content = csv_path.read_text(encoding="utf-8")
            self.assertIn("difference_min,attack_template,seed_count,attack_row_count", content)
            self.assertIn("10,differencing,3,6,3,3,6,3,3,0.5000,3,3,1.0000,6,3,3,0.5000", content)

    def test_write_policy_delta_csv_writes_long_form_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "policy_delta.csv"

            write_policy_delta_csv(_sample_sweep_summary(), csv_path)

            content = csv_path.read_text(encoding="utf-8")
            self.assertIn("threshold_name,threshold_value,seed_count,policy_variant_set", content)
            self.assertIn("difference_min,10,3,e3,minimum_cohort,stateful_privacy_ledger,-3,3,-3,3,1.0,0.9,0.1,0.12,marginal_utility,False,10,1", content)
            self.assertIn(
                "difference_min,10,3,e3,minimum_cohort,stateful_privacy_ledger_difference_only,-2,2,-2,2,1.0,0.95,0.05,0.05,primary_acceptable_utility,True,10,1",
                content,
            )

    def test_write_benign_family_breakdown_csv_writes_long_form_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "benign_family.csv"

            write_benign_family_breakdown_csv(_sample_sweep_summary(), csv_path)

            content = csv_path.read_text(encoding="utf-8")
            self.assertIn(
                "threshold_name,threshold_value,seed_count,policy_variant_set,policy,workload_family,benign_rows,accepted_rows,rejected_rows,acceptance_rate",
                content,
            )
            self.assertIn(
                "difference_min,10,3,e3,minimum_cohort,benign_broad_summary,10,10,0,1.0",
                content,
            )
            self.assertIn(
                "difference_min,10,3,e3,stateful_privacy_ledger,benign_near_overlap,2,1,1,0.5",
                content,
            )

    def test_render_policy_delta_matrix_report_handles_matrix_summary(self) -> None:
        matrix_summary = _sample_sweep_summary()["results"][0]["matrix_summary"]

        report = render_policy_delta_matrix_report(matrix_summary)

        self.assertIn("# Policy Delta Matrix Report", report)
        self.assertIn("policy variant set: e3", report)
        self.assertIn(
            "| minimum_cohort | stateful_privacy_ledger | -3 | 3 | -3 | 3 | 0.1000 | 0.1200 | marginal_utility | 0.9000 | 3 | 3 |",
            report,
        )
        self.assertIn("## Benign Utility Family Breakdown", report)


def _sample_sweep_summary() -> dict[str, object]:
    return {
        "sweep_type": "difference_min",
        "difference_min_values": [10],
        "seed_count": 3,
        "results": [
            {
                "difference_min": 10,
                "matrix_summary": {
                    "seed_count": 3,
                    "policy_variant_set": "e3",
                    "attack_run_count": 6,
                    "attack_enabling_run_count": 3,
                    "ledger_blocked_attack_run_count": 3,
                    "attack_pair_count": 6,
                    "attack_enabling_pair_count": 3,
                    "ledger_blocked_attack_pair_count": 3,
                    "attack_guess_count": 3,
                    "attack_correct_guess_count": 3,
                    "attack_guess_success_rate": 1.0,
                    "confidence_intervals_95": {
                        "attack_pair_block_rate": {
                            "mean": 0.5,
                            "lower": 0.4,
                            "upper": 0.6,
                        },
                        "attack_run_block_rate": {
                            "mean": 0.5,
                            "lower": 0.4,
                            "upper": 0.6,
                        },
                        "benign_acceptance_rate": {
                            "mean": 1.0,
                            "lower": 0.9,
                            "upper": 1.0,
                        },
                        "mean_acceptance_rate": {
                            "mean": 0.95,
                            "lower": 0.9,
                            "upper": 1.0,
                        },
                    },
                    "attack_breakdown_by_type": {
                        "non_adaptive": {
                            "rows": 3,
                            "accepted_rows": 3,
                            "rejected_rows": 0,
                            "run_count": 3,
                            "attack_enabling_run_count": 3,
                            "ledger_blocked_run_count": 0,
                            "pair_count": 3,
                            "attack_enabling_pair_count": 3,
                            "ledger_blocked_pair_count": 0,
                            "guess_count": 3,
                            "correct_guess_count": 3,
                            "guess_success_rate": 1.0,
                        },
                        "scripted_adaptive": {
                            "rows": 3,
                            "accepted_rows": 0,
                            "rejected_rows": 3,
                            "run_count": 3,
                            "attack_enabling_run_count": 0,
                            "ledger_blocked_run_count": 3,
                            "pair_count": 3,
                            "attack_enabling_pair_count": 0,
                            "ledger_blocked_pair_count": 3,
                            "guess_count": 0,
                            "correct_guess_count": 0,
                            "guess_success_rate": 0.0,
                        },
                    },
                    "attack_breakdown_by_template": {
                        "differencing": {
                            "rows": 6,
                            "accepted_rows": 3,
                            "rejected_rows": 3,
                            "run_count": 6,
                            "attack_enabling_run_count": 3,
                            "ledger_blocked_run_count": 3,
                            "pair_count": 6,
                            "attack_enabling_pair_count": 3,
                            "ledger_blocked_pair_count": 3,
                            "guess_count": 3,
                            "correct_guess_count": 3,
                            "guess_success_rate": 1.0,
                        }
                    },
                    "attack_breakdown_by_policy": {
                        "minimum_cohort": {
                            "rows": 3,
                            "accepted_rows": 3,
                            "rejected_rows": 0,
                            "run_count": 3,
                            "attack_enabling_run_count": 3,
                            "ledger_blocked_run_count": 0,
                            "pair_count": 3,
                            "attack_enabling_pair_count": 3,
                            "ledger_blocked_pair_count": 0,
                            "guess_count": 3,
                            "correct_guess_count": 3,
                            "guess_success_rate": 1.0,
                        },
                        "stateful_privacy_ledger": {
                            "rows": 3,
                            "accepted_rows": 0,
                            "rejected_rows": 3,
                            "run_count": 3,
                            "attack_enabling_run_count": 0,
                            "ledger_blocked_run_count": 3,
                            "pair_count": 3,
                            "attack_enabling_pair_count": 0,
                            "ledger_blocked_pair_count": 3,
                            "guess_count": 0,
                            "correct_guess_count": 0,
                            "guess_success_rate": 0.0,
                        },
                        "stateful_privacy_ledger_difference_only": {
                            "rows": 3,
                            "accepted_rows": 1,
                            "rejected_rows": 2,
                            "run_count": 3,
                            "attack_enabling_run_count": 1,
                            "ledger_blocked_run_count": 2,
                            "pair_count": 3,
                            "attack_enabling_pair_count": 1,
                            "ledger_blocked_pair_count": 2,
                            "guess_count": 1,
                            "correct_guess_count": 1,
                            "guess_success_rate": 1.0,
                        },
                    },
                    "benign_breakdown_by_policy_family": {
                        "minimum_cohort": {
                            "benign_broad_summary": {
                                "rows": 10,
                                "accepted_rows": 10,
                                "rejected_rows": 0,
                                "acceptance_rate": 1.0,
                            },
                            "benign_near_overlap": {
                                "rows": 2,
                                "accepted_rows": 2,
                                "rejected_rows": 0,
                                "acceptance_rate": 1.0,
                            },
                        },
                        "stateful_privacy_ledger": {
                            "benign_broad_summary": {
                                "rows": 10,
                                "accepted_rows": 9,
                                "rejected_rows": 1,
                                "acceptance_rate": 0.9,
                            },
                            "benign_near_overlap": {
                                "rows": 2,
                                "accepted_rows": 1,
                                "rejected_rows": 1,
                                "acceptance_rate": 0.5,
                            },
                        },
                        "stateful_privacy_ledger_difference_only": {
                            "benign_broad_summary": {
                                "rows": 10,
                                "accepted_rows": 10,
                                "rejected_rows": 0,
                                "acceptance_rate": 1.0,
                            },
                            "benign_near_overlap": {
                                "rows": 2,
                                "accepted_rows": 1,
                                "rejected_rows": 1,
                                "acceptance_rate": 0.5,
                            },
                        },
                    },
                    "paired_policy_delta": {
                        "baseline_policy": "minimum_cohort",
                        "comparison_policy": "stateful_privacy_ledger",
                        "attack_enabling_run_count_delta": -3,
                        "ledger_blocked_run_count_delta": 3,
                        "attack_enabling_pair_count_delta": -3,
                        "ledger_blocked_pair_count_delta": 3,
                        "baseline_benign_acceptance_rate": 1.0,
                        "comparison_benign_acceptance_rate": 0.9,
                        "benign_utility_loss": 0.1,
                        "benign_utility_loss_seed_values": [0.08, 0.10, 0.12],
                        "benign_utility_loss_one_sided_95_upper": 0.12,
                        "benign_utility_loss_ci_method": "normal_approximation_one_sided_95",
                        "e4_utility_band": "marginal_utility",
                        "e4_utility_pass": False,
                        "comparison_benign_rows": 10,
                        "comparison_benign_rejected_rows": 1,
                        "benign_utility_loss_by_family": {
                            "benign_broad_summary": {
                                "baseline_benign_acceptance_rate": 1.0,
                                "comparison_benign_acceptance_rate": 0.9,
                                "benign_utility_loss": 0.1,
                                "baseline_benign_rows": 10,
                                "comparison_benign_rows": 10,
                                "comparison_benign_rejected_rows": 1,
                            },
                            "benign_near_overlap": {
                                "baseline_benign_acceptance_rate": 1.0,
                                "comparison_benign_acceptance_rate": 0.5,
                                "benign_utility_loss": 0.5,
                                "baseline_benign_rows": 2,
                                "comparison_benign_rows": 2,
                                "comparison_benign_rejected_rows": 1,
                            },
                        },
                        "available_comparison_policies": [
                            "stateful_privacy_ledger",
                            "stateful_privacy_ledger_difference_only",
                        ],
                        "additional_policy_deltas": {
                            "stateful_privacy_ledger_difference_only": {
                                "attack_enabling_run_count_delta": -2,
                                "ledger_blocked_run_count_delta": 2,
                                "attack_enabling_pair_count_delta": -2,
                                "ledger_blocked_pair_count_delta": 2,
                                "baseline_benign_acceptance_rate": 1.0,
                                "comparison_benign_acceptance_rate": 0.95,
                                "benign_utility_loss": 0.05,
                                "benign_utility_loss_seed_values": [0.05, 0.05, 0.05],
                                "benign_utility_loss_one_sided_95_upper": 0.05,
                                "benign_utility_loss_ci_method": "normal_approximation_one_sided_95",
                                "e4_utility_band": "primary_acceptable_utility",
                                "e4_utility_pass": True,
                                "comparison_benign_rows": 10,
                                "comparison_benign_rejected_rows": 1,
                                "benign_utility_loss_by_family": {
                                    "benign_broad_summary": {
                                        "baseline_benign_acceptance_rate": 1.0,
                                        "comparison_benign_acceptance_rate": 1.0,
                                        "benign_utility_loss": 0.0,
                                        "baseline_benign_rows": 10,
                                        "comparison_benign_rows": 10,
                                        "comparison_benign_rejected_rows": 0,
                                    },
                                    "benign_near_overlap": {
                                        "baseline_benign_acceptance_rate": 1.0,
                                        "comparison_benign_acceptance_rate": 0.5,
                                        "benign_utility_loss": 0.5,
                                        "baseline_benign_rows": 2,
                                        "comparison_benign_rows": 2,
                                        "comparison_benign_rejected_rows": 1,
                                    },
                                },
                            }
                        },
                    },
                    "benign_acceptance_rate": 1.0,
                    "benign_rejected_rows": 0,
                    "mean_acceptance_rate": 0.95,
                },
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
