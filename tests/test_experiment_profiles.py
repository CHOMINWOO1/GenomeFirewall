from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

from genomefirewall.experiments.profiles import (
    build_sweep_args,
    build_sweep_command,
    get_profile,
    main as profiles_main,
)


class ExperimentProfileTests(unittest.TestCase):
    def test_get_profile_returns_smoke_defaults(self) -> None:
        profile = get_profile("smoke")

        self.assertEqual(profile.individuals, 80)
        self.assertEqual(profile.variants, 20)
        self.assertEqual(profile.seed_count, 3)
        self.assertEqual(profile.policy_variant_set, "core")
        self.assertEqual(profile.target_count, 1)

    def test_build_sweep_args_expands_pilot_symmetric_profile(self) -> None:
        args = build_sweep_args("pilot", "symmetric")

        self.assertIn("--sweep-type", args)
        self.assertIn("symmetric", args)
        self.assertIn("--threshold-values", args)
        self.assertIn("10,20,50,100", args)
        self.assertIn("--individuals", args)
        self.assertIn("1000", args)

    def test_build_sweep_command_keeps_explicit_cli_arguments(self) -> None:
        command = build_sweep_command("smoke", "difference")

        self.assertTrue(command.startswith("python -m genomefirewall.experiments.sweep"))
        self.assertIn("--threshold-values 1,10,1000", command)
        self.assertIn("--seed-count 3", command)
        self.assertIn("--policy-variant-set core", command)
        self.assertIn("--target-count 1", command)

    def test_build_sweep_command_can_request_e3_policy_variant_set(self) -> None:
        command = build_sweep_command("smoke", "difference", policy_variant_set="e3")

        self.assertIn("--policy-variant-set e3", command)
        self.assertIn("--output outputs/smoke_e3_difference_threshold_sweep.json", command)

    def test_profiles_cli_can_emit_json(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = profiles_main(["--profile", "smoke", "--sweep-type", "difference", "--format", "json"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["profile"]["name"], "smoke")
        self.assertEqual(payload["policy_variant_set"], "core")
        self.assertEqual(payload["args"][payload["args"].index("--sweep-type") + 1], "difference")


if __name__ == "__main__":
    unittest.main()
