"""Experiment profile command helpers for GenomeFirewall sweeps."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from typing import Literal, Sequence


SweepType = Literal["difference", "symmetric"]
PolicyVariantSet = Literal["core", "e3"]


@dataclass(frozen=True)
class ExperimentProfile:
    name: str
    individuals: int
    variants: int
    seed_count: int
    k_min: int
    benign_variant_count: int
    difference_thresholds: tuple[int, ...]
    symmetric_difference_thresholds: tuple[int, ...]
    policy_variant_set: PolicyVariantSet = "core"
    target_count: int = 1

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


PROFILES: dict[str, ExperimentProfile] = {
    "smoke": ExperimentProfile(
        name="smoke",
        individuals=80,
        variants=20,
        seed_count=3,
        k_min=1,
        benign_variant_count=1,
        difference_thresholds=(1, 10, 1000),
        symmetric_difference_thresholds=(1, 5, 10, 20),
    ),
    "pilot": ExperimentProfile(
        name="pilot",
        individuals=1_000,
        variants=500,
        seed_count=5,
        k_min=20,
        benign_variant_count=3,
        difference_thresholds=(5, 10, 20, 50),
        symmetric_difference_thresholds=(10, 20, 50, 100),
    ),
    "dev": ExperimentProfile(
        name="dev",
        individuals=5_000,
        variants=2_000,
        seed_count=10,
        k_min=20,
        benign_variant_count=5,
        difference_thresholds=(5, 10, 20, 50),
        symmetric_difference_thresholds=(10, 20, 50, 100),
    ),
    "main": ExperimentProfile(
        name="main",
        individuals=10_000,
        variants=10_000,
        seed_count=30,
        k_min=50,
        benign_variant_count=10,
        difference_thresholds=(5, 10, 20, 50),
        symmetric_difference_thresholds=(10, 20, 50, 100),
    ),
    "stress": ExperimentProfile(
        name="stress",
        individuals=50_000,
        variants=20_000,
        seed_count=10,
        k_min=100,
        benign_variant_count=10,
        difference_thresholds=(20, 50, 100),
        symmetric_difference_thresholds=(50, 100, 200),
    ),
}


def get_profile(name: str) -> ExperimentProfile:
    try:
        return PROFILES[name.lower()]
    except KeyError as exc:
        valid = ", ".join(sorted(PROFILES))
        raise ValueError(f"unknown profile {name!r}; expected one of: {valid}") from exc


def build_sweep_args(
    profile_name: str,
    sweep_type: SweepType,
    policy_variant_set: PolicyVariantSet | None = None,
) -> tuple[str, ...]:
    profile = get_profile(profile_name)
    variant_set = policy_variant_set or profile.policy_variant_set
    thresholds = (
        profile.difference_thresholds
        if sweep_type == "difference"
        else profile.symmetric_difference_thresholds
    )
    variant_prefix = "" if variant_set == "core" else f"{variant_set}_"
    output_path = f"outputs/{profile.name}_{variant_prefix}{sweep_type}_threshold_sweep.json"
    args = [
        "--output",
        output_path,
        "--sweep-type",
        sweep_type,
        "--threshold-values",
        ",".join(str(value) for value in thresholds),
        "--seed-count",
        str(profile.seed_count),
        "--individuals",
        str(profile.individuals),
        "--variants",
        str(profile.variants),
        "--k-min",
        str(profile.k_min),
        "--benign-variant-count",
        str(profile.benign_variant_count),
        "--policy-variant-set",
        variant_set,
        "--target-count",
        str(profile.target_count),
    ]
    return tuple(args)


def build_sweep_command(
    profile_name: str,
    sweep_type: SweepType,
    policy_variant_set: PolicyVariantSet | None = None,
) -> str:
    args = " ".join(build_sweep_args(profile_name, sweep_type, policy_variant_set))
    return f"python -m genomefirewall.experiments.sweep {args}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="List available profile names.")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="smoke")
    parser.add_argument("--sweep-type", choices=("difference", "symmetric"), default="symmetric")
    parser.add_argument("--policy-variant-set", choices=("core", "e3"))
    parser.add_argument("--format", choices=("command", "args", "json"), default="command")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list:
        print("\n".join(sorted(PROFILES)))
        return 0
    if args.format == "json":
        payload = {
            "profile": get_profile(args.profile).to_dict(),
            "sweep_type": args.sweep_type,
            "policy_variant_set": args.policy_variant_set or get_profile(args.profile).policy_variant_set,
            "args": list(build_sweep_args(args.profile, args.sweep_type, args.policy_variant_set)),
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    if args.format == "args":
        print(" ".join(build_sweep_args(args.profile, args.sweep_type, args.policy_variant_set)))
        return 0
    print(build_sweep_command(args.profile, args.sweep_type, args.policy_variant_set))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
