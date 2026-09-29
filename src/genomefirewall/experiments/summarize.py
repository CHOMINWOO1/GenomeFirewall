"""Summarize a GenomeFirewall JSONL transcript."""

from __future__ import annotations

import argparse
import json
from typing import Sequence

from genomefirewall.io import read_jsonl, write_json
from genomefirewall.metrics import summarize_transcript


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Path to transcript JSONL.")
    parser.add_argument("--output", help="Optional path to write summary JSON.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = summarize_transcript(read_jsonl(args.input)).to_dict()
    if args.output:
        write_json(args.output, summary)
    else:
        print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
