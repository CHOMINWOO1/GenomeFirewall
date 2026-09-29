# GenomeFirewall

**Stateful privacy defenses against inference from repeated genomic aggregate queries.**

개별 질의만으로는 드러나지 않는 유전체 정보 노출을, 질의 이력과 집합 관계를 추적하는 Privacy Ledger로 평가하는 연구입니다.

## Research question

How can a sequence of otherwise permitted aggregate queries enable differencing attacks, and what privacy/utility trade-offs arise when the system tracks overlaps and query history?

## What is implemented

- Synthetic genotype and metadata generation.
- Cohort-count, allele-count, and carrier-count query semantics.
- Minimum-cohort policies and a stateful ledger with overlap/difference checks.
- Non-adaptive and scripted adaptive attackers, a fake/local LLM interface, and a guarded real-provider adapter.
- Benign workloads, multi-seed experiments, threshold sweeps, transcript summaries, and regression tests.

## Quick start

Python 3.11+. The core synthetic evaluation uses the standard library.

```bash
python -m venv .venv
# Activate .venv using your operating system's command.
python -m pip install -e .
python -m unittest discover -s tests -v
python -m genomefirewall.experiments.pilot --output outputs/pilot_transcript.jsonl
python -m genomefirewall.experiments.summarize --input outputs/pilot_transcript.jsonl --output outputs/pilot_summary.json
```

## Evidence

- [Synthetic evaluation specification](docs/experiments/synthetic_evaluation_spec.md)
- [Attacker comparison](docs/experiments/a0_a1_a2_comparison_report.md)
- [LLM feedback boundary](docs/experiments/a2_feedback_boundary.md)

The recorded comparison distinguishes executed scripted/fake-provider experiments from a blocked real-provider run. It does not establish real-LLM attack performance. The HE sanity path must explicitly report when a cryptographic backend is unavailable; plaintext fallback is not encrypted evaluation.

## Layout

`src/genomefirewall/` contains query semantics, policies, attackers, logging, and experiment runners. `tests/` verifies those components. Selected reports are in `docs/experiments/`; synthetic runtime outputs are generated locally.

## Publication and validation

This is a curated research source snapshot, not the complete local experiment archive.
See [validation](VALIDATION.md), [publication scope](PUBLICATION_NOTES.md), and [credential handling](SECURITY.md).
