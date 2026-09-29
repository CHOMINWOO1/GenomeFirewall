# A2 Feedback Boundary v0

## Decision

The primary A2 LLM-attacker setting uses **binary rejection feedback**:

- accepted or rejected status is visible
- exact aggregate `result_value` is visible only when a query is accepted
- rejection reason buckets are hidden
- policy diagnostics such as cohort size, overlap, and difference are hidden

Reason-bucket feedback is reserved for secondary ablations. Detailed diagnostic feedback is stress-only.

## Planner Observation Modes

| Mode | Visible Fields |
| --- | --- |
| `binary` | query index, operator, variant, predicate, accepted flag, accepted result value |
| `reason_bucket` | all binary fields plus coarse rejection reason |
| `detailed` | reason-bucket fields plus cohort size and ledger diagnostics |

Evaluation-only fields such as target identity, target carrier status, and attack pair IDs are never included in the planner view.

## Implementation

`src/genomefirewall/llm_attackers.py` exposes:

- `FeedbackMode`
- `build_planner_view`
- `run_llm_adaptive_attack(..., feedback_mode="binary")`
- `JSONProposalLLMPlanner` for injectable JSON proposal generation

The mock `ReplayLLMPlanner` tests verify that binary mode hides rejection reasons and diagnostics, while reason-bucket and detailed modes add the intended fields.

## Rationale

Binary feedback is the safest primary setting because it does not directly teach the attacker which ledger threshold was crossed. Reason-bucket and detailed feedback remain useful for stress tests because real systems often leak too much diagnostic information during integration or debugging.
