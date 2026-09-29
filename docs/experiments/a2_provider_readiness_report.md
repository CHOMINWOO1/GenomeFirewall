# A2 Provider Readiness Report

| artifact | ready | status | provider | model | base URL | API key configured | network attempted | next step |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| default dry-run | false | missing_configuration | n/a | n/a | n/a | False | false | Configure required fields: GENOMEFIREWALL_LLM_PROVIDER, GENOMEFIREWALL_LLM_MODEL. |
| local dry-run | true | ready_no_network_call | local | local-json-model | n/a | False | false | Configuration is ready; use the guarded pilot path for an opt-in provider run. |
| guarded provider path | true | network_not_allowed | local | local-json-model | http://localhost:11434/v1 | False | false | Run again with `--allow-network` only when the configured gateway is intentionally available. |

This report is secret-redacted. It records whether the A2 configured-provider path is ready, blocked by missing configuration, or blocked by the explicit `--allow-network` guard. It is not evidence of a completed real-provider A2 attack unless a row reports `status=completed` and `network attempted=true`.
