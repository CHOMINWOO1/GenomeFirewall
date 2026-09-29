# A0/A1/A2 Attacker Comparison Scaffold

| attacker | source | seeds | targets | provider | status | network | attack runs | attack-enabling runs | ledger-blocked runs | attack pairs | ledger-blocked pairs | correct guesses | guess success rate |
| --- | --- | ---: | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A0 non-adaptive | pilot_matrix | 3 | 1 | n/a | completed | n/a | 3 | 3 | 0 | 3 | 0 | 3 / 3 | 1.0000 |
| A1 scripted adaptive | pilot_matrix | 3 | 1 | n/a | completed | n/a | 12 | 6 | 6 | 6 | 3 | 3 / 3 | 1.0000 |
| A2 fake/local LLM adaptive | a2_fake_llm_matrix | 3 | 1 | fake | completed | false | 6 | 3 | 3 | 6 | 3 | 3 / 3 | 1.0000 |
| A2 guarded OpenAI-compatible | a2_real_llm_blocked | 0 | 0 | local | network_not_allowed | false | 0 | 0 | 0 | 0 | 0 | 0 / 0 | 0.0000 |

This scaffold uses current pilot/matrix summaries, a matched fake-provider A2 matrix when available, and the guarded real-provider status artifact. It is not final real-provider A2 evidence.
