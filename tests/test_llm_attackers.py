from __future__ import annotations

import unittest

from genomefirewall import (
    ClientBackedLLMPlanner,
    FakeLLMJSONClient,
    LLMClientConfig,
    MinimumCohortPolicy,
    JSONProposalLLMPlanner,
    OpenAICompatibleLLMJSONClient,
    ReplayLLMPlanner,
    StatefulPrivacyLedgerPolicy,
    SyntheticConfig,
    build_planner_view,
    dry_run_llm_client_config,
    generate_differencing_attack_workload,
    generate_synthetic_dataset,
    load_llm_client_config_from_env,
    OpenAICompatibleHTTPTransport,
    run_llm_adaptive_attack,
    select_attack_target,
    workload_item_from_llm_payload,
)


class LLMAdaptiveAttackerTests(unittest.TestCase):
    def test_replay_planner_produces_llm_adaptive_transcript(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=2101))
        target = select_attack_target(dataset, target_seed=2102)
        planner = ReplayLLMPlanner(generate_differencing_attack_workload(dataset, target))

        result = run_llm_adaptive_attack(
            dataset=dataset,
            target=target,
            policy=MinimumCohortPolicy(k_min=1),
            run_id="llm-attack-minimum",
            workload_seed=1,
            attacker_seed=2,
            planner=planner,
        )

        self.assertEqual(result.outcome, "planner_stopped")
        self.assertEqual(result.turns, 2)
        self.assertTrue(all(record.attacker_type == "llm_adaptive" for record in result.transcript))
        self.assertTrue(all(record.accepted for record in result.transcript))
        self.assertEqual(result.transcript[0].attack_template, "differencing")

    def test_replay_planner_stops_on_ledger_rejection(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=2201))
        target = select_attack_target(dataset, target_seed=2202)
        planner = ReplayLLMPlanner(generate_differencing_attack_workload(dataset, target))

        result = run_llm_adaptive_attack(
            dataset=dataset,
            target=target,
            policy=StatefulPrivacyLedgerPolicy(k_min=1, difference_min=1000),
            run_id="llm-attack-ledger",
            workload_seed=1,
            attacker_seed=2,
            planner=planner,
        )

        self.assertEqual(result.outcome, "ledger_blocked")
        self.assertEqual(result.turns, 2)
        self.assertTrue(result.transcript[0].accepted)
        self.assertFalse(result.transcript[1].accepted)
        self.assertEqual(result.transcript[1].rejection_reason_bucket, "ledger_difference")

    def test_binary_planner_view_hides_rejection_reason_and_policy_diagnostics(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=2401))
        target = select_attack_target(dataset, target_seed=2402)
        planner = ReplayLLMPlanner(generate_differencing_attack_workload(dataset, target))
        result = run_llm_adaptive_attack(
            dataset=dataset,
            target=target,
            policy=StatefulPrivacyLedgerPolicy(k_min=1, difference_min=1000),
            run_id="llm-attack-binary-view",
            workload_seed=1,
            attacker_seed=2,
            planner=planner,
            feedback_mode="binary",
        )

        view = build_planner_view(result.transcript[1], feedback_mode="binary")

        self.assertFalse(view["accepted"])
        self.assertNotIn("rejection_reason_bucket", view)
        self.assertNotIn("cohort_size", view)
        self.assertNotIn("result_value", view)

    def test_reason_bucket_and_detailed_views_add_explicit_feedback(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=2501))
        target = select_attack_target(dataset, target_seed=2502)
        planner = ReplayLLMPlanner(generate_differencing_attack_workload(dataset, target))
        result = run_llm_adaptive_attack(
            dataset=dataset,
            target=target,
            policy=StatefulPrivacyLedgerPolicy(k_min=1, difference_min=1000),
            run_id="llm-attack-detailed-view",
            workload_seed=1,
            attacker_seed=2,
            planner=planner,
            feedback_mode="reason_bucket",
        )

        reason_view = build_planner_view(result.transcript[1], feedback_mode="reason_bucket")
        detailed_view = build_planner_view(result.transcript[1], feedback_mode="detailed")

        self.assertEqual(reason_view["rejection_reason_bucket"], "ledger_difference")
        self.assertNotIn("cohort_size", reason_view)
        self.assertEqual(detailed_view["rejection_reason_bucket"], "ledger_difference")
        self.assertIn("cohort_size", detailed_view)

    def test_rejects_non_positive_turn_limit(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=20, variants=4, dataset_seed=2301))
        target = select_attack_target(dataset, target_seed=2302)
        planner = ReplayLLMPlanner(())

        with self.assertRaises(ValueError):
            run_llm_adaptive_attack(
                dataset=dataset,
                target=target,
                policy=MinimumCohortPolicy(k_min=1),
                run_id="llm-attack-invalid",
                workload_seed=1,
                attacker_seed=2,
                planner=planner,
                max_turns=0,
            )

    def test_json_payload_is_converted_to_workload_item(self) -> None:
        item = workload_item_from_llm_payload(
            {
                "operator": "COHORT_COUNT",
                "predicate": {"sex": "F"},
                "label": "llm_test_query",
                "attack_template": "llm_probe",
            }
        )

        self.assertEqual(item.query.operator, "COHORT_COUNT")
        self.assertEqual(item.query.predicate, {"sex": "F"})
        self.assertEqual(item.label, "llm_test_query")
        self.assertEqual(item.attack_template, "llm_probe")

    def test_json_proposal_planner_uses_injected_completion_boundary(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=2601))
        target = select_attack_target(dataset, target_seed=2602)
        views_seen = []

        def proposal_fn(transcript_view):
            views_seen.append(tuple(transcript_view))
            if transcript_view:
                return None
            return {
                "operator": "CARRIER_COUNT",
                "predicate": {"ancestry_group": target.visible_profile["ancestry_group"]},
                "variant_id": target.variant_id,
                "attack_template": "llm_planned",
            }

        result = run_llm_adaptive_attack(
            dataset=dataset,
            target=target,
            policy=MinimumCohortPolicy(k_min=1),
            run_id="llm-json-boundary",
            workload_seed=1,
            attacker_seed=2,
            planner=JSONProposalLLMPlanner(proposal_fn),
            feedback_mode="binary",
        )

        self.assertEqual(result.outcome, "planner_stopped")
        self.assertEqual(result.turns, 1)
        self.assertEqual(result.transcript[0].attack_template, "llm_planned")
        self.assertEqual(len(views_seen), 2)
        self.assertNotIn("rejection_reason_bucket", views_seen[1][0])

    def test_client_backed_planner_uses_sanitized_config_metadata(self) -> None:
        dataset = generate_synthetic_dataset(SyntheticConfig(individuals=80, variants=20, dataset_seed=2701))
        target = select_attack_target(dataset, target_seed=2702)
        config = LLMClientConfig(
            provider="fake",
            model="fake-json-model",
            base_url="http://localhost/mock",
            timeout_seconds=5,
        )
        client = FakeLLMJSONClient(
            (
                {
                    "operator": "CARRIER_COUNT",
                    "predicate": {"ancestry_group": target.visible_profile["ancestry_group"]},
                    "variant_id": target.variant_id,
                },
                None,
            )
        )
        planner = ClientBackedLLMPlanner(client=client, config=config)

        result = run_llm_adaptive_attack(
            dataset=dataset,
            target=target,
            policy=MinimumCohortPolicy(k_min=1),
            run_id="llm-client-boundary",
            workload_seed=1,
            attacker_seed=2,
            planner=planner,
        )
        metadata = planner.log_metadata()

        self.assertEqual(result.outcome, "planner_stopped")
        self.assertEqual(result.turns, 1)
        self.assertEqual(metadata["provider"], "fake")
        self.assertEqual(metadata["model"], "fake-json-model")
        self.assertNotIn("api_key", metadata)
        self.assertNotIn("GENOMEFIREWALL_LLM_API_KEY", metadata)

    def test_load_llm_client_config_from_env_redacts_secret_in_logs(self) -> None:
        config = load_llm_client_config_from_env(
            {
                "GENOMEFIREWALL_LLM_PROVIDER": "openai",
                "GENOMEFIREWALL_LLM_MODEL": "gpt-test",
                "GENOMEFIREWALL_LLM_API_KEY": "secret-token",
                "GENOMEFIREWALL_LLM_BASE_URL": "https://api.example.test",
                "GENOMEFIREWALL_LLM_TIMEOUT_SECONDS": "7",
            }
        )

        metadata = config.to_log_dict()

        self.assertEqual(config.api_key, "secret-token")
        self.assertEqual(config.timeout_seconds, 7)
        self.assertTrue(metadata["api_key_configured"])
        self.assertNotIn("secret-token", str(metadata))
        self.assertNotIn("GENOMEFIREWALL_LLM_API_KEY", metadata)

    def test_dry_run_reports_missing_hosted_provider_api_key(self) -> None:
        status = dry_run_llm_client_config(
            {
                "GENOMEFIREWALL_LLM_PROVIDER": "openai",
                "GENOMEFIREWALL_LLM_MODEL": "gpt-test",
            }
        )

        payload = status.to_dict()

        self.assertFalse(status.ready)
        self.assertEqual(status.status, "missing_configuration")
        self.assertIn("GENOMEFIREWALL_LLM_API_KEY", status.missing_fields)
        self.assertFalse(payload["config_log"]["api_key_configured"])
        self.assertNotIn("api_key", payload["config_log"])

    def test_dry_run_allows_local_provider_without_api_key(self) -> None:
        status = dry_run_llm_client_config(
            {
                "GENOMEFIREWALL_LLM_PROVIDER": "local",
                "GENOMEFIREWALL_LLM_MODEL": "local-json-model",
            }
        )

        self.assertTrue(status.ready)
        self.assertEqual(status.status, "ready_no_network_call")
        self.assertEqual(status.config_log["provider"], "local")
        self.assertFalse(status.config_log["api_key_configured"])

    def test_openai_compatible_client_builds_secret_free_request(self) -> None:
        client = OpenAICompatibleLLMJSONClient()
        config = LLMClientConfig(provider="openai", model="gpt-test", api_key="secret-token")

        payload = client.build_request_payload(({"accepted": True},), config)

        self.assertEqual(payload["model"], "gpt-test")
        self.assertNotIn("secret-token", str(payload))
        self.assertIn("transcript_view", payload["messages"][1]["content"])

    def test_openai_compatible_client_parses_json_response(self) -> None:
        captured_payloads = []

        def transport(payload, config):
            captured_payloads.append(payload)
            return {
                "choices": [
                    {
                        "message": {
                            "content": '{"operator":"COHORT_COUNT","predicate":{"sex":"F"}}'
                        }
                    }
                ]
            }

        client = OpenAICompatibleLLMJSONClient(transport=transport)
        config = LLMClientConfig(provider="openai", model="gpt-test", api_key="secret-token")

        proposal = client.propose_query((), config)

        self.assertEqual(proposal["operator"], "COHORT_COUNT")
        self.assertEqual(proposal["predicate"], {"sex": "F"})
        self.assertEqual(captured_payloads[0]["model"], "gpt-test")

    def test_openai_compatible_client_requires_injected_transport(self) -> None:
        client = OpenAICompatibleLLMJSONClient()
        config = LLMClientConfig(provider="openai", model="gpt-test")

        with self.assertRaises(RuntimeError):
            client.propose_query((), config)

    def test_openai_compatible_http_transport_posts_secret_free_payload(self) -> None:
        captured = {}

        class FakeHTTPResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return b'{"choices":[{"message":{"content":"null"}}]}'

        def opener(request, timeout):
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            captured["headers"] = {
                key.lower(): value for key, value in request.header_items()
            }
            captured["body"] = request.data.decode("utf-8")
            return FakeHTTPResponse()

        transport = OpenAICompatibleHTTPTransport(opener=opener)
        response = transport(
            {"model": "gpt-test", "messages": []},
            LLMClientConfig(
                provider="openai",
                model="gpt-test",
                base_url="https://api.example.test/v1",
                api_key="secret-token",
                timeout_seconds=9,
            ),
        )

        self.assertEqual(captured["url"], "https://api.example.test/v1/chat/completions")
        self.assertEqual(captured["timeout"], 9)
        self.assertEqual(captured["headers"]["authorization"], "Bearer secret-token")
        self.assertEqual(captured["headers"]["content-type"], "application/json")
        self.assertNotIn("secret-token", captured["body"])
        self.assertEqual(response["choices"][0]["message"]["content"], "null")

    def test_openai_compatible_http_transport_requires_base_url(self) -> None:
        transport = OpenAICompatibleHTTPTransport(opener=lambda request, timeout: None)

        with self.assertRaises(ValueError):
            transport(
                {"model": "gpt-test"},
                LLMClientConfig(provider="openai", model="gpt-test", api_key="secret-token"),
            )


if __name__ == "__main__":
    unittest.main()
