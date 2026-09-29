"""LLM-style adaptive attacker wrapper interfaces.

This module intentionally does not call a network LLM. It defines the boundary
where an LLM planner can observe a sanitized transcript and propose the next
constrained workload item.
"""

from __future__ import annotations

import os
import json
from dataclasses import dataclass
from typing import Any, Callable, Literal, Mapping, Protocol, Sequence
import urllib.error
import urllib.request

from .attackers import _is_ledger_rejection
from .policies import QueryPolicy
from .query_log import QueryLogRecord
from .runner import QueryAttemptContext, evaluate_query_attempt
from .synthetic import GenomicQuery, SyntheticDataset
from .workloads import AttackTarget, WorkloadItem


FeedbackMode = Literal["binary", "reason_bucket", "detailed"]
LOCAL_LLM_PROVIDERS = frozenset({"fake", "local", "ollama", "lmstudio", "docker_model_runner"})


class LLMQueryPlanner(Protocol):
    def propose_next(self, transcript_view: Sequence[Mapping[str, Any]]) -> WorkloadItem | None:
        """Return the next query proposal or None to stop."""


class LLMJSONClient(Protocol):
    def propose_query(
        self,
        transcript_view: Sequence[Mapping[str, Any]],
        config: "LLMClientConfig",
    ) -> Mapping[str, Any] | None:
        """Return a JSON-like query payload or None to stop."""


LLMProposalFunction = Callable[[Sequence[Mapping[str, Any]]], Mapping[str, Any] | None]
LLMTransportFunction = Callable[[Mapping[str, Any], "LLMClientConfig"], Mapping[str, Any]]
HTTPOpenerFunction = Callable[..., Any]


@dataclass(frozen=True)
class LLMClientConfig:
    provider: str
    model: str
    prompt_template_id: str = "a2_binary_json_query_v0"
    base_url: str | None = None
    api_key: str | None = None
    timeout_seconds: int = 30

    def to_log_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "prompt_template_id": self.prompt_template_id,
            "base_url": self.base_url,
            "api_key_configured": self.api_key is not None,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class LLMClientDryRunStatus:
    ready: bool
    status: str
    missing_fields: tuple[str, ...]
    config_log: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "status": self.status,
            "missing_fields": list(self.missing_fields),
            "config_log": dict(self.config_log),
        }


@dataclass(frozen=True)
class ReplayLLMPlanner:
    """Deterministic planner for tests and offline scaffold runs."""

    workload: Sequence[WorkloadItem]

    def propose_next(self, transcript_view: Sequence[Mapping[str, Any]]) -> WorkloadItem | None:
        if len(transcript_view) >= len(self.workload):
            return None
        return self.workload[len(transcript_view)]


@dataclass(frozen=True)
class JSONProposalLLMPlanner:
    """Adapter boundary for a future JSON-output LLM client.

    The injected function may call a real model later. In tests it is a local
    callable, which keeps the boundary network-free and deterministic.
    """

    proposal_fn: LLMProposalFunction
    default_label: str = "llm_proposed_query"
    default_attack_template: str = "llm_planned"

    def propose_next(self, transcript_view: Sequence[Mapping[str, Any]]) -> WorkloadItem | None:
        payload = self.proposal_fn(transcript_view)
        if payload is None:
            return None
        return workload_item_from_llm_payload(
            payload,
            default_label=self.default_label,
            default_attack_template=self.default_attack_template,
        )


@dataclass(frozen=True)
class ClientBackedLLMPlanner:
    """Planner shell for a real or fake JSON-producing LLM client."""

    client: LLMJSONClient
    config: LLMClientConfig
    default_label: str = "llm_client_query"
    default_attack_template: str = "llm_planned"

    def propose_next(self, transcript_view: Sequence[Mapping[str, Any]]) -> WorkloadItem | None:
        payload = self.client.propose_query(transcript_view, self.config)
        if payload is None:
            return None
        return workload_item_from_llm_payload(
            payload,
            default_label=self.default_label,
            default_attack_template=self.default_attack_template,
        )

    def log_metadata(self) -> dict[str, Any]:
        return self.config.to_log_dict()


@dataclass(frozen=True)
class FakeLLMJSONClient:
    """Deterministic fake provider for adapter-shell tests."""

    responses: Sequence[Mapping[str, Any] | None]

    def propose_query(
        self,
        transcript_view: Sequence[Mapping[str, Any]],
        config: LLMClientConfig,
    ) -> Mapping[str, Any] | None:
        if len(transcript_view) >= len(self.responses):
            return None
        return self.responses[len(transcript_view)]


@dataclass(frozen=True)
class OpenAICompatibleLLMJSONClient:
    """OpenAI-compatible JSON client shell with injectable transport."""

    transport: LLMTransportFunction | None = None
    system_prompt: str = (
        "Return exactly one JSON genomic aggregate query proposal or null. "
        "Do not include explanatory text."
    )

    def propose_query(
        self,
        transcript_view: Sequence[Mapping[str, Any]],
        config: LLMClientConfig,
    ) -> Mapping[str, Any] | None:
        if self.transport is None:
            raise RuntimeError("OpenAICompatibleLLMJSONClient requires an injected transport")
        response = self.transport(self.build_request_payload(transcript_view, config), config)
        return self.parse_response(response)

    def build_request_payload(
        self,
        transcript_view: Sequence[Mapping[str, Any]],
        config: LLMClientConfig,
    ) -> dict[str, Any]:
        return {
            "model": config.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(
                        {"transcript_view": list(transcript_view)},
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                },
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0,
        }

    def parse_response(self, response: Mapping[str, Any]) -> Mapping[str, Any] | None:
        try:
            content = response["choices"][0]["message"]["content"]  # type: ignore[index]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("OpenAI-compatible response missing choices[0].message.content") from exc

        if content is None:
            return None
        if isinstance(content, Mapping):
            return content
        parsed = json.loads(str(content))
        if parsed is None:
            return None
        if not isinstance(parsed, Mapping):
            raise ValueError("OpenAI-compatible content must parse to a JSON object or null")
        return parsed


@dataclass(frozen=True)
class OpenAICompatibleHTTPTransport:
    """Opt-in HTTP transport for OpenAI-compatible chat completion gateways."""

    opener: HTTPOpenerFunction = urllib.request.urlopen

    def __call__(
        self,
        payload: Mapping[str, Any],
        config: LLMClientConfig,
    ) -> Mapping[str, Any]:
        if config.base_url is None:
            raise ValueError("GENOMEFIREWALL_LLM_BASE_URL is required for HTTP transport")

        request = urllib.request.Request(
            _chat_completions_url(config.base_url),
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=self._headers(config),
            method="POST",
        )
        try:
            with self.opener(request, timeout=config.timeout_seconds) as response:
                raw_body = response.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"OpenAI-compatible HTTP transport returned HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError("OpenAI-compatible HTTP transport failed") from exc

        parsed = json.loads(raw_body.decode("utf-8"))
        if not isinstance(parsed, Mapping):
            raise ValueError("OpenAI-compatible HTTP response must be a JSON object")
        return parsed

    def _headers(self, config: LLMClientConfig) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if config.api_key is not None:
            headers["Authorization"] = f"Bearer {config.api_key}"
        return headers


@dataclass(frozen=True)
class LLMAttackResult:
    transcript: tuple[QueryLogRecord, ...]
    outcome: str
    turns: int


def load_llm_client_config_from_env(
    env: Mapping[str, str] | None = None,
) -> LLMClientConfig:
    """Build client config from environment-style values without network access."""

    source = os.environ if env is None else env
    provider = _env_value(source, "GENOMEFIREWALL_LLM_PROVIDER")
    model = _env_value(source, "GENOMEFIREWALL_LLM_MODEL")
    if provider is None:
        raise ValueError("GENOMEFIREWALL_LLM_PROVIDER is required")
    if model is None:
        raise ValueError("GENOMEFIREWALL_LLM_MODEL is required")

    timeout_seconds = _parse_timeout_seconds(
        _env_value(source, "GENOMEFIREWALL_LLM_TIMEOUT_SECONDS")
    )
    return LLMClientConfig(
        provider=provider,
        model=model,
        prompt_template_id=(
            _env_value(source, "GENOMEFIREWALL_LLM_PROMPT_TEMPLATE_ID")
            or "a2_binary_json_query_v0"
        ),
        base_url=_env_value(source, "GENOMEFIREWALL_LLM_BASE_URL"),
        api_key=_env_value(source, "GENOMEFIREWALL_LLM_API_KEY"),
        timeout_seconds=timeout_seconds,
    )


def dry_run_llm_client_config(
    env: Mapping[str, str] | None = None,
) -> LLMClientDryRunStatus:
    """Validate real-client configuration and return sanitized status metadata."""

    source = os.environ if env is None else env
    missing = [
        field_name
        for field_name in ("GENOMEFIREWALL_LLM_PROVIDER", "GENOMEFIREWALL_LLM_MODEL")
        if _env_value(source, field_name) is None
    ]
    provider = _env_value(source, "GENOMEFIREWALL_LLM_PROVIDER")
    if (
        provider is not None
        and provider.lower() not in LOCAL_LLM_PROVIDERS
        and _env_value(source, "GENOMEFIREWALL_LLM_API_KEY") is None
    ):
        missing.append("GENOMEFIREWALL_LLM_API_KEY")

    if missing:
        return LLMClientDryRunStatus(
            ready=False,
            status="missing_configuration",
            missing_fields=tuple(missing),
            config_log=_sanitized_env_log(source),
        )

    try:
        config = load_llm_client_config_from_env(source)
    except ValueError as exc:
        return LLMClientDryRunStatus(
            ready=False,
            status=f"invalid_configuration:{exc}",
            missing_fields=(),
            config_log=_sanitized_env_log(source),
        )

    return LLMClientDryRunStatus(
        ready=True,
        status="ready_no_network_call",
        missing_fields=(),
        config_log=config.to_log_dict(),
    )


def run_llm_adaptive_attack(
    dataset: SyntheticDataset,
    target: AttackTarget,
    policy: QueryPolicy,
    run_id: str,
    workload_seed: int,
    attacker_seed: int,
    planner: LLMQueryPlanner,
    max_turns: int = 8,
    feedback_mode: FeedbackMode = "binary",
) -> LLMAttackResult:
    """Run an LLM-planner-shaped adaptive attack without requiring an LLM backend."""

    if max_turns <= 0:
        raise ValueError("max_turns must be positive")

    transcript: list[QueryLogRecord] = []
    transcript_view: list[Mapping[str, Any]] = []

    while len(transcript) < max_turns:
        item = planner.propose_next(tuple(transcript_view))
        if item is None:
            return LLMAttackResult(
                transcript=tuple(transcript),
                outcome="planner_stopped",
                turns=len(transcript),
            )

        context = QueryAttemptContext(
            run_id=run_id,
            workload_seed=workload_seed,
            attacker_seed=attacker_seed,
            attacker_type="llm_adaptive",
            query_index=len(transcript),
            target_individual_index=target.individual_index,
            target_variant_id=target.variant_id,
            attack_enabling_pair_id=item.attack_enabling_pair_id,
            workload_label=item.label,
            attack_template=item.attack_template,
        )
        record = evaluate_query_attempt(dataset, item.query, policy, context)
        transcript.append(record)
        transcript_view.append(build_planner_view(record, feedback_mode=feedback_mode))

        if _is_ledger_rejection(record):
            return LLMAttackResult(
                transcript=tuple(transcript),
                outcome="ledger_blocked",
                turns=len(transcript),
            )

    return LLMAttackResult(
        transcript=tuple(transcript),
        outcome="turn_limit",
        turns=len(transcript),
    )


def build_planner_view(
    record: QueryLogRecord,
    feedback_mode: FeedbackMode = "binary",
) -> Mapping[str, Any]:
    """Return the attacker-visible observation for one query attempt."""

    if feedback_mode not in {"binary", "reason_bucket", "detailed"}:
        raise ValueError("feedback_mode must be binary, reason_bucket, or detailed")

    view: dict[str, Any] = {
        "query_index": record.query_index,
        "operator": record.operator,
        "variant_id": record.variant_id,
        "predicate_json": record.predicate_json,
        "accepted": record.accepted,
    }

    if record.accepted:
        view["result_value"] = record.result_value

    if feedback_mode in {"reason_bucket", "detailed"}:
        view["rejection_reason_bucket"] = record.rejection_reason_bucket

    if feedback_mode == "detailed":
        view["cohort_size"] = record.cohort_size
        view["max_prior_overlap"] = record.max_prior_overlap
        view["min_prior_difference"] = record.min_prior_difference
        view["min_prior_symmetric_difference"] = record.min_prior_symmetric_difference

    return view


def workload_item_from_llm_payload(
    payload: Mapping[str, Any],
    default_label: str = "llm_proposed_query",
    default_attack_template: str = "llm_planned",
) -> WorkloadItem:
    try:
        operator = str(payload["operator"])
        predicate = payload["predicate"]
    except KeyError as exc:
        raise ValueError("LLM payload must include operator and predicate") from exc

    if not isinstance(predicate, Mapping):
        raise ValueError("LLM payload predicate must be a mapping")

    variant_value = payload.get("variant_id")
    variant_id = str(variant_value) if variant_value is not None else None
    label = str(payload.get("label", default_label))
    description = str(payload.get("description", "LLM-proposed constrained query."))
    pair_value = payload.get("attack_enabling_pair_id")
    attack_enabling_pair_id = str(pair_value) if pair_value is not None else None
    template_value = payload.get("attack_template", default_attack_template)
    attack_template = str(template_value) if template_value is not None else None
    family_value = payload.get("workload_family")
    workload_family = str(family_value) if family_value is not None else None

    return WorkloadItem(
        query=GenomicQuery(
            operator=operator,
            predicate=dict(predicate),
            variant_id=variant_id,
        ),
        label=label,
        description=description,
        attack_enabling_pair_id=attack_enabling_pair_id,
        attack_template=attack_template,
        workload_family=workload_family,
    )


def _env_value(env: Mapping[str, str], field_name: str) -> str | None:
    value = env.get(field_name)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _parse_timeout_seconds(value: str | None) -> int:
    if value is None:
        return 30
    try:
        timeout_seconds = int(value)
    except ValueError as exc:
        raise ValueError("GENOMEFIREWALL_LLM_TIMEOUT_SECONDS must be an integer") from exc
    if timeout_seconds <= 0:
        raise ValueError("GENOMEFIREWALL_LLM_TIMEOUT_SECONDS must be positive")
    return timeout_seconds


def _sanitized_env_log(env: Mapping[str, str]) -> dict[str, Any]:
    timeout_value = _env_value(env, "GENOMEFIREWALL_LLM_TIMEOUT_SECONDS")
    try:
        timeout_seconds: int | str = _parse_timeout_seconds(timeout_value)
    except ValueError:
        timeout_seconds = timeout_value or "30"
    return {
        "provider": _env_value(env, "GENOMEFIREWALL_LLM_PROVIDER"),
        "model": _env_value(env, "GENOMEFIREWALL_LLM_MODEL"),
        "prompt_template_id": (
            _env_value(env, "GENOMEFIREWALL_LLM_PROMPT_TEMPLATE_ID")
            or "a2_binary_json_query_v0"
        ),
        "base_url": _env_value(env, "GENOMEFIREWALL_LLM_BASE_URL"),
        "api_key_configured": _env_value(env, "GENOMEFIREWALL_LLM_API_KEY") is not None,
        "timeout_seconds": timeout_seconds,
    }


def _chat_completions_url(base_url: str) -> str:
    stripped = base_url.rstrip("/")
    if stripped.endswith("/chat/completions"):
        return stripped
    return f"{stripped}/chat/completions"
