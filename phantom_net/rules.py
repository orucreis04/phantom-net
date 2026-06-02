from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Rule:
    name: str
    condition: str
    tag: str
    score: int
    enabled: bool = True


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule("service_probe", "service_not_trusted", "service_probe", 25),
    Rule("port_scan", "unique_probe_services_gte:service_sweep_threshold", "port_scan", 40),
    Rule("rate_limit", "recent_burst_gte:rate_limit_hits", "rate_limit_exceeded", 30),
    Rule("rapid_requests", "recent_hits_gte:8", "rapid_requests", 25),
    Rule("path_sweep", "unique_paths_gte:path_sweep_threshold", "path_sweep", 30),
    Rule("sensitive_path", "haystack_contains:suspicious_path_hints", "sensitive_path", 30),
    Rule("credential_attack", "event_type_equals:auth_attempt", "credential_attack", 30),
    Rule("brute_force_pattern", "payload_contains:brute_force_hints", "brute_force_pattern", 15),
    Rule("session_memory", "session_max_risk_gte:session_memory_threshold", "session_memory", 30),
    Rule("decoy_session", "decoy_locked", "decoy_session", 20),
)


class RuleEngine:
    def __init__(self, rules: list[Rule] | tuple[Rule, ...] = DEFAULT_RULES) -> None:
        self.rules = list(rules)

    def evaluate(self, facts: dict[str, Any]) -> tuple[int, list[str]]:
        score = int(facts.get("base_score", 5))
        tags: list[str] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if _matches(rule.condition, facts):
                score += rule.score
                tags.append(rule.tag)
        return min(score, 100), sorted(set(tags))


def rules_from_config(items: list[dict[str, Any]] | None) -> list[Rule]:
    if not items:
        return list(DEFAULT_RULES)
    rules: list[Rule] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rules.append(
            Rule(
                name=str(item.get("name", item.get("tag", "custom_rule"))),
                condition=str(item.get("condition", "")),
                tag=str(item.get("tag", item.get("name", "custom_rule"))),
                score=int(item.get("score", 0)),
                enabled=bool(item.get("enabled", True)),
            )
        )
    return rules or list(DEFAULT_RULES)


def _matches(condition: str, facts: dict[str, Any]) -> bool:
    operator, _, operand = condition.partition(":")
    if operator == "service_not_trusted":
        return not bool(facts.get("service_trusted"))
    if operator == "decoy_locked":
        return bool(facts.get("decoy_locked"))
    if operator == "event_type_equals":
        return facts.get("event_type") == operand
    if operator == "unique_probe_services_gte":
        return int(facts.get("unique_probe_services", 0)) >= _threshold(operand, facts)
    if operator == "recent_burst_gte":
        return int(facts.get("recent_burst", 0)) >= _threshold(operand, facts)
    if operator == "recent_hits_gte":
        return int(facts.get("recent_hits", 0)) >= _threshold(operand, facts)
    if operator == "unique_paths_gte":
        return int(facts.get("unique_paths", 0)) >= _threshold(operand, facts)
    if operator == "session_max_risk_gte":
        return int(facts.get("session_max_risk", 0)) >= _threshold(operand, facts)
    if operator == "haystack_contains":
        return _contains_any(str(facts.get("haystack", "")), facts.get(operand, ()))
    if operator == "payload_contains":
        return _contains_any(str(facts.get("payload", "")), facts.get(operand, ()))
    return False


def _threshold(operand: str, facts: dict[str, Any]) -> int:
    try:
        return int(operand)
    except ValueError:
        return int(facts.get(operand, 0))


def _contains_any(value: str, needles: Any) -> bool:
    value = value.lower()
    return any(str(needle).lower() in value for needle in needles)
