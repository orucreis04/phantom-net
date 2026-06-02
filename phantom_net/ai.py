from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from collections import Counter
from random import randint
from typing import Any


TAG_EXPLANATIONS = {
    "brute_force_pattern": "credential guessing pattern",
    "credential_attack": "login or credential endpoint abuse",
    "decoy_session": "session already locked into the decoy environment",
    "path_sweep": "many different paths requested in a short window",
    "port_scan": "multiple service probes from one source",
    "rapid_requests": "high request tempo",
    "rate_limit_exceeded": "short burst exceeded the gateway threshold",
    "sensitive_path": "sensitive admin, backup, config, or secret path requested",
    "service_probe": "non-web service was probed",
    "session_memory": "previous risk from the same source influenced this decision",
}

_runtime_ai = {"provider": "local", "model": "gpt-5.2", "api_key": "", "timeout_seconds": 20}


def configure_ai(provider: str, model: str, api_key: str, timeout_seconds: int) -> None:
    _runtime_ai.update(
        {
            "provider": provider,
            "model": model,
            "api_key": api_key,
            "timeout_seconds": timeout_seconds,
        }
    )


def summarize_activity(events: list[dict[str, Any]], stats: dict[str, Any]) -> dict[str, Any]:
    if _openai_enabled():
        local = _local_summarize_activity(events, stats)
        return _openai_json("summary", events, stats, local) or local
    return _local_summarize_activity(events, stats)


def _local_summarize_activity(events: list[dict[str, Any]], stats: dict[str, Any]) -> dict[str, Any]:
    if not events:
        return {
            "headline": "No attack activity has been recorded yet.",
            "summary": "Phantom-Net is running, but there are no events to analyze.",
            "severity": "low",
            "key_findings": [],
            "recommended_actions": ["Generate demo traffic or expose the gateway in a controlled lab."],
        }

    tag_counter = _tag_counter(events)
    source_counter = Counter(event.get("source_ip", "-") for event in events)
    max_risk = max(int(event.get("risk_score") or 0) for event in events)
    redirected = sum(1 for event in events if event.get("decision") == "redirect_to_decoy")
    high_risk = sum(1 for event in events if int(event.get("risk_score") or 0) >= 70)
    top_source, top_source_count = source_counter.most_common(1)[0]
    top_tags = tag_counter.most_common(4)

    severity = "critical" if max_risk >= 90 or high_risk >= 5 else "high" if max_risk >= 70 else "medium"
    if max_risk < 35:
        severity = "low"

    headline = f"{top_source} is the most active source with {top_source_count} recent events."
    summary = (
        f"Analyzed {len(events)} recent events. {redirected} events were redirected into the decoy "
        f"environment and {high_risk} reached high-risk level. The strongest signal is "
        f"{top_tags[0][0] if top_tags else 'general probing'}."
    )

    findings = [
        f"{tag}: {count} event(s), interpreted as {TAG_EXPLANATIONS.get(tag, 'suspicious behavior')}"
        for tag, count in top_tags
    ]
    if stats.get("unique_sources"):
        findings.append(f"{stats['unique_sources']} unique source IP(s) observed across the dataset.")

    return {
        "headline": headline,
        "summary": summary,
        "severity": severity,
        "key_findings": findings,
        "recommended_actions": _recommendations(tag_counter, severity),
    }


def generate_decoy_data(events: list[dict[str, Any]]) -> dict[str, Any]:
    if _openai_enabled():
        local = _local_generate_decoy_data(events)
        return _openai_json("decoy_data", events, {}, local) or local
    return _local_generate_decoy_data(events)


def _local_generate_decoy_data(events: list[dict[str, Any]]) -> dict[str, Any]:
    tag_counter = _tag_counter(events)
    focus = "generic"
    if tag_counter.get("credential_attack") or tag_counter.get("brute_force_pattern"):
        focus = "identity"
    elif tag_counter.get("port_scan") or tag_counter.get("service_probe"):
        focus = "service_inventory"
    elif tag_counter.get("sensitive_path") or tag_counter.get("path_sweep"):
        focus = "filesystem"

    return {
        "focus": focus,
        "generated": {
            "users": _generated_users(focus),
            "files": _generated_files(focus),
            "database_tables": _generated_tables(focus),
            "secrets": _generated_secrets(focus),
        },
        "notes": [
            "Generated values are honeytokens and must not grant real access.",
            "Use these decoys to refresh fake panels, backups, and API responses.",
        ],
    }


def _openai_enabled() -> bool:
    return str(_runtime_ai.get("provider", "")).lower() == "openai" and bool(_runtime_ai.get("api_key"))


def _openai_json(kind: str, events: list[dict[str, Any]], stats: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any] | None:
    prompt = _prompt(kind, events[:80], stats, fallback)
    request_body = {
        "model": _runtime_ai["model"],
        "instructions": (
            "You are the AI Analyst inside Phantom-Net, a defensive deception platform. "
            "Return only valid JSON. Do not include markdown. Never create real credentials; generated data must be honeytokens."
        ),
        "input": prompt,
    }
    request = Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(request_body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {_runtime_ai['api_key']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=int(_runtime_ai["timeout_seconds"])) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None

    text = _extract_response_text(payload)
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _prompt(kind: str, events: list[dict[str, Any]], stats: dict[str, Any], fallback: dict[str, Any]) -> str:
    if kind == "summary":
        schema = {
            "headline": "string",
            "summary": "string",
            "severity": "low|medium|high|critical",
            "key_findings": ["string"],
            "recommended_actions": ["string"],
        }
    else:
        schema = {
            "focus": "generic|identity|service_inventory|filesystem",
            "generated": {
                "users": [{"username": "string", "role": "string", "mfa": "string"}],
                "files": [{"path": "string", "size": "string"}],
                "database_tables": [{"table": "string", "rows": 0, "columns": ["string"]}],
                "secrets": {"api_token": "string", "db_password": "string"},
            },
            "notes": ["string"],
        }
    return json.dumps(
        {
            "task": kind,
            "required_schema": schema,
            "events": events,
            "stats": stats,
            "local_fallback": fallback,
        },
        ensure_ascii=True,
    )


def _extract_response_text(payload: dict[str, Any]) -> str:
    if isinstance(payload.get("output_text"), str):
        return payload["output_text"]
    chunks: list[str] = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"} and isinstance(content.get("text"), str):
                chunks.append(content["text"])
    return "".join(chunks)


def _tag_counter(events: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for event in events:
        tags = str(event.get("tags") or "")
        for tag in tags.split(","):
            if tag:
                counter[tag] += 1
    return counter


def _recommendations(tags: Counter[str], severity: str) -> list[str]:
    actions = []
    if tags.get("credential_attack") or tags.get("brute_force_pattern"):
        actions.append("Keep the source in the decoy path and rotate real admin passwords if this mirrors production traffic.")
    if tags.get("port_scan") or tags.get("service_probe"):
        actions.append("Review exposed service ports and compare probes with expected firewall policy.")
    if tags.get("path_sweep") or tags.get("sensitive_path"):
        actions.append("Expand decoy file, backup, and config responses for the requested path families.")
    if severity in {"high", "critical"}:
        actions.append("Export the event set and preserve it as an incident artifact.")
    return actions or ["Continue observing and collect more evidence before changing routing policy."]


def _generated_users(focus: str) -> list[dict[str, str]]:
    suffix = randint(100, 999)
    users = [
        {"username": f"admin.ops{suffix}", "role": "platform_admin", "mfa": "enabled"},
        {"username": f"backup.reader{suffix}", "role": "service", "mfa": "exempt"},
    ]
    if focus == "identity":
        users.append({"username": f"iam.breakglass{suffix}", "role": "emergency_admin", "mfa": "pending"})
    return users


def _generated_files(focus: str) -> list[dict[str, str]]:
    suffix = randint(1000, 9999)
    files = [
        {"path": f"/srv/app/shared/customer_delta_{suffix}.csv", "size": "77 MB"},
        {"path": f"/mnt/backup/prod_manifest_{suffix}.json", "size": "18 KB"},
    ]
    if focus == "filesystem":
        files.append({"path": f"/opt/archive/env_snapshot_{suffix}.zip", "size": "42 KB"})
    return files


def _generated_tables(focus: str) -> list[dict[str, object]]:
    tables: list[dict[str, object]] = [
        {"table": "customer_sessions", "rows": randint(1200, 9000), "columns": ["id", "user_id", "ip", "created_at"]},
        {"table": "service_tokens", "rows": randint(12, 120), "columns": ["id", "owner", "token_prefix", "scope"]},
    ]
    if focus == "service_inventory":
        tables.append({"table": "service_registry", "rows": randint(20, 80), "columns": ["host", "port", "service", "owner"]})
    return tables


def _generated_secrets(focus: str) -> dict[str, str]:
    suffix = randint(100000, 999999)
    secret = {
        "api_token": f"pnet_ai_decoy_{suffix}",
        "db_password": f"PNET-AI-FAKE-{suffix}",
    }
    if focus == "identity":
        secret["recovery_code"] = f"PNET-RECOVERY-{suffix}"
    return secret
