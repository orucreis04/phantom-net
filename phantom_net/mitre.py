from __future__ import annotations

from typing import Any


MITRE_BY_TAG = {
    "brute_force_pattern": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    "credential_attack": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    "path_sweep": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
    },
    "port_scan": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "rapid_requests": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "rate_limit_exceeded": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "sensitive_path": {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
    },
    "service_probe": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
    },
}


def techniques_for_tags(tags: str | list[str]) -> list[dict[str, str]]:
    if isinstance(tags, str):
        tag_values = [tag for tag in tags.split(",") if tag]
    else:
        tag_values = tags

    seen = set()
    techniques = []
    for tag in tag_values:
        technique = MITRE_BY_TAG.get(tag)
        if not technique or technique["id"] in seen:
            continue
        seen.add(technique["id"])
        techniques.append(dict(technique))
    return techniques


def enrich_event(record: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(record)
    enriched["mitre_techniques"] = techniques_for_tags(str(enriched.get("tags") or ""))
    return enriched
