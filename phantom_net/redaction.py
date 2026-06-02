from __future__ import annotations

from urllib.parse import parse_qsl, urlencode


SENSITIVE_KEYS = {"password", "passwd", "pwd", "token", "api_key", "secret"}


def redact_payload(payload: str) -> str:
    if not payload:
        return ""

    pairs = parse_qsl(payload, keep_blank_values=True)
    if not pairs:
        return payload[:4000]

    redacted = []
    changed = False
    for key, value in pairs:
        if key.lower() in SENSITIVE_KEYS:
            redacted.append((key, "[redacted]"))
            changed = True
        else:
            redacted.append((key, value))

    return urlencode(redacted)[:4000] if changed else payload[:4000]
