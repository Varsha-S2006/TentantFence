import json
import re
import shlex
from typing import Any


SECRET_PATTERN = re.compile(
    r"(?i)(bearer\s+|basic\s+)[A-Za-z0-9._~+/-]+=*"
    r"|(\"?(?:access|refresh)?_?(?:token|secret|password|api[_-]?key|client[_-]?secret)\"?\s*:\s*\")[^\"]+"
    r"|([?&](?:access_token|refresh_token|token|secret|password|api_key)=)[^&\s]+"
)
SECRET_HEADER_PATTERN = re.compile(
    r"authorization|cookie|token|secret|password|api[-_]?key", re.IGNORECASE
)


def redact(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        prefix = next(group for group in match.groups() if group is not None)
        return f"{prefix}[REDACTED]"

    return SECRET_PATTERN.sub(replace, value)


def redact_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if SECRET_HEADER_PATTERN.search(str(key))
            else redact_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        return redact(value)
    return value


def build_evidence(
    method: str,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any] | None,
    status_code: int | None,
    response_text: str,
    canaries: list[str],
) -> dict[str, Any]:
    safe_headers = {
        key: value
        for key, value in headers.items()
        if not SECRET_HEADER_PATTERN.search(key)
    }
    safe_headers = redact_data(safe_headers)
    safe_payload = redact_data(payload)
    safe_url = redact(url)
    snippet = redact(response_text[:1200])
    curl_parts = ["curl", "-i", "-X", method]
    for key, value in safe_headers.items():
        curl_parts.extend(["-H", f"{key}: {value}"])
    if safe_payload is not None:
        curl_parts.extend(["-H", "Content-Type: application/json", "--data", json.dumps(safe_payload)])
    curl_parts.append(safe_url)
    curl = " ".join(shlex.quote(part) for part in curl_parts)
    return {
        "request": {"method": method, "url": safe_url, "headers": safe_headers, "body": safe_payload},
        "response": {
            "status": status_code,
            "snippet": snippet,
            "body": redact(response_text[:10000]),
        },
        "canaries": canaries,
        "curl": curl,
    }
