"""Deploy: turn on the detection engine and bulk-import rules into Kibana.

Why `_import?overwrite=true` instead of POST/PUT per rule?
  * Idempotent: re-running a deploy converges to the repo state (create OR update by rule_id).
  * Scales: one request per batch of rules instead of one per rule.
Known limitation (Kibana): import with overwrite cannot change an existing rule's `type`;
delete the old rule first if a PR changes e.g. query -> eql.
"""
from __future__ import annotations

import json

from .elastic import ElasticClient, ElasticError, error_reason
from .models import Rule


def bootstrap(client: ElasticClient) -> dict:
    """Initialise the detection engine in the target space (what opening the
    'Detection rules (SIEM)' page does in the UI), and verify prerequisites."""
    client.wait_for_kibana()
    priv = client.kibana("GET", "/api/detection_engine/privileges")
    if not priv.ok:
        raise ElasticError(f"privileges check: {error_reason(priv)}")
    info = priv.json()
    if not info.get("has_encryption_key"):
        raise ElasticError("Kibana has no xpack.encryptedSavedObjects.encryptionKey; rules cannot run")
    created = client.kibana("POST", "/api/detection_engine/index")
    if not created.ok:
        raise ElasticError(f"alerts index: {error_reason(created)}")
    index = client.kibana("GET", "/api/detection_engine/index").json()
    return {"has_encryption_key": True, "alerts_index": index.get("name"),
            "is_authenticated": info.get("is_authenticated")}


def to_ndjson(rules: list[Rule]) -> str:
    return "".join(json.dumps(r.payload, sort_keys=True, ensure_ascii=False) + "\n" for r in rules)


def deploy(rules: list[Rule], client: ElasticClient, batch_size: int = 200) -> dict:
    deployable = [r for r in rules if not r.load_errors]
    summary = {"requested": len(deployable), "imported": 0, "errors": []}
    for start in range(0, len(deployable), batch_size):
        batch = deployable[start:start + batch_size]
        files = {"file": ("rules.ndjson", to_ndjson(batch).encode("utf-8"), "application/ndjson")}
        resp = client.kibana("POST", "/api/detection_engine/rules/_import?overwrite=true", files=files)
        if not resp.ok:
            summary["errors"].append({"batch": start // batch_size, "error": error_reason(resp)})
            continue
        body = resp.json()
        summary["imported"] += body.get("success_count", 0)
        for err in body.get("errors", []):
            summary["errors"].append({"rule_id": err.get("rule_id"),
                                      "error": (err.get("error") or {}).get("message")})
    return summary


def verify_deployed(rules: list[Rule], client: ElasticClient) -> list[str]:
    """Return rule_ids that are missing in Kibana after a deploy."""
    missing = []
    for rule in rules:
        r = client.kibana("GET", "/api/detection_engine/rules", params={"rule_id": rule.rule_id})
        if r.status_code == 404:
            missing.append(rule.rule_id)
    return missing
