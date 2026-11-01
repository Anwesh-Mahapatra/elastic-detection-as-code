"""Thin Elasticsearch + Kibana HTTP client (requests only, no SDK lock-in)."""
from __future__ import annotations

import time

import requests

from .config import env


class ElasticError(RuntimeError):
    pass


class ElasticClient:
    """Auth: ELASTIC_API_KEY (preferred for CI/CD) or ELASTIC_USERNAME + ELASTIC_PASSWORD.
    TLS: set ELASTIC_CA_CERT to a CA bundle path for clusters with self-signed certs."""

    def __init__(self, es_url: str | None = None, kibana_url: str | None = None, space: str = "default"):
        self.es_url = (es_url or env("ES_URL", "http://localhost:9200")).rstrip("/")
        self.kibana_url = (kibana_url or env("KIBANA_URL", "http://localhost:5601")).rstrip("/")
        self.space = space
        self.session = requests.Session()
        api_key = env("ELASTIC_API_KEY")
        if api_key:
            self.session.headers["Authorization"] = f"ApiKey {api_key}"
        else:
            password = env("ELASTIC_PASSWORD")
            if not password:
                raise ElasticError("Set ELASTIC_API_KEY or ELASTIC_PASSWORD (env var or .env file)")
            self.session.auth = (env("ELASTIC_USERNAME", "elastic"), password)
        self.session.verify = env("ELASTIC_CA_CERT", True)

    # ------------------------------------------------------------------ Elasticsearch
    def es(self, method: str, path: str, **kwargs) -> requests.Response:
        return self.session.request(method, f"{self.es_url}/{path.lstrip('/')}", timeout=120, **kwargs)

    # ------------------------------------------------------------------------ Kibana
    def kibana(self, method: str, path: str, **kwargs) -> requests.Response:
        prefix = "" if self.space in ("", "default") else f"/s/{self.space}"
        headers = {"kbn-xsrf": "true", "elastic-api-version": "2023-10-31", **kwargs.pop("headers", {})}
        return self.session.request(method, f"{self.kibana_url}{prefix}/{path.lstrip('/')}",
                                    headers=headers, timeout=300, **kwargs)

    def wait_for_kibana(self, timeout: int = 300) -> None:
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            try:
                r = self.kibana("GET", "/api/status")
                if r.ok and r.json().get("status", {}).get("overall", {}).get("level") == "available":
                    return
                last = f"HTTP {r.status_code}"
            except requests.RequestException as exc:
                last = type(exc).__name__
            time.sleep(5)
        raise ElasticError(f"Kibana not available after {timeout}s ({last})")


def error_reason(resp: requests.Response) -> str:
    """Pull the human-readable reason out of an Elasticsearch/Kibana error body."""
    try:
        body = resp.json()
    except ValueError:
        return f"HTTP {resp.status_code}: {resp.text[:300]}"
    err = body.get("error", body)
    if isinstance(err, dict):
        causes = err.get("root_cause") or []
        reason = (causes[0].get("reason") if causes else None) or err.get("reason") or body.get("message")
        return f"HTTP {resp.status_code}: {reason or str(err)[:300]}"
    return f"HTTP {resp.status_code}: {body.get('message', err)}"
