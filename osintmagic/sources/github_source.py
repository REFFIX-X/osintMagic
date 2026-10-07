"""GitHub user/code search (requires optional GitHub token)."""
from __future__ import annotations

import json

from ..http_client import HttpError, get
from ..keys import get_key
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource


@source(category="username", name="GitHub search")
class GithubSearchSource(DataSource):
    key_name = "GITHUB_TOKEN"

    def check(self, target: str) -> SourceResult:
        key = get_key(self.key_name)
        if not key:
            return SourceResult(source=self.name, category=self.category, error="no GitHub token")
        try:
            resp = get(
                "https://api.github.com/search/users",
                params={"q": target, "per_page": 10},
                headers={"Authorization": f"token {key}", "Accept": "application/vnd.github+json"},
                timeout=15,
            )
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        if resp.status_code == 401:
            return SourceResult(source=self.name, category=self.category, error="invalid GitHub token")
        if resp.status_code != 200:
            return SourceResult(source=self.name, category=self.category, error=f"http {resp.status_code}")

        try:
            items = json.loads(resp.text).get("items", [])
        except json.JSONDecodeError:
            return SourceResult(source=self.name, category=self.category, error="non-JSON response")

        findings = [
            Finding(
                source=self.name, category=self.category, status="found",
                url=item.get("html_url"),
                detail={"type": "github_user", "login": item.get("login"), "score": item.get("score")},
            )
            for item in items
        ]
        if not findings:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found", detail={"type": "github_user"})],
            )
        return SourceResult(source=self.name, category=self.category, findings=findings)
