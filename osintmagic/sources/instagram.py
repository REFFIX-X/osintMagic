"""Instagram public-profile lookup (keyless, Toutatis-style).

Hits Instagram's public ``web_profile_info`` endpoint with a browser UA and the
standard ``x-ig-app-id`` header — no login. Returns public fields (full name,
bio, external URL, follower/following/post counts, category, profile pic).
Instagram rate-limits and may block, so results are best-effort and the source
degrades to a clear error. Private profiles are not visible (by design).
"""
from __future__ import annotations

import json

from ..http_client import HttpError, get
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource

_APP_ID = "936619743392459"
_HEADERS = {
    "x-ig-app-id": _APP_ID,
    "x-requested-with": "XMLHttpRequest",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
}


@source(category="instagram", name="Instagram (public)")
class InstagramSource(DataSource):
    def check(self, target: str) -> SourceResult:
        username = target.strip().lstrip("@").lower()
        url = f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}"
        try:
            resp = get(url, headers=_HEADERS, timeout=15)
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        if resp.status_code == 404:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found",
                                  detail={"type": "instagram", "username": username})],
            )
        try:
            data = json.loads(resp.text)
        except json.JSONDecodeError:
            return SourceResult(source=self.name, category=self.category,
                                error=f"non-JSON response (http {resp.status_code}; likely rate-limited)")

        user = (data.get("data") or {}).get("user")
        if not user:
            return SourceResult(source=self.name, category=self.category, error="no user data in response")

        detail = {
            "type": "instagram",
            "username": user.get("username"),
            "full_name": user.get("full_name"),
            "bio": user.get("biography"),
            "external_url": user.get("external_url"),
            "followers": user.get("edge_followed_by", {}).get("count"),
            "following": user.get("edge_follow", {}).get("count"),
            "posts": user.get("edge_owner_to_timeline_media", {}).get("count"),
            "category": user.get("category_name"),
            "verified": user.get("is_verified"),
            "private": user.get("is_private"),
            "profile_pic": user.get("profile_pic_url_hd") or user.get("profile_pic_url"),
        }
        status = "found"
        confidence = 0.7 if not user.get("is_private") else 0.5
        if user.get("is_private"):
            detail["note"] = "private account — limited data"
        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status=status,
                              url=f"https://www.instagram.com/{username}/",
                              detail=detail, confidence=confidence)],
        )
