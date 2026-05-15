from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Any

import praw

from collectors.base_collector import BaseCollector


class RedditCollector(BaseCollector):
    """
    Fetches unstructured threat intelligence from technical subreddits.
    Requires Reddit API credentials (client_id, client_secret, user_agent).
    """

    DEFAULT_DELAY = 1.5  # PRAW rate-limits internally; this is a safety buffer

    # Single source of truth for the default subreddit list
    DEFAULT_SUBREDDITS: list[str] = [
        "netsec",
        "cybersecurity",
        "blueteamsec",
        "redteamsec",
    ]

    # Sentinel strings PRAW uses for deleted/removed content
    _DELETED_SENTINELS: frozenset[str] = frozenset({"[deleted]", "[removed]", ""})

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        super().__init__(source_name="reddit")

        c_id     = client_id     or os.getenv("REDDIT_CLIENT_ID")
        c_secret = client_secret or os.getenv("REDDIT_CLIENT_SECRET")
        u_agent  = user_agent    or os.getenv("REDDIT_USER_AGENT", "ThreatIntel_Collector_v1.0")

        if not all([c_id, c_secret, u_agent]):
            print("[!] Warning: Missing Reddit API credentials. RedditCollector will fail.")
            self.reddit = None
        else:
            self.reddit = praw.Reddit(
                client_id=c_id,
                client_secret=c_secret,
                user_agent=u_agent,
            )
            print("[*] Reddit API credentials loaded successfully.")

    # ── Task 1: fetch by time window ──────────────────────────────────────────

    def fetch_by_time(
        self,
        days_back: int | None = 7,
        year: int | None = None,
        max_results: int = 100,
        subreddits: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Pull recent posts from the configured subreddits.

        PRAW's .new() returns posts in reverse-chronological order, so we stop
        as soon as we hit the cutoff - no need to over-fetch.
        """
        if not self.reddit:
            return []

        if subreddits is None:
            subreddits = self.DEFAULT_SUBREDDITS

        if year is not None:
            print("[!] Warning: Reddit API does not support arbitrary historical year queries. Defaulting to recent.")

        cutoff     = datetime.now(timezone.utc).timestamp() - (days_back or 7) * 86400
        sub_string = "+".join(subreddits)
        raw_submissions: list[Any] = []

        self._throttle()
        try:
            # FIX 4: request exactly max_results; cutoff is the only filter
            for submission in self.reddit.subreddit(sub_string).new(limit=max_results):
                if submission.created_utc < cutoff:
                    # .new() is sorted newest-first - once we pass the cutoff
                    # all remaining posts are older, so we can stop early.
                    break
                raw_submissions.append(submission)

            return self.normalize(raw_submissions)

        except Exception as e:
            print(f"[!] Reddit fetch_by_time error: {e}")
            return []

    # ── Task 2: fetch by keyword ──────────────────────────────────────────────

    def fetch_by_keyword(
        self,
        query: str,
        max_results: int = 20,
        subreddits: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Search Reddit for specific threat keywords or CVE identifiers."""
        if not self.reddit:
            return []

        if subreddits is None:
            subreddits = self.DEFAULT_SUBREDDITS

        sub_string = "+".join(subreddits)
        self._throttle()

        try:
            raw_submissions = list(
                self.reddit.subreddit(sub_string).search(query, sort="new", limit=max_results)
            )
            return self.normalize(raw_submissions)

        except Exception as e:
            print(f"[!] Reddit fetch_by_keyword error: {e}")
            return []

    # ── Normalization ─────────────────────────────────────────────────────────

    def normalize(self, raw_data: list[Any]) -> list[dict[str, Any]]:
        records = []
        for submission in raw_data:
            # Submission.edited is float | False - guard before float()
            if submission.edited:
                updated_utc = float(submission.edited)
            else:
                updated_utc = float(submission.created_utc)

            # Sentinel strings PRAW uses for deleted/removed content
            selftext = submission.selftext or ""
            if selftext in self._DELETED_SENTINELS:
                print(f"    [skip] Deleted/removed post: {submission.id}")
                continue

            # Link posts have empty selftext - fall back to the URL so
            # entity_extractor always has a non-empty string to work with.
            description = selftext if selftext else f"[Link post] {submission.url}"

            permalink = f"https://reddit.com{submission.permalink}"

            records.append(self.format_record(
                title          = submission.title,
                description    = description,
                url            = permalink,
                published_date = datetime.fromtimestamp(
                    submission.created_utc, timezone.utc
                ).isoformat(),
                raw={
                    "post_id":      submission.id,
                    # updated_date stored separately for change-detection logic
                    # in the preprocessor (reset processed=0 on edit).
                    "updated_date": datetime.fromtimestamp(
                        updated_utc, timezone.utc
                    ).isoformat(),
                    "author":       str(submission.author) if submission.author else "deleted",
                    "upvotes":      submission.score,
                    "num_comments": submission.num_comments,
                    "is_link_post": not bool(selftext),
                },
            ))
        return records

    # ── Override _make_dedup_key ──────────────────────────────────────────────

    def _make_dedup_key(self, title: str, description: str, raw: dict) -> str:
        """
        The key must be stable so ON CONFLICT(dedup_key) DO UPDATE fires
        correctly when a post is edited.  Change detection is handled by
        the preprocessor comparing raw["updated_date"] against the stored
        value and resetting processed=0 when they differ.

        If post_id is somehow absent (malformed PRAW response), fall back to
        hashing title + description[:300] rather than producing an empty key.
        """
        post_id = raw.get("post_id")
        content = (
            f"{self.source_name}:{post_id}"
            if post_id
            else f"{self.source_name}:{title}:{description[:300]}"
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()