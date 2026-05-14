from __future__ import annotations

import os
import praw
from datetime import datetime, timedelta, timezone
from typing import Any
import hashlib

from collectors.base_collector import BaseCollector

class RedditCollector(BaseCollector):
    """
    Fetches unstructured threat intelligence from technical subreddits.
    Requires Reddit API credentials (client_id, client_secret, user_agent).
    """

    DEFAULT_DELAY = 1.5  # PRAW handles its own rate limiting, but we add a safety buffer

    def __init__(self, client_id: str | None = None, client_secret: str | None = None, user_agent: str | None = None) -> None:
        super().__init__(source_name="reddit")
        
        c_id = client_id or os.getenv("REDDIT_CLIENT_ID")
        c_secret = client_secret or os.getenv("REDDIT_CLIENT_SECRET")
        u_agent = user_agent or os.getenv("REDDIT_USER_AGENT", "ThreatIntel_Collector_v1.0")

        if not all([c_id, c_secret, u_agent]):
            print("[!] Warning: Missing Reddit API credentials. RedditCollector will fail.")
            self.reddit = None
        else:
            self.reddit = praw.Reddit(
                client_id=c_id,
                client_secret=c_secret,
                user_agent=u_agent
            )
            print("[*] Reddit API credentials loaded successfully.")

    # ── Task 1: fetch by time window ──────────────────────────────────────────

    def fetch_by_time(
        self,
        days_back: int | None = 7,
        year: int | None = None,
        max_results: int = 100,
        subreddits: list[str] = None
    ) -> list[dict[str, Any]]:
        """
        Pulls recent posts from specified subreddits.
        Reddit API does not support querying by historical year easily, 
        so year mode is not natively supported here without third-party pushshift APIs.
        """
        if not self.reddit:
            return []

        if subreddits is None:
            subreddits = ["netsec", "cybersecurity", "blueteamsec", "redteamsec"]

        if year is not None:
            print("[!] Warning: Reddit API does not support arbitrary historical year queries natively. Defaulting to recent.")

        cutoff = datetime.now(timezone.utc).timestamp() - (days_back or 7) * 86400
        raw_submissions = []

        sub_string = "+".join(subreddits)
        self._throttle()
        
        try:
            # Fetch 'new' posts from combined subreddits
            for submission in self.reddit.subreddit(sub_string).new(limit=max_results * 2):
                if submission.created_utc >= cutoff:
                    raw_submissions.append(submission)
                
                if len(raw_submissions) >= max_results:
                    break
                    
            return self.normalize(raw_submissions)
            
        except Exception as e:
            print(f"[!] Reddit fetch_by_time error: {e}")
            return []

    # ── Task 2: fetch by keyword ──────────────────────────────────────────────

    def fetch_by_keyword(
        self,
        query: str,
        max_results: int = 20,
        subreddits: list[str] = None
    ) -> list[dict[str, Any]]:
        """Search Reddit for specific threat keywords or CVEs."""
        if not self.reddit:
            return []

        if subreddits is None:
            subreddits = ["netsec", "cybersecurity", "blueteamsec", "redteamsec"]

        sub_string = "+".join(subreddits)
        raw_submissions = []
        self._throttle()

        try:
            for submission in self.reddit.subreddit(sub_string).search(query, sort='new', limit=max_results):
                raw_submissions.append(submission)
            return self.normalize(raw_submissions)
            
        except Exception as e:
            print(f"[!] Reddit fetch_by_keyword error: {e}")
            return []

    # ── Normalization ─────────────────────────────────────────────────────────

    def normalize(self, raw_data: list[Any]) -> list[dict[str, Any]]:
        records = []
        for submission in raw_data:
            # Calculate heuristic confidence score
            confidence = self._calculate_confidence(submission)
            
            # Handle updated/edited timestamps
            updated_utc = submission.edited if submission.edited else submission.created_utc

            records.append(self.format_record(
                title          = submission.title,
                description    = submission.selftext,
                url            = f"https://reddit.com{submission.permalink}",
                published_date = datetime.fromtimestamp(submission.created_utc, timezone.utc).isoformat(),
                raw            = {
                    "post_id": submission.id,
                    "updated_date": datetime.fromtimestamp(updated_utc, timezone.utc).isoformat(),
                    "confidence_score": confidence,
                    "author": str(submission.author) if submission.author else "deleted",
                    "upvotes": submission.score,
                    "num_comments": submission.num_comments
                }
            ))
        return records

    # ── Override _make_dedup_key ──────────────────────────────────────────────
    
    def _make_dedup_key(self, title: str, description: str, raw: dict) -> str:
        """
        Override: Hash the immutable post_id and the updated_date.
        If a user edits a Reddit post to add a new IoC, the updated_date changes,
        generating a new hash and forcing the pipeline to re-process the new intel.
        """
        post_id = raw.get("post_id")
        updated = raw.get("updated_date", "")
        
        if post_id:
            content = f"{self.source_name}:{post_id}:{updated}"
        else:
            content = f"{self.source_name}:{title}:{description[:300]}"
            
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _calculate_confidence(self, submission: Any) -> float:
        """
        Assigns a heuristic weight (0.0 to 1.0) to differentiate highly credible 
        researcher PoCs from unverified rumors.
        """
        score = 0.3 # Baseline for unstructured social text
        
        text = str(submission.selftext).lower()
        title = str(submission.title).lower()
        
        # Boost for CVE mentions
        if "cve-" in text or "cve-" in title:
            score += 0.2
            
        # Boost for technical artifacts (code blocks, github links)
        if "```" in text or "github.com" in text:
            score += 0.2
            
        # Boost for community vetting (upvotes/engagement)
        if submission.score > 50 or submission.num_comments > 10:
            score += 0.15
            
        return min(round(score, 2), 1.0)