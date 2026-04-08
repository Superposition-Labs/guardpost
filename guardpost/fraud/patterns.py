"""Registration pattern detection — behavioral fraud analysis.

Detects coordinated registration attacks by analyzing patterns across
multiple registrations: username similarity, timing clusters, sequential
patterns, and velocity anomalies.

Usage::

    from guardpost.fraud.patterns import PatternDetector

    detector = PatternDetector()
    detector.add_registration("user1234@gmail.com", ip="1.2.3.4")
    detector.add_registration("user1235@gmail.com", ip="1.2.3.4")
    detector.add_registration("user1236@gmail.com", ip="1.2.3.4")

    report = detector.analyze()
    print(report.clusters)       # Grouped suspicious registrations
    print(report.risk_level)     # "high"
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any


@dataclass
class Registration:
    """A single registration event."""

    email: str
    username: str  # local part
    domain: str
    ip_address: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "username": self.username,
            "domain": self.domain,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Registration:
        return cls(
            email=data["email"],
            username=data["username"],
            domain=data["domain"],
            ip_address=data.get("ip_address"),
            timestamp=data.get("timestamp", time.time()),
        )


@dataclass
class Cluster:
    """A group of related suspicious registrations."""

    cluster_type: str  # "username_similarity", "sequential", "velocity", "ip_burst"
    registrations: list[Registration] = field(default_factory=list)
    confidence: float = 0.0
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_type": self.cluster_type,
            "count": len(self.registrations),
            "confidence": self.confidence,
            "description": self.description,
            "emails": [r.email for r in self.registrations],
        }


@dataclass
class PatternReport:
    """Analysis report from pattern detection."""

    total_registrations: int
    suspicious_count: int
    risk_level: str  # "low", "medium", "high", "critical"
    clusters: list[Cluster] = field(default_factory=list)
    velocity_per_minute: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_registrations": self.total_registrations,
            "suspicious_count": self.suspicious_count,
            "risk_level": self.risk_level,
            "velocity_per_minute": round(self.velocity_per_minute, 2),
            "clusters": [c.to_dict() for c in self.clusters],
        }


# Patterns that indicate auto-generated usernames
_SEQUENTIAL_RE = re.compile(r"^([a-zA-Z]+?)(\d{2,})$")  # user1234
# xk3jf8qw (no vowel structure)
_RANDOM_RE = re.compile(r"^[a-z0-9]{6,}$")
_VOWEL_RE = re.compile(r"[aeiouAEIOU]")


class PatternDetector:
    """Detects coordinated registration patterns.

    Operates on a window of recent registrations (in-memory).
    Call ``add_registration()`` as users register, then ``analyze()``
    to get a report.

    Args:
        window_seconds: How far back to analyze (default: 1 hour).
        similarity_threshold: Username similarity threshold 0–1 (default: 0.7).
        velocity_threshold: Registrations per minute to flag (default: 10).
        ip_burst_threshold: Registrations from same IP in window to flag (default: 5).
    """

    def __init__(
        self,
        *,
        window_seconds: int = 3600,
        similarity_threshold: float = 0.7,
        velocity_threshold: float = 10.0,
        ip_burst_threshold: int = 5,
    ) -> None:
        self.window_seconds = window_seconds
        self.similarity_threshold = similarity_threshold
        self.velocity_threshold = velocity_threshold
        self.ip_burst_threshold = ip_burst_threshold
        self._registrations: list[Registration] = []

    def add_registration(
        self,
        email: str,
        *,
        ip_address: str | None = None,
        timestamp: float | None = None,
    ) -> None:
        """Record a registration for pattern analysis."""
        email = email.strip().lower()
        if "@" not in email:
            return
        username, domain = email.rsplit("@", 1)
        ts = timestamp if timestamp is not None else time.time()
        self._registrations.append(
            Registration(
                email=email,
                username=username,
                domain=domain,
                ip_address=ip_address,
                timestamp=ts,
            )
        )

    def _prune_window(self) -> list[Registration]:
        """Return registrations within the analysis window."""
        cutoff = time.time() - self.window_seconds
        active = [r for r in self._registrations if r.timestamp >= cutoff]
        self._registrations = active
        return active

    def analyze(self) -> PatternReport:
        """Analyze current registrations for suspicious patterns.

        Returns:
            PatternReport with clusters and risk assessment.
        """
        active = self._prune_window()
        if not active:
            return PatternReport(
                total_registrations=0,
                suspicious_count=0,
                risk_level="low",
            )

        clusters: list[Cluster] = []

        # 1. Sequential username detection (user1234, user1235, user1236)
        seq_cluster = self._detect_sequential(active)
        if seq_cluster:
            clusters.append(seq_cluster)

        # 2. Username similarity clustering
        sim_clusters = self._detect_similarity(active)
        clusters.extend(sim_clusters)

        # 3. IP burst detection
        ip_clusters = self._detect_ip_burst(active)
        clusters.extend(ip_clusters)

        # 4. Velocity anomaly
        velocity = self._compute_velocity(active)

        # Deduplicate suspicious emails across clusters
        suspicious_emails: set[str] = set()
        for cluster in clusters:
            for reg in cluster.registrations:
                suspicious_emails.add(reg.email)

        # Determine risk level
        risk_level = self._assess_risk(len(suspicious_emails), len(active), velocity, clusters)

        return PatternReport(
            total_registrations=len(active),
            suspicious_count=len(suspicious_emails),
            risk_level=risk_level,
            clusters=clusters,
            velocity_per_minute=velocity,
        )

    def _detect_sequential(self, regs: list[Registration]) -> Cluster | None:
        """Detect sequential username patterns (user123, user124, user125)."""
        # Group by base prefix
        prefixed: dict[str, list[tuple[int, Registration]]] = defaultdict(list)
        for reg in regs:
            match = _SEQUENTIAL_RE.match(reg.username)
            if match:
                prefix, num_str = match.groups()
                prefixed[prefix.lower()].append((int(num_str), reg))

        # Find groups with sequential numbers
        best_group: list[Registration] = []
        for prefix, entries in prefixed.items():
            if len(entries) < 3:
                continue
            entries.sort(key=lambda x: x[0])
            # Check for sequential runs
            current_run: list[Registration] = [entries[0][1]]
            for i in range(1, len(entries)):
                if entries[i][0] - entries[i - 1][0] <= 2:  # allow small gaps
                    current_run.append(entries[i][1])
                else:
                    if len(current_run) >= 3 and len(current_run) > len(best_group):
                        best_group = current_run
                    current_run = [entries[i][1]]
            if len(current_run) >= 3 and len(current_run) > len(best_group):
                best_group = current_run

        if len(best_group) >= 3:
            return Cluster(
                cluster_type="sequential",
                registrations=best_group,
                confidence=min(1.0, len(best_group) / 5),
                description=f"Sequential username pattern: {len(best_group)} registrations with incrementing numbers",
            )
        return None

    def _detect_similarity(self, regs: list[Registration]) -> list[Cluster]:
        """Detect clusters of similar usernames."""
        if len(regs) < 3:
            return []

        # Group by domain first (similarity within same domain is more suspicious)
        by_domain: dict[str, list[Registration]] = defaultdict(list)
        for reg in regs:
            by_domain[reg.domain].append(reg)

        clusters: list[Cluster] = []
        for domain, domain_regs in by_domain.items():
            if len(domain_regs) < 3:
                continue

            # Simple O(n²) pairwise similarity — fine for window sizes < 1000
            used: set[int] = set()
            for i, reg_a in enumerate(domain_regs):
                if i in used:
                    continue
                group = [reg_a]
                for j in range(i + 1, len(domain_regs)):
                    if j in used:
                        continue
                    ratio = SequenceMatcher(None, reg_a.username, domain_regs[j].username).ratio()
                    if ratio >= self.similarity_threshold:
                        group.append(domain_regs[j])
                        used.add(j)
                if len(group) >= 3:
                    used.add(i)
                    avg_sim = sum(
                        SequenceMatcher(None, group[0].username, g.username).ratio() for g in group[1:]
                    ) / max(len(group) - 1, 1)
                    clusters.append(
                        Cluster(
                            cluster_type="username_similarity",
                            registrations=group,
                            confidence=avg_sim,
                            description=(
                                f"Similar usernames on @{domain}: "
                                f"{len(group)} registrations, avg similarity {avg_sim:.0%}"
                            ),
                        )
                    )

        return clusters

    def _detect_ip_burst(self, regs: list[Registration]) -> list[Cluster]:
        """Detect bursts of registrations from the same IP."""
        by_ip: dict[str, list[Registration]] = defaultdict(list)
        for reg in regs:
            if reg.ip_address:
                by_ip[reg.ip_address].append(reg)

        clusters: list[Cluster] = []
        for ip, ip_regs in by_ip.items():
            if len(ip_regs) >= self.ip_burst_threshold:
                clusters.append(
                    Cluster(
                        cluster_type="ip_burst",
                        registrations=ip_regs,
                        confidence=min(1.0, len(ip_regs) / (self.ip_burst_threshold * 2)),
                        description=(f"IP burst from {ip}: {len(ip_regs)} registrations in window"),
                    )
                )

        return clusters

    def _compute_velocity(self, regs: list[Registration]) -> float:
        """Compute registrations per minute."""
        if len(regs) < 2:
            return 0.0
        timestamps = sorted(r.timestamp for r in regs)
        span = timestamps[-1] - timestamps[0]
        if span <= 0:
            return float(len(regs))  # All at same time
        return len(regs) / (span / 60.0)

    def _assess_risk(
        self,
        suspicious_count: int,
        total: int,
        velocity: float,
        clusters: list[Cluster],
    ) -> str:
        """Determine overall risk level."""
        if suspicious_count == 0 and velocity < self.velocity_threshold:
            return "low"

        score = 0
        # Suspicious ratio
        if total > 0:
            ratio = suspicious_count / total
            if ratio > 0.5:
                score += 3
            elif ratio > 0.2:
                score += 2
            elif ratio > 0.1:
                score += 1

        # Velocity
        if velocity > self.velocity_threshold * 3:
            score += 3
        elif velocity > self.velocity_threshold:
            score += 2

        # Cluster severity
        for cluster in clusters:
            if cluster.cluster_type == "sequential" and cluster.confidence > 0.8:
                score += 2
            elif cluster.cluster_type == "ip_burst":
                score += 1
            elif cluster.cluster_type == "username_similarity" and cluster.confidence > 0.85:
                score += 2

        if score >= 5:
            return "critical"
        elif score >= 3:
            return "high"
        elif score >= 1:
            return "medium"
        return "low"

    def clear(self) -> None:
        """Clear all stored registrations."""
        self._registrations.clear()

    @property
    def registration_count(self) -> int:
        return len(self._registrations)
