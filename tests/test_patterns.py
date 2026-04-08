"""Tests for fraud pattern detection."""

from __future__ import annotations

import time

import pytest

from guardpost.fraud.patterns import Cluster, PatternDetector, PatternReport, Registration


class TestRegistration:
    def test_creation(self):
        r = Registration(
            email="user@gmail.com",
            username="user",
            domain="gmail.com",
            ip_address="1.2.3.4",
        )
        assert r.email == "user@gmail.com"
        assert r.username == "user"
        assert r.domain == "gmail.com"


class TestCluster:
    def test_to_dict(self):
        regs = [
            Registration(email="a@b.com", username="a", domain="b.com"),
            Registration(email="b@b.com", username="b", domain="b.com"),
        ]
        c = Cluster(
            cluster_type="test",
            registrations=regs,
            confidence=0.9,
            description="Test cluster",
        )
        d = c.to_dict()
        assert d["cluster_type"] == "test"
        assert d["count"] == 2
        assert d["confidence"] == 0.9
        assert d["emails"] == ["a@b.com", "b@b.com"]


class TestPatternReport:
    def test_to_dict(self):
        report = PatternReport(
            total_registrations=10,
            suspicious_count=3,
            risk_level="medium",
            velocity_per_minute=5.5,
        )
        d = report.to_dict()
        assert d["total_registrations"] == 10
        assert d["suspicious_count"] == 3
        assert d["risk_level"] == "medium"
        assert d["velocity_per_minute"] == 5.5
        assert d["clusters"] == []


class TestPatternDetector:
    def test_empty_analysis(self):
        detector = PatternDetector()
        report = detector.analyze()
        assert report.total_registrations == 0
        assert report.risk_level == "low"

    def test_add_registration(self):
        detector = PatternDetector()
        detector.add_registration("user@gmail.com", ip_address="1.2.3.4")
        assert detector.registration_count == 1

    def test_invalid_email_skipped(self):
        detector = PatternDetector()
        detector.add_registration("noemail")
        assert detector.registration_count == 0

    def test_clear(self):
        detector = PatternDetector()
        detector.add_registration("a@b.com")
        detector.add_registration("b@b.com")
        detector.clear()
        assert detector.registration_count == 0


class TestSequentialDetection:
    def test_detects_sequential_usernames(self):
        detector = PatternDetector(window_seconds=3600)
        now = time.time()
        for i in range(5):
            detector.add_registration(f"user{1000 + i}@gmail.com", timestamp=now + i)
        report = detector.analyze()
        seq_clusters = [c for c in report.clusters if c.cluster_type == "sequential"]
        assert len(seq_clusters) == 1
        assert len(seq_clusters[0].registrations) == 5

    def test_no_sequential_with_gaps(self):
        detector = PatternDetector(window_seconds=3600)
        now = time.time()
        # Numbers with big gaps: 100, 200, 300
        for i in [100, 200, 300]:
            detector.add_registration(f"user{i}@gmail.com", timestamp=now + i)
        report = detector.analyze()
        seq_clusters = [c for c in report.clusters if c.cluster_type == "sequential"]
        assert len(seq_clusters) == 0

    def test_minimum_three_for_sequential(self):
        detector = PatternDetector(window_seconds=3600)
        now = time.time()
        # Only 2 sequential — not enough
        detector.add_registration("user100@gmail.com", timestamp=now)
        detector.add_registration("user101@gmail.com", timestamp=now + 1)
        report = detector.analyze()
        seq_clusters = [c for c in report.clusters if c.cluster_type == "sequential"]
        assert len(seq_clusters) == 0


class TestSimilarityDetection:
    def test_detects_similar_usernames(self):
        detector = PatternDetector(window_seconds=3600, similarity_threshold=0.6)
        now = time.time()
        # Very similar usernames
        for name in ["johnsmith1", "johnsmith2", "johnsmith3", "johnsmith4"]:
            detector.add_registration(f"{name}@gmail.com", timestamp=now)
        report = detector.analyze()
        sim_clusters = [c for c in report.clusters if c.cluster_type == "username_similarity"]
        assert len(sim_clusters) >= 1

    def test_no_similarity_different_domains(self):
        detector = PatternDetector(window_seconds=3600, similarity_threshold=0.8)
        now = time.time()
        # Similar but spread across different domains
        detector.add_registration("john@gmail.com", timestamp=now)
        detector.add_registration("john@yahoo.com", timestamp=now)
        detector.add_registration("john@outlook.com", timestamp=now)
        report = detector.analyze()
        sim_clusters = [c for c in report.clusters if c.cluster_type == "username_similarity"]
        # Not clustered since they're in different domains
        assert len(sim_clusters) == 0


class TestIPBurstDetection:
    def test_detects_ip_burst(self):
        detector = PatternDetector(window_seconds=3600, ip_burst_threshold=3)
        now = time.time()
        for i in range(5):
            detector.add_registration(
                f"user{i}@different{i}.com",
                ip_address="1.2.3.4",
                timestamp=now + i,
            )
        report = detector.analyze()
        ip_clusters = [c for c in report.clusters if c.cluster_type == "ip_burst"]
        assert len(ip_clusters) == 1
        assert len(ip_clusters[0].registrations) == 5

    def test_no_burst_below_threshold(self):
        detector = PatternDetector(window_seconds=3600, ip_burst_threshold=5)
        now = time.time()
        for i in range(3):
            detector.add_registration(
                f"user{i}@test.com",
                ip_address="1.2.3.4",
                timestamp=now + i,
            )
        report = detector.analyze()
        ip_clusters = [c for c in report.clusters if c.cluster_type == "ip_burst"]
        assert len(ip_clusters) == 0

    def test_no_ip_no_burst(self):
        """Registrations without IP shouldn't trigger IP burst."""
        detector = PatternDetector(window_seconds=3600, ip_burst_threshold=2)
        now = time.time()
        for i in range(5):
            detector.add_registration(f"user{i}@test.com", timestamp=now + i)
        report = detector.analyze()
        ip_clusters = [c for c in report.clusters if c.cluster_type == "ip_burst"]
        assert len(ip_clusters) == 0


class TestVelocity:
    def test_velocity_computation(self):
        detector = PatternDetector(window_seconds=3600)
        now = time.time()
        # 60 registrations in 60 seconds = 60/min
        for i in range(60):
            detector.add_registration(f"u{i}@test.com", timestamp=now + i)
        report = detector.analyze()
        assert report.velocity_per_minute == pytest.approx(60.0, rel=0.1)


class TestRiskAssessment:
    def test_low_risk_normal_traffic(self):
        detector = PatternDetector(window_seconds=3600)
        now = time.time()
        # 3 normal registrations spread out
        for i, email in enumerate(["alice@gmail.com", "bob@yahoo.com", "charlie@outlook.com"]):
            detector.add_registration(email, timestamp=now + i * 100)
        report = detector.analyze()
        assert report.risk_level == "low"

    def test_high_risk_sequential_burst(self):
        detector = PatternDetector(
            window_seconds=3600,
            ip_burst_threshold=3,
            velocity_threshold=5,
        )
        now = time.time()
        # Sequential + IP burst + high velocity
        for i in range(10):
            detector.add_registration(
                f"user{1000 + i}@gmail.com",
                ip_address="1.2.3.4",
                timestamp=now + i * 0.5,
            )
        report = detector.analyze()
        assert report.risk_level in ("high", "critical")
        assert report.suspicious_count > 0


class TestWindowPruning:
    def test_old_registrations_pruned(self):
        detector = PatternDetector(window_seconds=60)
        old_time = time.time() - 120  # 2 minutes ago
        detector.add_registration("old@test.com", timestamp=old_time)
        detector.add_registration("new@test.com", timestamp=time.time())
        report = detector.analyze()
        assert report.total_registrations == 1
