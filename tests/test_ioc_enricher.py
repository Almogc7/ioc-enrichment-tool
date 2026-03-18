from pathlib import Path

from IOC_Enricher import IOCEnricher, IOCTypeDetector, ScoreConfig, prepare_iocs


class StubClient:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def enrich(self, *args, **kwargs):
        self.calls += 1
        return self.result

    @staticmethod
    def not_applicable_result(reason):
        return {"enabled": False, "status": "not_applicable", "error": reason}


def test_ioc_type_detection():
    assert IOCTypeDetector.detect("8.8.8.8") == "ip"
    assert IOCTypeDetector.detect("example.org") == "domain"
    assert IOCTypeDetector.detect("https://example.org/test") == "url"
    assert IOCTypeDetector.detect("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert IOCTypeDetector.detect("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert IOCTypeDetector.detect("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
    assert IOCTypeDetector.detect("not_an_ioc") == "unknown"


def test_prepare_iocs_deduplicates_invalidates_and_truncates():
    prepared = prepare_iocs(
        ["8.8.8.8", "8.8.8.8", "example.org", "bad value", "1.1.1.1"],
        max_batch_size=2,
    )

    assert prepared.valid_iocs == ["8.8.8.8", "example.org"]
    assert prepared.invalid_iocs == ["bad value"]
    assert prepared.duplicates_removed == 1
    assert prepared.truncated_count == 1


def test_enricher_uses_cache_and_preserves_order(tmp_path: Path):
    vt = StubClient({"enabled": True, "status": "ok", "malicious": 5, "suspicious": 1, "harmless": 0, "undetected": 0})
    abuse = StubClient({"enabled": True, "status": "ok", "abuse_confidence_score": 80, "total_reports": 20, "isp": "TestISP"})
    otx = StubClient({"enabled": True, "status": "ok", "pulse_count": 2, "pulse_names": ["Pulse A"]})

    enricher = IOCEnricher(
        vt_client=vt,
        abuse_client=abuse,
        otx_client=otx,
        score_config=ScoreConfig(),
        cache_file=str(tmp_path / ".ioc_cache.json"),
        history_file=str(tmp_path / "ioc_history.jsonl"),
        batch_workers=2,
        provider_workers=2,
    )

    first = enricher.enrich_one("8.8.8.8")
    second = enricher.enrich_one("8.8.8.8")
    batch = enricher.enrich_many(["8.8.8.8", "example.org"])

    assert first.cache_hit is False
    assert second.cache_hit is True
    assert batch[0].value == "8.8.8.8"
    assert batch[1].value == "example.org"
    assert vt.calls >= 2
    assert len(enricher.recent_history()) >= 3


def test_score_breakdown_uses_configurable_weights(tmp_path: Path):
    vt = StubClient({"enabled": True, "status": "ok", "malicious": 2, "suspicious": 0, "harmless": 0, "undetected": 0})
    abuse = StubClient({"enabled": False, "status": "disabled"})
    otx = StubClient({"enabled": False, "status": "disabled"})

    enricher = IOCEnricher(
        vt_client=vt,
        abuse_client=abuse,
        otx_client=otx,
        score_config=ScoreConfig(vt_malicious_weight=10, vt_malicious_cap=100),
        cache_file=str(tmp_path / ".ioc_cache.json"),
        history_file=str(tmp_path / "ioc_history.jsonl"),
    )

    result = enricher.enrich_one("example.org")

    assert result.risk_score == 20
    assert result.score_breakdown["components"][0]["contribution"] == 20
    assert result.verdict == "low-confidence suspicious"
