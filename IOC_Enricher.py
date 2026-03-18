import argparse
import base64
import ipaddress
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv


load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

TIMEOUT = int(os.getenv("IOC_TIMEOUT_SECONDS", "20"))
MAX_RETRIES = int(os.getenv("IOC_MAX_RETRIES", "2"))
RETRY_BACKOFF_SECONDS = float(os.getenv("IOC_RETRY_BACKOFF_SECONDS", "1.0"))
MAX_BATCH_SIZE = int(os.getenv("IOC_MAX_BATCH_SIZE", "100"))
BATCH_WORKERS = int(os.getenv("IOC_BATCH_WORKERS", "4"))
PROVIDER_WORKERS = int(os.getenv("IOC_PROVIDER_WORKERS", "3"))
CACHE_TTL_SECONDS = int(os.getenv("IOC_CACHE_TTL_SECONDS", "3600"))
CACHE_FILE = os.getenv("IOC_CACHE_FILE", ".ioc_cache.json")
HISTORY_FILE = os.getenv("IOC_HISTORY_FILE", "ioc_history.jsonl")
HISTORY_LIMIT = int(os.getenv("IOC_HISTORY_LIMIT", "200"))
LOG_LEVEL = os.getenv("IOC_LOG_LEVEL", "INFO").upper()

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

logger = logging.getLogger(__name__)


@dataclass
class IOCResult:
    value: str
    ioc_type: str
    risk_score: int
    verdict: str
    summary: str
    score_breakdown: Dict[str, Any]
    sources: Dict[str, Any]
    checked_at: str
    cache_hit: bool = False


@dataclass
class InputPreparationResult:
    valid_iocs: List[str]
    invalid_iocs: List[str]
    duplicates_removed: int
    truncated_count: int
    max_batch_size: int


@dataclass
class ScoreConfig:
    vt_malicious_weight: int = 8
    vt_malicious_cap: int = 50
    vt_suspicious_weight: int = 4
    vt_suspicious_cap: int = 15
    abuse_confidence_divisor: int = 2
    abuse_confidence_cap: int = 30
    abuse_report_threshold: int = 10
    abuse_report_bonus: int = 10
    otx_pulse_weight: int = 3
    otx_pulse_cap: int = 20

    @classmethod
    def from_env(cls) -> "ScoreConfig":
        return cls(
            vt_malicious_weight=int(os.getenv("IOC_VT_MALICIOUS_WEIGHT", "8")),
            vt_malicious_cap=int(os.getenv("IOC_VT_MALICIOUS_CAP", "50")),
            vt_suspicious_weight=int(os.getenv("IOC_VT_SUSPICIOUS_WEIGHT", "4")),
            vt_suspicious_cap=int(os.getenv("IOC_VT_SUSPICIOUS_CAP", "15")),
            abuse_confidence_divisor=int(os.getenv("IOC_ABUSE_CONFIDENCE_DIVISOR", "2")),
            abuse_confidence_cap=int(os.getenv("IOC_ABUSE_CONFIDENCE_CAP", "30")),
            abuse_report_threshold=int(os.getenv("IOC_ABUSE_REPORT_THRESHOLD", "10")),
            abuse_report_bonus=int(os.getenv("IOC_ABUSE_REPORT_BONUS", "10")),
            otx_pulse_weight=int(os.getenv("IOC_OTX_PULSE_WEIGHT", "3")),
            otx_pulse_cap=int(os.getenv("IOC_OTX_PULSE_CAP", "20")),
        )


class IOCTypeDetector:
    HASH_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
    HASH_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
    HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
    DOMAIN = re.compile(
        r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
    )

    @staticmethod
    def detect(value: str) -> str:
        value = value.strip()

        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass

        if IOCTypeDetector.HASH_MD5.match(value):
            return "md5"
        if IOCTypeDetector.HASH_SHA1.match(value):
            return "sha1"
        if IOCTypeDetector.HASH_SHA256.match(value):
            return "sha256"
        if IOCTypeDetector.DOMAIN.match(value):
            return "domain"
        if value.startswith("http://") or value.startswith("https://"):
            return "url"

        return "unknown"


def prepare_iocs(values: List[str], max_batch_size: int = MAX_BATCH_SIZE) -> InputPreparationResult:
    valid_iocs: List[str] = []
    invalid_iocs: List[str] = []
    seen = set()
    duplicates_removed = 0

    for value in values:
        normalized = value.strip()
        if not normalized:
            continue

        if normalized in seen:
            duplicates_removed += 1
            continue

        seen.add(normalized)
        if IOCTypeDetector.detect(normalized) == "unknown":
            invalid_iocs.append(normalized)
            continue

        valid_iocs.append(normalized)

    truncated_count = 0
    if len(valid_iocs) > max_batch_size:
        truncated_count = len(valid_iocs) - max_batch_size
        valid_iocs = valid_iocs[:max_batch_size]

    return InputPreparationResult(
        valid_iocs=valid_iocs,
        invalid_iocs=invalid_iocs,
        duplicates_removed=duplicates_removed,
        truncated_count=truncated_count,
        max_batch_size=max_batch_size,
    )


class BaseClient:
    session = requests.Session()

    @staticmethod
    def disabled_result() -> Dict[str, Any]:
        return {"enabled": False, "status": "disabled"}

    @staticmethod
    def not_applicable_result(reason: str) -> Dict[str, Any]:
        return {"enabled": False, "status": "not_applicable", "error": reason}

    @staticmethod
    def ok_result(**kwargs: Any) -> Dict[str, Any]:
        return {"enabled": True, "status": "ok", **kwargs}

    @staticmethod
    def error_result(status: str, error: str, http_status: Optional[int] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {"enabled": True, "status": status, "error": error}
        if http_status is not None:
            result["http_status"] = http_status
        return result

    def safe_get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        provider_name = self.__class__.__name__
        last_error = "Request failed"
        last_status = "failed"
        last_http_status: Optional[int] = None

        for attempt in range(MAX_RETRIES + 1):
            started_at = time.perf_counter()
            try:
                response = self.session.get(url, headers=headers, params=params, timeout=TIMEOUT)
                elapsed_ms = int((time.perf_counter() - started_at) * 1000)

                if response.status_code == 429:
                    last_error = "Provider rate limit reached"
                    last_status = "rate_limited"
                    last_http_status = response.status_code
                    logger.warning("%s rate limited after %sms url=%s", provider_name, elapsed_ms, url)
                elif 500 <= response.status_code < 600:
                    last_error = f"Provider server error ({response.status_code})"
                    last_status = "failed"
                    last_http_status = response.status_code
                    logger.warning(
                        "%s server error status=%s after %sms url=%s",
                        provider_name,
                        response.status_code,
                        elapsed_ms,
                        url,
                    )
                else:
                    response.raise_for_status()
                    try:
                        data = response.json()
                    except ValueError:
                        logger.error("%s returned invalid JSON url=%s", provider_name, url)
                        return {
                            "ok": False,
                            "status": "invalid_response",
                            "error": "Invalid JSON response",
                        }

                    logger.info("%s request succeeded in %sms url=%s", provider_name, elapsed_ms, url)
                    return {"ok": True, "data": data}

            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = str(exc)
                last_status = "failed"
                last_http_status = None
                logger.warning("%s network error attempt=%s url=%s error=%s", provider_name, attempt + 1, url, exc)
            except requests.HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else None
                last_http_status = status_code
                if status_code == 429:
                    last_error = "Provider rate limit reached"
                    last_status = "rate_limited"
                else:
                    last_error = str(exc)
                    last_status = "failed"
                logger.warning(
                    "%s http error attempt=%s status=%s url=%s error=%s",
                    provider_name,
                    attempt + 1,
                    status_code,
                    url,
                    exc,
                )
            except requests.RequestException as exc:
                last_error = str(exc)
                last_status = "failed"
                last_http_status = None
                logger.warning("%s request exception attempt=%s url=%s error=%s", provider_name, attempt + 1, url, exc)

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))

        return {
            "ok": False,
            "status": last_status,
            "error": last_error,
            "http_status": last_http_status,
        }


class VirusTotalClient(BaseClient):
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def enabled(self) -> bool:
        return bool(self.api_key)

    @staticmethod
    def _encode_vt_url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.enabled():
            return self.disabled_result()

        headers = {"x-apikey": self.api_key}

        if ioc_type == "ip":
            url = f"{self.BASE_URL}/ip_addresses/{ioc_value}"
        elif ioc_type == "domain":
            url = f"{self.BASE_URL}/domains/{ioc_value}"
        elif ioc_type in {"md5", "sha1", "sha256"}:
            url = f"{self.BASE_URL}/files/{ioc_value}"
        elif ioc_type == "url":
            vt_url_id = self._encode_vt_url_id(ioc_value)
            url = f"{self.BASE_URL}/urls/{vt_url_id}"
        else:
            return self.not_applicable_result(f"VirusTotal does not support IOC type: {ioc_type}")

        result = self.safe_get(url, headers=headers)
        if not result["ok"]:
            return self.error_result(result.get("status", "failed"), result["error"], result.get("http_status"))

        attributes = result["data"].get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return self.ok_result(
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            reputation=attributes.get("reputation"),
            tags=attributes.get("tags", []),
            categories=attributes.get("categories", {}),
        )


class AbuseIPDBClient(BaseClient):
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def enabled(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ip: str) -> Dict[str, Any]:
        if not self.enabled():
            return self.disabled_result()

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True,
        }

        result = self.safe_get(self.BASE_URL, headers=headers, params=params)
        if not result["ok"]:
            return self.error_result(result.get("status", "failed"), result["error"], result.get("http_status"))

        data = result["data"].get("data", {})
        return self.ok_result(
            abuse_confidence_score=data.get("abuseConfidenceScore", 0),
            country_code=data.get("countryCode"),
            usage_type=data.get("usageType"),
            isp=data.get("isp"),
            domain=data.get("domain"),
            total_reports=data.get("totalReports", 0),
            last_reported_at=data.get("lastReportedAt"),
        )


class OTXClient(BaseClient):
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def enabled(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.enabled():
            return self.disabled_result()

        headers = {"X-OTX-API-KEY": self.api_key}

        if ioc_type == "ip":
            url = f"{self.BASE_URL}/IPv4/{ioc_value}/general"
        elif ioc_type == "domain":
            url = f"{self.BASE_URL}/domain/{ioc_value}/general"
        elif ioc_type in {"md5", "sha1", "sha256"}:
            url = f"{self.BASE_URL}/file/{ioc_value}/general"
        else:
            return self.not_applicable_result(f"AlienVault OTX does not support IOC type: {ioc_type}")

        result = self.safe_get(url, headers=headers)
        if not result["ok"]:
            return self.error_result(result.get("status", "failed"), result["error"], result.get("http_status"))

        pulse_info = result["data"].get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        return self.ok_result(
            pulse_count=pulse_info.get("count", 0),
            pulse_names=[pulse.get("name") for pulse in pulses[:5] if pulse.get("name")],
            reputation=result["data"].get("reputation"),
        )


class RiskScorer:
    @staticmethod
    def explain(
        ioc_type: str,
        vt: Dict[str, Any],
        abuse: Dict[str, Any],
        otx: Dict[str, Any],
        config: Optional[ScoreConfig] = None,
    ) -> Dict[str, Any]:
        config = config or ScoreConfig.from_env()
        components: List[Dict[str, Any]] = []

        if vt.get("status") == "ok":
            vt_malicious = min(vt.get("malicious", 0) * config.vt_malicious_weight, config.vt_malicious_cap)
            if vt_malicious:
                components.append(
                    {
                        "source": "virustotal",
                        "label": "VT malicious detections",
                        "contribution": vt_malicious,
                        "raw_value": vt.get("malicious", 0),
                    }
                )

            vt_suspicious = min(vt.get("suspicious", 0) * config.vt_suspicious_weight, config.vt_suspicious_cap)
            if vt_suspicious:
                components.append(
                    {
                        "source": "virustotal",
                        "label": "VT suspicious detections",
                        "contribution": vt_suspicious,
                        "raw_value": vt.get("suspicious", 0),
                    }
                )

        if ioc_type == "ip" and abuse.get("status") == "ok":
            divisor = max(config.abuse_confidence_divisor, 1)
            abuse_confidence = min(abuse.get("abuse_confidence_score", 0) // divisor, config.abuse_confidence_cap)
            if abuse_confidence:
                components.append(
                    {
                        "source": "abuseipdb",
                        "label": "AbuseIPDB confidence",
                        "contribution": abuse_confidence,
                        "raw_value": abuse.get("abuse_confidence_score", 0),
                    }
                )

            if abuse.get("total_reports", 0) > config.abuse_report_threshold:
                components.append(
                    {
                        "source": "abuseipdb",
                        "label": "AbuseIPDB report volume bonus",
                        "contribution": config.abuse_report_bonus,
                        "raw_value": abuse.get("total_reports", 0),
                    }
                )

        if otx.get("status") == "ok":
            otx_pulses = min(otx.get("pulse_count", 0) * config.otx_pulse_weight, config.otx_pulse_cap)
            if otx_pulses:
                components.append(
                    {
                        "source": "alienvault_otx",
                        "label": "OTX pulse count",
                        "contribution": otx_pulses,
                        "raw_value": otx.get("pulse_count", 0),
                    }
                )

        total = min(sum(component["contribution"] for component in components), 100)
        return {
            "total": total,
            "components": components,
            "source_statuses": {
                "virustotal": vt.get("status", "unknown"),
                "abuseipdb": abuse.get("status", "unknown"),
                "alienvault_otx": otx.get("status", "unknown"),
            },
            "config": asdict(config),
        }

    @staticmethod
    def score(
        ioc_type: str,
        vt: Dict[str, Any],
        abuse: Dict[str, Any],
        otx: Dict[str, Any],
        config: Optional[ScoreConfig] = None,
    ) -> int:
        return RiskScorer.explain(ioc_type, vt, abuse, otx, config)["total"]

    @staticmethod
    def verdict(score: int) -> str:
        if score >= 70:
            return "high-confidence malicious"
        if score >= 40:
            return "suspicious"
        if score >= 15:
            return "low-confidence suspicious"
        return "no strong evidence"


class IOCEnricher:
    def __init__(
        self,
        vt_client: Optional[VirusTotalClient] = None,
        abuse_client: Optional[AbuseIPDBClient] = None,
        otx_client: Optional[OTXClient] = None,
        score_config: Optional[ScoreConfig] = None,
        cache_file: str = CACHE_FILE,
        history_file: str = HISTORY_FILE,
        cache_ttl_seconds: int = CACHE_TTL_SECONDS,
        batch_workers: int = BATCH_WORKERS,
        provider_workers: int = PROVIDER_WORKERS,
        history_limit: int = HISTORY_LIMIT,
    ):
        self.vt = vt_client or VirusTotalClient(VT_API_KEY)
        self.abuse = abuse_client or AbuseIPDBClient(ABUSEIPDB_API_KEY)
        self.otx = otx_client or OTXClient(OTX_API_KEY)
        self.score_config = score_config or ScoreConfig.from_env()
        self.cache_path = Path(cache_file)
        self.history_path = Path(history_file)
        self.cache_ttl_seconds = cache_ttl_seconds
        self.batch_workers = max(batch_workers, 1)
        self.provider_workers = max(provider_workers, 1)
        self.history_limit = max(history_limit, 1)
        self._cache_lock = Lock()
        self._history_lock = Lock()
        self._cache = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
        if not self.cache_path.exists():
            return {}

        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("Failed to load cache file %s: %s", self.cache_path, exc)
            return {}

    def _persist_cache(self) -> None:
        temp_path = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
        temp_path.write_text(json.dumps(self._cache, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_path.replace(self.cache_path)

    @staticmethod
    def _cache_key(ioc_value: str) -> str:
        return ioc_value.strip()

    @staticmethod
    def _result_from_payload(payload: Dict[str, Any], cache_hit: bool) -> IOCResult:
        result_data = dict(payload)
        result_data["cache_hit"] = cache_hit
        return IOCResult(**result_data)

    def _get_cached_result(self, ioc_value: str) -> Optional[IOCResult]:
        cache_key = self._cache_key(ioc_value)

        with self._cache_lock:
            entry = self._cache.get(cache_key)
            if not entry:
                return None

            cached_at = entry.get("cached_at", 0)
            if (time.time() - cached_at) > self.cache_ttl_seconds:
                self._cache.pop(cache_key, None)
                self._persist_cache()
                return None

            logger.info("Cache hit for IOC %s", ioc_value)
            return self._result_from_payload(entry["result"], cache_hit=True)

    def _store_cache(self, result: IOCResult) -> None:
        cache_key = self._cache_key(result.value)
        payload = asdict(result)
        payload["cache_hit"] = False

        with self._cache_lock:
            self._cache[cache_key] = {
                "cached_at": time.time(),
                "result": payload,
            }
            self._persist_cache()

    def _append_history(self, result: IOCResult) -> None:
        entry = {
            "value": result.value,
            "ioc_type": result.ioc_type,
            "risk_score": result.risk_score,
            "verdict": result.verdict,
            "checked_at": result.checked_at,
            "cache_hit": result.cache_hit,
        }

        with self._history_lock:
            with self.history_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

            lines = self.history_path.read_text(encoding="utf-8").splitlines()
            if len(lines) > self.history_limit:
                trimmed = lines[-self.history_limit :]
                self.history_path.write_text("\n".join(trimmed) + "\n", encoding="utf-8")

    def recent_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        if not self.history_path.exists():
            return []

        try:
            lines = self.history_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            logger.warning("Failed to read history file %s: %s", self.history_path, exc)
            return []

        entries = [json.loads(line) for line in lines[-limit:] if line.strip()]
        entries.reverse()
        return entries

    @staticmethod
    def _provider_exception_result(source_name: str, exc: Exception) -> Dict[str, Any]:
        logger.exception("Unhandled provider error source=%s error=%s", source_name, exc)
        return {
            "enabled": True,
            "status": "failed",
            "error": f"Unhandled provider error: {exc}",
        }

    def _fetch_provider_results(self, ioc_value: str, ioc_type: str) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {
            "abuseipdb": self.abuse.not_applicable_result("AbuseIPDB only supports IP indicators")
        }

        with ThreadPoolExecutor(max_workers=self.provider_workers) as executor:
            futures = {
                "virustotal": executor.submit(self.vt.enrich, ioc_value, ioc_type),
                "alienvault_otx": executor.submit(self.otx.enrich, ioc_value, ioc_type),
            }
            if ioc_type == "ip":
                futures["abuseipdb"] = executor.submit(self.abuse.enrich, ioc_value)

            for source_name, future in futures.items():
                try:
                    results[source_name] = future.result()
                except Exception as exc:  # pragma: no cover
                    results[source_name] = self._provider_exception_result(source_name, exc)

        return results

    def _build_live_result(self, ioc_value: str) -> IOCResult:
        ioc_type = IOCTypeDetector.detect(ioc_value)
        source_results = self._fetch_provider_results(ioc_value, ioc_type)
        vt_result = source_results["virustotal"]
        abuse_result = source_results["abuseipdb"]
        otx_result = source_results["alienvault_otx"]

        score_breakdown = RiskScorer.explain(
            ioc_type,
            vt_result,
            abuse_result,
            otx_result,
            self.score_config,
        )
        score = score_breakdown["total"]
        verdict = RiskScorer.verdict(score)
        summary = self.build_summary(
            ioc_value,
            ioc_type,
            vt_result,
            abuse_result,
            otx_result,
            score,
            verdict,
            score_breakdown,
        )

        return IOCResult(
            value=ioc_value,
            ioc_type=ioc_type,
            risk_score=score,
            verdict=verdict,
            summary=summary,
            score_breakdown=score_breakdown,
            sources=source_results,
            checked_at=datetime.now(timezone.utc).isoformat(),
        )

    def enrich_one(self, ioc_value: str) -> IOCResult:
        cached_result = self._get_cached_result(ioc_value)
        if cached_result is not None:
            self._append_history(cached_result)
            return cached_result

        result = self._build_live_result(ioc_value)
        self._store_cache(result)
        self._append_history(result)
        return result

    def enrich_many(self, iocs: List[str]) -> List[IOCResult]:
        if not iocs:
            return []

        if len(iocs) == 1:
            return [self.enrich_one(iocs[0])]

        started_at = time.perf_counter()
        ordered_results: List[Optional[IOCResult]] = [None] * len(iocs)

        with ThreadPoolExecutor(max_workers=min(self.batch_workers, len(iocs))) as executor:
            future_map = {
                executor.submit(self.enrich_one, ioc): index
                for index, ioc in enumerate(iocs)
            }

            for future in as_completed(future_map):
                index = future_map[future]
                ordered_results[index] = future.result()

        elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        logger.info("Batch enrichment completed count=%s elapsed_ms=%s", len(iocs), elapsed_ms)
        return [result for result in ordered_results if result is not None]

    @staticmethod
    def build_summary(
        ioc_value: str,
        ioc_type: str,
        vt: Dict[str, Any],
        abuse: Dict[str, Any],
        otx: Dict[str, Any],
        score: int,
        verdict: str,
        score_breakdown: Dict[str, Any],
    ) -> str:
        parts = [f"IOC '{ioc_value}' ({ioc_type}) scored {score}/100 - {verdict}."]

        if score_breakdown.get("components"):
            reasons = ", ".join(
                f"{component['label']} +{component['contribution']}"
                for component in score_breakdown["components"]
            )
            parts.append(f"Score drivers: {reasons}.")

        if vt.get("status") == "ok":
            parts.append(
                f"VirusTotal malicious={vt.get('malicious', 0)}, suspicious={vt.get('suspicious', 0)}, harmless={vt.get('harmless', 0)}."
            )
        elif vt.get("status") in {"rate_limited", "failed", "invalid_response"}:
            parts.append(f"VirusTotal status={vt.get('status')}: {vt.get('error')}.")

        if abuse.get("status") == "ok":
            parts.append(
                f"AbuseIPDB confidence={abuse.get('abuse_confidence_score', 0)}, reports={abuse.get('total_reports', 0)}, ISP={abuse.get('isp')}."
            )
        elif abuse.get("status") in {"rate_limited", "failed", "invalid_response"}:
            parts.append(f"AbuseIPDB status={abuse.get('status')}: {abuse.get('error')}.")

        if otx.get("status") == "ok":
            parts.append(f"OTX pulse_count={otx.get('pulse_count', 0)}.")
        elif otx.get("status") in {"rate_limited", "failed", "invalid_response"}:
            parts.append(f"OTX status={otx.get('status')}: {otx.get('error')}.")

        return " ".join(parts)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IOC Enricher")
    parser.add_argument("ioc", nargs="?", help="Single IOC value to enrich")
    parser.add_argument("--input", help="Path to text file with one IOC per line")
    parser.add_argument("--output", help="Path to JSON output file")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    parser.add_argument(
        "--show-history",
        action="store_true",
        help="Print recent local enrichment history instead of running a new lookup",
    )
    return parser.parse_args()


def load_iocs(single_ioc: Optional[str], input_file: Optional[str]) -> List[str]:
    iocs: List[str] = []

    if single_ioc:
        iocs.append(single_ioc.strip())

    if input_file:
        with open(input_file, "r", encoding="utf-8") as handle:
            for line in handle:
                value = line.strip()
                if value:
                    iocs.append(value)

    return iocs


def main() -> None:
    args = parse_args()
    enricher = IOCEnricher()

    if args.show_history:
        print(json.dumps(enricher.recent_history(), indent=2, ensure_ascii=False))
        return

    raw_iocs = load_iocs(args.ioc, args.input)
    prepared_iocs = prepare_iocs(raw_iocs)

    if prepared_iocs.invalid_iocs:
        logger.warning("Skipping invalid IOCs: %s", ", ".join(prepared_iocs.invalid_iocs))
    if prepared_iocs.duplicates_removed:
        logger.info("Removed duplicate IOC entries count=%s", prepared_iocs.duplicates_removed)
    if prepared_iocs.truncated_count:
        logger.warning(
            "Batch truncated to max size=%s truncated_count=%s",
            prepared_iocs.max_batch_size,
            prepared_iocs.truncated_count,
        )

    if not prepared_iocs.valid_iocs:
        raise SystemExit("Provide at least one valid IOC or use --input")

    results = [asdict(result) for result in enricher.enrich_many(prepared_iocs.valid_iocs)]

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=2 if args.pretty else None, ensure_ascii=False)
        print(f"Saved output to {args.output}")
    else:
        print(json.dumps(results, indent=2 if args.pretty else None, ensure_ascii=False))


if __name__ == "__main__":
    main()
