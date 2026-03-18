import argparse
import base64
import ipaddress
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv


load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

TIMEOUT = 20
MAX_RETRIES = 2
RETRY_BACKOFF_SECONDS = 1.0


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
        last_error = "Request failed"
        last_status = "failed"
        last_http_status: Optional[int] = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.get(url, headers=headers, params=params, timeout=TIMEOUT)

                if response.status_code == 429:
                    last_error = "Provider rate limit reached"
                    last_status = "rate_limited"
                    last_http_status = response.status_code
                elif 500 <= response.status_code < 600:
                    last_error = f"Provider server error ({response.status_code})"
                    last_status = "failed"
                    last_http_status = response.status_code
                else:
                    response.raise_for_status()
                    try:
                        return {"ok": True, "data": response.json()}
                    except ValueError:
                        return {"ok": False, "status": "invalid_response", "error": "Invalid JSON response"}

            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = str(exc)
                last_status = "failed"
                last_http_status = None
            except requests.HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else None
                last_http_status = status_code
                if status_code == 429:
                    last_error = "Provider rate limit reached"
                    last_status = "rate_limited"
                else:
                    last_error = str(exc)
                    last_status = "failed"
            except requests.RequestException as exc:
                last_error = str(exc)
                last_status = "failed"
                last_http_status = None

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
    def explain(ioc_type: str, vt: Dict[str, Any], abuse: Dict[str, Any], otx: Dict[str, Any]) -> Dict[str, Any]:
        components: List[Dict[str, Any]] = []

        if vt.get("status") == "ok":
            vt_malicious = min(vt.get("malicious", 0) * 8, 50)
            if vt_malicious:
                components.append(
                    {
                        "source": "virustotal",
                        "label": "VT malicious detections",
                        "contribution": vt_malicious,
                        "raw_value": vt.get("malicious", 0),
                    }
                )

            vt_suspicious = min(vt.get("suspicious", 0) * 4, 15)
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
            abuse_confidence = min(abuse.get("abuse_confidence_score", 0) // 2, 30)
            if abuse_confidence:
                components.append(
                    {
                        "source": "abuseipdb",
                        "label": "AbuseIPDB confidence",
                        "contribution": abuse_confidence,
                        "raw_value": abuse.get("abuse_confidence_score", 0),
                    }
                )

            if abuse.get("total_reports", 0) > 10:
                components.append(
                    {
                        "source": "abuseipdb",
                        "label": "AbuseIPDB report volume bonus",
                        "contribution": 10,
                        "raw_value": abuse.get("total_reports", 0),
                    }
                )

        if otx.get("status") == "ok":
            otx_pulses = min(otx.get("pulse_count", 0) * 3, 20)
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
        }

    @staticmethod
    def score(ioc_type: str, vt: Dict[str, Any], abuse: Dict[str, Any], otx: Dict[str, Any]) -> int:
        return RiskScorer.explain(ioc_type, vt, abuse, otx)["total"]

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
    def __init__(self):
        self.vt = VirusTotalClient(VT_API_KEY)
        self.abuse = AbuseIPDBClient(ABUSEIPDB_API_KEY)
        self.otx = OTXClient(OTX_API_KEY)

    def enrich_one(self, ioc_value: str) -> IOCResult:
        ioc_type = IOCTypeDetector.detect(ioc_value)

        vt_result = self.vt.enrich(ioc_value, ioc_type)
        abuse_result = (
            self.abuse.enrich(ioc_value)
            if ioc_type == "ip"
            else self.abuse.not_applicable_result("AbuseIPDB only supports IP indicators")
        )
        otx_result = self.otx.enrich(ioc_value, ioc_type)

        score_breakdown = RiskScorer.explain(ioc_type, vt_result, abuse_result, otx_result)
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
            sources={
                "virustotal": vt_result,
                "abuseipdb": abuse_result,
                "alienvault_otx": otx_result,
            },
            checked_at=datetime.now(timezone.utc).isoformat(),
        )

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
    parser = argparse.ArgumentParser(description="IOC Enricher MVP")
    parser.add_argument("ioc", nargs="?", help="Single IOC value to enrich")
    parser.add_argument("--input", help="Path to text file with one IOC per line")
    parser.add_argument("--output", help="Path to JSON output file")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    return parser.parse_args()


def load_iocs(single_ioc: Optional[str], input_file: Optional[str]) -> List[str]:
    iocs: List[str] = []

    if single_ioc:
        iocs.append(single_ioc.strip())

    if input_file:
        with open(input_file, "r", encoding="utf-8") as f:
            for line in f:
                value = line.strip()
                if value:
                    iocs.append(value)

    unique_iocs = []
    seen = set()
    for ioc in iocs:
        if ioc not in seen:
            unique_iocs.append(ioc)
            seen.add(ioc)

    return unique_iocs


def main() -> None:
    args = parse_args()
    iocs = load_iocs(args.ioc, args.input)

    if not iocs:
        raise SystemExit("Provide an IOC or use --input")

    enricher = IOCEnricher()
    results = [asdict(enricher.enrich_one(ioc)) for ioc in iocs]

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2 if args.pretty else None, ensure_ascii=False)
        print(f"Saved output to {args.output}")
    else:
        print(json.dumps(results, indent=2 if args.pretty else None, ensure_ascii=False))


if __name__ == "__main__":
    main()
