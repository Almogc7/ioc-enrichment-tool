import argparse
import base64
import ipaddress
import json
import os
import re
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


@dataclass
class IOCResult:
    value: str
    ioc_type: str
    risk_score: int
    verdict: str
    summary: str
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

    def safe_get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=TIMEOUT)
            response.raise_for_status()
            return {"ok": True, "data": response.json()}
        except requests.RequestException as exc:
            return {"ok": False, "error": str(exc)}
        except ValueError:
            return {"ok": False, "error": "Invalid JSON response"}


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
            return {"enabled": False}

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
            return {"enabled": True, "error": f"Unsupported IOC type for VT: {ioc_type}"}

        result = self.safe_get(url, headers=headers)
        if not result["ok"]:
            return {"enabled": True, "error": result["error"]}

        attributes = result["data"].get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "enabled": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "tags": attributes.get("tags", []),
            "categories": attributes.get("categories", {}),
        }


class AbuseIPDBClient(BaseClient):
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def enabled(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ip: str) -> Dict[str, Any]:
        if not self.enabled():
            return {"enabled": False}

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
            return {"enabled": True, "error": result["error"]}

        data = result["data"].get("data", {})
        return {
            "enabled": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt"),
        }


class OTXClient(BaseClient):
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def enabled(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.enabled():
            return {"enabled": False}

        headers = {"X-OTX-API-KEY": self.api_key}

        if ioc_type == "ip":
            url = f"{self.BASE_URL}/IPv4/{ioc_value}/general"
        elif ioc_type == "domain":
            url = f"{self.BASE_URL}/domain/{ioc_value}/general"
        elif ioc_type in {"md5", "sha1", "sha256"}:
            url = f"{self.BASE_URL}/file/{ioc_value}/general"
        else:
            return {"enabled": True, "error": f"Unsupported IOC type for OTX: {ioc_type}"}

        result = self.safe_get(url, headers=headers)
        if not result["ok"]:
            return {"enabled": True, "error": result["error"]}

        pulse_info = result["data"].get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        return {
            "enabled": True,
            "pulse_count": pulse_info.get("count", 0),
            "pulse_names": [pulse.get("name") for pulse in pulses[:5] if pulse.get("name")],
            "reputation": result["data"].get("reputation"),
        }


class RiskScorer:
    @staticmethod
    def score(ioc_type: str, vt: Dict[str, Any], abuse: Dict[str, Any], otx: Dict[str, Any]) -> int:
        score = 0

        if vt.get("enabled"):
            score += min(vt.get("malicious", 0) * 8, 50)
            score += min(vt.get("suspicious", 0) * 4, 15)

        if ioc_type == "ip" and abuse.get("enabled"):
            score += min(abuse.get("abuse_confidence_score", 0) // 2, 30)
            if abuse.get("total_reports", 0) > 10:
                score += 10

        if otx.get("enabled"):
            pulse_count = otx.get("pulse_count", 0)
            if pulse_count > 0:
                score += min(pulse_count * 3, 20)

        return min(score, 100)

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
        abuse_result = self.abuse.enrich(ioc_value) if ioc_type == "ip" else {"enabled": False}
        otx_result = self.otx.enrich(ioc_value, ioc_type)

        score = RiskScorer.score(ioc_type, vt_result, abuse_result, otx_result)
        verdict = RiskScorer.verdict(score)
        summary = self.build_summary(ioc_value, ioc_type, vt_result, abuse_result, otx_result, score, verdict)

        return IOCResult(
            value=ioc_value,
            ioc_type=ioc_type,
            risk_score=score,
            verdict=verdict,
            summary=summary,
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
    ) -> str:
        parts = [f"IOC '{ioc_value}' ({ioc_type}) scored {score}/100 - {verdict}."]

        if vt.get("enabled") and not vt.get("error"):
            parts.append(
                f"VirusTotal malicious={vt.get('malicious', 0)}, suspicious={vt.get('suspicious', 0)}, harmless={vt.get('harmless', 0)}."
            )

        if abuse.get("enabled") and not abuse.get("error"):
            parts.append(
                f"AbuseIPDB confidence={abuse.get('abuse_confidence_score', 0)}, reports={abuse.get('total_reports', 0)}, ISP={abuse.get('isp')}."
            )

        if otx.get("enabled") and not otx.get("error"):
            parts.append(f"OTX pulse_count={otx.get('pulse_count', 0)}.")

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
