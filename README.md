# IOC Enrichment Tool

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

A Python IOC enrichment project with:

- CLI workflow for bulk or single IOC analysis
- Streamlit web UI for analyst-friendly triage
- Multi-source enrichment from VirusTotal, AbuseIPDB, and AlienVault OTX
- Risk scoring and verdict generation
- Local cache and enrichment history
- Batch guardrails, score explainability, and JSON export

## Features

- Detects IOC types: IP, domain, URL, MD5, SHA1, SHA256
- Enriches indicators from multiple threat-intel providers
- Produces a unified result object with source details and score
- Retries transient provider failures and surfaces source status clearly
- Uses local caching to reduce repeat API calls
- Stores recent enrichment history locally for analyst reference
- UI includes filtering, risk-focused views, and CSV/JSON export
- GitHub Actions CI validates syntax and test coverage on every push

## Project Structure

- `IOC_Enricher.py` - core enrichment logic and CLI entrypoint
- `ioc_enricher_ui.py` - Streamlit analyst interface
- `tests/test_ioc_enricher.py` - unit tests for detection, validation, scoring, and caching
- `.github/workflows/ci.yml` - automated CI checks

## Requirements

- Python 3.10+
- API keys (optional but recommended):
  - VirusTotal (`VT_API_KEY`)
  - AbuseIPDB (`ABUSEIPDB_API_KEY`)
  - OTX (`OTX_API_KEY`)

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

For development and tests:

```bash
pip install -r requirements-dev.txt
```

## Configuration

Create a `.env` file in the project root:

```env
VT_API_KEY=your_vt_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_otx_api_key
```

## Run the CLI

Single IOC:

```bash
python IOC_Enricher.py 8.8.8.8 --pretty
```

From file:

```bash
python IOC_Enricher.py --input iocs.txt --output results.json --pretty
```

## Run the UI

```bash
streamlit run ioc_enricher_ui.py
```

Then open the local URL shown by Streamlit (usually `http://localhost:8501`).

## Run Tests

```bash
pytest
```

## Configuration Notes

Optional environment variables:

- `IOC_CACHE_TTL_SECONDS` - cache lifetime in seconds
- `IOC_MAX_BATCH_SIZE` - maximum valid IOC count per run
- `IOC_BATCH_WORKERS` - concurrent IOC workers
- `IOC_PROVIDER_WORKERS` - concurrent provider lookups per IOC
- `IOC_LOG_LEVEL` - logging verbosity (`INFO`, `DEBUG`, etc.)
- `IOC_VT_MALICIOUS_WEIGHT` and related `IOC_*` score variables - tune score weights without editing code

## Screenshot

Add a UI screenshot to `images/ui-overview.png` and GitHub will render it here:

![IOC Enricher UI](images/ui-overview.png)

## Example Output Highlights

- Provider-specific statuses: `ok`, `disabled`, `not_applicable`, `rate_limited`, `failed`
- Score breakdown with exact point contributions per source
- Cache visibility for repeated lookups
- Recent local history shown in the UI

## Security Note

Never commit real API keys. This repository ignores `.env` by default.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

