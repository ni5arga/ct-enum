# ct-enum: Certificate Transparency Subdomain Enumerator

Passive subdomain discovery via CT logs (crt.sh + optional Censys).

---

## Project Structure

```
ct-enum/
├── main.py          # CLI entry point
├── ct_sources.py    # CT provider implementations (crt.sh, Censys)
├── parser.py        # Name extraction, normalization, filtering
└── utils.py         # Domain validation, backoff, formatting
```

---

## Requirements

- Python 3.11+
- [aiohttp](https://docs.aiohttp.org/)

Install dependencies:

```bash
pip install aiohttp
```

---

## Usage

### Basic — print sorted subdomains to terminal

```bash
python main.py example.com
```

**Output:**
```
Subdomains of example.com (5 found)
──────────────────────────────────────────────────
  api.example.com
  cdn.example.com
  mail.example.com
  staging.example.com
  www.example.com
```

---

### JSON output

```bash
python main.py example.com --json
```

**Output:**
```json
{
  "domain": "example.com",
  "count": 5,
  "subdomains": [
    "api.example.com",
    "cdn.example.com",
    "mail.example.com",
    "staging.example.com",
    "www.example.com"
  ]
}
```

---

### Save results to a file

```bash
# Plain text
python main.py example.com --output results.txt

# JSON to file
python main.py example.com --json --output results.json
```

---

### Set a custom timeout

Default is 30 seconds. For large domains or slow connections:

```bash
python main.py example.com --timeout 60
```

---

### Verbose / debug logging

```bash
python main.py example.com --verbose
# or
python main.py example.com -v
```

Shows per-provider status, retry events, rate-limit warnings, and entry counts.

---

## All Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `domain` | positional | — | Target domain, e.g. `example.com` |
| `--json` | flag | off | Output as JSON instead of table |
| `--output FILE` | string | — | Write output to file |
| `--timeout SECS` | float | `30.0` | HTTP request timeout in seconds |
| `--verbose` / `-v` | flag | off | Enable debug logging |

---

## Optional: Censys Integration

Censys provides additional certificate data but requires a free API account.

**Step 1**: Sign up at [censys.io](https://search.censys.io/) and get your API ID and Secret.

**Step 2**: Set environment variables:

```bash
export CENSYS_API_ID="your-api-id"
export CENSYS_API_SECRET="your-api-secret"
```

**Step 3**: Run normally. Censys is detected and used automatically:

```bash
python main.py example.com --verbose
```

If credentials are not set, Censys is silently skipped and only crt.sh is queried. No configuration change needed.

---

## How It Works

1. Queries `crt.sh` for all certificates matching `%.example.com`
2. Optionally queries Censys (if credentials present)
3. Parses `name_value` and `common_name` fields from each certificate entry
4. Splits multi-line entries, lowercases everything, strips wildcard prefixes (`*.`)
5. Deduplicates using a set, filters to valid subdomains only
6. Returns a sorted list

Network errors, rate limits, and invalid JSON are all handled with exponential backoff (up to 4 retries, capped at 60 seconds).

---

## Examples

```bash
# Quick recon on a target
python main.py tesla.com

# Save JSON report
python main.py github.com --json --output github_subs.json

# Aggressive timeout for large domains
python main.py google.com --timeout 120 --verbose

# Pipe into other tools
python main.py example.com --json | jq '.subdomains[]'
```

---

## Adding a New CT Provider

`ct_sources.py` exposes an abstract base class `CTProvider`. To add a new source:

```python
from ct_sources import CTProvider

class MyProvider(CTProvider):
    async def fetch(self, domain: str, session: aiohttp.ClientSession) -> list[dict]:
        # fetch and return raw list of dicts
        ...
```

Then register it in `get_providers()`:

```python
def get_providers() -> list[CTProvider]:
    return [CrtShProvider(), CensysProvider(), MyProvider()]
```

---

## Notes

- crt.sh can be slow or temporarily rate-limit heavy queries — the tool retries automatically
- Results reflect **historical certificates**, not necessarily live subdomains
- Wildcard certs (`*.example.com`) are stripped and excluded since they don't represent a specific subdomain
- No DNS resolution is performed — this is purely passive