# dns-mapping

Mapping mail server dependencies using DNS data.

## Prerequisites

- **Python**: 3.13
- **uv** (package/dependency manager): install via:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Quick start

1. Place your input file `domains.csv` in the project root with at least these columns:

```csv
domain,rigsmyndighed
example.com,0
example.org,1
```

2. Run the program using uv (no virtualenv activation needed):

```bash
uv run main.py
```

This will resolve DNS records for each domain and produce:

- `domain_dns_results.csv`
- `analysis_results.csv`

The script also prints comparative tables to `stdout`.

## Notes on dependencies

Dependencies are defined in `pyproject.toml` and locked in `uv.lock`. You generally do not need to run anything besides `uv run ...`, but if you want to pre-sync the environment:

```bash
uv sync
```

## What the script does

For each domain in `domains.csv`, the script:

- Queries `MX`, `TXT` (SPF includes and ip4s), `A` (and looks up ASN country), and some common DKIM selector `CNAME`s
- Looks up `autodiscover.<domain>` `CNAME`
- Writes normalized data to `domain_dns_results.csv`
- Computes Microsoft 365 indicator columns and writes a full table to `analysis_results.csv`
- Prints side-by-side summaries split by `rigsmyndighed`

## Input schema

- **domain**: the domain to analyze (e.g., `example.com`)
- **rigsmyndighed**: categorical flag (`0` or `1` as strings/ints). Other values will be treated as strings.

## Output files

- `domain_dns_results.csv`: raw/normalized DNS lookups including SPF, DKIM, autodiscover, and derived `domain_countries`.
- `analysis_results.csv`: includes Microsoft-related indicator columns and summary-friendly fields.
