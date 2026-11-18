# MCP Tool-Contract, Agent-Readiness & x402 Auditor

Audit remote MCP servers, OpenAPI 3.0/3.1 specifications, and Apify Actors for fragile tool contracts and agent compatibility.

## Input

- **Targets**: MCP endpoint, OpenAPI URL, or Apify Actor ID/URL.
- **Checks**: Contract, agent-readiness, x402, Store metadata, and security checks.
- **Fail run severity**: Choose the lowest severity that should fail the run.
- **Export formats**: SUMMARY.md, SARIF, JUnit XML, and JSON.

## Output

Every check is stored as a dataset item. Reports are available in the Key-Value Store:

- `SUMMARY.md`
- `results.sarif`
- `junit.xml`
- `results.json`

## SARIF and GitHub Actions

Upload `results.sarif` as a code-scanning artifact. JUnit XML is suitable for test reporters and CI providers.

## Local use

```bash
npm install
npm test
npm run build
APIFY_LOCAL_STORAGE_DIR=./storage npm start
```

Put input in `storage/key_value_stores/default/INPUT.json` or pass an Apify Local input file.

## Monetization guidance

Suitable Pay Per Event events are:

| Event name | Title | Description | Suggested price |
|---|---|---|---:|
| `audit-complete` | Completed audit | Charge once after a target set completes successfully | $0.25 |
| `target-audited` | Audited target | Charge for each successfully audited MCP, OpenAPI, or Actor target | $0.10 |
| `finding-created` | Audit finding | Charge for each emitted failure or warning finding | $0.02 |
| `report-exported` | Report export | Charge once for each requested generated report | $0.05 |

Configure these names, titles, descriptions, prices, and discount tiers in the Actor's Apify Store monetization settings. The code charges custom events through the Apify SDK when monetization is enabled.
