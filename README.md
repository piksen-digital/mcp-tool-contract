# MCP Tool-Contract, Agent-Readiness & x402 Auditor

This Actor audits remote MCP endpoints, OpenAPI 3.0/3.1 specifications, and published Apify Actors. It produces structured findings for agent callers, CI systems, and GitHub Actions.

## What it checks

- MCP tool discovery and tool metadata
- JSON Schema input contracts and constrained string fields
- Operation IDs and parameter descriptions
- Missing agent-facing descriptions
- `readOnlyHint` and `openWorldHint` conflicts
- x402 payment declarations
- MCP HTTP response content types
- OpenAPI versions and operation structure
- Apify Actor Store metadata and input schemas

## Input

| Field | Description | Default |
|---|---|---|
| `targets` | MCP, OpenAPI, or Apify Actor targets | Required |
| `checks` | Audit categories | All categories |
| `failOn` | Severity that makes the run fail | `high` |
| `exportFormats` | Reports to generate | `summary`, `sarif`, `junit` |
| `requestTimeoutSecs` | Per-request timeout | `30` |
| `maxRedirects` | Maximum HTTP redirects | `5` |
| `includePassingChecks` | Include passed checks in reports | `true` |
| `dryRun` | Skip network access | `false` |

## Example input

```json
{
  "targets": [
    { "type": "openapi", "name": "Pet API", "url": "https://example.com/openapi.json" },
    { "type": "mcp", "name": "MCP server", "url": "https://mcp.example.com/mcp" },
    { "type": "apify-actor", "name": "Sample Actor", "actorId": "owner/sample-actor" }
  ],
  "checks": ["contracts", "agent-ready", "x402", "store", "security"],
  "failOn": "high",
  "exportFormats": ["summary", "sarif", "junit", "json"],
  "requestTimeoutSecs": 30,
  "includePassingChecks": true,
  "dryRun": false
}
```

## Outputs

- Default Dataset: one item per check or finding
- `SUMMARY.md`: human-readable summary
- `results.sarif`: SARIF 2.1.0 for code scanning
- `junit.xml`: JUnit XML for CI test reporters
- `results.json`: complete structured findings
- `OUTPUT`: summary counts and report names

## GitHub Actions

Upload the SARIF output to GitHub code scanning after downloading or forwarding the run's Key-Value Store record:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Download JUnit XML for your CI test publisher or inspect `junit.xml` directly.

## Run locally

Open this repository in GitHub Codespaces, then run:

```bash
npm ci
npm run check
npm start
```

Set local input in `storage/key_value_stores/default/INPUT.json`, or start with an Apify CLI-compatible input file.

## Pay Per Event

Configure these events in the Actor Store monetization UI:

| Event name | Title | Description | Suggested price |
|---|---|---|---:|
| `audit-complete` | Completed audit | Charged once after an audit finishes successfully | $0.25 |
| `target-audited` | Audited target | Charged for each MCP, OpenAPI, or Actor target audited | $0.10 |
| `finding-created` | Audit finding | Charged for each emitted actionable finding | $0.02 |
| `report-exported` | Report export | Charged once for each generated report | $0.05 |

The runtime calls `Actor.charge({ eventName: 'audit-complete' })`; remaining event calls can be enabled for target and report-level billing in the monetized release.
