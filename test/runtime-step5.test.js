import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const src = fs.readFileSync("src/main.js", "utf8");
const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
const schema = JSON.parse(fs.readFileSync(".actor/input_schema.json", "utf8"));

test("undici is a declared direct dependency", () => {
  assert.ok(pkg.dependencies.undici, "undici must be in dependencies, not just transitive");
});

test("runtime imports undici ProxyAgent and fetch", () => {
  assert.match(src, /import \{ ProxyAgent, fetch as undiciFetch \} from 'undici'/);
});

test("fetchText routes through an injectable fetchImpl", () => {
  const fetchSrc = fs.readFileSync("src/fetch.js", "utf8");
  assert.match(src, /from '\.\/fetch\.js'/);
  assert.match(fetchSrc, /async function fetchText\(url, timeoutMs, maxRedirects, fetchImpl = fetch\)/);
  assert.match(fetchSrc, /await fetchImpl\(currentUrl/);
});

test("proxyConfiguration is converted to a ProxyAgent dispatcher", () => {
  assert.match(src, /Actor\.createProxyConfiguration/);
  assert.match(src, /new ProxyAgent\(proxyUrl\)/);
  assert.match(src, /undiciFetch\(url, \{ \.\.\.opts, dispatcher \}\)/);
});

test("checks filter is derived from input.checks with all categories as default", () => {
  assert.match(src, /const ALL_CATEGORIES = \['contracts', 'agent-ready', 'x402', 'store', 'security'\]/);
  assert.match(src, /enabledChecks = new Set/);
  assert.match(src, /filterByChecks/);
});

test("TARGET_FETCH_ERROR bypasses checks filter", () => {
  assert.match(src, /f\.ruleId === 'TARGET_FETCH_ERROR'/);
});

test("dataset respects includePassingChecks", () => {
  assert.match(src, /datasetFindings = includePassing \? filteredFindings : filteredFindings\.filter/);
  assert.match(src, /for \(const item of datasetFindings\) await Actor\.pushData/);
});

test("results.json and OUTPUT use filteredFindings", () => {
  assert.match(src, /Actor\.setValue\('results\.json', filteredFindings/);
  assert.match(src, /findingsCount: filteredFindings\.length/);
  assert.match(src, /const shouldFail = .*filteredFindings\.some/);
});

test("schema keeps checks and proxyConfiguration as documented fields", () => {
  assert.ok(schema.properties.checks, "checks must exist in schema");
  assert.ok(schema.properties.proxyConfiguration, "proxyConfiguration must exist in schema");
});
