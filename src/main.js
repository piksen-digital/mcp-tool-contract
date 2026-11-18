import { Actor } from 'apify';
import yaml from 'js-yaml';
import { ProxyAgent, fetch as undiciFetch } from 'undici';
import { fetchText } from './fetch.js';

const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };

function finding(target, category, severity, status, ruleId, title, message, evidence = {}, remediation = '', docsUrl = '') {
  return {
    id: `${target.name || target.url || target.actorId || 'target'}:${ruleId}:${Date.now()}`,
    targetName: target.name || target.url || target.actorId || 'Unnamed target',
    targetType: target.type || 'auto',
    targetUrl: target.url || target.actorId || '',
    ruleId,
    category,
    severity,
    status,
    title,
    message,
    evidence,
    remediation,
    docsUrl,
    timestamp: new Date().toISOString(),
  };
}

function inferType(target) {
  if (target.type && target.type !== 'auto') return target.type;
  const value = String(target.url || target.actorId || '').toLowerCase();
  if (value.includes('openapi') || value.endsWith('.yaml') || value.endsWith('.yml') || value.endsWith('.json')) return 'openapi';
  if (value.includes('/mcp') || value.includes('mcp.apify.com')) return 'mcp';
  if (target.actorId || /^[^/]+\/[^/]+$/.test(value)) return 'apify-actor';
  return 'openapi';
}


function parseOpenApi(text) {
  const trimmed = text.trim();
  return trimmed.startsWith('{') ? JSON.parse(trimmed) : yaml.load(trimmed);
}

function auditOpenApi(target, spec, findings) {
  const checks = [
    ['OPENAPI_VERSION', 'contracts', 'high', 'Use OpenAPI 3.0 or 3.1', spec.openapi && /^3\.[01]\./.test(spec.openapi)],
    ['OPENAPI_INFO', 'contracts', 'medium', 'Include an info.title and info.description', Boolean(spec.info?.title && spec.info?.description)],
    ['OPENAPI_OPERATIONS', 'contracts', 'high', 'At least one documented operation must exist', Boolean(spec.paths && Object.values(spec.paths).some(path => path && ['get','post','put','patch','delete','options','head'].some(method => Boolean(path[method]))))],
  ];
  for (const [ruleId, category, severity, title, passed] of checks) {
    findings.push(passed
      ? finding(target, category, 'low', 'pass', ruleId, title, 'Check passed', { passed: true })
      : finding(target, category, severity, 'fail', ruleId, title, 'Required contract metadata is missing', { passed: false }, 'Add the missing OpenAPI metadata and constrained operation schemas.', 'https://spec.openapis.org/'));
  }

  for (const [pathName, pathItem] of Object.entries(spec.paths || {})) {
    for (const method of ['get','post','put','patch','delete','options','head']) {
      const operation = pathItem?.[method];
      if (!operation) continue;
      const rule = `${method.toUpperCase()} ${pathName}`;
      if (!operation.summary && !operation.description) {
        findings.push(finding(target, 'agent-ready', 'medium', 'fail', 'OPERATION_DESCRIPTION', rule, 'Operation is missing a summary or description', { operation: rule }, 'Add a concise summary and behavioral description for agent callers.'));
      }
      if (!operation.operationId) {
        findings.push(finding(target, 'contracts', 'medium', 'fail', 'OPERATION_ID', rule, 'Operation ID is missing', { operation: rule }, 'Add a stable, unique operationId.'));
      }
      for (const parameter of operation.parameters || []) {
        if (!parameter.description) findings.push(finding(target, 'contracts', 'medium', 'fail', 'PARAMETER_DESCRIPTION', rule, 'A parameter is missing a description', { name: parameter.name }, 'Describe the parameter and its allowed values.'));
        if (!parameter.schema?.enum && !parameter.schema?.pattern && !parameter.schema?.minimum && !parameter.schema?.maximum && parameter.schema?.type === 'string') {
          findings.push(finding(target, 'contracts', 'low', 'warn', 'STRING_CONSTRAINT', rule, 'A string parameter has no enum or pattern constraint', { name: parameter.name }, 'Add enum, pattern, format, or length constraints where applicable.'));
        }
      }
    }
  }
}

function auditMcpHeaders(target, response, text, findings) {
  const paymentRequired = response.headers.get('payment-required');
  const x402 = response.headers.has('payment-required') || /x402|PAYMENT-REQUIRED/i.test(text);
  findings.push(finding(target, 'x402', x402 ? 'low' : 'medium', x402 ? 'pass' : 'warn', 'X402_DECLARATION', 'x402 declaration', x402 ? 'An x402 payment declaration was detected.' : 'No x402 payment declaration was detected.', { x402, paymentRequired: paymentRequired || null }, x402 ? '' : 'Declare PAYMENT-REQUIRED using the x402 protocol when a paid tool is invoked.'));

  const contentType = response.headers.get('content-type') || '';
  findings.push(finding(target, 'contracts', contentType.includes('application/json') || contentType.includes('text/event-stream') ? 'low' : 'medium', contentType.includes('application/json') || contentType.includes('text/event-stream') ? 'pass' : 'warn', 'MCP_CONTENT_TYPE', 'MCP response content type', `Content-Type: ${contentType || 'missing'}`, { contentType }, 'Use application/json or text/event-stream for MCP HTTP transport.'));
}

function auditMcpToolList(target, payload, findings) {
  const tools = payload?.result?.tools || payload?.tools || [];
  if (!Array.isArray(tools) || tools.length === 0) {
    findings.push(finding(target, 'contracts', 'high', 'fail', 'MCP_TOOLS_EMPTY', 'MCP tool discovery', 'The endpoint did not return a tools/list payload.', {}, 'Expose a valid tools/list result containing tool names and input schemas.'));
    return;
  }
  for (const tool of tools) {
    const label = tool.name || 'unnamed-tool';
    if (!tool.name) findings.push(finding(target, 'contracts', 'high', 'fail', 'MCP_TOOL_NAME', label, 'A tool has no name.', { tool }, 'Assign a stable tool name.'));
    if (!tool.description) findings.push(finding(target, 'agent-ready', 'medium', 'fail', 'MCP_TOOL_DESCRIPTION', label, 'A tool description is missing.', { tool }, 'Describe the tool action, inputs, outputs, and limitations.'));
    if (!tool.inputSchema) findings.push(finding(target, 'contracts', 'high', 'fail', 'MCP_INPUT_SCHEMA', label, 'A tool is missing an inputSchema.', { tool }, 'Define a JSON Schema input contract.'));
    if (tool.annotations?.readOnlyHint === true && tool.annotations?.openWorldHint === true) findings.push(finding(target, 'agent-ready', 'medium', 'warn', 'MCP_HINT_CONFLICT', label, 'The tool is marked read-only and open-world.', { annotations: tool.annotations }, 'Verify readOnlyHint and openWorldHint describe the actual side effects and external reachability.'));
  }
}

function createSummary(findings) {
  const counts = { pass: 0, warn: 0, fail: 0 };
  for (const item of findings) counts[item.status] = (counts[item.status] || 0) + 1;
  const lines = ['# MCP Tool-Contract Audit Summary', '', `Generated: ${new Date().toISOString()}`, '', `| Pass | Warn | Fail |`, '|---:|---:|---:|', `| ${counts.pass} | ${counts.warn} | ${counts.fail} |`, '', '## Findings', ''];
  for (const item of findings) lines.push(`- **${item.status.toUpperCase()}** ${item.severity} — ${item.targetName}: ${item.title}: ${item.message}`);
  return lines.join('\n');
}

function createSarif(findings) {
  return {
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'MCP Tool-Contract Auditor', informationUri: 'https://docs.apify.com', rules: findings.map(f => ({ id: f.ruleId, name: f.ruleId, shortDescription: { text: f.title }, helpUri: f.docsUrl || undefined, defaultConfiguration: { level: f.severity === 'high' || f.severity === 'critical' ? 'error' : 'warning' } })) } }, results: findings.filter(f => f.status !== 'pass').map(f => ({ ruleId: f.ruleId, level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning', message: { text: f.message }, properties: { category: f.category, target: f.targetName } })) }]
  };
}

function escapeXml(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function createJUnit(findings) {
  const failures = findings.filter(f => f.status === 'fail');
  const tests = findings.length;
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="mcp-tool-contract" tests="${tests}" failures="${failures.length}" errors="0">\n${findings.filter(f => f.status !== 'pass').map(f => `  <testcase classname="${escapeXml(f.category)}" name="${escapeXml(`${f.targetName}: ${f.ruleId}`)}"><failure type="${escapeXml(f.severity)}" message="${escapeXml(f.message)}">${escapeXml(f.remediation)}</failure></testcase>`).join('\n')}\n</testsuite>\n`;
}

await Actor.init();

try {
  const input = await Actor.getInput() || {};
  if (!Array.isArray(input.targets) || input.targets.length === 0) throw new Error('Input must include at least one target.');

  const timeoutMs = (input.requestTimeoutSecs || 30) * 1000;
  const maxRedirects = input.maxRedirects ?? 5;
  const findings = [];

  const ALL_CATEGORIES = ['contracts', 'agent-ready', 'x402', 'store', 'security'];
  const enabledChecks = new Set(
    Array.isArray(input.checks) && input.checks.length > 0 ? input.checks : ALL_CATEGORIES
  );
  const filterByChecks = (items) =>
    items.filter((f) => enabledChecks.has(f.category) || f.ruleId === 'TARGET_FETCH_ERROR');

  let fetchImpl = fetch;
  if (input.proxyConfiguration && Object.keys(input.proxyConfiguration || {}).length > 0) {
    try {
      const proxyConfiguration = await Actor.createProxyConfiguration(input.proxyConfiguration);
      const proxyUrl = proxyConfiguration ? await proxyConfiguration.newUrl() : null;
      if (proxyUrl) {
        const dispatcher = new ProxyAgent(proxyUrl);
        fetchImpl = (url, opts = {}) => undiciFetch(url, { ...opts, dispatcher });
      }
    } catch (error) {
      throw new Error(`Proxy configuration requested but could not be created: ${error.message}`);
    }
  }

  for (const rawTarget of input.targets) {
    const target = { ...rawTarget, type: inferType(rawTarget) };
    if (input.dryRun) {
      findings.push(finding(target, 'contracts', 'low', 'pass', 'DRY_RUN_TARGET', 'Dry-run validation', 'Target structure is valid; network access was skipped.', { target }));
      continue;
    }

    try {
      if (target.type === 'apify-actor') {
        const actorId = target.actorId || String(target.url || '').split('/').slice(-1)[0];
        if (!actorId) throw new Error('Apify Actor target requires actorId or an Actor URL.');
        const apifyUrl = `https://api.apify.com/v2/acts/${encodeURIComponent(actorId)}?omit=readme`;
        const { response, text } = await fetchText(apifyUrl, timeoutMs, maxRedirects, fetchImpl);
        const actor = JSON.parse(text)?.data || {};
        const passedTitle = Boolean(actor.title);
        const passedDescription = Boolean(actor.description);
        const passedInput = Boolean(actor.inputSchema);
        findings.push(finding(target, 'store', passedDescription && passedTitle ? 'low' : 'medium', passedDescription && passedTitle ? 'pass' : 'fail', 'ACTOR_STORE_METADATA', 'Actor Store metadata', 'Checked Actor title and description.', { title: actor.title, descriptionPresent: passedDescription, titlePresent: passedTitle }, 'Complete title, description, and KYC/safety settings in Apify Console.'));
        findings.push(finding(target, 'contracts', passedInput ? 'low' : 'high', passedInput ? 'pass' : 'fail', 'ACTOR_INPUT_SCHEMA', 'Actor input schema', 'Checked whether an input schema is published.', { inputSchemaPresent: passedInput }, 'Publish an input schema and use constrained JSON Schema fields.'));
      } else {
        const url = target.url;
        if (!url) throw new Error(`${target.type} target requires url.`);
        const { response, text } = await fetchText(url, timeoutMs, maxRedirects, fetchImpl);
        if (target.type === 'openapi') {
          const spec = parseOpenApi(text);
          auditOpenApi(target, spec, findings);
        } else {
          auditMcpHeaders(target, response, text, findings);
          try {
            const payload = JSON.parse(text);
            auditMcpToolList(target, payload, findings);
          } catch {
            findings.push(finding(target, 'contracts', 'high', 'warn', 'MCP_RESPONSE_FORMAT', 'MCP response format', 'The endpoint did not return immediately parseable JSON; it may require a JSON-RPC POST.', { contentType: response.headers.get('content-type') }, 'Call tools/list using the MCP JSON-RPC transport or MCP Streamable HTTP protocol.'));
          }
        }
      }
    } catch (error) {
      findings.push(finding(target, 'security', 'critical', 'fail', 'TARGET_FETCH_ERROR', 'Target could not be audited', error.message, {}, 'Verify the URL, transport, authentication, redirects, and network access.'));
    }
  }

  const filteredFindings = filterByChecks(findings);
  const includePassing = input.includePassingChecks !== false;
  const datasetFindings = includePassing ? filteredFindings : filteredFindings.filter(f => f.status !== 'pass');
  const reportFindings = datasetFindings;
  for (const item of datasetFindings) await Actor.pushData(item);

  await Actor.setValue('results.json', filteredFindings, { contentType: 'application/json' });
  if ((input.exportFormats || []).includes('summary')) await Actor.setValue('SUMMARY.md', createSummary(reportFindings), { contentType: 'text/markdown' });
  if ((input.exportFormats || []).includes('sarif')) await Actor.setValue('results.sarif', createSarif(reportFindings), { contentType: 'application/sarif+json' });
  if ((input.exportFormats || []).includes('junit')) await Actor.setValue('junit.xml', createJUnit(reportFindings), { contentType: 'application/xml' });

  await Actor.charge({ eventName: 'audit-complete' }).catch(() => {});

  await Actor.setValue('OUTPUT', {
    summary: 'SUMMARY.md',
    findingsCount: filteredFindings.length,
    passed: filteredFindings.filter(f => f.status === 'pass').length,
    warnings: filteredFindings.filter(f => f.status === 'warn').length,
    failures: filteredFindings.filter(f => f.status === 'fail').length,
  });

  const failThreshold = input.failOn || 'high';
  const failRank = severityRank[failThreshold] || 3;
  const shouldFail = failThreshold !== 'none' && filteredFindings.some(f => f.status === 'fail' && severityRank[f.severity] >= failRank);
  if (shouldFail) throw new Error(`Audit failed because one or more findings reached ${failThreshold} severity.`);

  await Actor.exit();
} catch (error) {
  await Actor.fail(error);
}
