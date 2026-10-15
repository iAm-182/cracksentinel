// schema-depth.js — probe local MCP servers via stdio, measure tool inputSchema nesting depth
// Usage: node schema-depth.js
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const SERVERS = [
  { name: 'blitzstrike', cmd: 'node', args: ['E:/ilham_yarsi/lab-cve/blitzstrike/dist/index.js', 'serve', '--mcp'] },
  { name: 'rea', cmd: 'cmd.exe', args: ['/d', '/c', 'npx -y rea-agents@6.5.0 mcp'] },
  { name: 'yowes', cmd: 'C:\\Users\\USER\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\yowes-mcp.exe', args: [] },
  { name: 'agentmemory', cmd: 'cmd.exe', args: ['/d', '/c', 'npx -y @agentmemory/mcp'] },
];

const TIMEOUT_MS = 180000;
const PROTOCOL_VERSION = '2024-11-05';

// depth = 0 for leaf schema; every nested schema container adds 1
function schemaDepth(node) {
  if (node === null || typeof node !== 'object') return 0;
  let max = 0;
  for (const key of ['properties', '$defs', 'definitions', 'patternProperties']) {
    if (node[key] && typeof node[key] === 'object' && !Array.isArray(node[key])) {
      for (const v of Object.values(node[key])) max = Math.max(max, 1 + schemaDepth(v));
    }
  }
  for (const key of ['items', 'additionalProperties', 'contains', 'propertyNames', 'if', 'then', 'else', 'not']) {
    if (node[key] && typeof node[key] === 'object' && !Array.isArray(node[key])) {
      max = Math.max(max, 1 + schemaDepth(node[key]));
    }
  }
  for (const key of ['anyOf', 'oneOf', 'allOf', 'prefixItems']) {
    if (Array.isArray(node[key])) {
      for (const v of node[key]) max = Math.max(max, 1 + schemaDepth(v));
    }
  }
  return max;
}

function probeServer(server) {
  return new Promise((resolve) => {
    const started = Date.now();
    let child;
    try {
      child = spawn(server.cmd, server.args, { stdio: ['pipe', 'pipe', 'pipe'], env: process.env });
    } catch (e) {
      resolve({ name: server.name, error: 'spawn failed: ' + e.message, tools: [] });
      return;
    }
    let buf = '';
    const tools = [];
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      try { child.kill(); } catch (e) {}
      resolve(result);
    };
    child.stdout.on('data', (d) => {
      buf += d.toString();
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch (e) { continue; }
        if (msg.id === 1 && msg.result) {
          try {
            child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
            child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) + '\n');
          } catch (e) {}
        }
        if (msg.id === 2 && msg.result && Array.isArray(msg.result.tools)) {
          for (const t of msg.result.tools) {
            tools.push({ name: t.name, depth: schemaDepth(t.inputSchema || {}) });
          }
          finish({ name: server.name, toolCount: tools.length, elapsedMs: Date.now() - started, tools: tools.sort((a, b) => b.depth - a.depth) });
          return;
        }
      }
    });
    child.stderr.on('data', () => {});
    child.on('error', (e) => finish({ name: server.name, error: 'process error: ' + e.message, tools: [] }));
    child.on('exit', (code) => finish({ name: server.name, error: 'exited before tools/list, code=' + code, tools: [] }));
    try {
      child.stdin.write(JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'initialize',
        params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'schema-depth-probe', version: '1.0.0' } },
      }) + '\n');
    } catch (e) {
      finish({ name: server.name, error: 'stdin write failed: ' + e.message, tools: [] });
      return;
    }
    setTimeout(() => finish({ name: server.name, toolCount: tools.length, elapsedMs: Date.now() - started, error: 'timeout', tools: tools.sort((a, b) => b.depth - a.depth) }), TIMEOUT_MS);
  });
}

(async () => {
  const results = await Promise.all(SERVERS.map(probeServer));
  const report = {};
  const lines = [];
  for (const r of results) {
    if (!r.tools || r.tools.length === 0) {
      lines.push(`[${r.name}] ERROR: ${r.error || 'no tools returned'}`);
      report[r.name] = { error: r.error || 'no tools returned' };
      continue;
    }
    lines.push(`[${r.name}] ${r.toolCount} tools, ${r.elapsedMs}ms${r.error ? ' (' + r.error + ')' : ''}`);
    for (const t of r.tools.slice(0, 15)) lines.push(`  ${String(t.depth).padStart(3)}  ${t.name}`);
    report[r.name] = { toolCount: r.toolCount, elapsedMs: r.elapsedMs, error: r.error || null, tools: r.tools };
  }
  fs.writeFileSync(path.join(__dirname, 'schema-depth-report.json'), JSON.stringify(report, null, 2));
  console.log(lines.join('\n'));
  const offenders = [];
  for (const r of results) for (const t of (r.tools || [])) if (t.depth > 10) offenders.push(`${r.name}:${t.name} (${t.depth})`);
  console.log('\nOFFENDERS >10 (' + offenders.length + '): ' + (offenders.length ? offenders.join(', ') : 'none'));
  console.log('Report: ' + path.join(__dirname, 'schema-depth-report.json'));
})();
