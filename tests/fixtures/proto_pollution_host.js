'use strict';
// Prototype-pollution oracle host for T11.4 (SAM1-22) — a Node.js 2026-07-28 MCP HTTP host.
// Run as: node proto_pollution_host.js <vuln|safe>  (prints "PORT <n>" once listening).
// VulnerableHost deep-merges attacker JSON with the classic recursive merge (pollutable via
// __proto__); SafeHost skips __proto__/constructor/prototype. prototype_probe() is the ground-truth
// oracle: it observes a FRESH, server-owned {} (NOT the attacker's payload) and a default user.
const http = require('http');

const MODE = process.argv[2] === 'safe' ? 'safe' : 'vuln';
const PV = '2026-07-28';
const settings = {};                                   // the server config (merge target)

function merge(t, s) {                                  // VULNERABLE recursive merge
  for (const k of Object.keys(s)) {
    if (s[k] && typeof s[k] === 'object') { if (!t[k]) t[k] = {}; merge(t[k], s[k]); }
    else t[k] = s[k];
  }
}
function safeMerge(t, s) {                              // skips the prototype-reaching keys
  for (const k of Object.keys(s)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (s[k] && typeof s[k] === 'object') { if (!t[k]) t[k] = {}; safeMerge(t[k], s[k]); }
    else t[k] = s[k];
  }
}
function defaultUser() { return { name: 'guest' }; }   // no role set -> .isAdmin only via pollution

const ok = (id, text) => ({ jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text }] } });
const err = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', () => {
    const send = (status, obj) => {
      const b = JSON.stringify(obj);
      res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) });
      res.end(b);
    };
    let msg;
    try { msg = JSON.parse(body || '{}'); } catch { return send(400, err(null, -32700, 'parse')); }
    const id = msg.id, params = msg.params || {}, meta = params._meta || {};
    if (req.headers['mcp-protocol-version'] !== PV || meta['io.modelcontextprotocol/protocolVersion'] !== PV) {
      return send(400, err(id, -32022, 'bad/missing protocol version'));
    }
    if (msg.method !== 'tools/call') return send(400, err(id, -32601, 'method not found'));
    const name = params.name, args = params.arguments || {};
    if (name === 'update_settings') {
      (MODE === 'vuln' ? merge : safeMerge)(settings, args.patch || {});
      return send(200, ok(id, 'settings updated'));
    }
    if (name === 'prototype_probe') {
      const fresh = {};                                // a FRESH, server-owned object
      return send(200, ok(id, JSON.stringify({
        pp_canary: fresh.pp_canary === undefined ? null : fresh.pp_canary,
        default_user_is_admin: defaultUser().isAdmin === true,
      })));
    }
    if (name === 'get_settings') {
      return send(200, ok(id, JSON.stringify({ theme: settings.theme === undefined ? null : settings.theme })));
    }
    return send(400, err(id, -32601, `unknown tool ${name}`));
  });
});

server.listen(0, '127.0.0.1', () => { process.stdout.write(`PORT ${server.address().port}\n`); });
