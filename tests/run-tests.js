#!/usr/bin/env node
'use strict';
/*
 * Automated checks for the Network Traffic Triage Tool.
 *
 * This file is a development aid, not part of the web application. It exists so
 * that the claims in the README ("normal traffic produces no findings", "the
 * high-volume capture trips Rule 1") can be verified by running one command
 * instead of being taken on trust.
 *
 * Run it with:   node tests/run-tests.js
 * It needs no dependencies: Node.js reads script.js, which exposes its pure
 * functions when there is no browser around.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const NTT = require(path.join(ROOT, 'script.js'));

let passed = 0;
let failed = 0;
const failures = [];

function check(name, condition, detail) {
  if (condition) {
    passed += 1;
    console.log('  PASS  ' + name);
  } else {
    failed += 1;
    failures.push(name + (detail ? ' -> ' + detail : ''));
    console.log('  FAIL  ' + name + (detail ? ' -> ' + detail : ''));
  }
}

function group(title) {
  console.log('\n' + title);
}

function readSample(file) {
  return fs.readFileSync(path.join(ROOT, 'samples', file), 'utf8');
}

function loadSample(file) {
  const parse = NTT.parseCapture(readSample(file));
  return { parse, report: parse.ok ? NTT.analyse(parse.packets, NTT.DEFAULTS) : null };
}

function rulesFired(report) {
  return report.findings.map((f) => f.ruleId);
}

function findRule(report, ruleId) {
  return report.findings.find((f) => f.ruleId === ruleId);
}

/* ===========================================================================
 * 1. SAMPLE DATA BEHAVIOUR
 * ======================================================================== */

group('1. Sample captures behave as documented');

const normal = loadSample('normal-traffic.csv');
check('normal-traffic.csv parses', normal.parse.ok, normal.parse.error);
check('normal-traffic.csv loads 58 packets', normal.parse.packets.length === 58,
  'got ' + normal.parse.packets.length);
check('normal-traffic.csv produces no findings', normal.report.findings.length === 0,
  'got ' + normal.report.findings.length + ': ' + rulesFired(normal.report).join(', '));
check('normal-traffic.csv scores 0 with the "No findings" label',
  normal.report.score.total === 0 && normal.report.score.label === 'No findings',
  normal.report.score.total + ' / ' + normal.report.score.label);
check('normal-traffic.csv busiest host is under the default threshold of 50',
  normal.report.stats.mostActiveSource.count < NTT.DEFAULTS.packetsPerSource,
  'busiest = ' + normal.report.stats.mostActiveSource.count);
check('normal-traffic.csv reports a protocol distribution',
  normal.report.stats.protocolFamilies.length >= 5,
  'families = ' + normal.report.stats.protocolFamilies.length);
check('normal-traffic.csv has an average packet length',
  typeof normal.report.stats.averageLength === 'number');

const high = loadSample('high-volume-traffic.csv');
check('high-volume-traffic.csv parses', high.parse.ok, high.parse.error);
const highRule1 = findRule(high.report, 'high_packet_volume');
check('Rule 1 (high packet volume) fires on the high-volume capture', !!highRule1);
check('Rule 1 observed value is 183 packets from 192.168.1.25',
  highRule1 && highRule1.source === '192.168.1.25' && highRule1.observed === 183,
  highRule1 ? highRule1.source + ' / ' + highRule1.observed : 'no finding');
check('Rule 1 quotes the configured threshold of 50', highRule1 && highRule1.threshold === 50);
check('Rule 1 severity is Medium for 3.66x the threshold', highRule1 && highRule1.severity === 'Medium',
  highRule1 ? highRule1.severity : 'no finding');
check('Rule 6 also fires (a big transfer is repetitive too)',
  rulesFired(high.report).indexOf('repeated_pair') !== -1, rulesFired(high.report).join(', '));
check('high-volume capture does not trip the scanning rules',
  rulesFired(high.report).indexOf('many_destinations') === -1 &&
  rulesFired(high.report).indexOf('many_ports') === -1);
check('high-volume score label is "Elevated Activity"', high.report.score.label === 'Elevated Activity',
  high.report.score.label);

const mixed = loadSample('mixed-soc-lab.csv');
check('mixed-soc-lab.csv parses', mixed.parse.ok, mixed.parse.error);
check('mixed-soc-lab.csv loads 296 packets', mixed.parse.packets.length === 296,
  'got ' + mixed.parse.packets.length);
check('mixed-soc-lab.csv triggers all seven rules',
  ['high_packet_volume', 'many_destinations', 'many_ports', 'high_icmp', 'high_dns', 'repeated_pair', 'syn_heavy']
    .every((id) => rulesFired(mixed.report).indexOf(id) !== -1),
  'fired: ' + rulesFired(mixed.report).join(', '));

const mixedScan = findRule(mixed.report, 'many_destinations');
check('Rule 2 fires for 172.16.5.20 with 27 unique destinations',
  mixedScan && mixedScan.source === '172.16.5.20' && mixedScan.observed === 27,
  mixedScan ? mixedScan.source + ' / ' + mixedScan.observed : 'no finding');
check('Rule 2 severity is Medium for 2.7x the threshold', mixedScan && mixedScan.severity === 'Medium');

const mixedPorts = findRule(mixed.report, 'many_ports');
check('Rule 3 fires with 15 unique ports on one destination',
  mixedPorts && mixedPorts.observed === 15 && mixedPorts.destination === '192.168.1.40',
  mixedPorts ? mixedPorts.observed + ' / ' + mixedPorts.destination : 'no finding');

const mixedIcmp = findRule(mixed.report, 'high_icmp');
check('Rule 4 fires for 10.0.4.77 with 45 ICMP packets',
  mixedIcmp && mixedIcmp.source === '10.0.4.77' && mixedIcmp.observed === 45);

const mixedDns = findRule(mixed.report, 'high_dns');
check('Rule 5 fires for 10.0.4.90 with 34 DNS packets',
  mixedDns && mixedDns.source === '10.0.4.90' && mixedDns.observed === 34);

const mixedSyn = findRule(mixed.report, 'syn_heavy');
check('Rule 7 fires for 10.0.4.88 with 45 SYN packets',
  mixedSyn && mixedSyn.source === '10.0.4.88' && mixedSyn.observed === 45);
check('Rule 7 notes that no SYN/ACK replies were seen',
  mixedSyn && mixedSyn.notes.join(' ').indexOf('No SYN/ACK replies') !== -1);

check('mixed-soc-lab score equals the sum of its contributions',
  mixed.report.score.total === mixed.report.score.contributions.reduce((sum, c) => sum + c.points, 0));
check('every finding carries an explanation, benign options and next steps',
  mixed.report.findings.every((f) =>
    f.whyMatters && f.benign.length >= 3 && f.investigation.length >= 3 && f.evidence.length >= 4));
check('no finding claims that an attack occurred',
  mixed.report.findings.every((f) => {
    const text = (f.summary + ' ' + f.whyMatters + ' ' + f.notes.join(' ')).toLowerCase();
    return text.indexOf('attacker') === -1 && text.indexOf('infected') === -1;
  }));

/* ===========================================================================
 * 2. THRESHOLDS ARE CONFIGURABLE
 * ======================================================================== */

group('2. Thresholds really are configurable');

const strict = NTT.analyse(high.parse.packets, Object.assign({}, NTT.DEFAULTS, { packetsPerSource: 200 }));
check('raising the packet threshold above 183 removes the Rule 1 finding',
  !findRule(strict, 'high_packet_volume'));

const loose = NTT.analyse(normal.parse.packets, Object.assign({}, NTT.DEFAULTS, { packetsPerSource: 10 }));
check('lowering the packet threshold to 10 makes the quiet capture alert',
  !!findRule(loose, 'high_packet_volume'));

const noDests = NTT.analyse(mixed.parse.packets, Object.assign({}, NTT.DEFAULTS, { uniqueDestinations: 50 }));
check('raising the unique-destination threshold to 50 removes the Rule 2 finding',
  !findRule(noDests, 'many_destinations'));

const invalid = NTT.normaliseThresholds({ packetsPerSource: 'not a number', uniqueDestinations: -5 });
check('invalid threshold input falls back to the defaults',
  invalid.packetsPerSource === NTT.DEFAULTS.packetsPerSource &&
  invalid.uniqueDestinations === NTT.DEFAULTS.uniqueDestinations);

/* ===========================================================================
 * 3. CSV PARSING ROBUSTNESS
 * ======================================================================== */

group('3. CSV parsing');

const quoted = NTT.parseCsvText('"a","b"\r\n"1","Server Hello, Application Data"\r\n');
check('a comma inside a quoted field does not split the row',
  quoted.rows[1].length === 2 && quoted.rows[1][1] === 'Server Hello, Application Data',
  JSON.stringify(quoted.rows[1]));

const escaped = NTT.parseCsvText('"a"\r\n"he said ""hello"""\r\n');
check('doubled quotes become one literal quote',
  escaped.rows[1][0] === 'he said "hello"', JSON.stringify(escaped.rows[1]));

const crlf = NTT.parseCsvText('a,b\r\n1,2\r\n');
const lf = NTT.parseCsvText('a,b\n1,2\n');
check('CRLF and LF line endings give the same result',
  JSON.stringify(crlf.rows) === JSON.stringify(lf.rows));

const bom = NTT.parseCsvText('\uFEFF"No.","Source"\r\n"1","10.0.0.1"\r\n');
check('a UTF-8 byte order mark is stripped', bom.rows[0][0] === 'No.', JSON.stringify(bom.rows[0]));

const multiline = NTT.parseCsvText('"a","b"\r\n"1","line one\nline two"\r\n');
check('a line break inside quotes stays inside the field',
  multiline.rows[1][1] === 'line one\nline two', JSON.stringify(multiline.rows[1][1]));

const blank = NTT.parseCsvText('a,b\n\n1,2\n\n');
check('blank lines are ignored', blank.rows.length === 2, 'rows = ' + blank.rows.length);

check('an unterminated quote produces a warning, not a crash',
  NTT.parseCsvText('"a","b"\n"1","unterminated').warnings.length === 1);

/* ===========================================================================
 * 4. COLUMN NAMES AND MISSING FIELDS
 * ======================================================================== */

group('4. Column names and missing fields');

function captureFrom(header, rows) {
  return [header].concat(rows).join('\r\n') + '\r\n';
}

const aliasA = NTT.parseCapture(captureFrom('"Source IP","Destination IP","Protocol","Length","Info"',
  ['"10.0.0.1","10.0.0.2","TCP","74","1 -> 2 [SYN]"']));
check('headers "Source IP" / "Destination IP" are recognised', aliasA.ok, aliasA.error);

const aliasB = NTT.parseCapture(captureFrom('src,dst,proto,len,information',
  ['10.0.0.1,10.0.0.2,TCP,74,hello']));
check('headers "src" / "dst" / "proto" / "len" / "information" are recognised', aliasB.ok, aliasB.error);

const aliasC = NTT.parseCapture(captureFrom('ip.src,ip.dst,protocol_name,frame.length,info',
  ['10.0.0.1,10.0.0.2,UDP,90,hello']));
check('headers "ip.src" / "ip.dst" / "protocol_name" / "frame.length" are recognised', aliasC.ok, aliasC.error);

const noSource = NTT.parseCapture(captureFrom('"No.","Time","Destination","Protocol"',
  ['"1","0.1","10.0.0.2","TCP"']));
check('a missing Source column fails cleanly', noSource.ok === false);
check('the missing Source column produces the documented message',
  /does not appear to contain a Source address column/.test(noSource.error || ''), noSource.error);

const noDest = NTT.parseCapture(captureFrom('"Source","Protocol"', ['"10.0.0.1","TCP"']));
check('a missing Destination column produces the documented message',
  /does not appear to contain a Destination address column/.test(noDest.error || ''), noDest.error);

const noProtocol = NTT.parseCapture(captureFrom('"Source","Destination"', ['"10.0.0.1","10.0.0.2"']));
check('a capture without a Protocol column still parses', noProtocol.ok);
const noProtocolReport = NTT.analyse(noProtocol.packets, NTT.DEFAULTS);
check('four rules are reported as not evaluated without a Protocol column',
  noProtocolReport.ruleStatus.filter((r) => r.status === 'not_evaluated').length === 4,
  JSON.stringify(noProtocolReport.ruleStatus.filter((r) => r.status === 'not_evaluated').map((r) => r.id)));
check('optional columns are listed as missing',
  noProtocol.columns.missingOptional.indexOf('protocol') !== -1 &&
  noProtocol.columns.missingOptional.indexOf('info') !== -1);

const noInfo = NTT.parseCapture(captureFrom('"Source","Destination","Protocol"',
  ['"10.0.0.1","10.0.0.2","TCP"', '"10.0.0.2","10.0.0.1","TCP"']));
const noInfoReport = NTT.analyse(noInfo.packets, NTT.DEFAULTS);
check('port and SYN rules are reported as not evaluated without an Info column',
  noInfoReport.ruleStatus.filter((r) => r.id === 'many_ports' || r.id === 'syn_heavy')
    .every((r) => r.status === 'not_evaluated'));

/* ===========================================================================
 * 5. MALFORMED INPUT FAILS SAFELY
 * ======================================================================== */

group('5. Malformed input fails safely (no crashes)');

const badInputs = [
  ['empty string', ''],
  ['only whitespace', '   \n\n  '],
  ['header only', '"No.","Time","Source","Destination","Protocol","Length","Info"\n'],
  ['plain English text', 'This is not a CSV file at all.\nJust some sentences.\n'],
  ['semicolon separated', 'No.;Time;Source;Destination\n1;0.1;10.0.0.1;10.0.0.2\n'],
  ['html document', '<html><body><h1>Not a capture</h1></body></html>'],
  ['nul bytes', 'a,b,c\u0000d\n1,2,3\n'],
  ['very long single line', 'x'.repeat(5000)],
  ['unterminated quote', '"No.","Source","Destination"\n"1","10.0.0.1","10.0.0.2'],
  ['rows with empty addresses', '"Source","Destination"\n"",""\n"10.0.0.1",""\n'],
  ['numeric header', '1,2,3\n4,5,6\n']
];

badInputs.forEach(function (pair) {
  let threw = false;
  let result = null;
  try {
    result = NTT.parseCapture(pair[1]);
  } catch (error) {
    threw = true;
  }
  check('parseCapture survives: ' + pair[0], !threw && result !== null && typeof result.ok === 'boolean');
});

const garbage = NTT.parseCapture('not,a,capture\n1,2,3\n');
check('a file with unrelated columns is rejected with a readable reason',
  garbage.ok === false && typeof garbage.error === 'string' && garbage.error.length > 20, garbage.error);

/* ===========================================================================
 * 6. UNTRUSTED INPUT AND PRIVACY (static checks on the shipped files)
 * ======================================================================== */

group('6. Untrusted input, injection and privacy');

const scriptSource = fs.readFileSync(path.join(ROOT, 'script.js'), 'utf8');
const htmlSource = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const cssSource = fs.readFileSync(path.join(ROOT, 'styles.css'), 'utf8');

/* Comments in this project talk ABOUT innerHTML and fetch in order to explain
 * why they are not used, so the static checks below run against the code with
 * comments stripped out. Only real code counts. */
const scriptCode = scriptSource
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/^\s*\/\/.*$/gm, ' ');
const htmlText = htmlSource.replace(/\s+/g, ' ');

['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function',
  'setTimeout("'].forEach(function (pattern) {
  check('script.js does not use ' + pattern, scriptCode.indexOf(pattern) === -1);
});

check('script.js renders CSV values through textContent', scriptCode.indexOf('textContent') !== -1);

['fetch(', 'XMLHttpRequest', 'WebSocket', 'sendBeacon', 'localStorage', 'sessionStorage',
  'document.cookie', 'navigator.geolocation', 'importScripts'].forEach(function (pattern) {
  check('script.js does not use ' + pattern, scriptCode.indexOf(pattern) === -1);
});

check('index.html has no inline event handlers (onclick= etc.)',
  !/\son[a-z]+\s*=\s*["']/i.test(htmlSource));
check('index.html loads no external scripts or styles',
  !/<(script|link)[^>]+(src|href)\s*=\s*["']https?:/i.test(htmlSource));
check('index.html contains no iframes or tracking pixels',
  htmlSource.indexOf('<iframe') === -1 && htmlSource.indexOf('<img') === -1);
check('the privacy statement is present in the page',
  htmlText.indexOf('analysed locally in your browser and is not uploaded anywhere') !== -1);
check('the educational disclaimer is present in the page',
  htmlText.indexOf('do not prove malicious behaviour') !== -1);
check('the authorisation reminder is present in the page',
  htmlText.indexOf('you own or are authorised to monitor') !== -1);
check('styles.css loads no external fonts or images',
  !/@import|url\(\s*["']?https?:/i.test(cssSource));

/* A hostile CSV must not break the analysis or escape into the page. */
const hostile = captureFrom('"No.","Time","Source","Destination","Protocol","Length","Info"',
  ['"1","0.1","<img src=x onerror=alert(1)>","<script>alert(2)</script>","TCP","74","<svg onload=alert(3)>"]',
    '"2","0.2","10.0.0.1","10.0.0.2","TCP","74","x \u2192 443 [SYN] Seq=0"']);
const hostileParse = NTT.parseCapture(hostile);
check('a hostile CSV still parses without throwing', hostileParse.ok, hostileParse.error);
const hostileReport = NTT.analyse(hostileParse.packets, NTT.DEFAULTS);
check('the hostile payload is kept as plain text, not interpreted',
  hostileReport.stats.sourceCounts.has('<img src=x onerror=alert(1)>'));
check('analysis of a hostile capture completes',
  hostileReport.findings.every((f) => typeof f.summary === 'string'));

/* Prototype pollution attempt: a host literally called "__proto__". */
const proto = NTT.parseCapture(captureFrom('"Source","Destination","Protocol"',
  ['"__proto__","10.0.0.2","TCP"', '"__proto__","10.0.0.3","TCP"', '"__proto__","10.0.0.4","TCP"']));
const protoReport = NTT.analyse(proto.packets, Object.assign({}, NTT.DEFAULTS, { uniqueDestinations: 2 }));
check('a host named "__proto__" is counted like any other host',
  protoReport.stats.uniqueSources === 1 && protoReport.stats.mostActiveSource.key === '__proto__');
check('a host named "__proto__" does not pollute Object.prototype',
  typeof ({}).polluted === 'undefined' && Object.keys({}).length === 0);
check('the "__proto__" host still produces a Rule 2 finding',
  !!findRule(protoReport, 'many_destinations'));

/* ===========================================================================
 * 7. SMALL HELPERS
 * ======================================================================== */

group('7. Port, flag and protocol helpers');

check('the arrow form "52144 -> 443 [SYN]" gives ports 52144/443',
  JSON.stringify(NTT.extractPorts('52144 \u2192 443 [SYN] Seq=0', 'tcp')) ===
  JSON.stringify({ srcPort: 52144, dstPort: 443, guessed: false }));
check('the ASCII arrow form works too',
  NTT.extractPorts('52144 -> 443 [ACK]', 'tcp').dstPort === 443);
check('"Source port: 68  Destination port: 67" is understood',
  JSON.stringify(NTT.extractPorts('Source port: 68  Destination port: 67', 'udp')) ===
  JSON.stringify({ srcPort: 68, dstPort: 67, guessed: false }));
check('a TLS row with no ports falls back to 443 and is marked as a guess',
  NTT.extractPorts('Application Data', 'tls').dstPort === 443 &&
  NTT.extractPorts('Application Data', 'tls').guessed === true);
check('an unknown protocol with no ports yields nulls',
  NTT.extractPorts('something else', 'other').dstPort === null);

check('[SYN] is detected as a SYN', NTT.detectTcpFlags('1 \u2192 2 [SYN] Seq=0').syn === true);
check('[SYN, ACK] is detected as a reply, not a SYN',
  NTT.detectTcpFlags('2 \u2192 1 [SYN, ACK] Seq=0').syn === false &&
  NTT.detectTcpFlags('2 \u2192 1 [SYN, ACK] Seq=0').synAck === true);
check('a row with no flags reports no flags',
  NTT.detectTcpFlags('Application Data').anyFlag === false);

check('TLSv1.3 maps to the HTTPS/TLS family', NTT.protocolFamily('TLSv1.3') === 'tls');
check('ICMPv6 maps to the ICMP family', NTT.protocolFamily('ICMPv6') === 'icmp');
check('mDNS maps to the DNS family', NTT.protocolFamily('MDNS') === 'dns');
check('QUIC lands in Other', NTT.protocolFamily('QUIC') === 'other');
check('an empty protocol is Unknown', NTT.protocolFamily('') === 'unknown');

/* ===========================================================================
 * 8. THE PAGE AND ITS DEMO DATA FIT TOGETHER
 * ======================================================================== */

group('8. Page wiring and embedded demo data');

const embedded = {};
const embedRegex = /"([^"]+\.csv)": `([\s\S]*?)`,\n/g;
let match;
while ((match = embedRegex.exec(scriptSource)) !== null) {
  embedded[match[1]] = match[2];
}

const sampleFiles = fs.readdirSync(path.join(ROOT, 'samples')).filter((f) => f.endsWith('.csv')).sort();
check('there are exactly three sample CSV files', sampleFiles.length === 3, sampleFiles.join(', '));

sampleFiles.forEach(function (file) {
  const onDisk = readSample(file).replace(/\r\n/g, '\n');
  const inPage = (embedded[file] || '').replace(/\r\n/g, '\n');
  check('the embedded copy of ' + file + ' matches the file in samples/',
    inPage.length > 0 && inPage === onDisk,
    'page copy ' + inPage.length + ' chars, file ' + onDisk.length + ' chars');
});

const buttonSamples = (htmlSource.match(/data-sample="([^"]+)"/g) || [])
  .map((s) => s.replace(/data-sample="|"/g, ''));
check('the page has exactly three demo buttons', buttonSamples.length === 3, buttonSamples.join(', '));
check('every demo button points at an embedded capture',
  buttonSamples.every((name) => typeof embedded[name] === 'string'));

const usedIds = (scriptSource.match(/byId\('([^']+)'\)/g) || [])
  .map((s) => s.replace(/byId\('|'\)/g, ''));
const uniqueIds = Array.from(new Set(usedIds));
const missingIds = uniqueIds.filter((id) => htmlSource.indexOf('id="' + id + '"') === -1);
check('every element id used by script.js exists in index.html (' + uniqueIds.length + ' ids checked)',
  missingIds.length === 0, 'missing: ' + missingIds.join(', '));

const htmlIds = (htmlSource.match(/id="([^"]+)"/g) || []).map((s) => s.replace(/id="|"/g, ''));
const duplicates = htmlIds.filter((id, i) => htmlIds.indexOf(id) !== i);
check('index.html has no duplicate element ids', duplicates.length === 0, duplicates.join(', '));

check('the seven rule thresholds are present as inputs in the page',
  NTT.THRESHOLD_FIELDS.every((field) => htmlSource.indexOf('id="' + field.inputId + '"') !== -1));

/* ===========================================================================
 * SUMMARY
 * ======================================================================== */

console.log('\n' + '-'.repeat(64));
console.log(passed + ' checks passed, ' + failed + ' failed');
if (failed > 0) {
  console.log('\nFailures:');
  failures.forEach((f) => console.log('  - ' + f));
  process.exitCode = 1;
} else {
  console.log('All checks passed. The detections behave as the README describes.');
}




