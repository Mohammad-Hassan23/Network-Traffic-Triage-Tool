#!/usr/bin/env node
'use strict';
/*
 * UI smoke test for the Network Traffic Triage Tool.
 *
 * Runs the real script.js against a very small fake DOM, clicks the demo
 * buttons, changes a threshold, applies a filter and clears the capture. This
 * catches mistakes that the pure-function tests cannot see, such as a missing
 * element id or a typo in the rendering code.
 *
 * It is deliberately tiny: no jsdom, no dependencies, nothing to install.
 * Run it with:   node tests/run-ui-tests.js
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

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

/* ===========================================================================
 * A minimal DOM. Only the parts script.js actually uses.
 * ======================================================================== */

function makeElement(tag) {
  return {
    tagName: String(tag).toUpperCase(),
    children: [],
    listeners: {},
    attributes: {},
    style: {},
    options: [],
    className: '',
    textContent: '',
    hidden: false,
    value: '',
    id: '',
    firstChild: null,
    parent: null,
    appendChild(child) {
      this.children.push(child);
      child.parent = this;
      if (child.tagName === 'OPTION') this.options.push(child);
      this.firstChild = this.children[0] || null;
      return child;
    },
    removeChild(child) {
      const i = this.children.indexOf(child);
      if (i >= 0) this.children.splice(i, 1);
      if (child.tagName === 'OPTION') {
        const j = this.options.indexOf(child);
        if (j >= 0) this.options.splice(j, 1);
      }
      this.firstChild = this.children[0] || null;
      return child;
    },
    setAttribute(key, value) { this.attributes[key] = value; },
    getAttribute(key) {
      if (Object.prototype.hasOwnProperty.call(this.attributes, key)) return this.attributes[key];
      return null;
    },
    addEventListener(type, handler) {
      this.listeners[type] = this.listeners[type] || [];
      this.listeners[type].push(handler);
    },
    classList: { add() {}, remove() {}, contains() { return false; } },
    contains() { return false; },
    querySelectorAll() { return []; }
  };
}

function textOf(node) {
  let text = typeof node.textContent === 'string' ? node.textContent : '';
  node.children.forEach((child) => { text += ' ' + textOf(child); });
  return text.replace(/\s+/g, ' ').trim();
}

const htmlSource = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const htmlIds = (htmlSource.match(/id="([^"]+)"/g) || []).map((s) => s.replace(/id="|"/g, ''));

const registry = new Map();
htmlIds.forEach((id) => {
  const node = makeElement(id.indexOf('filter-') === 0 && id.indexOf('search') === -1 ? 'select' : 'div');
  node.id = id;
  registry.set(id, node);
});

/* the three demo buttons, as the page provides them */
const sampleNames = (htmlSource.match(/data-sample="([^"]+)"/g) || [])
  .map((s) => s.replace(/data-sample="|"/g, ''));
const sampleButtons = sampleNames.map((name) => {
  const button = makeElement('button');
  button.setAttribute('data-sample', name);
  return button;
});

const fakeDocument = {
  readyState: 'complete',
  getElementById(id) { return registry.has(id) ? registry.get(id) : null; },
  createElement(tag) { return makeElement(tag); },
  querySelectorAll(selector) { return selector === '[data-sample]' ? sampleButtons : []; },
  addEventListener() {}
};

const fakeWindow = { addEventListener() {} };

/* ===========================================================================
 * Boot the real application against the fake DOM
 * ======================================================================== */

console.log('Loading script.js against a fake DOM...');
global.document = fakeDocument;
global.window = fakeWindow;

let bootError = null;
try {
  require(path.join(ROOT, 'script.js'));
} catch (error) {
  bootError = error;
}
check('script.js boots without throwing', bootError === null, bootError ? bootError.message : '');

const get = (id) => registry.get(id);
const statusText = () => textOf(get('status'));
const findingsText = () => textOf(get('findings'));
const coverageText = () => textOf(get('rule-coverage'));
const overviewText = () => textOf(get('summary-cards'));

function clickSample(name) {
  const button = sampleButtons[sampleNames.indexOf(name)];
  button.listeners.click.forEach((handler) => handler({ preventDefault() {} }));
}

function trigger(id, type) {
  const node = get(id);
  (node.listeners[type] || []).forEach((handler) => handler({ preventDefault() {}, target: node }));
}

/* ===========================================================================
 * 1. EMPTY STATE
 * ======================================================================== */

console.log('\n1. Empty state');

check('the page starts with an empty-state message',
  /No capture loaded yet/.test(statusText()), statusText());
check('the overview starts hidden', get('overview-content').hidden === true);
check('the findings area starts with a placeholder',
  /Load a capture to see the network overview/.test(findingsText()), findingsText());
check('the filter status starts empty', /No capture loaded/.test(get('filter-status').textContent));

/* ===========================================================================
 * 2. DEMO BUTTONS RENDER THE REPORT
 * ======================================================================== */

console.log('\n2. Demo buttons');

clickSample('normal-traffic.csv');
check('the normal sample reports a successful load',
  /58 packets parsed successfully/.test(statusText()), statusText());
check('the normal sample is labelled as Demo Data',
  /Demo Data/.test(statusText()) && get('demo-badge-panel').hidden === false);
check('the normal sample shows no findings',
  /No rule thresholds were crossed/.test(findingsText()), findingsText());
check('the overview becomes visible', get('overview-content').hidden === false);
check('the overview shows the packet total',
  /Total packets 58/.test(overviewText()), overviewText().slice(0, 200));
check('the overview names the busiest host', /192.168.1.10/.test(overviewText()));
check('the score reads 0', get('score-number').textContent === '0');
check('the rule coverage lists the rules',
  /Rule 1/.test(coverageText()) && /Rule 7/.test(coverageText()));

clickSample('high-volume-traffic.csv');
check('the suspicious sample reports 217 packets',
  /217 packets parsed successfully/.test(statusText()), statusText());
check('the suspicious sample produces a High activity host finding',
  /High activity host/.test(findingsText()), findingsText().slice(0, 200));
check('the finding quotes 183 packets', /183/.test(findingsText()));
check('the finding quotes the threshold of 50', /50/.test(findingsText()));
check('the finding explains possible benign causes',
  /Possible benign explanations/.test(findingsText()));
check('the finding suggests investigation steps',
  /Suggested investigation/.test(findingsText()));
check('the score is 30 with the Elevated Activity label',
  get('score-number').textContent === '30' && /Elevated Activity/.test(get('score-label').textContent),
  get('score-number').textContent + ' / ' + get('score-label').textContent);
check('the score breakdown names what contributed',
  /Rule 1/.test(textOf(get('score-breakdown'))) && /\+15/.test(textOf(get('score-breakdown'))));
check('the filter status counts the findings',
  /of 2 findings/.test(get('filter-status').textContent), get('filter-status').textContent);

clickSample('mixed-soc-lab.csv');
check('the mixed sample produces a scanning finding',
  /Possible host scanning/.test(findingsText()));
check('the mixed sample quotes 27 unique destinations', /27/.test(findingsText()));
check('the mixed sample produces a port scanning finding',
  /Possible port scanning/.test(findingsText()));
check('the mixed sample produces an ICMP finding', /High ICMP activity/.test(findingsText()));
check('the mixed sample produces a DNS finding', /High DNS query activity/.test(findingsText()));
check('the mixed sample produces a SYN finding', /TCP SYN heavy activity/.test(findingsText()));
check('the mixed sample produces a repeated traffic finding',
  /Repeated source to destination traffic/.test(findingsText()));
check('the coverage list shows fired rules',
  /Rule 1 .*1 finding/.test(coverageText()) && /Rule 3 .*1 finding/.test(coverageText()),
  coverageText());
check('the packet table is populated',
  /Packets matching the current filters/.test(textOf(get('packet-table'))));
check('the score shows a high investigative priority',
  /High investigative priority/.test(get('score-label').textContent), get('score-label').textContent);

/* ===========================================================================
 * 3. THRESHOLDS AND FILTERS
 * ======================================================================== */

console.log('\n3. Thresholds');

get('t-packets').value = '500';
trigger('t-packets', 'change');
check('raising the packet threshold to 500 removes the High activity host finding',
  !/High activity host/.test(findingsText()), findingsText().slice(0, 200));
check('the threshold input is tidied back to a valid number', get('t-packets').value === 500,
  String(get('t-packets').value));

get('t-packets').value = 'abc';
trigger('t-packets', 'change');
check('typing nonsense falls back to the default of 50', get('t-packets').value === 50,
  String(get('t-packets').value));
check('the finding comes back at the default threshold',
  /High activity host/.test(findingsText()));

get('t-packets').value = '60';
trigger('t-packets', 'change');
check('a threshold of 60 keeps the 100-packet host but is quoted in the finding',
  /High activity host/.test(findingsText()) && /60/.test(findingsText()));

trigger('reset-thresholds', 'click');
check('Reset Defaults restores 50', get('t-packets').value === 50, String(get('t-packets').value));
check('Reset Defaults says so in the status line',
  /reset to the educational defaults/i.test(statusText()), statusText());

console.log('\n4. Filters');

const allFindings = get('filter-status').textContent;
get('filter-severity').value = 'Medium';
trigger('filter-severity', 'change');
check('filtering by Medium severity reduces the finding count',
  /of 9 findings/.test(allFindings) && /Showing 3 of 9 findings/.test(get('filter-status').textContent),
  get('filter-status').textContent);

get('filter-severity').value = 'High';
trigger('filter-severity', 'change');
check('filtering by High severity shows nothing on this capture',
  /Showing 0 of 9 findings/.test(get('filter-status').textContent) &&
  /No findings match the current filters/.test(findingsText()), get('filter-status').textContent);

trigger('clear-filters', 'click');
check('Clear filters restores every finding',
  /Showing 9 of 9 findings/.test(get('filter-status').textContent), get('filter-status').textContent);

get('filter-source').value = '172.16.5.20';
trigger('filter-source', 'change');
check('filtering by source host narrows the findings to that host',
  /Showing 3 of 9 findings/.test(get('filter-status').textContent), get('filter-status').textContent);
check('the packet table follows the same filter',
  /Showing 41 of 41 matching packets/.test(get('packet-count').textContent),
  get('packet-count').textContent);

trigger('clear-filters', 'click');
get('filter-search').value = '192.168.1.25';
trigger('filter-search', 'input');
check('the search field filters findings too',
  /Showing 2 of 9 findings/.test(get('filter-status').textContent), get('filter-status').textContent);
check('search also filters the packet list',
  /Showing 100 of 100 matching packets/.test(get('packet-count').textContent),
  get('packet-count').textContent);

get('filter-search').value = 'nothing-matches-this';
trigger('filter-search', 'input');
check('a search with no matches says so',
  /No packets match the current filters/.test(textOf(get('packet-table'))));
trigger('clear-filters', 'click');

/* ===========================================================================
 * 5. CLEARING
 * ======================================================================== */

console.log('\n5. Clearing the capture');

trigger('clear-btn', 'click');
check('the status confirms the capture was cleared',
  /Capture cleared/.test(statusText()), statusText());
check('the overview is hidden again', get('overview-content').hidden === true);
check('the findings area is back to its placeholder',
  /Load a capture to see the network overview/.test(findingsText()), findingsText());
check('the parse summary is hidden', get('parse-summary').hidden === true);
check('the demo badge is hidden again', get('demo-badge-panel').hidden === true);
check('the packet table is emptied', textOf(get('packet-table')) === '', textOf(get('packet-table')));

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
  console.log('The interface renders and reacts as expected.');
}


