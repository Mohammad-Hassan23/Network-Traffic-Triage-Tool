/* =============================================================================
 * Network Traffic Triage Tool - script.js
 * Version 1: Wireshark CSV triage. No frameworks, no dependencies, no network.
 *
 * HOW THIS FILE IS ORGANISED
 *   1. Configuration        - thresholds, column aliases, protocol families
 *   2. CSV parsing          - a real RFC4180-style reader (quotes, commas, CRLF)
 *   3. Column mapping       - tolerate "Source" / "src" / "ip.src" and friends
 *   4. Packet normalisation - one small object per packet, plus port/flag hints
 *   5. Analysis             - counting and statistics
 *   6. Rules                - seven explainable detections
 *   7. Scoring              - a visible, additive investigation score
 *   8. Rendering            - turns findings into DOM nodes (textContent only)
 *   9. UI wiring            - file input, drag and drop, filters, thresholds
 *
 * Sections 2-7 are pure functions: they never touch the DOM and never make a
 * network request, which is why the automated tests in tests/ can run them
 * under Node without a browser.
 *
 * SECURITY: every value that comes out of a CSV is untrusted text. It reaches
 * the page only through textContent (see the el() helper), never through
 * innerHTML, and never through eval or a Function constructor.
 * ========================================================================== */

'use strict';

var NTT; /* populated at the bottom so tests/run-tests.js can require() this file */

(function () {

  /* ===========================================================================
   * 1. CONFIGURATION
   * ======================================================================== */

  /* Educational defaults. These are NOT universal security thresholds. */
  var DEFAULTS = {
    packetsPerSource: 50,
    uniqueDestinations: 10,
    uniquePorts: 10,
    icmpPackets: 30,
    dnsPackets: 30,
    pairPackets: 40,
    synPackets: 30
  };

  var THRESHOLD_FIELDS = [
    { key: 'packetsPerSource', inputId: 't-packets', label: 'Packets per source' },
    { key: 'uniqueDestinations', inputId: 't-dests', label: 'Unique destinations' },
    { key: 'uniquePorts', inputId: 't-ports', label: 'Unique ports on one destination' },
    { key: 'icmpPackets', inputId: 't-icmp', label: 'ICMP packets per source' },
    { key: 'dnsPackets', inputId: 't-dns', label: 'DNS packets per source' },
    { key: 'pairPackets', inputId: 't-pairs', label: 'Packets per source/destination pair' },
    { key: 'synPackets', inputId: 't-syn', label: 'TCP SYN packets per source' }
  ];

  var LIMITS = {
    maxBytes: 30 * 1024 * 1024, /* 30 MB */
    maxPackets: 300000,
    maxTableRows: 200,
    topN: 10
  };

  /* Accepted header names. Normalised to lowercase letters and digits only,
   * so "No." -> "no", "ip.src" -> "ipsrc", "Source IP" -> "sourceip". */
  var FIELD_ALIASES = {
    source: ['source', 'sourceip', 'sourceaddress', 'src', 'ipsrc', 'sources',
      'srchost', 'sourcehost', 'sourcenode', 'srcip'],
    destination: ['destination', 'destinationip', 'destinationaddress', 'dest',
      'dst', 'ipdst', 'destip', 'destinationhost', 'desthost', 'dstip', 'target'],
    protocol: ['protocol', 'proto', 'protocolname', 'protocols'],
    length: ['length', 'packetlength', 'framelength', 'len', 'bytes', 'size',
      'packetsize', 'framesize', 'lengthbytes'],
    info: ['info', 'information', 'details', 'description', 'packetinfo', 'summary'],
    number: ['no', 'number', 'packet', 'packetnumber', 'framenumber', 'id',
      'index', 'packetno', 'seqno'],
    time: ['time', 'timestamp', 'frametime', 'timeepoch', 'timeutc', 'epochtime',
      'relativetime', 'datetime', 'timeoffset']
  };

  var FIELD_LABELS = {
    source: 'Source address',
    destination: 'Destination address',
    protocol: 'Protocol',
    length: 'Packet length',
    info: 'Info (Wireshark summary)',
    number: 'Packet number',
    time: 'Time'
  };

  /* Wireshark's Protocol column is Wireshark's opinion. These families keep the
   * dashboard readable while everything unrecognised lands in "Other". */
  var PROTOCOL_FAMILIES = [
    { key: 'dns', label: 'DNS', match: ['dns', 'mdns', 'llmnr', 'nbns', 'netbiosns', 'netbios'] },
    { key: 'icmp', label: 'ICMP', match: ['icmp', 'icmpv6', 'icmpv6nd'] },
    { key: 'arp', label: 'ARP', match: ['arp'] },
    { key: 'http', label: 'HTTP', match: ['http', 'http2', 'http3'] },
    { key: 'tls', label: 'HTTPS / TLS', match: ['tls', 'ssl', 'tlsv1', 'tlsv12', 'tlsv13', 'https'] },
    { key: 'tcp', label: 'TCP', match: ['tcp'] },
    { key: 'udp', label: 'UDP', match: ['udp'] }
  ];

  /* Port guesses used ONLY when the Info column does not reveal real ports.
   * They are conservative, well-known defaults, and are labelled as guesses. */
  var PROTOCOL_PORT_GUESSES = {
    http: { srcPort: null, dstPort: 80 },
    tls: { srcPort: null, dstPort: 443 },
    dns: { srcPort: null, dstPort: 53 },
    icmp: { srcPort: null, dstPort: null },
    arp: { srcPort: null, dstPort: null }
  };

  var SEVERITY_RANK = { Informational: 0, Low: 1, Medium: 2, High: 3 };
  var SEVERITY_POINTS = { Informational: 5, Low: 10, Medium: 15, High: 20 };

  /* A few rules are inherently noisier, so they are not allowed to shout louder
   * than "Medium". This is a deliberate, documented design choice. */
  var SEVERITY_CAPS = {
    high_packet_volume: 'High',
    many_destinations: 'High',
    many_ports: 'High',
    high_icmp: 'Medium',
    high_dns: 'Medium',
    repeated_pair: 'Medium',
    syn_heavy: 'High'
  };

  /* ===========================================================================
   * 2. CSV PARSING
   *
   * A Wireshark CSV export is not "split the line on commas". The Info column
   * frequently contains commas and quotes inside quoted fields, for example:
   *     "12","0.4","10.0.0.5","10.0.0.9","TCP","1514","Server Hello, App Data"
   * Splitting naively would shift every later column and produce nonsense.
   * This reader follows the usual CSV rules:
   *   - a field may be wrapped in double quotes
   *   - inside quotes, "" means a literal double quote
   *   - inside quotes, commas and line breaks are data, not separators
   *   - CRLF, LF and CR line endings are all accepted
   *   - a UTF-8 byte order mark at the start is ignored
   * ======================================================================== */

  function parseCsvText(input) {
    var text = typeof input === 'string' ? input : '';
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);

    var rows = [];
    var row = [];
    var field = '';
    var inQuotes = false;
    var i = 0;
    var len = text.length;

    while (i < len) {
      var ch = text.charAt(i);

      if (inQuotes) {
        if (ch === '"') {
          if (text.charAt(i + 1) === '"') { field += '"'; i += 2; continue; }
          inQuotes = false; i += 1; continue;
        }
        field += ch; i += 1; continue;
      }

      if (ch === '"' && field.length === 0) { inQuotes = true; i += 1; continue; }

      if (ch === ',') { row.push(field); field = ''; i += 1; continue; }

      if (ch === '\r' || ch === '\n') {
        if (ch === '\r' && text.charAt(i + 1) === '\n') i += 1;
        row.push(field); field = ''; rows.push(row); row = [];
        i += 1; continue;
      }

      field += ch;
      i += 1;
    }

    /* last line, with or without a trailing newline */
    if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); }

    var warnings = [];
    if (inQuotes) {
      warnings.push('The file ends inside an unterminated quoted field. The last value was kept as-is, ' +
        'but rows after that point may be unreliable.');
    }

    /* drop rows that are completely empty (blank lines in the middle of a file) */
    var clean = [];
    for (var r = 0; r < rows.length; r += 1) {
      var cells = rows[r];
      var hasContent = false;
      for (var c = 0; c < cells.length; c += 1) {
        if (cells[c].trim() !== '') { hasContent = true; break; }
      }
      if (hasContent) clean.push(cells);
    }

    return { rows: clean, warnings: warnings };
  }

  /* ===========================================================================
   * 3. COLUMN MAPPING
   * ======================================================================== */

  function normaliseHeader(name) {
    return String(name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  /* Returns { index: {field: columnIndex}, matched: {field: headerText},
   *           missingRequired: [...], missingOptional: [...] } */
  function mapColumns(headerCells) {
    var normalised = headerCells.map(normaliseHeader);
    var index = {};
    var matched = {};
    var used = {};

    Object.keys(FIELD_ALIASES).forEach(function (field) {
      var aliases = FIELD_ALIASES[field];
      for (var c = 0; c < normalised.length; c += 1) {
        if (used[c]) continue;
        if (normalised[c] === '') continue;
        if (aliases.indexOf(normalised[c]) !== -1) {
          index[field] = c;
          matched[field] = String(headerCells[c]).trim();
          used[c] = true;
          break;
        }
      }
    });

    var missingRequired = [];
    var missingOptional = [];
    ['source', 'destination'].forEach(function (f) {
      if (index[f] === undefined) missingRequired.push(f);
    });
    ['protocol', 'length', 'info', 'number', 'time'].forEach(function (f) {
      if (index[f] === undefined) missingOptional.push(f);
    });

    return {
      index: index,
      matched: matched,
      missingRequired: missingRequired,
      missingOptional: missingOptional
    };
  }

  /* ===========================================================================
   * 4. PACKET NORMALISATION
   * ======================================================================== */

  function protocolFamily(rawProtocol) {
    var norm = normaliseHeader(rawProtocol);
    if (norm === '') return 'unknown';
    for (var f = 0; f < PROTOCOL_FAMILIES.length; f += 1) {
      if (PROTOCOL_FAMILIES[f].match.indexOf(norm) !== -1) return PROTOCOL_FAMILIES[f].key;
    }
    /* prefix heuristics for versions we did not list explicitly, e.g. TLSv1.1 */
    if (norm.indexOf('tls') === 0 || norm.indexOf('ssl') === 0) return 'tls';
    if (norm.indexOf('icmp') === 0) return 'icmp';
    if (norm.indexOf('dns') === 0) return 'dns';
    if (norm.indexOf('http') === 0) return 'http';
    return 'other';
  }

  function familyLabel(key) {
    for (var f = 0; f < PROTOCOL_FAMILIES.length; f += 1) {
      if (PROTOCOL_FAMILIES[f].key === key) return PROTOCOL_FAMILIES[f].label;
    }
    if (key === 'unknown') return 'Unknown';
    return 'Other';
  }

  /* Wireshark's packet-list Info text carries port numbers in a few shapes.
   * Examples we handle:
   *   "52144 -> 443 [SYN] Seq=0 ..."        (the usual TCP/UDP arrow form)
   *   "Source port: 68  Destination port: 67"
   *   "Src Port: 12345, Dst Port: 443"
   * If nothing matches, we fall back to a well-known default port for a small
   * set of protocols and mark it as a guess so the UI can say so. */
  var RE_ARROW = /(\d{1,5})\s*(?:\u2192|->|-->|=>)\s*(\d{1,5})/;
  var RE_SRC_PORT = /(?:src|source)\s*port\s*[:=]?\s*(\d{1,5})/i;
  var RE_DST_PORT = /(?:dst|dest|destination)\s*port\s*[:=]?\s*(\d{1,5})/i;
  var RE_PORT_PAIR = /port\s*[:=]?\s*(\d{1,5})\D{1,12}port\s*[:=]?\s*(\d{1,5})/i;

  function extractPorts(info, family) {
    var text = String(info || '');
    var srcPort = null;
    var dstPort = null;

    var arrow = text.match(RE_ARROW);
    if (arrow) {
      srcPort = parseInt(arrow[1], 10);
      dstPort = parseInt(arrow[2], 10);
      return { srcPort: srcPort, dstPort: dstPort, guessed: false };
    }

    var srcMatch = text.match(RE_SRC_PORT);
    var dstMatch = text.match(RE_DST_PORT);
    if (srcMatch) srcPort = parseInt(srcMatch[1], 10);
    if (dstMatch) dstPort = parseInt(dstMatch[1], 10);
    if (srcPort !== null || dstPort !== null) {
      return { srcPort: srcPort, dstPort: dstPort, guessed: false };
    }

    var pair = text.match(RE_PORT_PAIR);
    if (pair) {
      return { srcPort: parseInt(pair[1], 10), dstPort: parseInt(pair[2], 10), guessed: false };
    }

    var guess = PROTOCOL_PORT_GUESSES[family];
    if (guess && guess.dstPort !== null) {
      return { srcPort: guess.srcPort, dstPort: guess.dstPort, guessed: true };
    }

    return { srcPort: null, dstPort: null, guessed: false };
  }

  /* TCP flags only exist in the Info column of some exports. We look for the
   * bracketed form Wireshark uses: "[SYN]" and "[SYN, ACK]". */
  var RE_SYN_ONLY = /\[\s*syn\s*\]/i;
  var RE_SYN_ACK = /\[\s*syn\s*,\s*ack\s*\]/i;
  var RE_ANY_FLAG = /\[\s*(?:syn|fin|rst|psh|ack|urg)[^\]]*\]/i;

  function detectTcpFlags(info) {
    var text = String(info || '');
    return {
      syn: RE_SYN_ONLY.test(text),
      synAck: RE_SYN_ACK.test(text),
      anyFlag: RE_ANY_FLAG.test(text)
    };
  }

  function cell(cells, columnIndex) {
    if (columnIndex === undefined) return '';
    var value = cells[columnIndex];
    return value === undefined || value === null ? '' : String(value);
  }

  /* Turns raw CSV rows into small packet objects. Rows without both a source
   * and a destination are skipped and counted, never guessed at. */
  function buildPackets(rows, map) {
    var packets = [];
    var skipped = 0;
    var portRows = 0;
    var guessedPortRows = 0;
    var flagRows = 0;
    var lengthRows = 0;

    for (var r = 1; r < rows.length; r += 1) {
      var cells = rows[r];
      var source = cell(cells, map.index.source).trim();
      var destination = cell(cells, map.index.destination).trim();
      if (source === '' || destination === '') { skipped += 1; continue; }

      var protocolRaw = cell(cells, map.index.protocol).trim();
      var info = cell(cells, map.index.info).trim();
      var lengthRaw = cell(cells, map.index.length).trim();
      var timeRaw = cell(cells, map.index.time).trim();
      var numberRaw = cell(cells, map.index.number).trim();

      var length = parseFloat(lengthRaw);
      if (!isFinite(length)) length = null; else lengthRows += 1;

      var time = parseFloat(timeRaw);
      if (!isFinite(time)) time = null;

      var family = protocolFamily(protocolRaw);
      var ports = extractPorts(info, family);
      if (ports.dstPort !== null) {
        portRows += 1;
        if (ports.guessed) guessedPortRows += 1;
      }

      var flags = detectTcpFlags(info);
      if (flags.anyFlag) flagRows += 1;

      packets.push({
        row: r + 1,
        number: numberRaw,
        time: time,
        source: source,
        destination: destination,
        protocol: protocolRaw === '' ? '(unknown)' : protocolRaw,
        family: family,
        length: length,
        info: info,
        srcPort: ports.srcPort,
        dstPort: ports.dstPort,
        portGuessed: ports.guessed,
        syn: flags.syn,
        synAck: flags.synAck,
        hasFlagInfo: flags.anyFlag
      });
    }

    return {
      packets: packets,
      skipped: skipped,
      portRows: portRows,
      guessedPortRows: guessedPortRows,
      flagRows: flagRows,
      lengthRows: lengthRows
    };
  }

  /* ===========================================================================
   * 5. FILE-LEVEL PARSE (text -> packets + an honest report about the parse)
   * ======================================================================== */

  function parseCapture(text) {
    var parsed = parseCsvText(text);
    var warnings = parsed.warnings.slice();

    if (parsed.rows.length === 0) {
      return { ok: false, error: 'The file appears to be empty. A Wireshark CSV export should contain ' +
        'a header row and at least one packet row.' };
    }

    var header = parsed.rows[0];
    var map = mapColumns(header);

    if (map.missingRequired.length > 0) {
      var messages = map.missingRequired.map(function (field) {
        return 'This CSV does not appear to contain a ' + FIELD_LABELS[field] + ' column.';
      });
      var hint = '';
      if (header.length <= 1) {
        hint = 'The first row only has one column, so the file may use a different separator ' +
          '(for example a semicolon). Wireshark CSV exports use commas.';
      }
      return {
        ok: false,
        error: messages.join(' '),
        hint: hint,
        columns: map,
        headerRow: header,
        dataRows: parsed.rows.length - 1,
        warnings: warnings
      };
    }

    var built = buildPackets(parsed.rows, map);
    if (built.packets.length === 0) {
      return {
        ok: false,
        error: 'The header row was recognised, but no row contained both a source and a destination ' +
          'address. The file may be truncated, or it may not be a Wireshark packet list.',
        columns: map,
        headerRow: header,
        dataRows: parsed.rows.length - 1,
        warnings: warnings
      };
    }

    if (built.skipped > 0) {
      warnings.push(built.skipped + ' row(s) were skipped because they had no source or destination value.');
    }
    if (built.packets.length > LIMITS.maxPackets) {
      warnings.push('This capture has ' + built.packets.length + ' packets, more than the ' + LIMITS.maxPackets +
        ' this tool is tuned for. Analysis will still run, but the page may feel slow.');
    }

    return {
      ok: true,
      packets: built.packets,
      columns: map,
      headerRow: header,
      dataRows: parsed.rows.length - 1,
      skipped: built.skipped,
      portRows: built.portRows,
      guessedPortRows: built.guessedPortRows,
      flagRows: built.flagRows,
      lengthRows: built.lengthRows,
      warnings: warnings
    };
  }

  /* ===========================================================================
   * 6. ANALYSIS - counting and statistics
   *
   * Map is used instead of a plain object for anything keyed by a value from
   * the CSV. A hostile file could contain a host literally named "__proto__",
   * which would pollute a normal object's prototype; Map keys are just data.
   * ======================================================================== */

  var PAIR_SEP = '\u0000';

  function sortCounts(map, limit) {
    var out = [];
    map.forEach(function (count, key) { out.push({ key: key, count: count }); });
    out.sort(function (a, b) {
      if (b.count !== a.count) return b.count - a.count;
      return a.key < b.key ? -1 : (a.key > b.key ? 1 : 0);
    });
    if (limit) out = out.slice(0, limit);
    return out;
  }

  function topOfMap(map, n) {
    var best = null;
    map.forEach(function (count, key) {
      if (best === null || count > best.count || (count === best.count && key < best.key)) {
        best = { key: key, count: count };
      }
    });
    return best;
  }

  function buildStatistics(packets) {
    var sourceCounts = new Map();
    var destCounts = new Map();
    var familyCounts = new Map();
    var rawProtocolCounts = new Map();
    var perSource = new Map();
    var pairs = new Map();
    var lengthSum = 0;
    var lengthCount = 0;
    var timeMin = null;
    var timeMax = null;
    var unresolvedIcmp = 0;

    function sourceEntry(host) {
      var entry = perSource.get(host);
      if (!entry) {
        entry = {
          host: host, packets: 0, dests: new Set(), destCounts: new Map(), icmp: 0, dns: 0,
          syn: 0, synAck: 0, unansweredIcmp: 0, protocols: new Map()
        };
        perSource.set(host, entry);
      }
      return entry;
    }

    for (var i = 0; i < packets.length; i += 1) {
      var p = packets[i];

      sourceCounts.set(p.source, (sourceCounts.get(p.source) || 0) + 1);
      destCounts.set(p.destination, (destCounts.get(p.destination) || 0) + 1);
      familyCounts.set(p.family, (familyCounts.get(p.family) || 0) + 1);
      rawProtocolCounts.set(p.protocol, (rawProtocolCounts.get(p.protocol) || 0) + 1);

      var se = sourceEntry(p.source);
      se.packets += 1;
      se.dests.add(p.destination);
      se.destCounts.set(p.destination, (se.destCounts.get(p.destination) || 0) + 1);
      se.protocols.set(p.protocol, (se.protocols.get(p.protocol) || 0) + 1);
      if (p.family === 'icmp') {
        se.icmp += 1;
        if (/no response/i.test(p.info)) { se.unansweredIcmp += 1; unresolvedIcmp += 1; }
      }
      if (p.family === 'dns') se.dns += 1;
      if (p.syn) se.syn += 1;
      if (p.synAck) se.synAck += 1;

      if (p.length !== null) { lengthSum += p.length; lengthCount += 1; }
      if (p.time !== null) {
        if (timeMin === null || p.time < timeMin) timeMin = p.time;
        if (timeMax === null || p.time > timeMax) timeMax = p.time;
      }

      var key = p.source + PAIR_SEP + p.destination;
      var pair = pairs.get(key);
      if (!pair) {
        pair = {
          key: key, source: p.source, destination: p.destination, packets: 0,
          protocols: new Map(), ports: new Set(), portRows: 0, guessedPortRows: 0, syn: 0
        };
        pairs.set(key, pair);
      }
      pair.packets += 1;
      pair.protocols.set(p.protocol, (pair.protocols.get(p.protocol) || 0) + 1);
      if (p.dstPort !== null) {
        pair.ports.add(p.dstPort);
        pair.portRows += 1;
        if (p.portGuessed) pair.guessedPortRows += 1;
      }
      if (p.syn) pair.syn += 1;
    }

    var total = packets.length;
    var share = function (count) { return total === 0 ? 0 : (count / total) * 100; };

    var topSources = sortCounts(sourceCounts, LIMITS.topN).map(function (e) {
      return { host: e.key, count: e.count, share: share(e.count) };
    });
    var topDestinations = sortCounts(destCounts, LIMITS.topN).map(function (e) {
      return { host: e.key, count: e.count, share: share(e.count) };
    });
    var pairList = [];
    pairs.forEach(function (pair) {
      pairList.push(pair);
    });
    pairList.sort(function (a, b) {
      if (b.packets !== a.packets) return b.packets - a.packets;
      var ak = a.source + PAIR_SEP + a.destination;
      var bk = b.source + PAIR_SEP + b.destination;
      return ak < bk ? -1 : (ak > bk ? 1 : 0);
    });
    var topPairs = pairList.slice(0, LIMITS.topN).map(function (pair) {
      return {
        source: pair.source,
        destination: pair.destination,
        count: pair.packets,
        share: share(pair.packets),
        topProtocol: topOfMap(pair.protocols),
        ports: pair.ports
      };
    });

    var familyList = sortCounts(familyCounts).map(function (e) {
      return { key: e.key, label: familyLabel(e.key), count: e.count, share: share(e.count) };
    });

    var mostActive = topOfMap(sourceCounts);
    var mostContacted = topOfMap(destCounts);
    var mostCommonFamily = familyList.length > 0 ? familyList[0] : null;

    return {
      totalPackets: total,
      uniqueSources: sourceCounts.size,
      uniqueDestinations: destCounts.size,
      topSources: topSources,
      topDestinations: topDestinations,
      topPairs: topPairs,
      mostActiveSource: mostActive,
      mostContactedDestination: mostContacted,
      mostCommonProtocol: mostCommonFamily,
      protocolFamilies: familyList,
      rawProtocols: sortCounts(rawProtocolCounts),
      averageLength: lengthCount > 0 ? lengthSum / lengthCount : null,
      lengthCount: lengthCount,
      timeSpan: (timeMin === null || timeMax === null) ? null : { start: timeMin, end: timeMax, seconds: timeMax - timeMin },
      unresolvedIcmp: unresolvedIcmp,
      sourceCounts: sourceCounts,
      destCounts: destCounts,
      perSource: perSource,
      pairs: pairs,
      pairList: pairList
    };
  }

  /* ===========================================================================
   * 7. DETECTION RULES
   *
   * Every rule is a simple comparison: "is this count bigger than the number
   * the user configured?" No machine learning, no hidden weighting, no black
   * box. Each rule also carries its own educational text so the alert explains
   * itself: what was seen, why it might matter, what innocent things look the
   * same, and what to check next.
   *
   * Language rule: findings describe ACTIVITY, never intent. Words such as
   * "attacker", "infected" or "malicious" are deliberately avoided.
   * ======================================================================== */

  var RULE_META = [
    { id: 'high_packet_volume', rule: 'Rule 1', name: 'High activity host',
      thresholdKey: 'packetsPerSource', needs: [] },
    { id: 'many_destinations', rule: 'Rule 2', name: 'Possible host scanning',
      thresholdKey: 'uniqueDestinations', needs: [] },
    { id: 'many_ports', rule: 'Rule 3', name: 'Possible port scanning',
      thresholdKey: 'uniquePorts', needs: ['info'] },
    { id: 'high_icmp', rule: 'Rule 4', name: 'High ICMP activity',
      thresholdKey: 'icmpPackets', needs: ['protocol'] },
    { id: 'high_dns', rule: 'Rule 5', name: 'High DNS query activity',
      thresholdKey: 'dnsPackets', needs: ['protocol'] },
    { id: 'repeated_pair', rule: 'Rule 6', name: 'Repeated source to destination traffic',
      thresholdKey: 'pairPackets', needs: [] },
    { id: 'syn_heavy', rule: 'Rule 7', name: 'TCP SYN heavy activity',
      thresholdKey: 'synPackets', needs: ['info'] }
  ];

  /* Severity = investigative priority, not certainty. It is derived from how far
   * past the threshold the observation went, then capped for noisier rules. */
  function severityFor(ratio, ruleId) {
    var severity = ratio < 2 ? 'Low' : (ratio < 5 ? 'Medium' : 'High');
    var cap = SEVERITY_CAPS[ruleId];
    if (cap && SEVERITY_RANK[severity] > SEVERITY_RANK[cap]) severity = cap;
    return severity;
  }

  function pct(value, total) {
    if (!total) return '0%';
    return (Math.round((value / total) * 1000) / 10) + '%';
  }

  function timesThreshold(observed, threshold) {
    if (!threshold) return '';
    var ratio = observed / threshold;
    return (Math.round(ratio * 100) / 100) + 'x the configured threshold';
  }

  function portList(ports, limit) {
    var list = [];
    ports.forEach(function (p) { list.push(p); });
    list.sort(function (a, b) { return a - b; });
    var shown = list.slice(0, limit).join(', ');
    if (list.length > limit) shown += ' (+' + (list.length - limit) + ' more)';
    return shown;
  }

  function destinationSamples(entry, limit) {
    var list = [];
    entry.dests.forEach(function (d) { list.push(d); });
    list.sort();
    var shown = list.slice(0, limit).join(', ');
    if (list.length > limit) shown += ' (+' + (list.length - limit) + ' more)';
    return shown;
  }

  function topProtocolOf(entry) {
    var best = topOfMap(entry.protocols);
    return best ? best.key : 'unknown';
  }

  /* ---------------------------- RULE 1 ------------------------------------ */
  /* More than <threshold> packets from a single source host. */
  function ruleHighPacketVolume(stats, t) {
    var findings = [];
    stats.perSource.forEach(function (entry) {
      var threshold = t.packetsPerSource;
      if (entry.packets <= threshold) return;
      var ratio = entry.packets / threshold;
      var topDest = topOfMap(entry.destCounts);

      findings.push({
        id: 'high_packet_volume:' + entry.host,
        rule: 'Rule 1',
        ruleId: 'high_packet_volume',
        name: 'High activity host',
        severity: severityFor(ratio, 'high_packet_volume'),
        source: entry.host,
        destination: null,
        observed: entry.packets,
        metricLabel: 'Packets sent',
        threshold: threshold,
        ratio: ratio,
        summary: entry.host + ' sent ' + entry.packets + ' packets, which is more than the configured ' +
          'threshold of ' + threshold + ' packets per source.',
        evidence: [
          { label: 'Source host', value: entry.host },
          { label: 'Packets sent', value: entry.packets },
          { label: 'Share of capture', value: pct(entry.packets, stats.totalPackets) },
          { label: 'Configured threshold', value: threshold },
          { label: 'Unique destinations', value: entry.dests.size },
          { label: 'Top destination', value: topDest ? topDest.key + ' (' + topDest.count + ' packets)' : 'n/a' },
          { label: 'Most common protocol', value: topProtocolOf(entry) }
        ],
        whyMatters: 'A host generating significantly more traffic than its peers may warrant investigation. ' +
          'Volume on its own does not indicate anything hostile: it says "look here", not "this is an attack".',
        benign: [
          'a legitimate file transfer or large download',
          'software or operating system updates',
          'backups or file synchronisation',
          'an authorised network scanner or monitoring agent',
          'an automated script or scheduled job',
          'a misconfigured application retrying requests in a loop',
          'malicious activity is also possible, which is why this deserves a look'
        ],
        investigation: [
          'Identify which device owns this address.',
          'Confirm whether this volume is normal for that device role.',
          'Review which protocols and destinations it used.',
          'Compare it with the same host on another day or in another capture.',
          'Check whether an authorised backup, scanner or update service runs at this time.',
          'Review endpoint or firewall telemetry if available.'
        ],
        notes: ['Severity is derived from how far past the threshold the host went (' +
          timesThreshold(entry.packets, threshold) + '), then capped by design.']
      });
    });
    return findings;
  }

  /* ---------------------------- RULE 2 ------------------------------------ */
  /* One source talking to more than <threshold> unique destinations. */
  function ruleManyDestinations(stats, t) {
    var findings = [];
    stats.perSource.forEach(function (entry) {
      var threshold = t.uniqueDestinations;
      var unique = entry.dests.size;
      if (unique <= threshold) return;
      var ratio = unique / threshold;

      findings.push({
        id: 'many_destinations:' + entry.host,
        rule: 'Rule 2',
        ruleId: 'many_destinations',
        name: 'Possible host scanning',
        severity: severityFor(ratio, 'many_destinations'),
        source: entry.host,
        destination: null,
        observed: unique,
        metricLabel: 'Unique destinations',
        threshold: threshold,
        ratio: ratio,
        summary: entry.host + ' communicated with ' + unique + ' unique destination addresses, more than the ' +
          'configured threshold of ' + threshold + '.',
        evidence: [
          { label: 'Source host', value: entry.host },
          { label: 'Unique destinations', value: unique },
          { label: 'Configured threshold', value: threshold },
          { label: 'Packets sent', value: entry.packets },
          { label: 'Protocol values seen', value: entry.protocols.size },
          { label: 'Example destinations', value: destinationSamples(entry, 6) }
        ],
        whyMatters: 'A single host communicating with many destination systems over a short capture may be ' +
          'consistent with network discovery or scanning behaviour, but legitimate network-management tools ' +
          'can generate very similar traffic. This is a pattern worth confirming, not a conclusion.',
        benign: [
          'network management or monitoring software checking many devices',
          'an authorised vulnerability scanner',
          'an asset discovery or inventory system',
          'DHCP, DNS or address-management tooling',
          'software update distribution or peer-to-peer traffic',
          'a misconfigured application connecting across a whole subnet'
        ],
        investigation: [
          'Identify the source device.',
          'Determine whether the behaviour is expected for that device.',
          'Review the protocols and destination ports involved.',
          'Check whether the source is an authorised scanner or management system.',
          'Review endpoint telemetry if available.',
          'Confirm with the system owner before escalating.'
        ],
        notes: ['Severity reflects how far past the threshold this went (' +
          timesThreshold(unique, threshold) + ').']
      });
    });
    return findings;
  }

  /* ---------------------------- RULE 3 ------------------------------------ */
  /* One source contacting more than <threshold> different destination ports on
   * the same destination. Only evaluated when port information is available. */
  function ruleManyPorts(stats, t, coverage) {
    var findings = [];
    if (!coverage.portDataUsable) return findings;

    stats.pairList.forEach(function (pair) {
      var threshold = t.uniquePorts;
      var unique = pair.ports.size;
      if (unique <= threshold) return;
      var ratio = unique / threshold;

      var mostlyGuessed = pair.portRows > 0 && (pair.guessedPortRows / pair.portRows) > 0.5;
      var severity = severityFor(ratio, 'many_ports');
      var notes = ['Severity reflects how far past the threshold this went (' +
        timesThreshold(unique, threshold) + ').'];
      if (mostlyGuessed) {
        severity = 'Informational';
        notes.push('Most of these port values were inferred from protocol defaults rather than read from the ' +
          'Info column, so treat this as context rather than a port-scan signal.');
      }

      findings.push({
        id: 'many_ports:' + pair.source + '>' + pair.destination,
        rule: 'Rule 3',
        ruleId: 'many_ports',
        name: 'Possible port scanning',
        severity: severity,
        source: pair.source,
        destination: pair.destination,
        observed: unique,
        metricLabel: 'Unique destination ports',
        threshold: threshold,
        ratio: ratio,
        summary: pair.source + ' contacted ' + unique + ' different destination ports on ' + pair.destination +
          ', more than the configured threshold of ' + threshold + '.',
        evidence: [
          { label: 'Source host', value: pair.source },
          { label: 'Destination host', value: pair.destination },
          { label: 'Unique destination ports', value: unique },
          { label: 'Configured threshold', value: threshold },
          { label: 'Packets on this pair', value: pair.packets },
          { label: 'Ports seen', value: portList(pair.ports, 12) },
          { label: 'Ports read from Info', value: (pair.portRows - pair.guessedPortRows) + ' of ' + pair.portRows }
        ],
        whyMatters: 'One host contacting many different ports on the same destination can be consistent with ' +
          'port scanning, but it also happens during legitimate service discovery, application failover and ' +
          'monitoring checks. Port numbers here come from the Info column, which is a summary, so treat the ' +
          'list as indicative rather than complete.',
        benign: [
          'a service-discovery or inventory tool',
          'an application retrying across several ports',
          'a vulnerability scanner',
          'failover or health-checking behaviour',
          'an authorised penetration test',
          'a misconfigured client pointed at the wrong port range'
        ],
        investigation: [
          'Identify the source device.',
          'Check whether the destination is a system that should be probed at all.',
          'Review which ports answered and which did not.',
          'Confirm whether a scanner or monitoring tool is expected from that host.',
          'Look for the same pattern from other sources in the same capture.',
          'Correlate with firewall or endpoint logs.'
        ],
        notes: notes
      });
    });
    return findings;
  }

  /* ---------------------------- RULE 4 ------------------------------------ */
  /* More than <threshold> ICMP packets from one source. */
  function ruleHighIcmp(stats, t, coverage) {
    var findings = [];
    if (!coverage.protocolDataUsable) return findings;

    stats.perSource.forEach(function (entry) {
      var threshold = t.icmpPackets;
      if (entry.icmp <= threshold) return;
      var ratio = entry.icmp / threshold;
      var evidence = [
        { label: 'Source host', value: entry.host },
        { label: 'ICMP packets sent', value: entry.icmp },
        { label: 'Configured threshold', value: threshold },
        { label: 'ICMP destinations', value: entry.dests.size },
        { label: 'Share of capture', value: pct(entry.icmp, stats.totalPackets) }
      ];
      if (entry.unansweredIcmp > 0) {
        evidence.push({ label: 'With no reply seen', value: entry.unansweredIcmp });
      }

      findings.push({
        id: 'high_icmp:' + entry.host,
        rule: 'Rule 4',
        ruleId: 'high_icmp',
        name: 'High ICMP activity',
        severity: severityFor(ratio, 'high_icmp'),
        source: entry.host,
        destination: null,
        observed: entry.icmp,
        metricLabel: 'ICMP packets',
        threshold: threshold,
        ratio: ratio,
        summary: entry.host + ' sent ' + entry.icmp + ' ICMP packets, more than the configured threshold of ' +
          threshold + '.',
        evidence: evidence,
        whyMatters: 'ICMP is ordinary: ping, traceroute and reachability checks all use it. A high volume from ' +
          'one host is worth a look because the same pattern appears in ping sweeps and network discovery, and ' +
          'in much larger volumes during ICMP flooding. Volume alone cannot tell those apart.',
        benign: [
          'troubleshooting a connection by hand',
          'a monitoring system checking reachability',
          'an inventory or discovery tool performing a ping sweep',
          'network discovery features in management software',
          'a device retrying a link that is genuinely down'
        ],
        investigation: [
          'Identify the source device.',
          'Check whether it is expected to monitor or discover other hosts.',
          'See whether the destinations are a contiguous range, which suggests a sweep.',
          'Check whether replies came back or the packets went unanswered.',
          'Review change records for new monitoring or discovery tooling.'
        ],
        notes: ['ICMP flooding is possible but is not the same as proving it happened. ' +
          'Severity here is capped at Medium for this reason, and reflects how far past the threshold the ' +
          'source went (' + timesThreshold(entry.icmp, threshold) + ').']
      });
    });
    return findings;
  }

  /* ---------------------------- RULE 5 ------------------------------------ */
  /* More than <threshold> DNS packets from one source. */
  function ruleHighDns(stats, t, coverage) {
    var findings = [];
    if (!coverage.protocolDataUsable) return findings;

    stats.perSource.forEach(function (entry) {
      var threshold = t.dnsPackets;
      if (entry.dns <= threshold) return;
      var ratio = entry.dns / threshold;

      findings.push({
        id: 'high_dns:' + entry.host,
        rule: 'Rule 5',
        ruleId: 'high_dns',
        name: 'High DNS query activity',
        severity: severityFor(ratio, 'high_dns'),
        source: entry.host,
        destination: null,
        observed: entry.dns,
        metricLabel: 'DNS packets',
        threshold: threshold,
        ratio: ratio,
        summary: entry.host + ' was involved in ' + entry.dns + ' DNS packets, more than the configured ' +
          'threshold of ' + threshold + '.',
        evidence: [
          { label: 'Source host', value: entry.host },
          { label: 'DNS packets sent', value: entry.dns },
          { label: 'Configured threshold', value: threshold },
          { label: 'DNS servers contacted', value: entry.dests.size },
          { label: 'Share of capture', value: pct(entry.dns, stats.totalPackets) },
          { label: 'Example destinations', value: destinationSamples(entry, 4) }
        ],
        whyMatters: 'DNS is how almost every application starts a conversation, so a busy resolver or a busy ' +
          'client is normal. High DNS activity is worth a look because it can also be produced by automated ' +
          'lookups, misconfigured systems retrying, or periodic beaconing. Name data in the CSV is limited to ' +
          'the Info column, so this rule counts packets rather than inspecting domains.',
        benign: [
          'normal web browsing across many sites',
          'software updates checking for new versions',
          'an automated application or agent resolving endpoints',
          'a resolver or DNS server answering many clients',
          'a misconfigured system retrying failed lookups'
        ],
        investigation: [
          'Identify the source device and whether it is a DNS server or a client.',
          'Look at the query names in the Info column for anything unexpected.',
          'Check whether the queries are evenly spaced over time, which can suggest automation.',
          'Confirm whether the destination addresses are your own resolvers or external ones.',
          'Correlate with endpoint telemetry to see which process is making the requests.'
        ],
        notes: ['Severity is capped at Medium for this rule because DNS volume is so environment-dependent. ' +
          'Observed value was ' + timesThreshold(entry.dns, threshold) + '.']
      });
    });
    return findings;
  }

  /* ---------------------------- RULE 6 ------------------------------------ */
  /* More than <threshold> packets between one source and one destination. */
  function ruleRepeatedPair(stats, t) {
    var findings = [];
    stats.pairList.forEach(function (pair) {
      var threshold = t.pairPackets;
      if (pair.packets <= threshold) return;
      var ratio = pair.packets / threshold;
      var sourceTotal = stats.sourceCounts.get(pair.source) || pair.packets;
      var topProto = topOfMap(pair.protocols);

      findings.push({
        id: 'repeated_pair:' + pair.source + '>' + pair.destination,
        rule: 'Rule 6',
        ruleId: 'repeated_pair',
        name: 'Repeated source to destination traffic',
        severity: severityFor(ratio, 'repeated_pair'),
        source: pair.source,
        destination: pair.destination,
        observed: pair.packets,
        metricLabel: 'Packets on this pair',
        threshold: threshold,
        ratio: ratio,
        summary: pair.source + ' sent ' + pair.packets + ' packets to ' + pair.destination +
          ', more than the configured threshold of ' + threshold + ' packets for a single conversation.',
        evidence: [
          { label: 'Source host', value: pair.source },
          { label: 'Destination host', value: pair.destination },
          { label: 'Packets on this pair', value: pair.packets },
          { label: 'Configured threshold', value: threshold },
          { label: 'Most common protocol', value: topProto ? topProto.key : 'unknown' },
          { label: 'Share of source traffic', value: pct(pair.packets, sourceTotal) },
          { label: 'Destination ports seen', value: pair.ports.size > 0 ? portList(pair.ports, 6) : 'not available' }
        ],
        whyMatters: 'A long, repetitive conversation between two hosts is usually just application traffic ' +
          'doing its job, but it is also the shape of automated polling, synchronisation and, occasionally, ' +
          'unwanted automated activity. The pattern is worth confirming, especially when the destination is ' +
          'unexpected for that host.',
        benign: [
          'a file share, backup or synchronisation job',
          'streaming media or a large download',
          'a database or application server conversation',
          'an agent polling a management server',
          'a mail client or browser holding a long connection open'
        ],
        investigation: [
          'Identify both devices.',
          'Confirm whether the conversation is expected between them.',
          'Check whether the volume is one long session or many short ones.',
          'Review the destination ports to understand the service involved.',
          'Compare with the same pair on a previous day.',
          'Ask the system owner before treating it as a problem.'
        ],
        notes: ['Severity for this rule is capped at Medium: long conversations are common and rarely mean ' +
          'anything on their own. Observed value was ' + timesThreshold(pair.packets, threshold) + '.']
      });
    });
    return findings;
  }

  /* ---------------------------- RULE 7 ------------------------------------ */
  /* More than <threshold> TCP SYN packets from one source. Only evaluated when
   * the Info column actually exposes TCP flags. */
  function ruleSynHeavy(stats, t, coverage) {
    var findings = [];
    if (!coverage.flagDataUsable) return findings;

    stats.perSource.forEach(function (entry) {
      var threshold = t.synPackets;
      if (entry.syn <= threshold) return;
      var ratio = entry.syn / threshold;

      var severity = severityFor(ratio, 'syn_heavy');
      var notes = ['Severity reflects how far past the threshold this went (' +
        timesThreshold(entry.syn, threshold) + ').'];
      var handshakesCompleted = entry.synAck > 0 && entry.synAck >= entry.syn / 2;
      if (handshakesCompleted) {
        severity = 'Informational';
        notes.push('Roughly as many SYN/ACK replies were seen as SYN packets, which suggests the connections ' +
          'were being answered. That looks more like normal connection churn than unanswered scanning.');
      } else if (entry.synAck === 0) {
        notes.push('No SYN/ACK replies were seen for these packets, which is the more interesting case: the ' +
          'destination did not answer. It still does not prove intent.');
      }

      findings.push({
        id: 'syn_heavy:' + entry.host,
        rule: 'Rule 7',
        ruleId: 'syn_heavy',
        name: 'TCP SYN heavy activity',
        severity: severity,
        source: entry.host,
        destination: null,
        observed: entry.syn,
        metricLabel: 'TCP SYN packets',
        threshold: threshold,
        ratio: ratio,
        summary: entry.host + ' sent ' + entry.syn + ' TCP SYN packets, more than the configured threshold of ' +
          threshold + '.',
        evidence: [
          { label: 'Source host', value: entry.host },
          { label: 'SYN packets', value: entry.syn },
          { label: 'Configured threshold', value: threshold },
          { label: 'SYN/ACK replies seen', value: entry.synAck },
          { label: 'Destinations contacted', value: entry.dests.size },
          { label: 'Packets sent in total', value: entry.packets }
        ],
        whyMatters: 'A large number of connection attempts can be associated with ordinary connections to ' +
          'services that are slow or unavailable, with network scanning, or with SYN flood behaviour. It is ' +
          'not proof of a flood: failed connections and rapid reconnects look almost identical in a packet list.',
        benign: [
          'normal connection attempts to a slow or busy service',
          'a service that is unavailable, so the client retries',
          'an application reconnecting rapidly after errors',
          'a load balancer or proxy with high connection churn',
          'network scanning by an authorised tool'
        ],
        investigation: [
          'Identify the source and destination devices.',
          'Check whether replies came back, which distinguishes retries from unanswered attempts.',
          'Review the destination ports being contacted.',
          'Look at how the attempts are spaced in time.',
          'Check the target service logs for errors or restarts.',
          'Confirm whether the source is expected to open many connections.'
        ],
        notes: notes
      });
    });
    return findings;
  }

  /* ===========================================================================
   * 8. COVERAGE, SCORING AND THE ANALYSIS ENTRY POINT
   * ======================================================================== */

  /* What can this capture actually support? A rule that cannot be evaluated is
   * reported as "not evaluated" with a reason, never silently skipped. */
  function computeCoverage(packets) {
    var portRows = 0;
    var guessedPortRows = 0;
    var flagRows = 0;
    var lengthRows = 0;
    var infoRows = 0;
    var protocolRows = 0;

    for (var i = 0; i < packets.length; i += 1) {
      var p = packets[i];
      if (p.dstPort !== null) {
        portRows += 1;
        if (p.portGuessed) guessedPortRows += 1;
      }
      if (p.hasFlagInfo) flagRows += 1;
      if (p.length !== null) lengthRows += 1;
      if (p.info !== '') infoRows += 1;
      if (p.family !== 'unknown') protocolRows += 1;
    }

    return {
      totalPackets: packets.length,
      infoRows: infoRows,
      infoDataUsable: infoRows > 0,
      protocolRows: protocolRows,
      protocolDataUsable: protocolRows > 0,
      lengthRows: lengthRows,
      lengthDataUsable: lengthRows > 0,
      portRows: portRows,
      guessedPortRows: guessedPortRows,
      portDataUsable: portRows > 0,
      flagRows: flagRows,
      flagDataUsable: flagRows > 0
    };
  }

  function normaliseThresholds(input) {
    var out = {};
    THRESHOLD_FIELDS.forEach(function (field) {
      var raw = input ? input[field.key] : undefined;
      var value = parseInt(raw, 10);
      if (!isFinite(value) || value < 1) value = DEFAULTS[field.key];
      out[field.key] = value;
    });
    return out;
  }

  function compareFindings(a, b) {
    var bySeverity = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (bySeverity !== 0) return bySeverity;
    if (b.ratio !== a.ratio) return b.ratio - a.ratio;
    if (a.rule !== b.rule) return a.rule < b.rule ? -1 : 1;
    return a.id < b.id ? -1 : (a.id > b.id ? 1 : 0);
  }

  function scoreLabel(total) {
    if (total === 0) return 'No findings';
    if (total < 20) return 'Low investigative priority';
    if (total < 60) return 'Elevated Activity';
    return 'High investigative priority';
  }

  function buildScore(findings) {
    var total = 0;
    var contributions = findings.map(function (f) {
      var points = SEVERITY_POINTS[f.severity];
      if (!isFinite(points)) points = 5;
      total += points;
      return {
        ruleId: f.ruleId,
        label: f.rule + ' - ' + f.name + ' (' + f.source + (f.destination ? ' to ' + f.destination : '') + ')',
        severity: f.severity,
        points: points
      };
    });
    return {
      total: total,
      contributions: contributions,
      label: scoreLabel(total),
      note: 'This score adds up the findings above, weighted by investigative priority. It is not a ' +
        'probability of compromise and must not be read as one.'
    };
  }

  function ruleStatusFor(meta, findings, coverage) {
    var count = 0;
    findings.forEach(function (f) { if (f.ruleId === meta.id) count += 1; });

    if (meta.id === 'many_ports' && !coverage.portDataUsable) {
      return { id: meta.id, rule: meta.rule, name: meta.name, status: 'not_evaluated', count: 0,
        reason: 'No destination ports could be read from the Info column of this capture.' };
    }
    if (meta.id === 'syn_heavy' && !coverage.flagDataUsable) {
      return { id: meta.id, rule: meta.rule, name: meta.name, status: 'not_evaluated', count: 0,
        reason: 'No TCP flag markers such as [SYN] were found in the Info column of this capture.' };
    }
    if ((meta.id === 'high_icmp' || meta.id === 'high_dns') && !coverage.protocolDataUsable) {
      return { id: meta.id, rule: meta.rule, name: meta.name, status: 'not_evaluated', count: 0,
        reason: 'The Protocol column is missing, so protocol-specific counts cannot be trusted.' };
    }
    return {
      id: meta.id, rule: meta.rule, name: meta.name,
      status: count > 0 ? 'fired' : 'evaluated', count: count, reason: ''
    };
  }

  /* The single entry point used by both the browser UI and the tests. */
  function analyse(packets, thresholds) {
    var t = normaliseThresholds(thresholds);
    var stats = buildStatistics(packets);
    var coverage = computeCoverage(packets);

    var findings = [];
    findings = findings.concat(ruleHighPacketVolume(stats, t));
    findings = findings.concat(ruleManyDestinations(stats, t));
    findings = findings.concat(ruleManyPorts(stats, t, coverage));
    findings = findings.concat(ruleHighIcmp(stats, t, coverage));
    findings = findings.concat(ruleHighDns(stats, t, coverage));
    findings = findings.concat(ruleRepeatedPair(stats, t));
    findings = findings.concat(ruleSynHeavy(stats, t, coverage));

    findings.sort(compareFindings);

    return {
      thresholds: t,
      stats: stats,
      coverage: coverage,
      findings: findings,
      score: buildScore(findings),
      ruleStatus: RULE_META.map(function (meta) {
        return ruleStatusFor(meta, findings, coverage);
      })
    };
  }

  /* @@NEXT@@ */

  /* ===========================================================================
   * PUBLIC SURFACE
   *
   * Everything below is exposed for two callers:
   *   - the browser UI in this same file
   *   - tests/run-tests.js, which runs the pure functions under Node
   *     (this is why the analysis code never touches the DOM)
   * ======================================================================== */

  NTT = {
    DEFAULTS: DEFAULTS,
    LIMITS: LIMITS,
    THRESHOLD_FIELDS: THRESHOLD_FIELDS,
    parseCsvText: parseCsvText,
    mapColumns: mapColumns,
    parseCapture: parseCapture,
    buildPackets: buildPackets,
    analyse: analyse,
    buildStatistics: buildStatistics,
    computeCoverage: computeCoverage,
    normaliseThresholds: normaliseThresholds,
    scoreLabel: scoreLabel,
    severityFor: severityFor,
    protocolFamily: protocolFamily,
    familyLabel: familyLabel,
    extractPorts: extractPorts,
    detectTcpFlags: detectTcpFlags
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = NTT;
  }

  /* In a browser, wire the page up. In Node there is no document, so nothing
   * happens and the tests can call the pure functions directly. */
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', startUI);
    } else {
      startUI();
    }
  }

})();














