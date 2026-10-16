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

  /* ===========================================================================
   * 9. RENDERING
   *
   * SECURITY: the only way CSV-derived text reaches the page is through
   * el() -> textContent. There is no innerHTML anywhere in this file, so a
   * packet whose Info column contains "<script>alert(1)</script>" or an
   * "<img onerror=...>" payload is displayed as harmless characters.
   * ======================================================================== */

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function severityClass(severity) {
    return 'sev-' + String(severity || 'Informational').toLowerCase();
  }

  function formatNumber(value) {
    if (value === null || value === undefined || value === '') return 'n/a';
    var parts = String(value).split('.');
    parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    return parts.join('.');
  }

  function formatDecimal(value, places) {
    if (value === null || value === undefined || !isFinite(value)) return 'n/a';
    return value.toFixed(places);
  }

  function formatSeconds(seconds) {
    if (seconds === null || seconds === undefined || !isFinite(seconds)) return 'n/a';
    if (seconds < 1) return (Math.round(seconds * 1000)) + ' ms';
    if (seconds < 90) return (Math.round(seconds * 10) / 10) + ' s';
    return (Math.round((seconds / 60) * 10) / 10) + ' min';
  }

  function summaryCard(label, value, unit, sub) {
    var card = el('div', 'summary-card');
    card.appendChild(el('dt', null, label));
    var dd = el('dd', null, value);
    if (unit) dd.appendChild(el('span', 'unit', unit));
    if (sub) dd.appendChild(el('span', 'sub', sub));
    card.appendChild(dd);
    return card;
  }

  function renderSummaryCards(target, report) {
    var stats = report.stats;
    clear(target);

    target.appendChild(summaryCard('Total packets', formatNumber(stats.totalPackets)));
    target.appendChild(summaryCard('Unique source hosts', formatNumber(stats.uniqueSources)));
    target.appendChild(summaryCard('Unique destination hosts', formatNumber(stats.uniqueDestinations)));

    target.appendChild(summaryCard(
      'Most active source host',
      stats.mostActiveSource ? stats.mostActiveSource.key : 'n/a',
      null,
      stats.mostActiveSource ? formatNumber(stats.mostActiveSource.count) + ' packets sent' : null
    ));

    target.appendChild(summaryCard(
      'Most contacted destination',
      stats.mostContactedDestination ? stats.mostContactedDestination.key : 'n/a',
      null,
      stats.mostContactedDestination ? formatNumber(stats.mostContactedDestination.count) + ' packets received' : null
    ));

    target.appendChild(summaryCard(
      'Most common protocol',
      stats.mostCommonProtocol ? stats.mostCommonProtocol.label : 'n/a',
      null,
      stats.mostCommonProtocol
        ? formatNumber(stats.mostCommonProtocol.count) + ' packets (' + formatDecimal(stats.mostCommonProtocol.share, 1) + '%)'
        : null
    ));

    target.appendChild(summaryCard(
      'Average packet length',
      stats.averageLength === null ? 'not available' : formatNumber(Math.round(stats.averageLength)),
      stats.averageLength === null ? null : 'bytes',
      stats.averageLength === null
        ? 'No usable Length column in this capture'
        : 'From ' + formatNumber(stats.lengthCount) + ' packets with a length value'
    ));

    target.appendChild(summaryCard(
      'Capture time span',
      stats.timeSpan ? formatSeconds(stats.timeSpan.seconds) : 'not available',
      null,
      stats.timeSpan
        ? 'From ' + stats.timeSpan.start + ' to ' + stats.timeSpan.end + ' seconds of capture time'
        : 'No usable Time column in this capture'
    ));
  }

  function renderScore(targetNumber, targetLabel, targetBreakdown, score) {
    targetNumber.textContent = formatNumber(score.total);
    targetLabel.textContent = score.label;
    clear(targetBreakdown);

    if (score.contributions.length === 0) {
      targetBreakdown.appendChild(el('li', 'none',
        'No rule thresholds were crossed, so there is nothing to add up. That is a normal and good result ' +
        'for a small, quiet capture.'));
      return;
    }

    score.contributions.forEach(function (item) {
      var li = el('li');
      li.appendChild(el('span', null, item.label + ' [' + item.severity + ']'));
      li.appendChild(el('span', 'points', '+' + item.points));
      targetBreakdown.appendChild(li);
    });

    var total = el('li');
    total.appendChild(el('span', null, 'Total'));
    total.appendChild(el('span', 'points', score.total));
    targetBreakdown.appendChild(total);
  }

  /* ------------------------------- bars ----------------------------------- */

  function barRow(label, value, max, valueText) {
    var row = el('div', 'chart-row');
    row.setAttribute('role', 'listitem');
    row.appendChild(el('span', 'chart-label', label));

    var track = el('div', 'bar-track');
    var fill = el('span', 'bar-fill');
    var width = max > 0 ? Math.max(1, Math.round((value / max) * 100)) : 0;
    fill.style.width = width + '%';
    track.appendChild(fill);
    row.appendChild(track);

    row.appendChild(el('span', 'chart-value', valueText));
    return row;
  }

  function renderProtocolChart(target, report) {
    clear(target);
    var families = report.stats.protocolFamilies;
    if (families.length === 0) {
      target.appendChild(el('p', 'table-empty', 'No protocol information was available in this capture.'));
      return;
    }
    var max = families[0].count;
    families.forEach(function (family) {
      target.appendChild(barRow(
        family.label,
        family.count,
        max,
        formatNumber(family.count) + ' (' + formatDecimal(family.share, 1) + '%)'
      ));
    });
  }

  /* ------------------------------ host tables ----------------------------- */

  function renderHostTable(target, captionText, rows, hostLabel) {
    clear(target);
    if (rows.length === 0) {
      target.appendChild(el('p', 'table-empty', 'Nothing to show.'));
      return;
    }

    var table = el('table');
    table.appendChild(el('caption', null, captionText));

    var thead = el('thead');
    var headRow = el('tr');
    var headers = ['#', hostLabel, 'Packets', 'Share', 'Relative activity'];
    headers.forEach(function (text, i) {
      var th = el('th', i === 2 || i === 3 ? 'num' : null, text);
      th.setAttribute('scope', 'col');
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el('tbody');
    var max = rows[0].count;
    rows.forEach(function (row, index) {
      var tr = el('tr');
      tr.appendChild(el('td', 'num', index + 1));
      tr.appendChild(el('td', 'host', row.host));
      tr.appendChild(el('td', 'num', formatNumber(row.count)));
      tr.appendChild(el('td', 'num', formatDecimal(row.share, 1) + '%'));

      var barCell = el('td');
      var track = el('div', 'bar-track');
      var fill = el('span', 'bar-fill');
      fill.style.width = (max > 0 ? Math.max(1, Math.round((row.count / max) * 100)) : 0) + '%';
      track.appendChild(fill);
      barCell.appendChild(track);
      tr.appendChild(barCell);

      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    target.appendChild(table);
  }

  function renderPairTable(target, pairs) {
    clear(target);
    if (pairs.length === 0) {
      target.appendChild(el('p', 'table-empty', 'Nothing to show.'));
      return;
    }

    var table = el('table');
    table.appendChild(el('caption', null, 'Top 10 source to destination conversations by packet count'));

    var thead = el('thead');
    var headRow = el('tr');
    [['#', null], ['Source', null], ['Destination', null], ['Packets', 'num'],
      ['Share', 'num'], ['Most common protocol', null]].forEach(function (pair) {
      var th = el('th', pair[1], pair[0]);
      th.setAttribute('scope', 'col');
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el('tbody');
    pairs.forEach(function (pair, index) {
      var tr = el('tr');
      tr.appendChild(el('td', 'num', index + 1));
      tr.appendChild(el('td', 'host', pair.source));
      tr.appendChild(el('td', 'host', pair.destination));
      tr.appendChild(el('td', 'num', formatNumber(pair.count)));
      tr.appendChild(el('td', 'num', formatDecimal(pair.share, 1) + '%'));
      tr.appendChild(el('td', 'info', pair.topProtocol ? pair.topProtocol.key : 'unknown'));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    target.appendChild(table);
  }

  /* ------------------------------- findings -------------------------------- */

  function evidenceList(items) {
    var dl = el('dl', 'evidence');
    items.forEach(function (item) {
      var box = el('div');
      box.appendChild(el('dt', null, item.label));
      box.appendChild(el('dd', null, item.value));
      dl.appendChild(box);
    });
    return dl;
  }

  function listBlock(heading, items, ordered) {
    var box = el('div');
    box.appendChild(el('h4', null, heading));
    var list = el(ordered ? 'ol' : 'ul');
    items.forEach(function (item) { list.appendChild(el('li', null, item)); });
    box.appendChild(list);
    return box;
  }

  function renderFinding(finding) {
    var article = el('article', 'finding ' + severityClass(finding.severity));
    article.id = 'finding-' + String(finding.id).replace(/[^A-Za-z0-9_.>-]/g, '_');

    var head = el('div', 'finding-head');
    head.appendChild(el('h3', 'finding-title', finding.name));
    head.appendChild(el('span', 'sev-badge ' + severityClass(finding.severity), finding.severity));
    head.appendChild(el('span', 'rule-tag', finding.rule));
    article.appendChild(head);

    article.appendChild(el('p', 'finding-summary', finding.summary));
    article.appendChild(evidenceList(finding.evidence));

    var body = el('div', 'finding-body');
    var why = el('div');
    why.appendChild(el('h4', null, 'Why this could matter'));
    why.appendChild(el('p', null, finding.whyMatters));
    body.appendChild(why);

    body.appendChild(listBlock('Possible benign explanations', finding.benign, false));
    body.appendChild(listBlock('Suggested investigation', finding.investigation, true));
    article.appendChild(body);

    if (finding.notes && finding.notes.length) {
      finding.notes.forEach(function (note) {
        article.appendChild(el('p', 'threshold-note', note));
      });
    }

    return article;
  }

  function renderFindings(target, findings, filters) {
    clear(target);
    var filtered = filterFindings(findings, filters);

    if (findings.length === 0) {
      target.appendChild(el('p', 'no-findings',
        'No rule thresholds were crossed in this capture. That does not prove the traffic is harmless; it ' +
        'means nothing stood out at the thresholds you have configured. A busy environment may need different ' +
        'numbers, and encrypted traffic hides a great deal from a packet list.'));
      return filtered;
    }

    if (filtered.length === 0) {
      target.appendChild(el('p', 'table-empty',
        'No findings match the current filters. Clear or widen the filters to see the full list.'));
      return filtered;
    }

    filtered.forEach(function (finding) {
      target.appendChild(renderFinding(finding));
    });
    return filtered;
  }

  function renderRuleCoverage(target, ruleStatus) {
    clear(target);
    target.appendChild(el('h3', null, 'Which rules ran on this capture'));
    var list = el('ul');

    ruleStatus.forEach(function (status) {
      var text;
      if (status.status === 'not_evaluated') {
        text = status.rule + ' (' + status.name + '): not evaluated - ' + status.reason;
      } else if (status.status === 'fired') {
        text = status.rule + ' (' + status.name + '): ' + status.count + ' finding(s)';
      } else {
        text = status.rule + ' (' + status.name + '): evaluated, nothing crossed the threshold';
      }
      list.appendChild(el('li', null, text));
    });

    target.appendChild(list);
    target.appendChild(el('p', 'hint',
      'Rules 3 and 7 need port or TCP flag detail in the Info column. When that detail is missing they are ' +
      'reported as not evaluated instead of guessing, so you always know what this report does and does not cover.'));
  }

  /* ------------------------------- packets -------------------------------- */

  function renderPacketTable(target, countTarget, packets, filters) {
    var filtered = filterPackets(packets, filters);
    var shown = filtered.slice(0, LIMITS.maxTableRows);

    clear(target);
    clear(countTarget);

    if (packets.length === 0) {
      countTarget.textContent = '';
      return;
    }

    countTarget.textContent = 'Showing ' + formatNumber(shown.length) + ' of ' + formatNumber(filtered.length) +
      ' matching packets (capture total: ' + formatNumber(packets.length) + ').';

    if (shown.length === 0) {
      target.appendChild(el('p', 'table-empty', 'No packets match the current filters.'));
      return;
    }

    var table = el('table');
    table.appendChild(el('caption', null, 'Packets matching the current filters'));

    var thead = el('thead');
    var headRow = el('tr');
    ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Destination port', 'Info'].forEach(function (text) {
      var th = el('th', text === 'No.' || text === 'Time' || text === 'Length' || text === 'Destination port' ? 'num' : null, text);
      th.setAttribute('scope', 'col');
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el('tbody');
    shown.forEach(function (packet) {
      var tr = el('tr');
      tr.appendChild(el('td', 'num', packet.number === '' ? packet.row : packet.number));
      tr.appendChild(el('td', 'num', packet.time === null ? 'n/a' : packet.time));
      tr.appendChild(el('td', 'host', packet.source));
      tr.appendChild(el('td', 'host', packet.destination));
      tr.appendChild(el('td', 'info', packet.protocol));
      tr.appendChild(el('td', 'num', packet.length === null ? 'n/a' : formatNumber(packet.length)));
      tr.appendChild(el('td', 'num', packet.dstPort === null
        ? 'n/a'
        : (packet.dstPort + (packet.portGuessed ? ' (guess)' : ''))));
      tr.appendChild(el('td', 'info', packet.info));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    target.appendChild(table);
  }

  /* ===========================================================================
   * 10. FILTERS
   * ======================================================================== */

  function normaliseFilterText(value) {
    return String(value || '').trim().toLowerCase();
  }

  function contains(haystack, needle) {
    return String(haystack || '').toLowerCase().indexOf(needle) !== -1;
  }

  function findingProtocolKeys(finding) {
    var keys = [];
    finding.evidence.forEach(function (item) {
      if (/protocol/i.test(item.label)) keys.push(protocolFamily(String(item.value)));
    });
    if (finding.ruleId === 'high_icmp') keys.push('icmp');
    if (finding.ruleId === 'high_dns') keys.push('dns');
    return keys;
  }

  function findingMatchesSearch(finding, needle) {
    if (contains(finding.name, needle)) return true;
    if (contains(finding.rule, needle)) return true;
    if (contains(finding.severity, needle)) return true;
    if (contains(finding.source, needle)) return true;
    if (contains(finding.destination, needle)) return true;
    if (contains(finding.summary, needle)) return true;
    var hit = false;
    finding.evidence.forEach(function (item) {
      if (contains(item.value, needle) || contains(item.label, needle)) hit = true;
    });
    return hit;
  }

  function filterFindings(findings, filters) {
    var search = normaliseFilterText(filters.search);
    return findings.filter(function (finding) {
      if (filters.source && finding.source !== filters.source) return false;
      if (filters.destination && finding.destination !== filters.destination) return false;
      if (filters.severity && finding.severity !== filters.severity) return false;
      if (filters.protocol && findingProtocolKeys(finding).indexOf(filters.protocol) === -1) return false;
      if (search !== '' && !findingMatchesSearch(finding, search)) return false;
      return true;
    });
  }

  function filterPackets(packets, filters) {
    var search = normaliseFilterText(filters.search);
    return packets.filter(function (packet) {
      if (filters.source && packet.source !== filters.source) return false;
      if (filters.destination && packet.destination !== filters.destination) return false;
      if (filters.protocol && packet.family !== filters.protocol) return false;
      if (search !== '') {
        var matched = contains(packet.source, search) || contains(packet.destination, search) ||
          contains(packet.protocol, search) || contains(packet.info, search) ||
          (packet.dstPort !== null && contains(String(packet.dstPort), search));
        if (!matched) return false;
      }
      return true;
    });
  }

  function fillSelect(select, options, allLabel) {
    var previous = select.value;
    clear(select);
    var all = el('option', null, allLabel);
    all.value = '';
    select.appendChild(all);

    options.forEach(function (option) {
      var node = el('option', null, option.label);
      node.value = option.value;
      select.appendChild(node);
    });

    var stillThere = false;
    for (var i = 0; i < select.options.length; i += 1) {
      if (select.options[i].value === previous) stillThere = true;
    }
    select.value = stillThere ? previous : '';
  }

  function populateFilters(report, filters) {
    var sourceOptions = sortCounts(report.stats.sourceCounts).map(function (entry) {
      return { value: entry.key, label: entry.key + ' (' + entry.count + ')' };
    });
    var destOptions = sortCounts(report.stats.destCounts).map(function (entry) {
      return { value: entry.key, label: entry.key + ' (' + entry.count + ')' };
    });
    var protocolOptions = report.stats.protocolFamilies.map(function (family) {
      return { value: family.key, label: family.label + ' (' + family.count + ')' };
    });

    fillSelect(filters.sourceSelect, sourceOptions, 'All sources');
    fillSelect(filters.destinationSelect, destOptions, 'All destinations');
    fillSelect(filters.protocolSelect, protocolOptions, 'All protocols');
  }

  function readFilters(nodes) {
    return {
      source: nodes.sourceSelect.value,
      destination: nodes.destinationSelect.value,
      protocol: nodes.protocolSelect.value,
      severity: nodes.severitySelect.value,
      search: nodes.searchInput.value
    };
  }

  function resetFilters(nodes) {
    nodes.sourceSelect.value = '';
    nodes.destinationSelect.value = '';
    nodes.protocolSelect.value = '';
    nodes.severitySelect.value = '';
    nodes.searchInput.value = '';
  }

  /* ===========================================================================
   * 11. LOAD STATUS AND PARSE SUMMARY
   * ======================================================================== */

  var MISSING_FIELD_EFFECTS = {
    source: 'Source addresses are required for every rule. Analysis cannot run without this column.',
    destination: 'Destination addresses are required for every rule. Analysis cannot run without this column.',
    protocol: 'Rule 4 (ICMP) and Rule 5 (DNS) cannot run, and the protocol distribution will show Unknown.',
    length: 'Average packet length is unavailable.',
    info: 'Rule 3 (port scanning) and Rule 7 (SYN heavy) cannot run, and the packet view will have no Info text.',
    number: 'Packets are numbered by their row position instead of the No. column.',
    time: 'Capture time span is unavailable.'
  };

  function setStatus(nodes, message, kind) {
    nodes.status.className = 'status' + (kind ? ' is-' + kind : '');
    clear(nodes.status);
    nodes.status.appendChild(el('span', null, message));
  }

  function parseSummaryItem(label, value) {
    var box = el('div', 'parse-item');
    box.appendChild(el('dt', null, label));
    box.appendChild(el('dd', null, value));
    return box;
  }

  function renderParseSummary(nodes, state) {
    var target = nodes.parseSummary;
    clear(target);

    if (!state.parse) {
      target.hidden = true;
      return;
    }
    target.hidden = false;

    var parse = state.parse;
    target.appendChild(el('h3', null, 'Capture details'));

    var grid = el('dl', 'parse-grid');
    grid.appendChild(parseSummaryItem('File name', state.fileName));
    grid.appendChild(parseSummaryItem('Data source', state.isDemo ? 'Demo Data (built into this page)' : 'Uploaded file'));
    grid.appendChild(parseSummaryItem('Parsed successfully', parse.ok ? 'Yes' : 'No'));
    grid.appendChild(parseSummaryItem('Packets loaded', parse.ok ? formatNumber(parse.packets.length) : '0'));
    grid.appendChild(parseSummaryItem('Rows in file', formatNumber(parse.dataRows || 0)));

    if (parse.ok && parse.skipped) {
      grid.appendChild(parseSummaryItem('Rows skipped', formatNumber(parse.skipped) +
        ' (no source or destination value)'));
    }

    if (parse.columns) {
      var found = [];
      Object.keys(parse.columns.matched).forEach(function (field) {
        found.push(FIELD_LABELS[field] + ' (header: "' + parse.columns.matched[field] + '")');
      });
      grid.appendChild(parseSummaryItem('Columns recognised', found.length ? found.join('; ') : 'none'));
    }
    target.appendChild(grid);

    var missing = [];
    if (parse.columns) {
      parse.columns.missingRequired.forEach(function (field) { missing.push(field); });
      parse.columns.missingOptional.forEach(function (field) { missing.push(field); });
    }

    if (missing.length > 0) {
      var list = el('ul', 'missing-list');
      missing.forEach(function (field) {
        var item = el('li');
        item.appendChild(el('strong', null, FIELD_LABELS[field] + ': '));
        item.appendChild(el('span', null, MISSING_FIELD_EFFECTS[field]));
        list.appendChild(item);
      });
      target.appendChild(list);
    }

    if (parse.warnings && parse.warnings.length > 0) {
      var warnings = el('ul', 'missing-list');
      parse.warnings.forEach(function (warning) {
        warnings.appendChild(el('li', null, warning));
      });
      target.appendChild(warnings);
    }
  }

  /* ===========================================================================
   * 12. UI WIRING
   *
   * The browser-only part. It reads thresholds from the form, hands the text
   * to the pure functions above, and paints the result. No network calls, no
   * storage APIs, no cookies: everything lives in the variables below and
   * disappears when the tab is closed.
   * ======================================================================== */

  var uiState = {
    fileName: '',
    isDemo: false,
    parse: null,
    report: null,
    packets: []
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function cacheDom() {
    return {
      fileInput: byId('file-input'),
      dropzone: byId('dropzone'),
      clearButton: byId('clear-btn'),
      status: byId('status'),
      parseSummary: byId('parse-summary'),
      demoBadge: byId('demo-badge-panel'),
      demoBadgeOverview: byId('demo-badge-overview'),
      overviewEmpty: byId('overview-empty'),
      overviewContent: byId('overview-content'),
      summaryCards: byId('summary-cards'),
      scoreNumber: byId('score-number'),
      scoreLabel: byId('score-label'),
      scoreBreakdown: byId('score-breakdown'),
      protocolChart: byId('protocol-chart'),
      topSources: byId('top-sources'),
      topDestinations: byId('top-destinations'),
      topPairs: byId('top-pairs'),
      findings: byId('findings'),
      ruleCoverage: byId('rule-coverage'),
      packetTable: byId('packet-table'),
      packetCount: byId('packet-count'),
      filterStatus: byId('filter-status'),
      resetThresholds: byId('reset-thresholds'),
      sampleButtons: document.querySelectorAll('[data-sample]'),
      filters: {
        sourceSelect: byId('filter-source'),
        destinationSelect: byId('filter-destination'),
        protocolSelect: byId('filter-protocol'),
        severitySelect: byId('filter-severity'),
        searchInput: byId('filter-search'),
        clearButton: byId('clear-filters')
      }
    };
  }

  function readThresholds() {
    var values = {};
    THRESHOLD_FIELDS.forEach(function (field) {
      var input = byId(field.inputId);
      values[field.key] = input ? input.value : DEFAULTS[field.key];
    });
    return normaliseThresholds(values);
  }

  function writeThresholds(values) {
    THRESHOLD_FIELDS.forEach(function (field) {
      var input = byId(field.inputId);
      if (input) input.value = values[field.key];
    });
  }

  function showEmptyState(nodes, message) {
    nodes.overviewEmpty.textContent = message;
    nodes.overviewEmpty.hidden = false;
    nodes.overviewContent.hidden = true;

    clear(nodes.protocolChart);
    nodes.protocolChart.appendChild(el('p', 'table-empty', message));
    clear(nodes.topSources);
    nodes.topSources.appendChild(el('p', 'table-empty', message));
    clear(nodes.topDestinations);
    nodes.topDestinations.appendChild(el('p', 'table-empty', message));
    clear(nodes.topPairs);
    nodes.topPairs.appendChild(el('p', 'table-empty', message));
    clear(nodes.ruleCoverage);
    clear(nodes.packetTable);
    clear(nodes.packetCount);

    clear(nodes.findings);
    nodes.findings.appendChild(el('p', 'table-empty', message));
    nodes.filterStatus.textContent = 'No capture loaded.';
    nodes.demoBadge.hidden = true;
    nodes.demoBadgeOverview.hidden = true;
  }

  function renderReport(nodes) {
    var report = uiState.report;
    if (!report) return;

    nodes.overviewEmpty.hidden = true;
    nodes.overviewContent.hidden = false;
    nodes.demoBadge.hidden = !uiState.isDemo;
    nodes.demoBadgeOverview.hidden = !uiState.isDemo;

    renderSummaryCards(nodes.summaryCards, report);
    renderScore(nodes.scoreNumber, nodes.scoreLabel, nodes.scoreBreakdown, report.score);
    renderProtocolChart(nodes.protocolChart, report);
    renderHostTable(nodes.topSources, 'Top 10 source hosts by packets sent',
      report.stats.topSources, 'Source host');
    renderHostTable(nodes.topDestinations, 'Top 10 destinations by packets received',
      report.stats.topDestinations, 'Destination');
    renderPairTable(nodes.topPairs, report.stats.topPairs);
    renderRuleCoverage(nodes.ruleCoverage, report.ruleStatus);

    populateFilters(report, nodes.filters);
    renderFiltered(nodes);
  }

  function renderFiltered(nodes) {
    if (!uiState.report) return;
    var filters = readFilters(nodes.filters);
    var shownFindings = renderFindings(nodes.findings, uiState.report.findings, filters);
    renderPacketTable(nodes.packetTable, nodes.packetCount, uiState.packets, filters);

    var matchingPackets = filterPackets(uiState.packets, filters).length;
    nodes.filterStatus.textContent = 'Showing ' + shownFindings.length + ' of ' +
      uiState.report.findings.length + ' findings, and ' + formatNumber(matchingPackets) + ' of ' +
      formatNumber(uiState.packets.length) + ' packets.';
  }

  /* ------------------------------- loading -------------------------------- */

  function loadText(nodes, text, fileName, isDemo) {
    var parse = parseCapture(text);

    uiState.fileName = fileName;
    uiState.isDemo = !!isDemo;
    uiState.parse = parse;
    uiState.report = null;
    uiState.packets = [];
    resetFilters(nodes.filters);
    nodes.clearButton.hidden = false;

    if (!parse.ok) {
      var message = 'Could not analyse "' + fileName + '". ' + parse.error;
      if (parse.hint) message += ' ' + parse.hint;
      setStatus(nodes, message, 'error');
      renderParseSummary(nodes, uiState);
      showEmptyState(nodes, 'This file could not be analysed, so there is nothing to report. ' +
        'The message above explains why.');
      return;
    }

    uiState.packets = parse.packets;
    setStatus(nodes, 'Loaded "' + fileName + '": ' + formatNumber(parse.packets.length) +
      ' packets parsed successfully.' + (isDemo ? ' This is Demo Data, not a real capture.' : ''), 'ok');
    renderParseSummary(nodes, uiState);
    applyThresholds(nodes);
  }

  function applyThresholds(nodes) {
    if (!uiState.parse || !uiState.parse.ok) return;
    uiState.report = analyse(uiState.packets, readThresholds());
    renderReport(nodes);
  }

  function readFile(nodes, file) {
    if (!file) return;

    var name = String(file.name || 'capture');
    if (!/\.(csv|txt)$/i.test(name)) {
      setStatus(nodes, 'That file type is not supported in Version 1. Please choose a Wireshark CSV export ' +
        '(".csv" or ".txt"). Raw .pcap and .pcapng files are not parsed yet.', 'error');
      return;
    }
    if (file.size > LIMITS.maxBytes) {
      setStatus(nodes, '"' + name + '" is about ' + formatNumber(Math.round(file.size / (1024 * 1024))) +
        ' MB, which is larger than the ' + Math.round(LIMITS.maxBytes / (1024 * 1024)) +
        ' MB limit. Export a shorter capture from Wireshark and try again.', 'error');
      return;
    }

    setStatus(nodes, 'Reading "' + name + '" locally in your browser...', 'warn');

    var reader = new FileReader();
    reader.onerror = function () {
      setStatus(nodes, 'The browser could not read that file. It may have been moved, or you may not have ' +
        'permission to open it.', 'error');
    };
    reader.onload = function () {
      try {
        loadText(nodes, String(reader.result || ''), name, false);
      } catch (error) {
        setStatus(nodes, 'Something went wrong while analysing "' + name + '". No data left your browser. ' +
          'Detail: ' + (error && error.message ? error.message : 'unknown error'), 'error');
      }
    };
    reader.readAsText(file, 'utf-8');
  }

  function clearAll(nodes) {
    uiState.fileName = '';
    uiState.isDemo = false;
    uiState.parse = null;
    uiState.report = null;
    uiState.packets = [];

    nodes.fileInput.value = '';
    nodes.clearButton.hidden = true;
    nodes.parseSummary.hidden = true;
    clear(nodes.parseSummary);
    resetFilters(nodes.filters);
    setStatus(nodes, 'Capture cleared. No packet data is held in this page any more.', 'ok');
    showEmptyState(nodes, 'Load a capture to see the network overview.');
  }

  /* ------------------------------- events --------------------------------- */

  function loadSample(nodes, fileName) {
    var text = EMBEDDED_SAMPLES[fileName];
    if (typeof text !== 'string') {
      setStatus(nodes, 'That demo capture is not available in this build.', 'error');
      return;
    }
    try {
      var label = SAMPLE_LABELS[fileName] || 'Demo capture';
      loadText(nodes, text, label + ' - ' + fileName, true);
    } catch (error) {
      setStatus(nodes, 'Could not load the demo capture: ' +
        (error && error.message ? error.message : 'unknown error'), 'error');
    }
  }

  function attachEvents(nodes) {
    /* file picker */
    nodes.fileInput.addEventListener('change', function (event) {
      var files = event.target.files;
      if (files && files.length > 0) readFile(nodes, files[0]);
    });

    /* drag and drop */
    ['dragenter', 'dragover'].forEach(function (type) {
      nodes.dropzone.addEventListener(type, function (event) {
        event.preventDefault();
        event.stopPropagation();
        nodes.dropzone.classList.add('is-dragover');
      });
    });
    ['dragleave', 'dragend'].forEach(function (type) {
      nodes.dropzone.addEventListener(type, function (event) {
        event.preventDefault();
        event.stopPropagation();
        nodes.dropzone.classList.remove('is-dragover');
      });
    });
    nodes.dropzone.addEventListener('drop', function (event) {
      event.preventDefault();
      event.stopPropagation();
      nodes.dropzone.classList.remove('is-dragover');
      var files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length > 0) {
        readFile(nodes, files[0]);
      } else {
        setStatus(nodes, 'No file was found in that drop. Try choosing the CSV with the file picker instead.',
          'warn');
      }
    });

    /* stop the browser from navigating away when a file is dropped elsewhere */
    ['dragover', 'drop'].forEach(function (type) {
      window.addEventListener(type, function (event) {
        if (event.target !== nodes.dropzone && !nodes.dropzone.contains(event.target)) {
          event.preventDefault();
        }
      });
    });

    nodes.clearButton.addEventListener('click', function () { clearAll(nodes); });

    Array.prototype.forEach.call(nodes.sampleButtons, function (button) {
      button.addEventListener('click', function () {
        loadSample(nodes, button.getAttribute('data-sample'));
      });
    });

    /* thresholds: re-run the analysis instantly, keeping any filters */
    THRESHOLD_FIELDS.forEach(function (field) {
      var input = byId(field.inputId);
      if (!input) return;
      input.addEventListener('change', function () {
        input.value = normaliseThresholds(readThresholds())[field.key];
        applyThresholds(nodes);
      });
    });

    nodes.resetThresholds.addEventListener('click', function () {
      writeThresholds(DEFAULTS);
      applyThresholds(nodes);
      setStatus(nodes, 'Thresholds reset to the educational defaults.', 'ok');
    });

    /* filters */
    nodes.filters.sourceSelect.addEventListener('change', function () { renderFiltered(nodes); });
    nodes.filters.destinationSelect.addEventListener('change', function () { renderFiltered(nodes); });
    nodes.filters.protocolSelect.addEventListener('change', function () { renderFiltered(nodes); });
    nodes.filters.severitySelect.addEventListener('change', function () { renderFiltered(nodes); });
    nodes.filters.searchInput.addEventListener('input', function () { renderFiltered(nodes); });
    nodes.filters.clearButton.addEventListener('click', function () {
      resetFilters(nodes.filters);
      renderFiltered(nodes);
    });
  }

  function startUI() {
    var nodes = cacheDom();
    writeThresholds(DEFAULTS);
    attachEvents(nodes);
    showEmptyState(nodes, 'Load a capture to see the network overview.');
    setStatus(nodes, 'No capture loaded yet. Upload a CSV or pick a demo capture.', null);
  }

/* =========================================================================
 * EMBEDDED DEMO DATA
 *
 * The three sample CSVs are also stored as real files in samples/ so that
 * students can practise the upload workflow. They are duplicated here as
 * plain text because a page opened directly from disk (file://) is not
 * allowed to read neighbouring files with fetch(). Nothing is downloaded.
 * Generated by tests/generate-samples.js - do not edit by hand.
 * ========================================================================= */

const EMBEDDED_SAMPLES = {
  "normal-traffic.csv": `"No.","Time","Source","Destination","Protocol","Length","Info"
"1","0.001000","192.168.1.10","192.168.1.1","ARP","42","Who has 192.168.1.1? Tell 192.168.1.10"
"2","0.002000","192.168.1.1","192.168.1.10","ARP","60","192.168.1.1 is at 00:11:22:33:44:55"
"3","0.003000","192.168.1.50","192.168.1.1","ARP","42","Who has 192.168.1.1? Tell 192.168.1.50"
"4","0.004000","192.168.1.1","192.168.1.50","ARP","60","192.168.1.1 is at 00:11:22:33:44:55"
"5","0.314000","192.168.1.15","255.255.255.255","DHCP","342","DHCP Request  - Transaction ID 0x3f2a91c4"
"6","0.334000","192.168.1.1","192.168.1.15","DHCP","342","DHCP ACK      - Transaction ID 0x3f2a91c4"
"7","0.354000","192.168.1.10","192.168.1.1","DNS","74","Standard query 0x1a2b A api.example.org"
"8","0.367000","192.168.1.1","192.168.1.10","DNS","90","Standard query response 0x1a2b A api.example.org A 203.0.113.10"
"9","0.767000","192.168.1.10","192.168.1.1","DNS","74","Standard query 0x1a2c A cdn.example.net"
"10","0.778000","192.168.1.1","192.168.1.10","DNS","93","Standard query response 0x1a2c A cdn.example.net A 198.51.100.45"
"11","1.678000","192.168.1.15","192.168.1.1","DNS","78","Standard query 0x2b10 AAAA mail.example.org"
"12","1.690000","192.168.1.1","192.168.1.15","DNS","94","Standard query response 0x2b10 AAAA mail.example.org AAAA 2001:db8:1::25"
"13","2.890000","192.168.1.20","192.168.1.1","DNS","82","Standard query 0x3c77 A time.example.net"
"14","2.904000","192.168.1.1","192.168.1.20","DNS","98","Standard query response 0x3c77 A time.example.net A 198.51.100.123"
"15","5.004000","192.168.1.50","192.168.1.1","DNS","76","Standard query 0x4d21 A print.example.org"
"16","5.017000","192.168.1.1","192.168.1.50","DNS","92","Standard query response 0x4d21 A print.example.org A 192.168.1.50"
"17","5.167000","192.168.1.10","203.0.113.10","TCP","74","52144 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
"18","5.188000","203.0.113.10","192.168.1.10","TCP","66","443 → 52144 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400 WS=128"
"19","5.189000","192.168.1.10","203.0.113.10","TCP","66","52144 → 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
"20","5.191000","192.168.1.10","203.0.113.10","TLSv1.3","571","Client Hello (SNI=api.example.org)"
"21","5.224000","203.0.113.10","192.168.1.10","TLSv1.3","1445","Server Hello, Change Cipher Spec, Application Data"
"22","5.226000","192.168.1.10","203.0.113.10","TLSv1.3","1180","Application Data"
"23","5.254000","203.0.113.10","192.168.1.10","TLSv1.3","1454","Application Data"
"24","5.255000","192.168.1.10","203.0.113.10","TCP","66","52144 → 443 [ACK] Seq=1123 Ack=1417 Win=63488 Len=0"
"25","6.305000","192.168.1.10","198.51.100.45","TCP","74","52146 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
"26","6.347000","198.51.100.45","192.168.1.10","TCP","66","443 → 52146 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1400"
"27","6.349000","192.168.1.10","198.51.100.45","TLSv1.3","583","Client Hello (SNI=cdn.example.net)"
"28","6.410000","198.51.100.45","192.168.1.10","TLSv1.3","1454","Server Hello, Application Data"
"29","6.411000","192.168.1.10","198.51.100.45","TCP","66","52146 → 443 [ACK] Seq=520 Ack=1401 Win=63488 Len=0"
"30","9.611000","192.168.1.10","203.0.113.20","TCP","74","52150 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
"31","9.666000","203.0.113.20","192.168.1.10","TCP","74","80 → 52150 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400 WS=128"
"32","9.667000","192.168.1.10","203.0.113.20","TCP","66","52150 → 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
"33","9.669000","192.168.1.10","203.0.113.20","HTTP","348","GET /index.html HTTP/1.1 "
"34","9.741000","203.0.113.20","192.168.1.10","HTTP","1414","HTTP/1.1 200 OK  (text/html)"
"35","9.742000","192.168.1.10","203.0.113.20","TCP","66","52150 → 80 [ACK] Seq=283 Ack=1349 Win=63488 Len=0"
"36","14.142000","192.168.1.15","203.0.113.20","TCP","74","53120 → 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 SACK_PERM"
"37","14.187000","203.0.113.20","192.168.1.15","TCP","66","443 → 53120 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400"
"38","14.189000","192.168.1.15","203.0.113.20","TLSv1.3","512","Client Hello (SNI=mail.example.org)"
"39","14.239000","203.0.113.20","192.168.1.15","TLSv1.3","1332","Server Hello, Application Data"
"40","14.243000","192.168.1.15","203.0.113.20","TLSv1.3","190","Application Data"
"41","14.643000","203.0.113.20","192.168.1.15","TCP","66","443 → 53120 [FIN, ACK] Seq=1398 Ack=449 Win=65535 Len=0"
"42","14.644000","192.168.1.15","203.0.113.20","TCP","66","53120 → 443 [FIN, ACK] Seq=449 Ack=1399 Win=65535 Len=0"
"43","20.744000","192.168.1.20","198.51.100.45","TCP","74","54880 → 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 SACK_PERM"
"44","20.802000","198.51.100.45","192.168.1.20","TCP","66","443 → 54880 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400"
"45","20.805000","192.168.1.20","198.51.100.45","TLSv1.2","517","Client Hello (SNI=cdn.example.net)"
"46","20.871000","198.51.100.45","192.168.1.20","TLSv1.2","1454","Server Hello, Application Data"
"47","21.071000","198.51.100.45","192.168.1.20","TLSv1.2","1514","Application Data"
"48","21.271000","198.51.100.45","192.168.1.20","TLSv1.2","1514","Application Data"
"49","28.771000","192.168.1.50","203.0.113.60","TCP","74","49312 → 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460"
"50","28.861000","203.0.113.60","192.168.1.50","TCP","66","443 → 49312 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400"
"51","28.865000","192.168.1.50","203.0.113.60","TLSv1.2","480","Client Hello (SNI=print.example.org)"
"52","28.975000","203.0.113.60","192.168.1.50","TLSv1.2","1206","Server Hello, Application Data"
"53","40.975000","192.168.1.20","198.51.100.123","NTP","90","NTP Version 4, Client"
"54","40.995000","198.51.100.123","192.168.1.20","NTP","90","NTP Version 4, Server"
"55","53.995000","192.168.1.10","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0001, seq=1/256, ttl=128 (reply in 2)"
"56","53.997000","192.168.1.1","192.168.1.10","ICMP","74","Echo (ping) reply    id=0x0001, seq=1/256, ttl=64 (request in 1)"
"57","54.997000","192.168.1.10","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0001, seq=2/512, ttl=128 (reply in 4)"
"58","54.999000","192.168.1.1","192.168.1.10","ICMP","74","Echo (ping) reply    id=0x0001, seq=2/512, ttl=64 (request in 3)"
`,
  "high-volume-traffic.csv": `"No.","Time","Source","Destination","Protocol","Length","Info"
"1","0.010000","192.168.1.25","192.168.1.1","DNS","74","Standard query 0x5e01 A backup.example.org"
"2","0.022000","192.168.1.1","192.168.1.25","DNS","106","Standard query response 0x5e01 A backup.example.org A 203.0.113.50"
"3","0.042000","192.168.1.10","192.168.1.1","DNS","74","Standard query 0x5e02 A api.example.org"
"4","0.055000","192.168.1.1","192.168.1.10","DNS","90","Standard query response 0x5e02 A api.example.org A 203.0.113.10"
"5","0.075000","192.168.1.10","192.168.1.1","ARP","42","Who has 192.168.1.1? Tell 192.168.1.10"
"6","0.076000","192.168.1.1","192.168.1.10","ARP","60","192.168.1.1 is at 00:11:22:33:44:55"
"7","0.476000","192.168.1.50","192.168.1.1","DNS","76","Standard query 0x5e03 A print.example.org"
"8","0.489000","192.168.1.1","192.168.1.50","DNS","92","Standard query response 0x5e03 A print.example.org A 192.168.1.50"
"9","1.389000","192.168.1.25","203.0.113.50","TCP","74","52410 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
"10","1.430000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1400"
"11","1.431000","192.168.1.25","203.0.113.50","TCP","66","52410 → 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
"12","1.433000","192.168.1.25","203.0.113.50","TLSv1.3","571","Client Hello (SNI=backup.example.org)"
"13","1.471000","203.0.113.50","192.168.1.25","TLSv1.3","1332","Server Hello, Change Cipher Spec, Application Data"
"14","1.476000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"15","1.482000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"16","1.489000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"17","1.494000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"18","1.500000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"19","1.507000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"20","1.512000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"21","1.516000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1427 Ack=309940 Win=29200 Len=0"
"22","1.523000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"23","1.528000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"24","1.534000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"25","1.541000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"26","1.546000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"27","1.552000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"28","1.559000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"29","1.563000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1435 Ack=321300 Win=29200 Len=0"
"30","1.569000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"31","1.576000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"32","1.581000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"33","1.587000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"34","1.594000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"35","1.599000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"36","1.605000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"37","1.609000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1443 Ack=332660 Win=29200 Len=0"
"38","1.614000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"39","1.620000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"40","1.627000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"41","1.632000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"42","1.638000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"43","1.645000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"44","1.650000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"45","1.654000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1451 Ack=344020 Win=29200 Len=0"
"46","1.661000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"47","1.666000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"48","1.672000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"49","1.679000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"50","1.684000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"51","1.690000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"52","1.697000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"53","1.701000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1459 Ack=355380 Win=29200 Len=0"
"54","1.707000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"55","1.714000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"56","1.719000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"57","1.725000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"58","1.732000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"59","1.737000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"60","1.743000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"61","1.747000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1467 Ack=366740 Win=29200 Len=0"
"62","1.752000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"63","1.758000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"64","1.765000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"65","1.770000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"66","1.776000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"67","1.783000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"68","1.788000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"69","1.792000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1475 Ack=378100 Win=29200 Len=0"
"70","1.799000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"71","1.804000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"72","1.810000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"73","1.817000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"74","1.822000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"75","1.828000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"76","1.835000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"77","1.839000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1483 Ack=389460 Win=29200 Len=0"
"78","1.845000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"79","1.852000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"80","1.857000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"81","1.863000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"82","1.870000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"83","1.875000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"84","1.881000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"85","1.885000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1491 Ack=400820 Win=29200 Len=0"
"86","1.890000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"87","1.896000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"88","1.903000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"89","1.908000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"90","1.914000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"91","1.921000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"92","1.926000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"93","1.930000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1499 Ack=412180 Win=29200 Len=0"
"94","1.937000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"95","1.942000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"96","1.948000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"97","1.955000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"98","1.960000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"99","1.966000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"100","1.973000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"101","1.977000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1507 Ack=423540 Win=29200 Len=0"
"102","1.983000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"103","1.990000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"104","1.995000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"105","2.001000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"106","2.008000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"107","2.013000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"108","2.019000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"109","2.023000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1515 Ack=434900 Win=29200 Len=0"
"110","2.028000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"111","2.034000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"112","2.041000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"113","2.046000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"114","2.052000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"115","2.059000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"116","2.064000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"117","2.068000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1523 Ack=446260 Win=29200 Len=0"
"118","2.075000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"119","2.080000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"120","2.086000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"121","2.093000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"122","2.098000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"123","2.104000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"124","2.111000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"125","2.115000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1531 Ack=457620 Win=29200 Len=0"
"126","2.121000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"127","2.128000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"128","2.133000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"129","2.139000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"130","2.146000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"131","2.151000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"132","2.157000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"133","2.161000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1539 Ack=468980 Win=29200 Len=0"
"134","2.166000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"135","2.172000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"136","2.179000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"137","2.184000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"138","2.190000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"139","2.197000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"140","2.202000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"141","2.206000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1547 Ack=480340 Win=29200 Len=0"
"142","2.213000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"143","2.218000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"144","2.224000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"145","2.231000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"146","2.236000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"147","2.242000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"148","2.249000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"149","2.253000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1555 Ack=491700 Win=29200 Len=0"
"150","2.259000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"151","2.266000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"152","2.271000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"153","2.277000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"154","2.284000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"155","2.289000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"156","2.295000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"157","2.299000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1563 Ack=503060 Win=29200 Len=0"
"158","2.304000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"159","2.310000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"160","2.317000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"161","2.322000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"162","2.328000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"163","2.335000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"164","2.340000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"165","2.344000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1571 Ack=514420 Win=29200 Len=0"
"166","2.351000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"167","2.356000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"168","2.362000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"169","2.369000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"170","2.374000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"171","2.380000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"172","2.387000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"173","2.391000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1579 Ack=525780 Win=29200 Len=0"
"174","2.397000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"175","2.404000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"176","2.409000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"177","2.415000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"178","2.422000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"179","2.427000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"180","2.433000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"181","2.437000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1587 Ack=537140 Win=29200 Len=0"
"182","2.442000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"183","2.448000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"184","2.455000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"185","2.460000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"186","2.466000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"187","2.473000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"188","2.478000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"189","2.482000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1595 Ack=548500 Win=29200 Len=0"
"190","2.489000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"191","2.494000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"192","2.500000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"193","2.507000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"194","2.512000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"195","2.518000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"196","2.525000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"197","2.529000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1603 Ack=559860 Win=29200 Len=0"
"198","2.535000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"199","2.542000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"200","2.547000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"201","2.553000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"202","2.560000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"203","2.565000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"204","2.571000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"205","2.575000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1611 Ack=571220 Win=29200 Len=0"
"206","2.580000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"207","2.586000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"208","2.593000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"209","2.598000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"210","2.604000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"211","2.611000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"212","2.616000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"213","2.620000","203.0.113.50","192.168.1.25","TCP","66","443 → 52410 [ACK] Seq=1619 Ack=582580 Win=29200 Len=0"
"214","2.627000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"215","2.632000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"216","2.638000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
"217","2.645000","192.168.1.25","203.0.113.50","TLSv1.3","1514","Application Data"
`,
  "mixed-soc-lab.csv": `"No.","Time","Source","Destination","Protocol","Length","Info"
"1","0.001000","192.168.1.10","192.168.1.1","ARP","42","Who has 192.168.1.1? Tell 192.168.1.10"
"2","0.002000","192.168.1.1","192.168.1.10","ARP","60","192.168.1.1 is at 00:11:22:33:44:55"
"3","0.022000","192.168.1.10","192.168.1.1","DNS","74","Standard query 0x1001 A mail.example.org"
"4","0.035000","192.168.1.1","192.168.1.10","DNS","90","Standard query response 0x1001 A mail.example.org A 203.0.113.20"
"5","0.135000","192.168.1.10","203.0.113.20","TCP","74","52144 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
"6","0.180000","203.0.113.20","192.168.1.10","TCP","66","443 → 52144 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400"
"7","0.182000","192.168.1.10","203.0.113.20","TLSv1.3","571","Client Hello (SNI=mail.example.org)"
"8","0.232000","203.0.113.20","192.168.1.10","TLSv1.3","1445","Server Hello, Application Data"
"9","0.235000","192.168.1.10","203.0.113.20","TLSv1.3","1180","Application Data"
"10","0.535000","203.0.113.20","192.168.1.10","TCP","66","443 → 52144 [FIN, ACK] Seq=1400 Ack=1 Win=65535 Len=0"
"11","1.035000","192.168.1.15","203.0.113.20","TCP","74","53120 → 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64"
"12","1.083000","203.0.113.20","192.168.1.15","TCP","66","443 → 53120 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400"
"13","1.086000","192.168.1.15","203.0.113.20","TLSv1.2","512","Client Hello (SNI=mail.example.org)"
"14","1.138000","203.0.113.20","192.168.1.15","TLSv1.2","1332","Server Hello, Application Data"
"15","1.142000","192.168.1.15","203.0.113.20","TLSv1.2","190","Application Data"
"16","4.142000","192.168.1.20","198.51.100.123","NTP","90","NTP Version 4, Client"
"17","4.172000","198.51.100.123","192.168.1.20","NTP","90","NTP Version 4, Server"
"18","8.172000","192.168.1.10","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0002, seq=1/256, ttl=128 (reply in 19)"
"19","8.174000","192.168.1.1","192.168.1.10","ICMP","74","Echo (ping) reply    id=0x0002, seq=1/256, ttl=64 (request in 18)"
"20","12.374000","192.168.1.10","192.168.1.1","HTTP","348","GET /router-status HTTP/1.1 "
"21","12.434000","192.168.1.1","192.168.1.10","HTTP","1216","HTTP/1.1 200 OK  (text/html)"
"22","12.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=1/512, ttl=64 (reply in 2)"
"23","12.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=1/512, ttl=64 (reply in 3)"
"24","13.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=2/512, ttl=64 (reply in 4)"
"25","13.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=2/512, ttl=64 (reply in 5)"
"26","13.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=3/512, ttl=64 (reply in 6)"
"27","13.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=3/512, ttl=64 (reply in 7)"
"28","14.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=4/512, ttl=64 (reply in 8)"
"29","14.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=4/512, ttl=64 (reply in 9)"
"30","14.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=5/512, ttl=64 (reply in 10)"
"31","14.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=5/512, ttl=64 (reply in 11)"
"32","15.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=6/512, ttl=64 (reply in 12)"
"33","15.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=6/512, ttl=64 (reply in 13)"
"34","15.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=7/512, ttl=64 (reply in 14)"
"35","15.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=7/512, ttl=64 (reply in 15)"
"36","16.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=8/512, ttl=64 (reply in 16)"
"37","16.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=8/512, ttl=64 (reply in 17)"
"38","16.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=9/512, ttl=64 (reply in 18)"
"39","16.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=9/512, ttl=64 (reply in 19)"
"40","17.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=10/512, ttl=64 (reply in 20)"
"41","17.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=10/512, ttl=64 (reply in 21)"
"42","17.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=11/512, ttl=64 (reply in 22)"
"43","17.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=11/512, ttl=64 (reply in 23)"
"44","18.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=12/512, ttl=64 (reply in 24)"
"45","18.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=12/512, ttl=64 (no response found!)"
"46","18.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=13/512, ttl=64 (no response found!)"
"47","18.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=13/512, ttl=64 (no response found!)"
"48","19.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=14/512, ttl=64 (no response found!)"
"49","19.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=14/512, ttl=64 (no response found!)"
"50","19.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=15/512, ttl=64 (no response found!)"
"51","19.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=15/512, ttl=64 (no response found!)"
"52","20.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=16/512, ttl=64 (no response found!)"
"53","20.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=16/512, ttl=64 (no response found!)"
"54","20.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=17/512, ttl=64 (no response found!)"
"55","20.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=17/512, ttl=64 (no response found!)"
"56","21.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=18/512, ttl=64 (no response found!)"
"57","21.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=18/512, ttl=64 (no response found!)"
"58","21.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=19/512, ttl=64 (no response found!)"
"59","21.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=19/512, ttl=64 (no response found!)"
"60","22.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=20/512, ttl=64 (no response found!)"
"61","22.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=20/512, ttl=64 (no response found!)"
"62","22.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=21/512, ttl=64 (no response found!)"
"63","22.934000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=21/512, ttl=64 (no response found!)"
"64","23.184000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=22/512, ttl=64 (no response found!)"
"65","23.434000","10.0.4.77","192.168.1.10","ICMP","74","Echo (ping) request  id=0x0b1e, seq=22/512, ttl=64 (no response found!)"
"66","23.684000","10.0.4.77","192.168.1.1","ICMP","74","Echo (ping) request  id=0x0b1e, seq=23/512, ttl=64 (no response found!)"
"67","23.774000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x2000 A host1.example.net"
"68","23.864000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2001 A host2.example.net"
"69","23.954000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2002 A host3.example.net"
"70","24.044000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x2003 A host4.example.net"
"71","24.134000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2004 A host5.example.net"
"72","24.224000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2005 A host6.example.net"
"73","24.314000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x2006 A host7.example.net"
"74","24.404000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2007 A host8.example.net"
"75","24.494000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2008 A host9.example.net"
"76","24.584000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x2009 A host10.example.net"
"77","24.674000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x200a A host11.example.net"
"78","24.764000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x200b A host12.example.net"
"79","24.854000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x200c A host13.example.net"
"80","24.944000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x200d A host14.example.net"
"81","25.034000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x200e A host15.example.net"
"82","25.124000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x200f A host16.example.net"
"83","25.214000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2010 A host17.example.net"
"84","25.304000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2011 A host18.example.net"
"85","25.394000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x2012 A host19.example.net"
"86","25.484000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2013 A host20.example.net"
"87","25.574000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2014 A host21.example.net"
"88","25.664000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x2015 A host22.example.net"
"89","25.754000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2016 A host23.example.net"
"90","25.844000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2017 A host24.example.net"
"91","25.934000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x2018 A host25.example.net"
"92","26.024000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2019 A host26.example.net"
"93","26.114000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x201a A host27.example.net"
"94","26.204000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x201b A host28.example.net"
"95","26.294000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x201c A host29.example.net"
"96","26.384000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x201d A host30.example.net"
"97","26.474000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x201e A host31.example.net"
"98","26.564000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x201f A host32.example.net"
"99","26.654000","10.0.4.90","192.168.1.1","DNS","78","Standard query 0x2020 A host33.example.net"
"100","26.744000","10.0.4.90","203.0.113.53","DNS","78","Standard query 0x2021 A host34.example.net"
"101","26.755000","192.168.1.1","10.0.4.90","DNS","94","Standard query response 0x2000 A host1.example.net A 203.0.113.100"
"102","26.766000","192.168.1.1","10.0.4.90","DNS","94","Standard query response 0x2001 A host2.example.net A 203.0.113.101"
"103","26.777000","192.168.1.1","10.0.4.90","DNS","94","Standard query response 0x2002 A host3.example.net A 203.0.113.102"
"104","26.788000","192.168.1.1","10.0.4.90","DNS","94","Standard query response 0x2003 A host4.example.net A 203.0.113.103"
"105","26.799000","192.168.1.1","10.0.4.90","DNS","94","Standard query response 0x2004 A host5.example.net A 203.0.113.104"
"106","26.810000","192.168.1.1","10.0.4.90","DNS","94","Standard query response 0x2005 A host6.example.net A 203.0.113.105"
"107","26.821000","192.168.1.1","10.0.4.90","DNS","94","Standard query response 0x2006 A host7.example.net A 203.0.113.106"
"108","26.832000","192.168.1.1","10.0.4.90","DNS","94","Standard query response 0x2007 A host8.example.net A 203.0.113.107"
"109","26.843000","192.168.1.1","10.0.4.90","DNS","94","Standard query response 0x2008 A host9.example.net A 203.0.113.108"
"110","26.854000","192.168.1.1","10.0.4.90","DNS","94","Standard query response 0x2009 A host10.example.net A 203.0.113.109"
"111","26.874000","172.16.5.20","192.168.1.40","TCP","74","54000 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"112","26.894000","172.16.5.20","192.168.1.41","TCP","74","54001 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"113","26.914000","172.16.5.20","192.168.1.42","TCP","74","54002 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"114","26.934000","172.16.5.20","192.168.1.43","TCP","74","54003 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"115","26.954000","172.16.5.20","192.168.1.44","TCP","74","54004 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"116","26.974000","172.16.5.20","192.168.1.45","TCP","74","54005 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"117","26.994000","172.16.5.20","192.168.1.46","TCP","74","54006 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"118","27.014000","172.16.5.20","192.168.1.47","TCP","74","54007 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"119","27.034000","172.16.5.20","192.168.1.48","TCP","74","54008 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"120","27.054000","172.16.5.20","192.168.1.49","TCP","74","54009 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"121","27.074000","172.16.5.20","192.168.1.60","TCP","74","54010 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"122","27.094000","172.16.5.20","192.168.1.61","TCP","74","54011 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"123","27.114000","172.16.5.20","192.168.1.62","TCP","74","54012 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"124","27.134000","172.16.5.20","172.16.5.30","TCP","74","54013 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"125","27.154000","172.16.5.20","172.16.5.31","TCP","74","54014 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"126","27.174000","172.16.5.20","172.16.5.32","TCP","74","54015 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"127","27.194000","172.16.5.20","172.16.5.33","TCP","74","54016 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"128","27.214000","172.16.5.20","172.16.5.34","TCP","74","54017 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"129","27.234000","172.16.5.20","10.0.4.10","TCP","74","54018 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"130","27.254000","172.16.5.20","10.0.4.11","TCP","74","54019 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"131","27.274000","172.16.5.20","10.0.4.12","TCP","74","54020 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"132","27.294000","172.16.5.20","10.0.4.20","TCP","74","54021 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"133","27.314000","172.16.5.20","10.0.4.21","TCP","74","54022 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"134","27.334000","172.16.5.20","10.0.4.22","TCP","74","54023 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"135","27.354000","172.16.5.20","10.0.4.30","TCP","74","54024 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"136","27.374000","172.16.5.20","10.0.4.31","TCP","74","54025 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"137","27.394000","172.16.5.20","10.0.4.32","TCP","74","54026 → 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"138","27.409000","172.16.5.20","192.168.1.40","TCP","74","54100 → 21 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"139","27.424000","172.16.5.20","192.168.1.40","TCP","74","54101 → 22 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"140","27.439000","172.16.5.20","192.168.1.40","TCP","74","54102 → 23 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"141","27.454000","172.16.5.20","192.168.1.40","TCP","74","54103 → 25 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"142","27.469000","172.16.5.20","192.168.1.40","TCP","74","54104 → 53 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"143","27.484000","172.16.5.20","192.168.1.40","TCP","74","54105 → 80 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"144","27.499000","172.16.5.20","192.168.1.40","TCP","74","54106 → 110 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"145","27.514000","172.16.5.20","192.168.1.40","TCP","74","54107 → 135 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"146","27.529000","172.16.5.20","192.168.1.40","TCP","74","54108 → 139 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"147","27.544000","172.16.5.20","192.168.1.40","TCP","74","54109 → 443 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"148","27.559000","172.16.5.20","192.168.1.40","TCP","74","54110 → 1433 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"149","27.574000","172.16.5.20","192.168.1.40","TCP","74","54111 → 3306 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"150","27.589000","172.16.5.20","192.168.1.40","TCP","74","54112 → 3389 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"151","27.604000","172.16.5.20","192.168.1.40","TCP","74","54113 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460"
"152","27.734000","10.0.4.88","192.168.1.60","TCP","74","53200 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"153","27.864000","10.0.4.88","192.168.1.60","TCP","74","53201 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"154","27.994000","10.0.4.88","192.168.1.60","TCP","74","53202 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"155","28.124000","10.0.4.88","192.168.1.60","TCP","74","53203 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"156","28.254000","10.0.4.88","192.168.1.60","TCP","74","53204 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"157","28.384000","10.0.4.88","192.168.1.60","TCP","74","53205 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"158","28.514000","10.0.4.88","192.168.1.60","TCP","74","53206 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"159","28.644000","10.0.4.88","192.168.1.60","TCP","74","53207 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"160","28.774000","10.0.4.88","192.168.1.60","TCP","74","53208 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"161","28.904000","10.0.4.88","192.168.1.60","TCP","74","53209 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"162","29.034000","10.0.4.88","192.168.1.60","TCP","74","53210 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"163","29.164000","10.0.4.88","192.168.1.60","TCP","74","53211 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"164","29.294000","10.0.4.88","192.168.1.60","TCP","74","53212 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"165","29.424000","10.0.4.88","192.168.1.60","TCP","74","53213 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"166","29.554000","10.0.4.88","192.168.1.60","TCP","74","53214 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"167","29.684000","10.0.4.88","192.168.1.60","TCP","74","53215 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"168","29.814000","10.0.4.88","192.168.1.60","TCP","74","53216 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"169","29.944000","10.0.4.88","192.168.1.60","TCP","74","53217 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"170","30.074000","10.0.4.88","192.168.1.60","TCP","74","53218 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"171","30.204000","10.0.4.88","192.168.1.60","TCP","74","53219 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"172","30.334000","10.0.4.88","192.168.1.60","TCP","74","53220 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"173","30.464000","10.0.4.88","192.168.1.60","TCP","74","53221 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"174","30.594000","10.0.4.88","192.168.1.60","TCP","74","53222 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"175","30.724000","10.0.4.88","192.168.1.60","TCP","74","53223 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"176","30.854000","10.0.4.88","192.168.1.60","TCP","74","53224 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"177","30.984000","10.0.4.88","192.168.1.60","TCP","74","53225 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"178","31.114000","10.0.4.88","192.168.1.60","TCP","74","53226 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"179","31.244000","10.0.4.88","192.168.1.60","TCP","74","53227 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"180","31.374000","10.0.4.88","192.168.1.60","TCP","74","53228 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"181","31.504000","10.0.4.88","192.168.1.60","TCP","74","53229 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"182","31.634000","10.0.4.88","192.168.1.60","TCP","74","53230 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"183","31.764000","10.0.4.88","192.168.1.60","TCP","74","53231 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"184","31.894000","10.0.4.88","192.168.1.60","TCP","74","53232 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"185","32.024000","10.0.4.88","192.168.1.60","TCP","74","53233 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"186","32.154000","10.0.4.88","192.168.1.60","TCP","74","53234 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"187","32.284000","10.0.4.88","192.168.1.60","TCP","74","53235 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"188","32.414000","10.0.4.88","192.168.1.60","TCP","74","53236 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"189","32.544000","10.0.4.88","192.168.1.60","TCP","74","53237 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"190","32.674000","10.0.4.88","192.168.1.60","TCP","74","53238 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"191","32.804000","10.0.4.88","192.168.1.60","TCP","74","53239 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"192","32.934000","10.0.4.88","192.168.1.60","TCP","74","53240 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"193","33.064000","10.0.4.88","192.168.1.60","TCP","74","53241 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"194","33.194000","10.0.4.88","192.168.1.60","TCP","74","53242 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"195","33.324000","10.0.4.88","192.168.1.60","TCP","74","53243 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"196","33.454000","10.0.4.88","192.168.1.60","TCP","74","53244 → 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM"
"197","39.454000","192.168.1.25","192.168.1.30","TCP","74","52400 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
"198","39.456000","192.168.1.25","192.168.1.30","TLSv1.3","571","Client Hello (SNI=srv-backup.example.org)"
"199","39.462000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"200","39.468000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"201","39.474000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"202","39.480000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"203","39.486000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"204","39.492000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"205","39.498000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"206","39.504000","192.168.1.25","192.168.1.30","TCP","66","52400 → 443 [ACK] Seq=1009 Ack=2009 Win=63488 Len=0"
"207","39.510000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"208","39.516000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"209","39.522000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"210","39.528000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"211","39.534000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"212","39.540000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"213","39.546000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"214","39.552000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"215","39.558000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"216","39.564000","192.168.1.25","192.168.1.30","TCP","66","52400 → 443 [ACK] Seq=1019 Ack=2019 Win=63488 Len=0"
"217","39.570000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"218","39.576000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"219","39.582000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"220","39.588000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"221","39.594000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"222","39.600000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"223","39.606000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"224","39.612000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"225","39.618000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"226","39.624000","192.168.1.25","192.168.1.30","TCP","66","52400 → 443 [ACK] Seq=1029 Ack=2029 Win=63488 Len=0"
"227","39.630000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"228","39.636000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"229","39.642000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"230","39.648000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"231","39.654000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"232","39.660000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"233","39.666000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"234","39.672000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"235","39.678000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"236","39.684000","192.168.1.25","192.168.1.30","TCP","66","52400 → 443 [ACK] Seq=1039 Ack=2039 Win=63488 Len=0"
"237","39.690000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"238","39.696000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"239","39.702000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"240","39.708000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"241","39.714000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"242","39.720000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"243","39.726000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"244","39.732000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"245","39.738000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"246","39.744000","192.168.1.25","192.168.1.30","TCP","66","52400 → 443 [ACK] Seq=1049 Ack=2049 Win=63488 Len=0"
"247","39.750000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"248","39.756000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"249","39.762000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"250","39.768000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"251","39.774000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"252","39.780000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"253","39.786000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"254","39.792000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"255","39.798000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"256","39.804000","192.168.1.25","192.168.1.30","TCP","66","52400 → 443 [ACK] Seq=1059 Ack=2059 Win=63488 Len=0"
"257","39.810000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"258","39.816000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"259","39.822000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"260","39.828000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"261","39.834000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"262","39.840000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"263","39.846000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"264","39.852000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"265","39.858000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"266","39.864000","192.168.1.25","192.168.1.30","TCP","66","52400 → 443 [ACK] Seq=1069 Ack=2069 Win=63488 Len=0"
"267","39.870000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"268","39.876000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"269","39.882000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"270","39.888000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"271","39.894000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"272","39.900000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"273","39.906000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"274","39.912000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"275","39.918000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"276","39.924000","192.168.1.25","192.168.1.30","TCP","66","52400 → 443 [ACK] Seq=1079 Ack=2079 Win=63488 Len=0"
"277","39.930000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"278","39.936000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"279","39.942000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"280","39.948000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"281","39.954000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"282","39.960000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"283","39.966000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"284","39.972000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"285","39.978000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"286","39.984000","192.168.1.25","192.168.1.30","TCP","66","52400 → 443 [ACK] Seq=1089 Ack=2089 Win=63488 Len=0"
"287","39.990000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"288","39.996000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"289","40.002000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"290","40.008000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"291","40.014000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"292","40.020000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"293","40.026000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"294","40.032000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"295","40.038000","192.168.1.25","192.168.1.30","TLSv1.3","1514","Application Data"
"296","40.044000","192.168.1.25","192.168.1.30","TCP","66","52400 → 443 [ACK] Seq=1099 Ack=2099 Win=63488 Len=0"
`,
};

const SAMPLE_LABELS = {
  "normal-traffic.csv": "Normal traffic",
  "high-volume-traffic.csv": "High volume traffic",
  "mixed-soc-lab.csv": "Mixed SOC lab"
};

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














