'use strict';
/*
 * Sample-data generator for the Network Traffic Triage Tool.
 *
 * This script is a DEVELOPMENT TOOL only. It is not part of the shipped application.
 * It writes three fictional Wireshark-style CSV exports into /workspace/samples/
 * and emits the browser-embeddable copy used by the "Load ... Sample" demo buttons.
 *
 * All addresses are private (RFC1918) or reserved for documentation (RFC 5737):
 *   192.168.x.x / 10.x.x.x / 172.16.x.x  -> private
 *   192.0.2.x / 198.51.100.x / 203.0.113.x -> documentation ranges
 * No real infrastructure, malicious or otherwise, is referenced.
 *
 * Deterministic: no randomness, so re-running produces identical files.
 */

const fs = require('fs');
const path = require('path');

const OUT_DIR = '/workspace/samples';
const EMBED_OUT = '/tmp/samples-embed.part.js';

/* ---------- tiny CSV writer (mirrors the quoting Wireshark uses) ---------- */

function field(v) {
  return '"' + String(v).replace(/"/g, '""') + '"';
}
function csvRow(cells) {
  return cells.map(field).join(',');
}
const HEADER = csvRow(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']);

/* ---------- row builder: keeps packet numbers + timestamps monotonic ---------- */

function builder() {
  let n = 0;
  let t = 0;
  const rows = [];
  return {
    add(src, dst, proto, len, info, gap) {
      n += 1;
      t += typeof gap === 'number' ? gap : 0.003 + (n % 9) * 0.002;
      rows.push(csvRow([n, t.toFixed(6), src, dst, proto, len, info]));
      return n;
    },
    /* repeat the same shape of row `times` times with slightly varying values */
    repeat(times, fn) {
      for (let i = 0; i < times; i += 1) fn(i, this);
    },
    count() {
      return rows.length;
    },
    text() {
      return [HEADER].concat(rows).join('\r\n') + '\r\n';
    }
  };
}

/* =======================================================================
 * SAMPLE 1 - normal-traffic.csv
 * Ordinary small-office traffic. Nothing should trip a default threshold.
 * ======================================================================= */

function normalTraffic() {
  const b = builder();
  const LAPTOP = '192.168.1.10';
  const PHONE = '192.168.1.15';
  const TV = '192.168.1.20';
  const PRINTER = '192.168.1.50';
  const GW = '192.168.1.1';
  const WEB = '203.0.113.20';
  const API = '203.0.113.10';
  const CDN = '198.51.100.45';
  const NTP = '198.51.100.123';

  // ARP housekeeping
  b.add(LAPTOP, GW, 'ARP', 42, 'Who has ' + GW + '? Tell ' + LAPTOP, 0.001);
  b.add(GW, LAPTOP, 'ARP', 60, GW + ' is at 00:11:22:33:44:55', 0.001);
  b.add(PRINTER, GW, 'ARP', 42, 'Who has ' + GW + '? Tell ' + PRINTER, 0.001);
  b.add(GW, PRINTER, 'ARP', 60, GW + ' is at 00:11:22:33:44:55', 0.001);

  // DHCP renew for the phone
  b.add(PHONE, '255.255.255.255', 'DHCP', 342, 'DHCP Request  - Transaction ID 0x3f2a91c4', 0.31);
  b.add(GW, PHONE, 'DHCP', 342, 'DHCP ACK      - Transaction ID 0x3f2a91c4', 0.02);

  // DNS lookups (small numbers per host)
  b.add(LAPTOP, GW, 'DNS', 74, 'Standard query 0x1a2b A api.example.org', 0.02);
  b.add(GW, LAPTOP, 'DNS', 90, 'Standard query response 0x1a2b A api.example.org A ' + API, 0.013);
  b.add(LAPTOP, GW, 'DNS', 74, 'Standard query 0x1a2c A cdn.example.net', 0.4);
  b.add(GW, LAPTOP, 'DNS', 93, 'Standard query response 0x1a2c A cdn.example.net A ' + CDN, 0.011);
  b.add(PHONE, GW, 'DNS', 78, 'Standard query 0x2b10 AAAA mail.example.org', 0.9);
  b.add(GW, PHONE, 'DNS', 94, 'Standard query response 0x2b10 AAAA mail.example.org AAAA 2001:db8:1::25', 0.012);
  b.add(TV, GW, 'DNS', 82, 'Standard query 0x3c77 A time.example.net', 1.2);
  b.add(GW, TV, 'DNS', 98, 'Standard query response 0x3c77 A time.example.net A ' + NTP, 0.014);
  b.add(PRINTER, GW, 'DNS', 76, 'Standard query 0x4d21 A print.example.org', 2.1);
  b.add(GW, PRINTER, 'DNS', 92, 'Standard query response 0x4d21 A print.example.org A 192.168.1.50', 0.013);

  // Laptop browsing: TCP handshake then TLS application data
  b.add(LAPTOP, API, 'TCP', 74, '52144 \u2192 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM', 0.15);
  b.add(API, LAPTOP, 'TCP', 66, '443 \u2192 52144 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400 WS=128', 0.021);
  b.add(LAPTOP, API, 'TCP', 66, '52144 \u2192 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0', 0.001);
  b.add(LAPTOP, API, 'TLSv1.3', 571, 'Client Hello (SNI=api.example.org)', 0.002);
  b.add(API, LAPTOP, 'TLSv1.3', 1445, 'Server Hello, Change Cipher Spec, Application Data', 0.033);
  b.add(LAPTOP, API, 'TLSv1.3', 1180, 'Application Data', 0.002);
  b.add(API, LAPTOP, 'TLSv1.3', 1454, 'Application Data', 0.028);
  b.add(LAPTOP, API, 'TCP', 66, '52144 \u2192 443 [ACK] Seq=1123 Ack=1417 Win=63488 Len=0', 0.001);

  b.add(LAPTOP, CDN, 'TCP', 74, '52146 \u2192 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM', 1.05);
  b.add(CDN, LAPTOP, 'TCP', 66, '443 \u2192 52146 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1400', 0.042);
  b.add(LAPTOP, CDN, 'TLSv1.3', 583, 'Client Hello (SNI=cdn.example.net)', 0.002);
  b.add(CDN, LAPTOP, 'TLSv1.3', 1454, 'Server Hello, Application Data', 0.061);
  b.add(LAPTOP, CDN, 'TCP', 66, '52146 \u2192 443 [ACK] Seq=520 Ack=1401 Win=63488 Len=0', 0.001);

  // Laptop plain HTTP to a documentation site
  b.add(LAPTOP, WEB, 'TCP', 74, '52150 \u2192 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM', 3.2);
  b.add(WEB, LAPTOP, 'TCP', 74, '80 \u2192 52150 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400 WS=128', 0.055);
  b.add(LAPTOP, WEB, 'TCP', 66, '52150 \u2192 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0', 0.001);
  b.add(LAPTOP, WEB, 'HTTP', 348, 'GET /index.html HTTP/1.1 ', 0.002);
  b.add(WEB, LAPTOP, 'HTTP', 1414, 'HTTP/1.1 200 OK  (text/html)', 0.072);
  b.add(LAPTOP, WEB, 'TCP', 66, '52150 \u2192 80 [ACK] Seq=283 Ack=1349 Win=63488 Len=0', 0.001);

  // Phone app traffic
  b.add(PHONE, WEB, 'TCP', 74, '53120 \u2192 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 SACK_PERM', 4.4);
  b.add(WEB, PHONE, 'TCP', 66, '443 \u2192 53120 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400', 0.045);
  b.add(PHONE, WEB, 'TLSv1.3', 512, 'Client Hello (SNI=mail.example.org)', 0.002);
  b.add(WEB, PHONE, 'TLSv1.3', 1332, 'Server Hello, Application Data', 0.05);
  b.add(PHONE, WEB, 'TLSv1.3', 190, 'Application Data', 0.004);
  b.add(WEB, PHONE, 'TCP', 66, '443 \u2192 53120 [FIN, ACK] Seq=1398 Ack=449 Win=65535 Len=0', 0.4);
  b.add(PHONE, WEB, 'TCP', 66, '53120 \u2192 443 [FIN, ACK] Seq=449 Ack=1399 Win=65535 Len=0', 0.001);

  // Smart TV fetching a manifest plus video segments
  b.add(TV, CDN, 'TCP', 74, '54880 \u2192 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 SACK_PERM', 6.1);
  b.add(CDN, TV, 'TCP', 66, '443 \u2192 54880 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400', 0.058);
  b.add(TV, CDN, 'TLSv1.2', 517, 'Client Hello (SNI=cdn.example.net)', 0.003);
  b.add(CDN, TV, 'TLSv1.2', 1454, 'Server Hello, Application Data', 0.066);
  b.add(CDN, TV, 'TLSv1.2', 1514, 'Application Data', 0.2);
  b.add(CDN, TV, 'TLSv1.2', 1514, 'Application Data', 0.2);

  // Printer management page
  b.add(PRINTER, '203.0.113.60', 'TCP', 74, '49312 \u2192 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460', 7.5);
  b.add('203.0.113.60', PRINTER, 'TCP', 66, '443 \u2192 49312 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400', 0.09);
  b.add(PRINTER, '203.0.113.60', 'TLSv1.2', 480, 'Client Hello (SNI=print.example.org)', 0.004);
  b.add('203.0.113.60', PRINTER, 'TLSv1.2', 1206, 'Server Hello, Application Data', 0.11);

  // NTP sync from the TV
  b.add(TV, NTP, 'NTP', 90, 'NTP Version 4, Client', 12.0);
  b.add(NTP, TV, 'NTP', 90, 'NTP Version 4, Server', 0.02);

  // Two harmless pings while the user checks the gateway
  b.add(LAPTOP, GW, 'ICMP', 74, 'Echo (ping) request  id=0x0001, seq=1/256, ttl=128 (reply in 2)', 13.0);
  b.add(GW, LAPTOP, 'ICMP', 74, 'Echo (ping) reply    id=0x0001, seq=1/256, ttl=64 (request in 1)', 0.002);
  b.add(LAPTOP, GW, 'ICMP', 74, 'Echo (ping) request  id=0x0001, seq=2/512, ttl=128 (reply in 4)', 1.0);
  b.add(GW, LAPTOP, 'ICMP', 74, 'Echo (ping) reply    id=0x0001, seq=2/512, ttl=64 (request in 3)', 0.002);

  return b;
}

/* =======================================================================
 * SAMPLE 2 - high-volume-traffic.csv
 * One workstation pushes 183 packets at a single server (a large upload /
 * backup / sync). Rule 1 (>50 packets from one source) must fire.
 * It also fires Rule 6 (>40 packets to the same destination), which is
 * intentional and realistic: a big transfer is chatty *and* repetitive.
 * ======================================================================= */

function highVolumeTraffic() {
  const b = builder();
  const WORKSTATION = '192.168.1.25';
  const BACKUP_SERVER = '203.0.113.50';
  const GW = '192.168.1.1';
  const LAPTOP = '192.168.1.10';
  const PRINTER = '192.168.1.50';

  // A little ordinary background noise so the dashboard is not a single host.
  b.add(WORKSTATION, GW, 'DNS', 74, 'Standard query 0x5e01 A backup.example.org', 0.01);
  b.add(GW, WORKSTATION, 'DNS', 106, 'Standard query response 0x5e01 A backup.example.org A ' + BACKUP_SERVER, 0.012);
  b.add(LAPTOP, GW, 'DNS', 74, 'Standard query 0x5e02 A api.example.org', 0.02);
  b.add(GW, LAPTOP, 'DNS', 90, 'Standard query response 0x5e02 A api.example.org A 203.0.113.10', 0.013);
  b.add(LAPTOP, GW, 'ARP', 42, 'Who has ' + GW + '? Tell ' + LAPTOP, 0.02);
  b.add(GW, LAPTOP, 'ARP', 60, GW + ' is at 00:11:22:33:44:55', 0.001);
  b.add(PRINTER, GW, 'DNS', 76, 'Standard query 0x5e03 A print.example.org', 0.4);
  b.add(GW, PRINTER, 'DNS', 92, 'Standard query response 0x5e03 A print.example.org A 192.168.1.50', 0.013);

  // The workstation opens a TLS session to the backup service, then keeps sending.
  b.add(WORKSTATION, BACKUP_SERVER, 'TCP', 74, '52410 \u2192 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM', 0.9);
  b.add(BACKUP_SERVER, WORKSTATION, 'TCP', 66, '443 \u2192 52410 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1400', 0.041);
  b.add(WORKSTATION, BACKUP_SERVER, 'TCP', 66, '52410 \u2192 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0', 0.001);
  b.add(WORKSTATION, BACKUP_SERVER, 'TLSv1.3', 571, 'Client Hello (SNI=backup.example.org)', 0.002);
  b.add(BACKUP_SERVER, WORKSTATION, 'TLSv1.3', 1332, 'Server Hello, Change Cipher Spec, Application Data', 0.038);

  // 204 further packets: a steady encrypted upload of 1.4 KB segments.
  // (Together with the handshake this gives exactly 183 packets sourced by
  //  192.168.1.25, which is the figure quoted in the project documentation.)
  b.repeat(204, (i, self) => {
    const isAck = i % 8 === 7;
    if (isAck) {
      self.add(BACKUP_SERVER, WORKSTATION, 'TCP', 66,
        '443 \u2192 52410 [ACK] Seq=' + (1420 + i) + ' Ack=' + (300000 + i * 1420) + ' Win=29200 Len=0', 0.004);
    } else {
      self.add(WORKSTATION, BACKUP_SERVER, 'TLSv1.3', 1514,
        'Application Data', 0.005 + (i % 3) * 0.001);
    }
  });

  return b;
}

/* =======================================================================
 * SAMPLE 3 - mixed-soc-lab.csv
 * The "everything at once" teaching capture. It contains one example of
 * each of the seven detection rules plus ordinary background traffic:
 *
 *   Rule 1 High packet volume ....... 192.168.1.25 (100 pkts to one server)
 *   Rule 2 Possible host scanning ... 172.16.5.20 (27 unique destinations)
 *   Rule 3 Possible port scanning ... 172.16.5.20 -> 192.168.1.40 (15 ports)
 *   Rule 4 High ICMP activity ....... 10.0.4.77 (45 ICMP packets)
 *   Rule 5 High DNS activity ........ 10.0.4.90 (34 DNS packets)
 *   Rule 6 Repeated source -> dest .. 10.0.4.88 -> 192.168.1.60 (45 pkts)
 *   Rule 7 TCP SYN heavy ............ 10.0.4.88 (45 SYN packets)
 *
 * Every one of these has a plausible innocent explanation, which is the
 * point of the exercise. Keep the background traffic below every threshold.
 * ======================================================================= */

function mixedSocLab() {
  const b = builder();
  const LAPTOP = '192.168.1.10';
  const PHONE = '192.168.1.15';
  const TV = '192.168.1.20';
  const GW = '192.168.1.1';
  const WEB = '203.0.113.20';
  const NTP = '198.51.100.123';

  /* ---- background: ordinary office traffic ---- */
  b.add(LAPTOP, GW, 'ARP', 42, 'Who has ' + GW + '? Tell ' + LAPTOP, 0.001);
  b.add(GW, LAPTOP, 'ARP', 60, GW + ' is at 00:11:22:33:44:55', 0.001);
  b.add(LAPTOP, GW, 'DNS', 74, 'Standard query 0x1001 A mail.example.org', 0.02);
  b.add(GW, LAPTOP, 'DNS', 90, 'Standard query response 0x1001 A mail.example.org A ' + WEB, 0.013);
  b.add(LAPTOP, WEB, 'TCP', 74, '52144 \u2192 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM', 0.1);
  b.add(WEB, LAPTOP, 'TCP', 66, '443 \u2192 52144 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400', 0.045);
  b.add(LAPTOP, WEB, 'TLSv1.3', 571, 'Client Hello (SNI=mail.example.org)', 0.002);
  b.add(WEB, LAPTOP, 'TLSv1.3', 1445, 'Server Hello, Application Data', 0.05);
  b.add(LAPTOP, WEB, 'TLSv1.3', 1180, 'Application Data', 0.003);
  b.add(WEB, LAPTOP, 'TCP', 66, '443 \u2192 52144 [FIN, ACK] Seq=1400 Ack=1 Win=65535 Len=0', 0.3);
  b.add(PHONE, WEB, 'TCP', 74, '53120 \u2192 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64', 0.5);
  b.add(WEB, PHONE, 'TCP', 66, '443 \u2192 53120 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400', 0.048);
  b.add(PHONE, WEB, 'TLSv1.2', 512, 'Client Hello (SNI=mail.example.org)', 0.003);
  b.add(WEB, PHONE, 'TLSv1.2', 1332, 'Server Hello, Application Data', 0.052);
  b.add(PHONE, WEB, 'TLSv1.2', 190, 'Application Data', 0.004);
  b.add(TV, NTP, 'NTP', 90, 'NTP Version 4, Client', 3.0);
  b.add(NTP, TV, 'NTP', 90, 'NTP Version 4, Server', 0.03);
  b.add(LAPTOP, GW, 'ICMP', 74, 'Echo (ping) request  id=0x0002, seq=1/256, ttl=128 (reply in 19)', 4.0);
  b.add(GW, LAPTOP, 'ICMP', 74, 'Echo (ping) reply    id=0x0002, seq=1/256, ttl=64 (request in 18)', 0.002);
  b.add(LAPTOP, GW, 'HTTP', 348, 'GET /router-status HTTP/1.1 ', 4.2);
  b.add(GW, LAPTOP, 'HTTP', 1216, 'HTTP/1.1 200 OK  (text/html)', 0.06);

  /* ---- Rule 4 example: one host pinging two systems, 45 ICMP packets ---- */
  const PINGER = '10.0.4.77';
  const PING_TARGETS = ['192.168.1.1', '192.168.1.10'];
  b.repeat(45, (i, self) => {
    const target = PING_TARGETS[i % 2];
    const seq = Math.floor(i / 2) + 1;
    if (i < 23) {
      self.add(PINGER, target, 'ICMP', 74,
        'Echo (ping) request  id=0x0b1e, seq=' + seq + '/512, ttl=64 (reply in ' + (i + 2) + ')', 0.25);
    } else {
      self.add(PINGER, target, 'ICMP', 74,
        'Echo (ping) request  id=0x0b1e, seq=' + seq + '/512, ttl=64 (no response found!)', 0.25);
    }
  });

  /* ---- Rule 5 example: one host making 34 DNS lookups ---- */
  const DNS_HOST = '10.0.4.90';
  const RESOLVER = '192.168.1.1';
  const EXT_RESOLVER = '203.0.113.53';
  b.repeat(34, (i, self) => {
    const upstream = i % 3 === 0 ? EXT_RESOLVER : RESOLVER;
    self.add(DNS_HOST, upstream, 'DNS', 78,
      'Standard query 0x' + (0x2000 + i).toString(16) + ' A host' + (i + 1) + '.example.net', 0.09);
  });
  b.repeat(10, (i, self) => {
    self.add(RESOLVER, DNS_HOST, 'DNS', 94,
      'Standard query response 0x' + (0x2000 + i).toString(16) + ' A host' + (i + 1) + '.example.net A 203.0.113.' + (100 + i), 0.011);
  });

  /* ---- Rules 2 + 3 example: one host touching 27 destinations, and 15 ports on one of them ---- */
  const SCANNER = '172.16.5.20';
  const SCAN_TARGETS = [
    '192.168.1.40', '192.168.1.41', '192.168.1.42', '192.168.1.43', '192.168.1.44',
    '192.168.1.45', '192.168.1.46', '192.168.1.47', '192.168.1.48', '192.168.1.49',
    '192.168.1.60', '192.168.1.61', '192.168.1.62', '172.16.5.30', '172.16.5.31',
    '172.16.5.32', '172.16.5.33', '172.16.5.34', '10.0.4.10', '10.0.4.11',
    '10.0.4.12', '10.0.4.20', '10.0.4.21', '10.0.4.22', '10.0.4.30',
    '10.0.4.31', '10.0.4.32'
  ];
  b.repeat(SCAN_TARGETS.length, (i, self) => {
    self.add(SCANNER, SCAN_TARGETS[i], 'TCP', 74,
      (54000 + i) + ' \u2192 445 [SYN] Seq=0 Win=1024 Len=0 MSS=1460', 0.02);
  });
  // 14 more ports on the first target -> 15 distinct ports on that pair
  const SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 1433, 3306, 3389, 8080];
  b.repeat(SCAN_PORTS.length, (i, self) => {
    self.add(SCANNER, '192.168.1.40', 'TCP', 74,
      (54100 + i) + ' \u2192 ' + SCAN_PORTS[i] + ' [SYN] Seq=0 Win=1024 Len=0 MSS=1460', 0.015);
  });

  /* ---- Rules 6 + 7 example: 45 failed connection attempts at one server ---- */
  const SYN_HOST = '10.0.4.88';
  const SYN_TARGET = '192.168.1.60';
  b.repeat(45, (i, self) => {
    self.add(SYN_HOST, SYN_TARGET, 'TCP', 74,
      (53200 + i) + ' \u2192 8080 [SYN] Seq=0 Win=1024 Len=0 MSS=1460 SACK_PERM', 0.13);
  });

  /* ---- Rules 1 + 6 example: an internal host pushing 100 packets at one server ---- */
  const HV_SOURCE = '192.168.1.25';
  const HV_TARGET = '192.168.1.30';
  b.repeat(100, (i, self) => {
    if (i === 0) {
      self.add(HV_SOURCE, HV_TARGET, 'TCP', 74,
        '52400 \u2192 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM', 6.0);
    } else if (i === 1) {
      self.add(HV_SOURCE, HV_TARGET, 'TLSv1.3', 571, 'Client Hello (SNI=srv-backup.example.org)', 0.002);
    } else if (i % 10 === 9) {
      self.add(HV_SOURCE, HV_TARGET, 'TCP', 66,
        '52400 \u2192 443 [ACK] Seq=' + (1000 + i) + ' Ack=' + (2000 + i) + ' Win=63488 Len=0', 0.006);
    } else {
      self.add(HV_SOURCE, HV_TARGET, 'TLSv1.3', 1514, 'Application Data', 0.006);
    }
  });

  return b;
}

/* ============================ write the files ============================ */

const SAMPLES = [
  { file: 'normal-traffic.csv', label: 'Normal traffic', build: normalTraffic },
  { file: 'high-volume-traffic.csv', label: 'High volume traffic', build: highVolumeTraffic },
  { file: 'mixed-soc-lab.csv', label: 'Mixed SOC lab', build: mixedSocLab }
];

fs.mkdirSync(OUT_DIR, { recursive: true });

const embed = [];
embed.push('/* =========================================================================');
embed.push(' * EMBEDDED DEMO DATA');
embed.push(' *');
embed.push(' * The three sample CSVs are also stored as real files in samples/ so that');
embed.push(' * students can practise the upload workflow. They are duplicated here as');
embed.push(' * plain text because a page opened directly from disk (file://) is not');
embed.push(' * allowed to read neighbouring files with fetch(). Nothing is downloaded.');
embed.push(' * Generated by tests/generate-samples.js - do not edit by hand.');
embed.push(' * ========================================================================= */');
embed.push('');
embed.push('const EMBEDDED_SAMPLES = {');

const stats = [];

SAMPLES.forEach(function (sample) {
  const built = sample.build();
  const text = built.text();
  const target = path.join(OUT_DIR, sample.file);
  fs.writeFileSync(target, text, 'utf8');

  embed.push('  ' + JSON.stringify(sample.file) + ': `' + text.replace(/`/g, '\\`') + '`,');

  // quick summary so the generator can be checked at a glance
  const lines = text.split('\r\n').filter(Boolean).slice(1);
  const perSource = {};
  const perDest = {};
  const proto = {};
  const destsBySource = {};
  lines.forEach(function (line) {
    const cells = line.split('","').map(function (c) { return c.replace(/^"|"$/g, ''); });
    const src = cells[2];
    const dst = cells[3];
    perSource[src] = (perSource[src] || 0) + 1;
    perDest[dst] = (perDest[dst] || 0) + 1;
    proto[cells[4]] = (proto[cells[4]] || 0) + 1;
    destsBySource[src] = destsBySource[src] || {};
    destsBySource[src][dst] = true;
  });
  const topSource = Object.keys(perSource).sort(function (a, b) { return perSource[b] - perSource[a]; })[0];
  const topDests = Object.keys(destsBySource).sort(function (a, b) {
    return Object.keys(destsBySource[b]).length - Object.keys(destsBySource[a]).length;
  })[0];
  stats.push({
    file: sample.file,
    packets: lines.length,
    bytes: Buffer.byteLength(text, 'utf8'),
    busiestSource: topSource + ' (' + perSource[topSource] + ' pkts)',
    widestSource: topDests + ' (' + Object.keys(destsBySource[topDests]).length + ' unique dests)',
    protocols: Object.keys(proto).sort(function (a, b) { return proto[b] - proto[a]; }).join(', ')
  });
});

embed.push('};');
embed.push('');
embed.push('const SAMPLE_LABELS = {');
SAMPLES.forEach(function (sample, i) {
  const comma = i === SAMPLES.length - 1 ? '' : ',';
  embed.push('  ' + JSON.stringify(sample.file) + ': ' + JSON.stringify(sample.label) + comma);
});
embed.push('};');
embed.push('');

fs.writeFileSync(EMBED_OUT, embed.join('\n'), 'utf8');

console.log('Wrote ' + SAMPLES.length + ' sample files to ' + OUT_DIR);
console.table(stats);
console.log('Embedded copy: ' + EMBED_OUT + ' (' + fs.statSync(EMBED_OUT).size + ' bytes)');





