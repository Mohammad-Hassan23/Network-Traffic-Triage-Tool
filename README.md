# Network Traffic Triage Tool

**Version 1.0 — Wireshark CSV triage that runs entirely in your browser.**

An educational tool that turns a Wireshark packet-list CSV export into an explainable
triage report. It counts what is in the capture, highlights activity that is worth a
look, and — just as importantly — explains the innocent things that look exactly the
same.

> Educational network triage tool. Alerts indicate activity worth investigating and do
> **not** prove malicious behaviour.

> Only analyse traffic from systems and networks you own or are authorised to monitor.

---

## Contents

- [What this project does](#what-this-project-does)
- [Why it exists](#why-it-exists)
- [Quick start on Windows](#quick-start-on-windows)
- [The workflow](#the-workflow)
- [Privacy design](#privacy-design)
- [Exporting from Wireshark](#exporting-from-wireshark)
- [Supported CSV fields](#supported-csv-fields)
- [What the dashboard shows](#what-the-dashboard-shows)
- [Detection rules](#detection-rules)
- [Default thresholds](#default-thresholds)
- [Why thresholds are not universal](#why-thresholds-are-not-universal)
- [The investigation score](#the-investigation-score)
- [Filters and search](#filters-and-search)
- [Sample data](#sample-data)
- [Suggested demonstration script](#suggested-demonstration-script)
- [Limitations](#limitations)
- [False positives](#false-positives)
- [Security design](#security-design)
- [Accessibility](#accessibility)
- [Project structure](#project-structure)
- [Testing](#testing)
- [Known issues found during development](#known-issues-found-during-development)
- [Future improvements](#future-improvements)
- [Educational use](#educational-use)

---

## What this project does

You capture traffic in Wireshark, export the **packet list as a CSV file**, and load that
CSV into this page. The page:

1. parses the CSV locally, tolerating different column names;
2. builds a network overview (packet totals, hosts, protocols, conversations);
3. runs seven explainable detection rules against thresholds you control;
4. produces findings that each state the evidence, the threshold that was crossed, why
   the pattern might matter, what innocent explanations exist, and what to check next;
5. lets you filter and search everything, and inspect the raw packets behind any finding.

It is a static website: `index.html`, `styles.css` and `script.js`. No frameworks, no
build step, no package manager, no server, no database, no API keys, no AI service.

## Why it exists

Most beginner tools stop at "suspicious!". Real triage is the opposite: an analyst sees a
pattern, decides whether it is expected, gathers supporting evidence, and only then
concludes anything. This tool is built around that reasoning step.

Two sentences capture the whole idea:

- **An anomaly is a starting point for investigation, not proof of compromise.**
- **Detection tells an analyst where to look. Investigation determines what actually
  happened.**

Every detection in this tool is a plain comparison — "is this count bigger than the number
you typed?" — with no machine learning and no hidden weighting. Nothing in the report is a
guess about intent.

## Quick start on Windows

1. Copy the project folder somewhere convenient, for example
   `C:\Users\<you>\Documents\Network-Traffic-Triage-Tool`.
2. Double-click **`index.html`**. It opens in your default browser.
   - To pick a specific browser: right-click `index.html` → **Open with** → Chrome / Edge / Firefox.
3. Click **Load Mixed SOC Lab** to see a full report immediately.

That is all. **Nothing needs to be installed** — no Python, no Node.js, no Wireshark
plug-in, no admin rights. Your laptop only needs a modern browser.

To host it later as a static website, upload the same folder to GitHub Pages, Netlify or
Cloudflare Pages. There is no build command and no configuration: it is plain files.

### Opening the samples by hand

The three files in `samples/` are ordinary CSV files. You can upload them through the page
to practise the real workflow, or drag them onto the upload box.

### Optional: running the automated checks

The `tests/` folder is a development aid, not part of the application. If you have Node.js
installed you can run:

```
node tests/run-tests.js      # engine and detection checks (113 checks)
node tests/run-ui-tests.js   # interface smoke test (53 checks)
```

If you do not have Node.js, ignore this — the application itself does not need it.

---

## The workflow

```
Wireshark capture  ->  Export Packet Dissections as CSV  ->  Upload here
                                                            |
                              parse locally (no upload) ----+
                                                            |
                       count packets, hosts, protocols, conversations
                                                            |
                              run seven threshold rules
                                                            |
                       report: overview, findings, score, filters
```

## Privacy design

**Your packet capture data is analysed locally in your browser and is not uploaded
anywhere.**

The project is built so this is true by construction, not by promise:

- There is **no server, no backend, no database**. The app is three static files.
- `script.js` contains **no** `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon` or
  `importScripts` call. It makes no network requests at all.
- No analytics, no tracking pixels, no cookies, no `localStorage`, no `sessionStorage`,
  no telemetry, no advertising.
- The CSV is read into the tab's memory with the browser's built-in `FileReader`, analysed
  in JavaScript on your machine, and discarded when you close or refresh the tab. There is
  no "save" button because nothing is saved.
- The demo captures are embedded as text inside `script.js` so that the page works when
  opened directly from disk (a `file://` page is not allowed to read neighbouring files).

You can verify this yourself: open the browser developer tools, switch to the **Network**
tab, load a capture, and watch. You will see this page's own three files and nothing else.
You can also search `script.js` for `fetch` — you will find the word only in a comment
explaining why it is not used.

## Exporting from Wireshark

1. Open Wireshark and select the interface you are authorised to monitor.
2. Start the capture and generate the traffic you want to study.
3. Stop the capture.
4. Choose **File → Export Packet Dissections → As CSV…**, then pick a destination file.
5. Upload that CSV into this tool.

Two practical tips:

- Keep the capture short. Ten minutes of focused traffic tells a clearer story than an
  hour, and the tool treats the whole capture as a single time window.
- If your export includes the `Info` column, Rules 3 and 7 (port scanning and SYN-heavy
  activity) become available. Without it, those two rules report themselves as *not
  evaluated* rather than guessing.

**Legal and ethical reminder:** capture only traffic from systems and networks you own or
are explicitly authorised to monitor. Capturing other people's traffic can be illegal and
can breach workplace or school policy. When in doubt, use the demo data.

---

## Supported CSV fields

The parser reads the CSV properly (quoted fields, commas inside quotes, `""` escapes, CRLF
or LF line endings, an optional UTF-8 byte order mark). Column names are matched
case-insensitively, ignoring spaces, dots and underscores, so all of these are accepted:

| Field | Required? | Accepted header names (examples) | What happens if it is missing |
|---|---|---|---|
| Source | **Yes** | `Source`, `Source IP`, `Source Address`, `src`, `ip.src`, `sourcehost` | Analysis cannot run. The page says: *"This CSV does not appear to contain a Source address column."* |
| Destination | **Yes** | `Destination`, `Destination IP`, `dest`, `dst`, `ip.dst`, `target` | Same clear message for Destination. |
| Protocol | No | `Protocol`, `Proto`, `protocol_name` | Rules 4 and 5 are *not evaluated*; the protocol distribution shows `Unknown`. |
| Length | No | `Length`, `Packet Length`, `Frame Length`, `len`, `Bytes`, `size` | Average packet length is unavailable. |
| Info | No | `Info`, `Information`, `Details`, `Description`, `Summary` | Rules 3 and 7 are *not evaluated*; the packet view has no Info text. |
| No. | No | `No.`, `Number`, `Packet`, `frame.number`, `index` | Packets are numbered by row position. |
| Time | No | `Time`, `Timestamp`, `frame.time`, `timeepoch` | Capture time span is unavailable. |

Rows without both a source and a destination are skipped and counted, and the count is
shown in the capture details — never guessed at.

### How ports and TCP flags are recovered

Rule 3 (port scanning) and Rule 7 (SYN-heavy activity) need details that live in the `Info`
column. The tool looks for these shapes, in order:

1. the Wireshark arrow form: `52144 → 443 [SYN] Seq=0 …` (both `→` and `->` are accepted);
2. `Source port: 68  Destination port: 67`;
3. `Src Port: 12345, Dst Port: 443`;
4. a conservative fallback: if no port is present, a well-known default is used for a small
   set of protocols (HTTP 80, TLS/HTTPS 443, DNS 53). These values are marked as guesses.
   The packet table shows them as `443 (guess)`, and if more than half of the ports on a
   pair are guesses, Rule 3 downgrades itself to **Informational** and says why.

TCP flags are detected from the bracketed form: `[SYN]` counts as a connection attempt,
`[SYN, ACK]` counts separately as a reply. If a capture contains no flag markers at all,
Rule 7 is reported as not evaluated.

---

## What the dashboard shows

- **Summary cards** — total packets, unique source hosts, unique destination hosts, most
  active source host, most contacted destination, most common protocol, average packet
  length, capture time span.
- **Protocol distribution** — TCP, UDP, DNS, ICMP, ARP, HTTP, HTTPS/TLS and Other, shown
  only when actually present, as simple CSS bars with counts and percentages.
- **Top 10 source hosts** and **Top 10 destinations**, each with a bar scaled to the
  busiest host so you can see at a glance who generated the traffic.
- **Busiest conversations** — the top 10 source → destination pairs, which is the view that
  makes Rule 6 easy to see.
- **Findings** — one card per alert, with severity, evidence, threshold, why it matters,
  benign explanations and suggested investigation steps.
- **Rule coverage** — which rules ran, which fired, and which could not be evaluated (with
  the reason), so you always know what the report does and does not cover.
- **Packet view** — the raw rows behind the analysis (first 200 matches), including the
  derived destination port, so you can check the tool's working.

---

## Detection rules

Seven rules, all threshold comparisons. Each finding contains the rule name, severity, the
source host, the destination host where relevant, the observed value, the configured
threshold, why the activity could matter, possible benign explanations, and suggested
investigation steps.

| # | Rule name | What it counts | Default threshold | Notes |
|---|---|---|---|---|
| 1 | High activity host | packets sent per source host | > 50 | The plainest "look here" signal |
| 2 | Possible host scanning | unique destinations per source host | > 10 | Pattern of discovery or scanning |
| 3 | Possible port scanning | unique destination ports per source→destination pair | > 10 | Needs port detail in `Info` |
| 4 | High ICMP activity | ICMP packets per source host | > 30 | Ping sweeps, monitoring, flooding |
| 5 | High DNS query activity | DNS packets per source host | > 30 | Browsing, updates, automated lookups |
| 6 | Repeated source to destination traffic | packets per source→destination pair | > 40 | Big transfers and automated polling |
| 7 | TCP SYN heavy activity | TCP SYN packets per source host | > 30 | Needs flag detail in `Info` |

### Rule 1 — High activity host

*Example:* `192.168.1.25` sent 183 packets against a threshold of 50.
Why it matters: a host generating significantly more traffic than its peers may warrant
investigation. Possible explanations include a legitimate file transfer, software updates,
backups, an authorised scanner, automated scripts, a misconfiguration, or malicious
activity. The finding says its activity deserves a look; it does not say the host is
attacking anything.

### Rule 2 — Possible host scanning

*Example:* `172.16.5.20` communicated with 27 unique destinations against a threshold of 10.
This pattern may be consistent with host discovery or network scanning, but legitimate
network-management tools — vulnerability scanners, asset discovery, monitoring — can
generate very similar traffic.

### Rule 3 — Possible port scanning

*Example:* one source contacted 15 different ports on the same destination. This can
indicate port scanning, but it also happens during legitimate service discovery, failover
and health checking. Port numbers come from the `Info` column, which is a summary, so the
list is indicative rather than complete. If the required detail is unavailable, the rule
reports itself as not evaluated.

### Rule 4 — High ICMP activity

ICMP is ordinary: ping, traceroute and reachability checks all use it. High volume from one
host is worth a look because ping sweeps, network discovery and (at much larger volumes)
ICMP flooding look similar. The finding also reports how many of those packets had no
reply seen, which is useful context.

### Rule 5 — High DNS query activity

DNS is how almost every application starts a conversation, so a busy resolver or client is
normal. High DNS activity can also come from software updates, automated applications,
misconfigured systems retrying, or suspicious beaconing. The rule counts packets rather
than inspecting domains.

### Rule 6 — Repeated source to destination traffic

*Example:* `192.168.1.25` sent 100 packets to `192.168.1.30` against a threshold of 40. This
shows the source, destination, packet count and most common protocol. It might be normal
application traffic, or it might be unusual automated activity — the finding lists both
possibilities and tells you to confirm the pair is expected.

### Rule 7 — TCP SYN heavy activity

*Example:* `10.0.4.88` sent 45 SYN packets. Repeated SYN packets may be associated with
normal connection attempts, unavailable services causing retries, network scanning, or SYN
flood behaviour. The finding shows how many `[SYN, ACK]` replies were seen: lots of SYNs
with no replies is more interesting than SYNs that were answered. It never calls the
activity a SYN flood.

### Severity: investigative priority, not certainty

Severity is derived from how far past the threshold the observation went, and it is capped
for the noisier rules:

| How far past the threshold | Severity |
|---|---|
| up to 2× | Low |
| 2× to 5× | Medium |
| 5× or more | High |

Caps: Rules 4, 5 and 6 can never exceed **Medium**, because ICMP volume, DNS volume and long
conversations are extremely environment-dependent. Rule 3 becomes **Informational** when
most of its port values were inferred rather than read from the capture, and Rule 7 becomes
**Informational** when the handshakes were largely answered.

The scale is Informational, Low, Medium, High. **"Critical" is never used.** Severity tells
you where to look first; it is not a probability that anything bad happened.

---

## Default thresholds

| Setting | Default | Rule |
|---|---|---|
| Packets per source | 50 | Rule 1 |
| Unique destinations | 10 | Rule 2 |
| Unique ports | 10 | Rule 3 |
| ICMP packets | 30 | Rule 4 |
| DNS packets | 30 | Rule 5 |
| Repeated source → destination packets | 40 | Rule 6 |
| TCP SYN packets | 30 | Rule 7 |

All seven are editable in the **Detection thresholds** panel. Change one and the report
recomputes instantly — no reload, no re-upload. **Reset Defaults** restores them.

A value has to be *exceeded* to produce a finding: 51 packets against a threshold of 50
fires, 50 does not.

## Why thresholds are not universal

These numbers are **educational defaults, not security thresholds**. They were chosen so
that the sample captures demonstrate each rule on a small, readable dataset.

> Thresholds should be adjusted based on the environment. A busy server may legitimately
> generate thousands of packets, while the same activity from another endpoint might
> deserve investigation.

A domain controller, a build server, a backup target and a user's laptop all look wildly
different while behaving perfectly normally. Real deployments establish a baseline for each
asset and alert on deviation from that baseline. This tool cannot do that, which is exactly
why the thresholds are in your hands.

---

## The investigation score

The score adds up the findings, weighted by investigative priority:

| Severity | Points |
|---|---|
| Informational | +5 |
| Low | +10 |
| Medium | +15 |
| High | +20 |

Labels: `0` = **No findings**, `1–19` = **Low investigative priority**, `20–59` =
**Elevated Activity**, `60+` = **High investigative priority**.

The report shows every contribution next to the total, so the arithmetic is never hidden:

```
+15  Rule 1 - High activity host (192.168.1.25) [Medium]
+15  Rule 6 - Repeated source to destination traffic (192.168.1.25 to 203.0.113.50) [Medium]
----
 30  Elevated Activity
```

This is a tally of what the rules noticed, **not a probability**. A score of 30 does not
mean a 30% chance of compromise. There is deliberately no "97% malicious" style figure
anywhere in this project.

---

## Filters and search

- **Source host** — a dropdown of every source, with packet counts.
- **Destination host** — the same for destinations.
- **Protocol** — protocol families present in the capture.
- **Alert severity** — Informational / Low / Medium / High (applies to findings).
- **Search text** — matches hosts, protocols, rule names, severities and evidence values.
  It also filters the packet table, so you can type `443` or `10.0.4.88` and see the raw
  rows behind a finding.

A status line always tells you what is being shown, for example *"Showing 3 of 9 findings,
and 41 of 296 packets."* **Clear filters** resets everything.

---

## Sample data

Three fictional captures live in `samples/` and are also embedded in the page for the demo
buttons. They use only private ranges (`192.168.x.x`, `10.x.x.x`, `172.16.x.x`) and
documentation ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`). No real infrastructure,
malicious or otherwise, appears anywhere.

| File | Packets | What it contains | Expected findings with defaults |
|---|---|---|---|
| `normal-traffic.csv` | 58 | Ordinary small-office traffic: ARP, DNS, DHCP, NTP, TLS, HTTP, two harmless pings | **None.** Score 0, "No findings" |
| `high-volume-traffic.csv` | 217 | One workstation uploading 183 packets to a backup server, plus quiet background traffic | **Rule 1** (183 > 50, Medium) and **Rule 6** (182 > 40, Medium). Score 30, "Elevated Activity" |
| `mixed-soc-lab.csv` | 296 | Background traffic plus one example of every rule | **9 findings covering all seven rules.** Score 105, "High investigative priority" |

Expected findings in `mixed-soc-lab.csv`:

| Rule | Host | Observed | Threshold |
|---|---|---|---|
| 1 High activity host | 192.168.1.25 | 100 packets | 50 |
| 2 Possible host scanning | 172.16.5.20 | 27 unique destinations | 10 |
| 3 Possible port scanning | 172.16.5.20 → 192.168.1.40 | 15 unique ports | 10 |
| 4 High ICMP activity | 10.0.4.77 | 45 ICMP packets | 30 |
| 5 High DNS query activity | 10.0.4.90 | 34 DNS packets | 30 |
| 6 Repeated traffic | 192.168.1.25 → 192.168.1.30 | 100 packets | 40 |
| 6 Repeated traffic | 10.0.4.88 → 192.168.1.60 | 45 packets | 40 |
| 7 TCP SYN heavy | 10.0.4.88 | 45 SYN packets | 30 |
| 7 TCP SYN heavy | 172.16.5.20 | 41 SYN packets | 30 |

Note the last two rows: the scanner produces both a Rule 2 finding and a Rule 7 finding,
and Rule 3 as well. **One behaviour can legitimately trigger several rules.** That is not a
bug; it is how triage works in practice, and it is a good thing to point out during a
demonstration.

The `samples/` files are generated by `tests/generate-samples.js` (a development tool, not
part of the app) so the data is deterministic and every threshold is hit exactly.

## Suggested demonstration script

**Test 1 — a quiet capture.**
Click **Load Normal Sample**. Result: score 0, "No findings", the message *"No rule
thresholds were crossed in this capture."* Point out that a tool which screams on normal
traffic is useless, and that this one also refuses to claim the traffic is "clean" — it
says nothing crossed *these* thresholds.

**Test 2 — high packet volume.**
Click **Load Suspicious Sample**. Result: **High activity host**, 183 packets against a
threshold of 50, severity Medium. Expand it and read out the benign explanations (backup,
file transfer, updates) before the investigation steps.

**Test 3 — many destinations.**
Click **Load Mixed SOC Lab** and find **Possible host scanning**: 27 unique destinations
against a threshold of 10, with six example destinations and the suggested investigation
list.

**Test 4 — why this is not an accusation.**
Still on the mixed capture, point at the *same* source host producing several findings, then
read the "Possible benign explanations" section of each. Then change a threshold live (set
*Unique destinations* to 50) and watch the Rule 2 finding disappear. Finish with the two
lines from the education panel:

> **An anomaly is a starting point for investigation, not proof of compromise.**
>
> **Detection tells an analyst where to look. Investigation determines what actually
> happened.**

---

## Limitations

- **A CSV holds less than a capture file.** Wireshark can show flags, options, payloads,
  response times and TLS details. The packet-list CSV export does not, so some questions
  cannot be answered from this input at all.
- **Raw `.pcap` and `.pcapng` files are not supported in Version 1.** Only CSV and `.txt`.
- **Encrypted traffic hides its contents.** You can see that two hosts exchanged 1.4 KB
  segments; you cannot see whether it was a backup, a video, or something else.
- **Packet volume alone does not indicate malicious activity.** A nightly backup is 100,000
  packets of entirely good news.
- **Thresholds vary greatly by environment.** See above; this is the single biggest caveat
  in the project.
- **NAT and proxies affect host attribution.** Hundreds of devices behind one public address
  appear as a single very busy host.
- **The whole capture is treated as one time window.** A 10-minute and a 6-hour capture of
  identical traffic produce very different counts, so thresholds are not comparable across
  captures of different lengths. There is no time-based or per-second analysis in Version 1.
- **Protocol labels depend on Wireshark's interpretation.** Values such as `TLSv1.2`,
  `QUIC` or `SSDP` are mapped into simple families for readability, and anything
  unrecognised is grouped under *Other*.
- **Port and TCP-flag detection depends on the `Info` column.** If your export lacks
  recognisable port or flag text, Rules 3 and 7 report themselves as *not evaluated*.
  Some ports are inferred from protocol defaults and are labelled as guesses.
- **The tool does not perform malware analysis.** It never inspects payloads, hashes or
  files, and it has no threat-intelligence feed.
- **The tool does not replace Wireshark, an IDS, a SIEM or professional network
  monitoring.** It is a teaching aid for the reasoning step of triage.
- **Only the first 200 matching packets are displayed** in the packet table, to keep the
  page responsive. The counts and analysis always use the full capture.
- **Files larger than 30 MB are refused**, with an explanation, rather than freezing your
  browser.

## False positives

This tool produces false positives *by design*, and that is the point: a threshold rule
flags anything unusual, and most unusual things are innocent. Typical examples:

| What fires | Innocent explanation |
|---|---|
| Rule 1 High activity host | A backup, a large download, a video call, an OS update |
| Rule 2 Possible host scanning | A monitoring system checking every device, a printer discovering peers |
| Rule 3 Possible port scanning | An application retrying across ports, a health check, a service discovery tool |
| Rule 4 High ICMP activity | Someone troubleshooting with ping, a monitoring agent, a ping sweep by inventory software |
| Rule 5 High DNS activity | Normal browsing, a resolver serving many clients, a retry loop |
| Rule 6 Repeated traffic | Any long-lived session: streaming, database traffic, file share, agent polling |
| Rule 7 TCP SYN heavy | A service that was down and got retried, high connection churn behind a proxy |

A finding is a question, not an answer. If you can explain the activity and confirm it is
expected, the correct outcome is "expected, no further action" — documented, not hidden.

## Security design

Because the CSV is untrusted input, the code treats it that way:

- **File validation.** Extension check (`.csv`, `.txt`), size limit (30 MB), and a clear
  message for anything else. Nothing is executed, ever.
- **A real CSV parser.** Quoted fields, escaped quotes, embedded commas and newlines, CRLF,
  and a BOM are all handled, so malformed data cannot shift columns and produce misleading
  numbers.
- **Malformed input fails safely.** Empty files, plain text, HTML, semicolon-separated data,
  NUL bytes, an unterminated quote and a 5,000-character line all produce a readable error
  instead of a crash. Every one of these is covered by an automated test.
- **No HTML injection.** Values from the CSV reach the page only through `textContent` and
  `document.createElement`. `script.js` contains no `innerHTML`, no `insertAdjacentHTML`,
  no `document.write`, no `eval`, and no `new Function`. A packet whose `Info` column
  contains `<script>alert(1)</script>` is displayed as those literal characters.
- **No prototype pollution.** Anything keyed by a value from the CSV uses a `Map`, so a host
  named `__proto__` is just a host. This is covered by a test too.
- **No data leaves the page.** No network calls, no storage, no cookies, no analytics.
- **No inline event handlers** in the HTML, and no external scripts, styles, fonts or
  images. Everything is local, which also means the page works offline.

## Accessibility

- Semantic HTML: `header`, `main`, `section`, `article`, `footer`, real tables with
  `<caption>` and `<th scope="col">`, `dl` lists for key/value evidence.
- Every input has a visible `<label>`; the file picker is a native control, so it works with
  a keyboard and with screen readers. Drag and drop is an extra, never the only way.
- Live regions (`role="status"`, `aria-live="polite"`) announce load results, filter counts
  and errors.
- A "Skip to main content" link is the first focusable element.
- Focus is always visible: a 3px high-contrast outline on every interactive control.
- Severity is never conveyed by colour alone — every finding carries a text badge such as
  "MEDIUM" as well as a coloured border.
- Contrast: body text and status colours were chosen for readability on the dark background,
  and the theme avoids neon green and decorative animation. Motion is disabled automatically
  when the operating system asks for reduced motion.
- A print stylesheet keeps cards from being split across pages if you print or export to PDF.

---

## Project structure

```
Network-Traffic-Triage-Tool/
├── index.html                  The page: upload area, thresholds, dashboard, education panels
├── styles.css                  Dark theme, bars, badges, responsive layout, print styles
├── script.js                   CSV parser + analysis engine + rendering + UI wiring
├── README.md                   This file
├── .gitignore                  Editor and operating-system clutter
├── samples/
│   ├── normal-traffic.csv      58 packets, ordinary traffic
│   ├── high-volume-traffic.csv 217 packets, one host over the threshold
│   └── mixed-soc-lab.csv       296 packets, one example of every rule
└── tests/                      Development aids, not needed to use the app
    ├── run-tests.js            113 checks: parsing, rules, thresholds, security
    ├── run-ui-tests.js         53 checks: the interface against a fake DOM
    └── generate-samples.js     Regenerates the three sample CSVs deterministically
```

Inside `script.js` the code is split into twelve labelled sections: configuration, CSV
parsing, column mapping, packet normalisation, file-level parse, statistics, rules,
coverage/scoring, rendering, filters, load status, and UI wiring. Sections 2–8 are pure
functions that never touch the DOM and never make a network request — which is what makes
the automated tests possible.

---

## Testing

Two dependency-free test suites back up the claims in this README.

```
node tests/run-tests.js       ->  113 checks passed, 0 failed
node tests/run-ui-tests.js    ->   53 checks passed, 0 failed
```

**What `run-tests.js` covers (113 checks)**

- **Sample behaviour** — the normal capture produces zero findings; the high-volume capture
  fires Rule 1 with exactly 183 packets against 50; the mixed capture fires all seven rules
  with the expected values; every finding carries explanations and next steps; no finding
  text contains the words "attacker" or "infected".
- **Thresholds** — raising the packet threshold above 183 removes the finding, lowering it
  to 10 makes the quiet capture alert, and nonsense input falls back to the defaults.
- **CSV parsing** — commas inside quotes, doubled quotes, CRLF vs LF, a UTF-8 BOM, embedded
  newlines, blank lines and an unterminated quote.
- **Column names** — `Source IP`, `src`, `ip.src`, `protocol_name`, `frame.length` and
  friends are recognised; a missing Source or Destination column produces exactly the
  documented message; missing optional columns are listed with their consequences.
- **Malformed input** — eleven hostile or broken inputs (empty, whitespace only, header
  only, prose, semicolons, HTML, NUL bytes, a 5,000-character line, unterminated quote,
  empty addresses, numeric header) all fail safely without throwing.
- **Security and privacy** — static checks that the shipped files contain no `innerHTML`,
  `eval`, `fetch`, `XMLHttpRequest`, storage APIs or cookies; a hostile CSV containing
  `<script>` and `<img onerror=...>` payloads is handled as plain text; a host named
  `__proto__` is counted normally and does not pollute `Object.prototype`.
- **Helpers** — port extraction from the arrow form and the `Source port:` form, guess
  fallbacks, `[SYN]` vs `[SYN, ACK]`, and protocol family mapping.
- **Wiring** — every element id used by the script exists in the page, there are no
  duplicate ids, the page has exactly three demo buttons, and the demo data embedded in
  `script.js` is byte-for-byte identical to the files in `samples/`.

**What `run-ui-tests.js` covers (53 checks)**

The real `script.js` is loaded against a 60-line fake DOM, then driven like a user would:
loading each demo capture and checking what appears, changing a threshold to 500 and
confirming the finding disappears, typing nonsense into a threshold, resetting defaults,
filtering by severity/source/search, and clearing the capture. This is what caught the
duplicate element id mentioned below.

---

## Known issues found during development

Being honest about these matters more than looking flawless:

1. **A duplicate element id (`demo-badge`) existed in the first draft of the HTML.** It was
   used both in the demo panel and in the overview header. Browsers tolerate this, but
   `getElementById` then only ever finds the first one, so the badge would have updated in
   the wrong place. Found by the automated id check, renamed to `demo-badge-panel`, and a
   regression check now fails if any duplicate id reappears.
2. **My first test expectation for the source filter was wrong** (I expected 2 findings for
   `172.16.5.20`; the tool correctly produced 3 — Rules 2, 3 and 7). The product was right
   and the test was wrong, so the expectation was corrected rather than the code.
3. **One behaviour, several findings.** The scanning host in `mixed-soc-lab.csv` triggers
   Rules 2, 3 and 7. This is realistic, but it means the findings list is not a list of
   unrelated problems — read the source host before assuming you are looking at three
   separate events.
4. **Guessed ports inflate the port data.** In `high-volume-traffic.csv`, 187 of 215 rows
   have no port text in `Info`, so the tool falls back to 443 for TLS. Rule 3 is not fooled
   (one unique port is not a scan), but the packet table marks those values `(guess)`, and
   Rule 3 downgrades itself to Informational when most values on a pair are guesses.
5. **The arrow form depends on your Wireshark version and language.** Some exports use
   `->`, and some localise the `Info` string. Both arrow styles are supported; other forms
   may not be, in which case Rules 3 and 7 report themselves as not evaluated.
6. **No Content-Security-Policy meta tag is included, deliberately.** CSP behaves
   inconsistently on `file://` pages and can break the local double-click workflow, which is
   the primary way this tool is meant to be used. When you host it as a website, add CSP as
   a real HTTP header instead, for example:
   `Content-Security-Policy: default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'`.
7. **Everything is one time window.** A capture spanning hours will cross the default
   thresholds for entirely innocent reasons. Export a short capture, or raise the thresholds.

---

## Future improvements

Not implemented in Version 1, listed so the roadmap is clear. **None of them require an
external API or an online service.**

- Direct `.pcap` support (a parser reading the file locally in the browser).
- Direct `.pcapng` support.
- Deeper TCP flag analysis (FIN/RST patterns, retransmissions, half-open connections).
- Time-window detections (packets per second, bursts) instead of one total per capture.
- Traffic baselining: compare a capture against a previously saved baseline for the same
  host, stored locally in a file you choose.
- Network graphs (who talks to whom) drawn with the canvas API.
- GeoIP enrichment using an offline database file supplied by the user.
- Threat-intelligence enrichment, only ever via a user-supplied local file.
- DNS domain analysis (query names, label length, entropy) from the `Info` column.
- Exportable SOC report (print-friendly page or a downloadable Markdown summary).
- IDS-style detection rules in a readable text format that students can write themselves.

## Educational use

This project exists to teach the reasoning behind network triage, and it is free to use in
classrooms, study groups, streams and portfolio demonstrations. When you use it:

- Keep the disclaimer visible: a finding means *worth investigating*, not *malicious*.
- Emphasise the "Possible benign explanations" section before the investigation steps. The
  habit of asking "what else could this be?" is the skill being taught.
- Change the thresholds live and show that the same capture produces a different report.
  Thresholds are a policy decision, not a fact about the traffic.
- Never present the investigation score as a probability of compromise.
- Only analyse captures from systems and networks you own or are authorised to monitor.

If you improve it, the most valuable contributions are honest ones: better explanations,
better documentation of the limits, and clearer teaching text.

---

*Educational network triage tool. Alerts indicate activity worth investigating and do not
prove malicious behaviour. Provided as-is for learning purposes; it is not a security
control and must not be relied on to detect or prevent attacks.*







