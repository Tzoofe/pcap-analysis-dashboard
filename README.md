# PCAP / PCAPNG Analysis Dashboard

A local web dashboard that opens a PCAP/PCAPNG capture, runs Wireshark's `tshark` on it,
and shows the same values you would find by hand in Wireshark: packet count, start/end
time, duration, top endpoints, protocols, and HTTP request/response pairs.

## Install

Requirements: macOS (or Linux), Python 3.10+, and Wireshark (which includes `tshark`).

```bash
git clone https://github.com/Tzoofe/pcap-analysis-dashboard.git
cd pcap-analysis-dashboard
python3 -m venv .venv                     # create a virtual environment in .venv/
.venv/bin/pip install -r requirements.txt # install streamlit, pandas, plotly
```

## Run

```bash
.venv/bin/streamlit run app.py
```

A browser tab opens at http://localhost:8501. Upload a `.pcap` / `.pcapng` file.
Capture files are not included in this repository; use your own, saved from Wireshark.

Command-line test (no UI), which prints the summary, the protocols and the HTTP table:

```bash
.venv/bin/python pcap_parser.py capture.pcapng
```

## Files

| File | Contents |
|---|---|
| `pcap_parser.py` | All tshark and pandas logic. No UI code. |
| `app.py` | The Streamlit UI only. |
| `requirements.txt` | Python packages (pinned versions). |

## Functions in `pcap_parser.py`

| Function | What it does |
|---|---|
| `find_tshark()` | Finds tshark with `shutil.which("tshark")`. If that fails, it uses `/Applications/Wireshark.app/Contents/MacOS/tshark`. |
| `get_tshark_version(path)` | Runs `tshark --version` and returns e.g. `(4, 6, 9)`. |
| `get_protocol_field(version)` | Returns `_ws.col.protocol` for Wireshark 4.2 and newer, and `_ws.col.Protocol` for older versions. The field was renamed in 4.2. |
| `run_tshark(path, fields, display_filter, two_pass)` | Builds and runs the tshark command and loads its tab-separated output into a pandas DataFrame. Raises `TsharkError` with tshark's message if the file cannot be read. If tshark read some packets but complained (for example, a truncated file), it returns the data plus a warning. |
| `load_packets(path)` | Returns one row per packet: frame number, times, length, source/destination IP and the Protocol column. Uses the IPv4 address if there is one, otherwise IPv6. If there is neither (ARP), the address is left empty. |
| `capture_summary(packets)` | Returns the packet count, the first and last packet time (in local time) and the duration (last − first). |
| `format_duration(seconds)` | Formats seconds as `HH:MM:SS`, like Wireshark's "Elapsed" field. |
| `top_endpoints(packets, n)` | Counts packets per IP address, as sender or receiver. This matches the "Packets" column in Statistics → Endpoints. |
| `protocol_counts(packets)` | Counts packets per value of the Protocol column. |
| `packets_per_second(packets)` | Counts packets in each 1-second interval. Seconds with no packets get 0. |
| `load_http_transactions(path)` | Returns one row per HTTP request, joined to its response through tshark's own `http.response_in` field. Requests with no response keep empty response columns. |

### tshark command-line options used

| Option | Meaning |
|---|---|
| `-r <file>` | Read packets from a file instead of capturing live. |
| `-n` | No name resolution: show raw IP addresses. |
| `-T fields` | Print only the fields requested with `-e`. |
| `-e <field>` | Add one output column. |
| `-E header=y` | The first line holds the field names. |
| `-E separator=/t` | Separate the columns with TAB characters. |
| `-E occurrence=f` | If a field appears more than once in a packet, print only the first occurrence. |
| `-Y <filter>` | Display filter, the same syntax as Wireshark's filter bar. |
| `-2` | Two-pass analysis. Needed for `http.response_in`: while reading a request, tshark has not yet seen the response, so this field is filled in only on the second pass. |

### tshark fields used

| Field | Meaning / Wireshark equivalent |
|---|---|
| `frame.number` | Packet number ("No." column) |
| `frame.time_epoch` | Arrival time, in seconds since 1970-01-01 UTC |
| `frame.time_relative` | Seconds since the first packet (the default "Time" column) |
| `frame.len` | Bytes on the wire ("Length" column) |
| `ip.src`, `ip.dst` | IPv4 source/destination |
| `ipv6.src`, `ipv6.dst` | IPv6 source/destination |
| `_ws.col.protocol` (`_ws.col.Protocol` before 4.2) | The "Protocol" column exactly as Wireshark shows it |
| `tcp.srcport`, `tcp.dstport` | TCP source/destination port |
| `http.request.method` | GET, POST, … (only in request frames) |
| `http.host` | The `Host:` header |
| `http.request.uri` | The requested path, e.g. `/index.html` |
| `http.request.version` | e.g. `HTTP/1.1` |
| `http.response_in` | In a request frame: the frame number of its response |
| `http.request_in` | In a response frame: the frame number of its request |
| `http.response.code` | Status code (200, 404, …) |
| `http.response.phrase` | Status text (OK, Not Found, …) |
| `http.time` | In a response frame: seconds since the request ("Time since request") |
| `http.content_type` | The response's `Content-Type` header |

## Dashboard sections (`app.py`)

1. **File upload** (`st.file_uploader`). The uploaded bytes are written to a temporary file and its path is passed to tshark. Results are cached with `@st.cache_data`, so tshark is not run again on every click.
2. **Capture overview**: packet count, first/last packet time, duration.
3. **Top endpoints and protocols**: two tables.
4. **Charts**: packets per second over time, and protocol distribution.
5. **HTTP transactions**: a table with one row per request. Clicking a row shows all its details below the table, plus a Wireshark display filter for the same two frames.
6. **Extra feature**: filters by Host, Method and Status code, which apply to both the table and a response-time bar chart. The chart has one bar per transaction, labeled by request frame number, and 4xx/5xx responses are drawn in red.

Edge cases handled:
- **No HTTP in the capture**: shows a message.
- **Corrupted file**: shows tshark's error.
- **Truncated file**: shows a warning plus the partial results.
- **ARP / IPv6 frames**: an empty or IPv6 address is used.
- **Request without a response**: the response columns are left empty.

Note: HTTPS traffic is encrypted (TLS), so tshark cannot show it as HTTP. Only plain HTTP (usually port 80) appears in the HTTP section.
