# PCAP / PCAPNG Analysis Dashboard

A local web dashboard that opens a PCAP/PCAPNG capture, runs Wireshark's `tshark` on it,
and shows the same values you would find by hand in Wireshark: packet count, start/end
time, duration, top endpoints, protocols, and HTTP request/response pairs.
It also lets you ask questions about the capture in plain English, answered by Google's
Gemini model with frame-level evidence.

## Install

Requirements: macOS (or Linux), Python 3.10+, and Wireshark (which includes `tshark`).

```bash
git clone https://github.com/Tzoofe/pcap-analysis-dashboard.git
cd pcap-analysis-dashboard
python3 -m venv .venv                     # create a virtual environment in .venv/
.venv/bin/pip install -r requirements.txt # install streamlit, pandas, plotly, google-genai, python-dotenv
```

### Gemini API key (for the AI questions only)

The dashboard works without a key; only the "Ask about this capture" section needs one.
Get a free key at https://aistudio.google.com/apikey, then either:

- **type it into the "Gemini API key" field** in the dashboard (it is kept only in the browser
  session, never saved to disk or to the log), or
- copy `.env.example` to `.env` and set `GEMINI_API_KEY=...` there. `.env` is in `.gitignore`.

`GEMINI_MODEL` in `.env` chooses the model (default `gemini-3.8-flash`).

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
| `ai_context.py` | Builds the text sent to the AI from the extracted DataFrames, plus pre-computed facts. |
| `prompts.py` | The system prompt (`SYSTEM_PROMPT`) and its version (`PROMPT_VERSION`). |
| `ai.py` | Calls Gemini, parses the JSON answer, validates the evidence, logs every call. |
| `ai_tests.py` + `ai_test_questions.json` | Command-line test of several questions against expected answers. |
| `.env.example` | Template for `.env` (API key and model name). |
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
| `load_http_transactions(path)` | Returns one row per HTTP request, joined to its response through tshark's own `http.response_in` field. Requests with no response keep empty response columns. Includes the request/response frame times and the `tcp.stream` number. |
| `get_info_field(version)` | Returns `_ws.col.info` for Wireshark 4.2 and newer, `_ws.col.Info` for older versions. |
| `load_tcp_stream(path, n)` | Every frame of one TCP connection (`-Y "tcp.stream == n"`): times, addresses, ports, flags, seq/ack, payload length, Info column. |

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
| `tcp.stream` | Index of the TCP connection (the number used by Follow → TCP Stream) |
| `tcp.flags.str` | TCP flags as text, e.g. `·······AP···` (S=SYN, A=ACK, P=PUSH, F=FIN, R=RST) |
| `tcp.seq`, `tcp.ack` | Relative sequence / acknowledgment numbers |
| `tcp.len` | TCP payload length in bytes |
| `_ws.col.info` (`_ws.col.Info` before 4.2) | The "Info" column exactly as Wireshark shows it |

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

## AI questions (requirements 30–34)

### How it works

1. **Extract** (`pcap_parser.py`): the same DataFrames the dashboard already shows, plus the
   frames of a selected TCP stream if the user chose one.
2. **Build the context** (`ai_context.py`): turns that data into compact text. It contains:
   - the capture summary
   - protocol counts and the top endpoints
   - the HTTP transactions as CSV
   - pre-computed facts (see below)
   - the selected stream's frames, with facts about that stream
3. **Ask** (`ai.py`): sends the system prompt (`prompts.py`) plus the context and the question
   to Gemini. The model must reply with JSON only:
   `{"answer": ..., "evidence": [{"frame", "timestamp", "detail"}], "confidence": "high|medium|low"}`.
4. **Validate and show** (`app.py`): the dashboard shows the answer, the confidence, and an
   evidence table. Evidence rows that fail the check are highlighted in red. An expander shows
   the exact context that was sent.

### Why we send pre-computed facts and not the raw capture

- **Size and privacy.** A capture can hold tens of thousands of packets (`capture.pcapng` has
  28,559). Sending all of it is slow and expensive, and would send every packet to an
  outside service. We send only a few KB of tables that we already extracted.
- **Language models count badly.** Counting rows or finding the maximum in a table is exactly
  where they make mistakes. So `ai_context.py` computes these in pandas: the slowest and
  fastest transaction, requests per Host / Method / Status Code / TCP stream, and SYN/FIN/RST
  frames and bytes per side in a stream. The prompt tells the model to read these numbers
  instead of calculating them.
- **Checkable.** Because the model sees only our extracted data, every frame it cites can be
  checked against that same data.

If a table is too long (more than 200 HTTP rows or 200 stream frames), it is cut. The
context then says exactly which part is missing, and the prompt tells the model to mention it.

### How evidence validation works

The model's claims are only as good as its evidence, so `ai.validate_evidence()` checks every
cited frame against the data we extracted:

| Check | Meaning |
|---|---|
| `ok` | The frame is in the data we sent, and the timestamp matches (within 1 µs). |
| `ok, but the timestamp is wrong` | The frame is real, but the model wrote a different time. |
| `in capture, but not given to the AI` | The frame exists (1 ≤ frame ≤ packet count), but the model never saw it, so it guessed. |
| `not found in capture` | The frame number does not exist: hallucinated evidence. |
| `invalid frame number` | Not a number. |

Invalid JSON from the model does not crash the dashboard: the error and the raw response are shown.

### Logging (requirement 34)

Every call is appended as one JSON line to `logs/ai_log.jsonl` (`logs/` is in `.gitignore`).
Each line holds:
- the time and the `PROMPT_VERSION`
- the model
- the question and the selected stream
- the **full context** that was sent
- the raw model response
- the parsed answer and the evidence validation
- any error, and the token usage

The API key is never logged. Increase `PROMPT_VERSION` in `prompts.py` whenever you change
the prompt, so before/after answers can be told apart in the log.

### Testing against the manual analysis (requirement 33)

Fill in the `"expected"` values in `ai_test_questions.json` from your Wireshark analysis, then run:

```bash
.venv/bin/python ai_tests.py capture.pcapng
```

For each question, the script prints the AI's answer, its evidence with the check result, and
the expected value. `"stream"` selects a TCP stream to include, like the dashboard's selector.
In `capture.pcapng`, the HTTP traffic is stream 58.

## Documented AI failure case (requirement 34)

### Question

### What the AI answered

### Correct answer (from Wireshark)

### Why it was wrong

### What I changed

### Result after the fix
