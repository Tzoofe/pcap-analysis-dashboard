"""
ai_context.py - builds the text ("context") that is sent to the AI model.

The model never sees the PCAP file or raw tshark output. It only sees data the
dashboard ALREADY EXTRACTED (pandas DataFrames from pcap_parser.py), plus facts
we PRE-COMPUTE here with pandas (counts, slowest request ...), because language
models are unreliable at counting rows or finding a maximum in a table.
"""

import pandas as pd

import pcap_parser

# Limits that keep the context a reasonable size. If a table is longer, it is cut
# and the context says so explicitly, so the model knows it is not seeing everything.
MAX_HTTP_ROWS = 200
MAX_STREAM_ROWS = 200        # we keep the first half and the last half of the stream
MAX_CONTEXT_CHARS = 150_000  # final safety limit for the whole text (~40k tokens)


def table_to_csv(df):
    """DataFrame -> compact CSV text (no index column, times with 6 decimals like Wireshark)."""
    return df.to_csv(index=False, float_format="%.6f").strip()


def counts_to_text(series):
    """A pandas value_counts() result -> lines like '  gaia.cs.umass.edu: 2'."""
    return "\n".join(f"  {value}: {count}" for value, count in series.items())


# ---------------------------------------------------------------------------
# Pre-computed HTTP facts
# ---------------------------------------------------------------------------

def http_facts(http):
    """Counts and extremes computed in pandas, written as plain text lines."""
    lines = []
    answered = http.dropna(subset=["response_time"])   # only requests that got a response
    lines.append(f"Total HTTP requests: {len(http)}")
    lines.append(f"Requests with a response: {len(answered)}")
    lines.append(f"Requests without a response: {len(http) - len(answered)}")

    if len(answered) > 0:
        # idxmax / idxmin return the row label of the largest / smallest http.time.
        slowest = answered.loc[answered["response_time"].idxmax()]
        fastest = answered.loc[answered["response_time"].idxmin()]
        for name, row in [("Slowest", slowest), ("Fastest", fastest)]:
            lines.append(
                f"{name} transaction: request frame {row['request_frame']} "
                f"(time {row['request_time']:.6f}) -> response frame {row['response_frame']} "
                f"(time {row['response_frame_time']:.6f}), http.time = {row['response_time']:.6f} s, "
                f"{row['method']} {row['host']}{row['uri']}, status {row['status_code']}"
            )

    # Status code as text, with "no response" for requests that were never answered.
    status = http["status_code"].apply(lambda c: "no response" if pd.isna(c) else str(c))
    lines.append("Requests per Host:\n" + counts_to_text(http["host"].value_counts()))
    lines.append("Requests per Method:\n" + counts_to_text(http["method"].value_counts()))
    lines.append("Requests per Status Code:\n" + counts_to_text(status.value_counts()))
    lines.append("Requests per TCP stream:\n" + counts_to_text(http["tcp_stream"].value_counts()))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pre-computed facts about one TCP stream
# ---------------------------------------------------------------------------

def frames_with_flag(stream, letter):
    """Frames whose TCP flags text contains this letter (S=SYN, F=FIN, R=RST)."""
    # str.contains checks each row's flags text, e.g. "·······A···F" contains "F".
    rows = stream[stream["flags"].str.contains(letter, regex=False)]
    if len(rows) == 0:
        return "none"
    return ", ".join(f"frame {r.frame} (time {r.time:.6f}, from {r.src}:{r.src_port})"
                     for r in rows.itertuples())


def stream_facts(stream):
    """Summary of one TCP connection, computed in pandas."""
    first = stream.iloc[0]
    last = stream.iloc[-1]
    # Bytes of TCP payload sent by each side: group the rows by sender and add up payload_len.
    payload = pd.to_numeric(stream["payload_len"], errors="coerce").fillna(0).astype(int)
    sender = stream["src"] + ":" + stream["src_port"]
    bytes_per_sender = payload.groupby(sender).sum()
    lines = [
        f"Frames in stream: {len(stream)}",
        f"First frame: {first['frame']} (time {first['time']:.6f})",
        f"Last frame: {last['frame']} (time {last['time']:.6f})",
        f"Duration: {last['time'] - first['time']:.6f} s",
        f"SYN frames: {frames_with_flag(stream, 'S')}",
        f"FIN frames: {frames_with_flag(stream, 'F')}",
        f"RST frames: {frames_with_flag(stream, 'R')}",
        "TCP payload bytes sent by each side:\n" + counts_to_text(bytes_per_sender),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Building the full context
# ---------------------------------------------------------------------------

def build_context(packets, http, stream=None, stream_number=None):
    """
    Build the context for the model.

    packets: DataFrame from pcap_parser.load_packets
    http:    DataFrame from pcap_parser.load_http_transactions
    stream:  DataFrame from pcap_parser.load_tcp_stream, or None if no stream was selected

    Returns a dict:
      text          - the text sent to the model
      frames        - {frame number: relative time} for every frame that appears in the text
                      (used later to check the frames the model cites as evidence)
      packet_count  - number of packets in the capture (frame numbers go from 1 to this)
      stream_number - the selected TCP stream, or None
      truncated     - list of the parts that were cut
    """
    sections = []
    frames = {}
    truncated = []

    # 1. Capture summary
    summary = pcap_parser.capture_summary(packets)
    sections.append(
        "## CAPTURE SUMMARY\n"
        f"Packets: {summary['packet_count']}\n"
        f"First packet (local time): {summary['start']}\n"
        f"Last packet (local time): {summary['end']}\n"
        f"Duration: {summary['duration_seconds']:.6f} s\n"
        "All 'time' values below are seconds since the first packet (Wireshark's default Time column)."
    )

    # 2. Protocols and endpoints
    sections.append("## PROTOCOLS (packets per value of Wireshark's Protocol column)\n"
                    + table_to_csv(pcap_parser.protocol_counts(packets)))
    sections.append("## TOP IP ENDPOINTS (packets sent + received)\n"
                    + table_to_csv(pcap_parser.top_endpoints(packets, n=10)))

    # 3. HTTP: pre-computed facts first, then the full table.
    if len(http) == 0:
        sections.append("## HTTP\nNo HTTP requests were found in this capture.")
    else:
        sections.append("## PRE-COMPUTED HTTP FACTS (use these for counts and extremes)\n" + http_facts(http))

        columns = ["request_frame", "request_time", "response_frame", "response_frame_time",
                   "method", "host", "uri", "src_ip", "src_port", "dst_ip", "dst_port",
                   "status_code", "response_time", "tcp_stream"]
        table = http[columns].rename(columns={"response_time": "http_time"})
        if len(table) > MAX_HTTP_ROWS:
            truncated.append(f"HTTP table: showing the first {MAX_HTTP_ROWS} of {len(table)} rows")
            table = table.head(MAX_HTTP_ROWS)
        sections.append(
            "## HTTP TRANSACTIONS (one row per request; response columns empty if no response)\n"
            "http_time = Wireshark's http.time (seconds between request and response)\n"
            + table_to_csv(table))

        # Remember every frame shown, with its time, for evidence validation.
        for row in http.itertuples():
            frames[int(row.request_frame)] = row.request_time
            if not pd.isna(row.response_frame):
                frames[int(row.response_frame)] = row.response_frame_time

    # 4. The selected TCP stream (optional)
    if stream is not None and stream_number is not None:
        if len(stream) == 0:
            sections.append(f"## TCP STREAM {stream_number}\nThis stream has no frames.")
        else:
            shown = stream
            if len(stream) > MAX_STREAM_ROWS:
                # Keep the start (handshake) and the end (connection close), drop the middle.
                half = MAX_STREAM_ROWS // 2
                shown = pd.concat([stream.head(half), stream.tail(half)])
                truncated.append(f"TCP stream {stream_number}: showing the first {half} and last {half} "
                                 f"of {len(stream)} frames; the middle frames are missing")
            sections.append(f"## PRE-COMPUTED FACTS FOR TCP STREAM {stream_number}\n" + stream_facts(stream))
            sections.append(f"## FRAMES OF TCP STREAM {stream_number} (Wireshark filter: tcp.stream == {stream_number})\n"
                            + table_to_csv(shown))
            # Only frames the model can actually see: the rows shown, plus the SYN/FIN/RST
            # frames listed in the facts (regex "S|F|R" = flags text contains S or F or R).
            flagged = stream[stream["flags"].str.contains("S|F|R")]
            for row in pd.concat([shown, flagged]).itertuples():
                frames[int(row.frame)] = row.time

    # 5. Tell the model what was cut, if anything.
    if truncated:
        sections.append("## TRUNCATION NOTICE\nSome data was cut to keep the context short:\n- "
                        + "\n- ".join(truncated))

    text = "\n\n".join(sections)
    if len(text) > MAX_CONTEXT_CHARS:
        truncated.append(f"whole context cut at {MAX_CONTEXT_CHARS} characters")
        text = text[:MAX_CONTEXT_CHARS] + "\n\n## TRUNCATION NOTICE\nThe context was cut here because it was too long."

    return {
        "text": text,
        "frames": frames,
        "packet_count": summary["packet_count"],
        "stream_number": stream_number,
        "truncated": truncated,
    }


# Command-line check:  .venv/bin/python ai_context.py capture.pcapng 58
if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "capture.pcapng"
    number = int(sys.argv[2]) if len(sys.argv) > 2 else None
    packets, _ = pcap_parser.load_packets(path)
    http = pcap_parser.load_http_transactions(path)
    stream = pcap_parser.load_tcp_stream(path, number) if number is not None else None
    context = build_context(packets, http, stream, number)
    print(context["text"])
    print("\n---")
    print("Characters:", len(context["text"]), "| frames known:", len(context["frames"]),
          "| truncated:", context["truncated"])
