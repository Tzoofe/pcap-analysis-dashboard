"""
pcap_parser.py - all the tshark + pandas logic for the dashboard (no UI code here).

Every function runs `tshark` (Wireshark's command-line version) with
"-T fields", which prints one line per packet and one column per field,
and loads that text into a pandas DataFrame.
"""

import csv
import io
import os
import shutil
import subprocess
import sys
from datetime import datetime

import pandas as pd

# Default location of tshark inside the macOS Wireshark app bundle.
MAC_TSHARK_PATH = "/Applications/Wireshark.app/Contents/MacOS/tshark"


class TsharkError(Exception):
    """Raised when tshark cannot read the capture (e.g. a corrupted file)."""


# ---------------------------------------------------------------------------
# Finding tshark
# ---------------------------------------------------------------------------

def find_tshark():
    """Return the full path of the tshark program, or raise TsharkError."""
    # shutil.which searches the PATH, exactly like typing "tshark" in a terminal.
    path = shutil.which("tshark")
    if path is None and os.path.exists(MAC_TSHARK_PATH):
        path = MAC_TSHARK_PATH
    if path is None:
        raise TsharkError("tshark was not found. Install Wireshark or add tshark to your PATH.")
    return path


def get_tshark_version(tshark_path):
    """Return the tshark version as a tuple of ints, e.g. (4, 6, 9)."""
    result = subprocess.run([tshark_path, "--version"], capture_output=True, text=True)
    # The first line looks like: "TShark (Wireshark) 4.6.9 (v4.6.9-0-g2d548b197c75)."
    first_line = result.stdout.splitlines()[0]
    version_text = first_line.split()[2]            # -> "4.6.9"
    return tuple(int(part) for part in version_text.split("."))


def get_protocol_field(version):
    """Name of the 'Protocol' column field. It was renamed in Wireshark 4.2."""
    if version >= (4, 2):
        return "_ws.col.protocol"
    return "_ws.col.Protocol"


def get_info_field(version):
    """Name of the 'Info' column field. It was renamed in Wireshark 4.2, like Protocol."""
    if version >= (4, 2):
        return "_ws.col.info"
    return "_ws.col.Info"


# ---------------------------------------------------------------------------
# Running tshark
# ---------------------------------------------------------------------------

def run_tshark(pcap_path, fields, display_filter=None, two_pass=False):
    """
    Run tshark on a capture file and return (DataFrame, warning_text).

    Each element of `fields` becomes one DataFrame column (all values are strings).
    warning_text is tshark's error output if it complained but still printed packets
    (for example a file that was cut short), otherwise "".
    """
    command = [
        find_tshark(),
        "-r", pcap_path,         # -r: read packets from this file (instead of capturing live)
        "-n",                    # -n: no name resolution, show raw IP addresses (also faster)
        "-T", "fields",          # -T fields: print only the fields we ask for with -e
        "-E", "header=y",        # header=y: first line contains the field names (column headers)
        "-E", "separator=/t",    # separator=/t: separate the fields with a TAB character
        "-E", "occurrence=f",    # occurrence=f: if a field appears several times in a packet, take the first one
    ]
    if two_pass:
        # -2: read the file twice. Needed for fields that point *forward* in the capture,
        # like http.response_in (the request frame only learns its response frame on pass 2).
        command.append("-2")
    if display_filter:
        # -Y: display filter, same syntax as the filter bar in Wireshark.
        command += ["-Y", display_filter]
    for field in fields:
        command += ["-e", field]  # -e: add one field (one output column)

    result = subprocess.run(command, capture_output=True, text=True)

    # tshark returns a non-zero exit code if it could not read the file.
    # If it printed nothing at all (not even the header line) the file is unusable.
    if result.returncode != 0 and result.stdout.strip() == "":
        raise TsharkError(result.stderr.strip() or "tshark failed with exit code %d" % result.returncode)

    warning = result.stderr.strip() if result.returncode != 0 else ""

    # Turn tshark's tab-separated text into a DataFrame.
    df = pd.read_csv(
        io.StringIO(result.stdout),  # read from the text in memory, as if it were a file
        sep="\t",                    # columns are separated by tabs (matches separator=/t)
        dtype=str,                   # keep everything as text; we convert numbers ourselves
        keep_default_na=False,       # empty fields stay "" instead of becoming NaN
        quoting=csv.QUOTE_NONE,      # tshark does not quote values, so '"' is a normal character
    )
    return df, warning


# ---------------------------------------------------------------------------
# All packets (overview)
# ---------------------------------------------------------------------------

def load_packets(pcap_path):
    """
    Return (packets DataFrame, warning_text) with one row per packet and columns:
    frame, time_epoch, time_relative, length, src, dst, protocol.
    """
    protocol_field = get_protocol_field(get_tshark_version(find_tshark()))
    fields = [
        "frame.number",          # packet number, the "No." column in Wireshark
        "frame.time_epoch",      # absolute arrival time, seconds since 1970-01-01 UTC
        "frame.time_relative",   # seconds since the first packet, the default "Time" column
        "frame.len",             # packet length on the wire in bytes, the "Length" column
        "ip.src", "ip.dst",      # IPv4 source/destination (empty if the packet is not IPv4)
        "ipv6.src", "ipv6.dst",  # IPv6 source/destination (empty if the packet is not IPv6)
        protocol_field,          # the "Protocol" column exactly as Wireshark shows it
    ]
    df, warning = run_tshark(pcap_path, fields)

    packets = pd.DataFrame()
    packets["frame"] = df["frame.number"].astype(int)
    packets["time_epoch"] = df["frame.time_epoch"].astype(float)
    packets["time_relative"] = df["frame.time_relative"].astype(float)
    packets["length"] = df["frame.len"].astype(int)
    # Use the IPv4 address if present, otherwise the IPv6 one.
    # ARP frames have neither, so they stay "" (empty).
    packets["src"] = df["ip.src"].where(df["ip.src"] != "", df["ipv6.src"])
    packets["dst"] = df["ip.dst"].where(df["ip.dst"] != "", df["ipv6.dst"])
    packets["protocol"] = df[protocol_field]
    return packets, warning


def capture_summary(packets):
    """Packet count, first/last packet time and duration (like Capture File Properties)."""
    if len(packets) == 0:
        return {"packet_count": 0, "start": None, "end": None, "duration_seconds": 0.0}
    first = packets["time_epoch"].min()
    last = packets["time_epoch"].max()
    return {
        "packet_count": len(packets),
        # datetime.fromtimestamp converts epoch seconds to this computer's local time,
        # which is also how Wireshark displays "First packet" / "Last packet".
        "start": datetime.fromtimestamp(first),
        "end": datetime.fromtimestamp(last),
        "duration_seconds": last - first,
    }


def format_duration(seconds):
    """Format seconds as HH:MM:SS (Wireshark's 'Elapsed' format)."""
    seconds = int(seconds)
    return "%02d:%02d:%02d" % (seconds // 3600, (seconds % 3600) // 60, seconds % 60)


def top_endpoints(packets, n=10):
    """
    Top IP addresses by number of packets they sent OR received.
    Same idea as Statistics -> Endpoints -> IPv4 / IPv6 tab, "Packets" column.
    """
    # Put every (frame, address) pair in one long table: one row for the source, one for the destination.
    as_src = packets[["frame", "src"]].rename(columns={"src": "address"})
    as_dst = packets[["frame", "dst"]].rename(columns={"dst": "address"})
    both = pd.concat([as_src, as_dst])
    both = both[both["address"] != ""]          # drop packets without an IP address (e.g. ARP)
    both = both.drop_duplicates()               # a packet sent to itself counts only once
    counts = both["address"].value_counts()     # count rows per address, largest first
    result = counts.head(n).reset_index()       # turn the Series into a 2-column DataFrame
    result.columns = ["address", "packets"]
    return result


def protocol_counts(packets):
    """Number of packets per value of the Protocol column."""
    result = packets["protocol"].value_counts().reset_index()
    result.columns = ["protocol", "packets"]
    return result


def packets_per_second(packets):
    """Packets per 1-second interval since the start of the capture (like an I/O Graph with 1 s interval)."""
    # Integer part of the relative time = the second the packet falls in (0, 1, 2, ...).
    seconds = packets["time_relative"].astype(int)
    counts = seconds.value_counts().sort_index()
    # reindex fills in seconds that had no packets with 0, so the line does not skip them.
    all_seconds = range(0, seconds.max() + 1) if len(seconds) else []
    counts = counts.reindex(all_seconds, fill_value=0)
    result = counts.reset_index()
    result.columns = ["second", "packets"]
    return result


# ---------------------------------------------------------------------------
# HTTP transactions
# ---------------------------------------------------------------------------

HTTP_FIELDS = [
    "frame.number",
    "frame.time_relative",          # seconds since the first packet (Wireshark's "Time" column)
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport",   # TCP source / destination port
    "tcp.stream",                   # TCP connection index (Wireshark's "Follow TCP Stream" number)
    "http.request.method",          # GET, POST, ... (only in request frames)
    "http.host",                    # value of the Host: header
    "http.request.uri",             # the path, e.g. /index.html
    "http.request.version",         # e.g. HTTP/1.1
    "http.response_in",             # in a request frame: number of the frame with its response
    "http.response.code",           # 200, 404, ... (only in response frames)
    "http.response.phrase",         # OK, Not Found, ...
    "http.request_in",              # in a response frame: number of the frame with its request
    "http.time",                    # in a response frame: seconds since the request ("Time since request")
    "http.content_type",            # Content-Type header of the response
]


def load_http_transactions(pcap_path):
    """
    Return a DataFrame with one row per HTTP request and its matching response.
    The pairing comes from tshark itself (http.response_in), we do not match them by hand.
    Requests without a response keep empty response columns.
    """
    # two_pass=True so that http.response_in is filled in for request frames.
    df, _ = run_tshark(pcap_path, HTTP_FIELDS,
                       display_filter="http.request || http.response", two_pass=True)

    # IPv4 address if present, otherwise IPv6.
    df["src_ip"] = df["ip.src"].where(df["ip.src"] != "", df["ipv6.src"])
    df["dst_ip"] = df["ip.dst"].where(df["ip.dst"] != "", df["ipv6.dst"])

    # Split into request frames (have a method) and response frames (have a status code).
    requests = df[df["http.request.method"] != ""]
    responses = df[df["http.response.code"] != ""]

    requests = pd.DataFrame({
        "request_frame": requests["frame.number"].astype(int),
        "request_time": requests["frame.time_relative"].astype(float),
        "method": requests["http.request.method"],
        "host": requests["http.host"],
        "uri": requests["http.request.uri"],
        "version": requests["http.request.version"],
        "src_ip": requests["src_ip"],
        "dst_ip": requests["dst_ip"],
        "src_port": requests["tcp.srcport"],
        "dst_port": requests["tcp.dstport"],
        "tcp_stream": requests["tcp.stream"],
        "response_in": requests["http.response_in"],   # still text; "" if there was no response
    })
    responses = pd.DataFrame({
        "response_frame": responses["frame.number"],
        "response_frame_time": responses["frame.time_relative"],
        "status_code": responses["http.response.code"],
        "status_phrase": responses["http.response.phrase"],
        "response_time": responses["http.time"],
        "content_type": responses["http.content_type"],
    })

    # Left join: keep every request; attach the response whose frame number equals
    # the request's http.response_in (tshark's own pairing). No match -> empty (NaN) columns.
    transactions = requests.merge(responses, how="left",
                                  left_on="response_in", right_on="response_frame")
    transactions = transactions.drop(columns=["response_in"])

    # Convert text columns to numbers. errors="coerce" turns "" into NaN (= no value).
    # "Int64" (capital I) is pandas' integer type that allows missing values.
    for column in ["response_frame", "status_code", "src_port", "dst_port", "tcp_stream"]:
        transactions[column] = pd.to_numeric(transactions[column], errors="coerce").astype("Int64")
    for column in ["response_time", "response_frame_time"]:
        transactions[column] = pd.to_numeric(transactions[column], errors="coerce")
    # Missing text fields (no response) become "" so the table shows blanks.
    transactions[["status_phrase", "content_type"]] = transactions[["status_phrase", "content_type"]].fillna("")

    return transactions.sort_values("request_frame").reset_index(drop=True)


# ---------------------------------------------------------------------------
# One TCP stream (used by the AI feature)
# ---------------------------------------------------------------------------

def load_tcp_stream(pcap_path, stream_number):
    """
    Return every frame of one TCP connection, like Wireshark's filter "tcp.stream == N".
    Columns: frame, time, src, dst, src_port, dst_port, flags, seq, ack, payload_len, length, info.
    """
    info_field = get_info_field(get_tshark_version(find_tshark()))
    fields = [
        "frame.number", "frame.time_relative", "frame.len",
        "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "tcp.srcport", "tcp.dstport",
        "tcp.flags.str",   # the TCP flags as text, e.g. "·······AP···" (A=ACK, P=PUSH, S=SYN, F=FIN, R=RST)
        "tcp.seq",         # relative sequence number (starts at 0, as Wireshark shows it)
        "tcp.ack",         # relative acknowledgment number
        "tcp.len",         # TCP payload length in bytes (0 for pure ACK/SYN/FIN packets)
        info_field,        # the "Info" column exactly as Wireshark shows it
    ]
    # int() makes sure only a number goes into the filter text.
    df, _ = run_tshark(pcap_path, fields, display_filter="tcp.stream == %d" % int(stream_number))

    stream = pd.DataFrame()
    stream["frame"] = df["frame.number"].astype(int)
    stream["time"] = df["frame.time_relative"].astype(float)
    stream["src"] = df["ip.src"].where(df["ip.src"] != "", df["ipv6.src"])
    stream["dst"] = df["ip.dst"].where(df["ip.dst"] != "", df["ipv6.dst"])
    stream["src_port"] = df["tcp.srcport"]
    stream["dst_port"] = df["tcp.dstport"]
    stream["flags"] = df["tcp.flags.str"]
    stream["seq"] = df["tcp.seq"]
    stream["ack"] = df["tcp.ack"]
    stream["payload_len"] = df["tcp.len"]
    stream["length"] = df["frame.len"].astype(int)
    stream["info"] = df[info_field]
    return stream


# ---------------------------------------------------------------------------
# Command-line test:  .venv/bin/python pcap_parser.py capture.pcapng
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "capture.pcapng"
    tshark = find_tshark()
    print("tshark:", tshark, "version", get_tshark_version(tshark))

    packets, warning = load_packets(path)
    if warning:
        print("WARNING:", warning)
    summary = capture_summary(packets)
    print("Packets:", summary["packet_count"])
    print("Start:  ", summary["start"])
    print("End:    ", summary["end"])
    print("Duration: %.6f s (%s)" % (summary["duration_seconds"], format_duration(summary["duration_seconds"])))
    print("\nTop endpoints:\n", top_endpoints(packets).to_string(index=False))
    print("\nProtocols:\n", protocol_counts(packets).to_string(index=False))

    http = load_http_transactions(path)
    print("\nHTTP transactions:", len(http))
    if len(http):
        pd.set_option("display.width", 250)
        print(http.to_string(index=False))
