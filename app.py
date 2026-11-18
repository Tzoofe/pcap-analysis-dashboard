"""
app.py - Streamlit user interface only.
Parsing is in pcap_parser.py; the AI feature is in ai_context.py, prompts.py and ai.py.

Run with:  .venv/bin/streamlit run app.py
"""

import os
import tempfile

import pandas as pd
import plotly.express as px
import streamlit as st

import ai
import ai_context
import pcap_parser

st.set_page_config(page_title="PCAP Analysis Dashboard", layout="wide")
st.title("PCAP / PCAPNG Analysis Dashboard")


def save_temp_file(file_bytes, file_name):
    """Write the uploaded bytes to a temporary file and return its path (tshark needs a path)."""
    # Keep the original extension (.pcap / .pcapng) - tshark detects the format by content anyway.
    suffix = os.path.splitext(file_name)[1]
    # delete=False: we close the file before tshark opens it, then delete it ourselves.
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp:
        temp.write(file_bytes)
        return temp.name


@st.cache_data
def analyze(file_bytes, file_name):
    """
    Write the uploaded bytes to a temp file, run tshark on it and return the results.
    @st.cache_data remembers the result for the same file, because Streamlit re-runs
    this whole script on every click and we do not want to run tshark again each time.
    """
    temp_path = save_temp_file(file_bytes, file_name)
    try:
        packets, warning = pcap_parser.load_packets(temp_path)
        http = pcap_parser.load_http_transactions(temp_path)
    finally:
        os.remove(temp_path)  # always clean up, even if tshark failed
    return packets, warning, http


@st.cache_data
def get_stream(file_bytes, file_name, stream_number):
    """Frames of one TCP stream (tcp.stream == N), cached like analyze()."""
    temp_path = save_temp_file(file_bytes, file_name)
    try:
        return pcap_parser.load_tcp_stream(temp_path, stream_number)
    finally:
        os.remove(temp_path)


# ---------------------------------------------------------------------------
# 23. Choose a capture file
# ---------------------------------------------------------------------------
uploaded = st.file_uploader("Choose a PCAP or PCAPNG file", type=["pcap", "pcapng", "cap"])
if uploaded is None:
    st.info("Upload a capture file to start.")
    st.stop()  # stop running the script until a file is chosen

try:
    packets, warning, http = analyze(uploaded.getvalue(), uploaded.name)
except pcap_parser.TsharkError as error:
    # Corrupted / unsupported file: show tshark's own error message.
    st.error("tshark could not read this file:\n\n" + str(error))
    st.stop()

if warning:
    # tshark read some packets but complained (e.g. the file was cut short).
    st.warning("tshark reported a problem (the results below may be partial):\n\n" + warning)

if len(packets) == 0:
    st.warning("The capture file contains no packets.")
    st.stop()

# ---------------------------------------------------------------------------
# 24. Packet count, start, end, duration
# ---------------------------------------------------------------------------
st.header("Capture overview")
summary = pcap_parser.capture_summary(packets)
col1, col2, col3, col4 = st.columns(4)
col1.metric("Packets", f"{summary['packet_count']:,}")
col2.metric("First packet", summary["start"].strftime("%Y-%m-%d %H:%M:%S"))
col3.metric("Last packet", summary["end"].strftime("%Y-%m-%d %H:%M:%S"))
col4.metric("Duration", pcap_parser.format_duration(summary["duration_seconds"]),
            help=f"{summary['duration_seconds']:.6f} seconds")

# ---------------------------------------------------------------------------
# 25. Main endpoints and protocols
# ---------------------------------------------------------------------------
endpoints = pcap_parser.top_endpoints(packets, n=10)
protocols = pcap_parser.protocol_counts(packets)

left, right = st.columns(2)
with left:
    st.subheader("Top IP endpoints (packets sent + received)")
    st.dataframe(endpoints, hide_index=True, width="stretch")
with right:
    st.subheader("Protocols (Wireshark 'Protocol' column)")
    st.dataframe(protocols, hide_index=True, width="stretch")

# ---------------------------------------------------------------------------
# 26. Visualizations
# ---------------------------------------------------------------------------
st.subheader("Traffic volume over time")
per_second = pcap_parser.packets_per_second(packets)
fig = px.line(per_second, x="second", y="packets",
              labels={"second": "Seconds since first packet", "packets": "Packets per second"})
st.plotly_chart(fig, width="stretch")

st.subheader("Protocol distribution")
# Horizontal bars sorted so the most common protocol is at the top.
fig = px.bar(protocols, x="packets", y="protocol", orientation="h",
             labels={"packets": "Packets", "protocol": "Protocol"})
fig.update_yaxes(categoryorder="total ascending")
st.plotly_chart(fig, width="stretch")

def show_http_section(http):
    """HTTP table, details and response-time chart (requirements 27-29 + extra feature).
    It is a function so that 'return' ends only this section, not the whole page."""
    # ---------------------------------------------------------------------------
    # 27-28. HTTP transactions (request + response, paired by tshark)
    # ---------------------------------------------------------------------------
    st.header("HTTP transactions")
    if len(http) == 0:
        st.info("No HTTP requests were found in this capture. "
                "(HTTPS traffic is encrypted with TLS, so tshark cannot see it as HTTP.)")
        return

    # Choose and rename the columns shown in the table.
    table = http[["request_frame", "method", "host", "uri", "src_ip", "src_port",
                  "dst_ip", "dst_port", "status_code", "response_time", "response_frame"]]
    table = table.rename(columns={
        "request_frame": "Request frame", "method": "Method", "host": "Host", "uri": "URI",
        "src_ip": "Source IP", "src_port": "Source port", "dst_ip": "Destination IP",
        "dst_port": "Destination port", "status_code": "Status code",
        "response_time": "Response time (s)", "response_frame": "Response frame",
    })

    # ---------------------------------------------------------------------------
    # Creativity feature, part 1: filters by Host, Method and Status code.
    # They apply to both the table and the response-time chart below.
    # ---------------------------------------------------------------------------
    # Status code as text, so "no response" can be one of the filter choices.
    # .apply runs the small function on every value; pd.isna is True when there was no response.
    status_text = table["Status code"].apply(lambda code: "no response" if pd.isna(code) else str(code))

    filter1, filter2, filter3 = st.columns(3)
    # st.multiselect returns the list of chosen values; an empty list means "no filter".
    chosen_hosts = filter1.multiselect("Host", sorted(table["Host"].unique()))
    chosen_methods = filter2.multiselect("Method", sorted(table["Method"].unique()))
    chosen_status = filter3.multiselect("Status code", sorted(status_text.unique()))

    # Build a True/False mask, one value per row, and keep only rows where it is True.
    mask = pd.Series(True, index=table.index)
    if chosen_hosts:
        mask &= table["Host"].isin(chosen_hosts)       # &= : keep rows that also match this filter
    if chosen_methods:
        mask &= table["Method"].isin(chosen_methods)
    if chosen_status:
        mask &= status_text.isin(chosen_status)
    table = table[mask]

    if len(table) == 0:
        st.info("No transactions match the selected filters.")
        return

    st.caption(f"{len(table)} transaction(s). Click a row to see its details.")
    # on_select="rerun": clicking a row re-runs the script and returns which row was selected.
    event = st.dataframe(
        table,
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        key="http_table",
        # Show http.time with 6 decimals, like Wireshark's "Time since request".
        column_config={"Response time (s)": st.column_config.NumberColumn(format="%.6f")},
    )

    # ---------------------------------------------------------------------------
    # 29. Details of the selected transaction
    # ---------------------------------------------------------------------------
    selected_rows = event.selection.rows      # list of selected row positions, e.g. [0] or []
    if selected_rows:
        position = selected_rows[0]
        # table.index[position] is the label of that row, which is the same label in `http`.
        row = http.loc[table.index[position]]

        st.subheader(f"Transaction details - request frame {row['request_frame']}")
        details = {
            "Request frame": row["request_frame"],
            "Method": row["method"],
            "Host": row["host"],
            "URI": row["uri"],
            "HTTP version": row["version"],
            "Full URL": "http://" + row["host"] + row["uri"] if row["host"] else "",
            "Source": f"{row['src_ip']}:{row['src_port']}",
            "Destination": f"{row['dst_ip']}:{row['dst_port']}",
            "Response frame": row["response_frame"],
            "Status code": row["status_code"],
            "Status phrase": row["status_phrase"],
            "Content-Type": row["content_type"],
            "Response time (http.time)": row["response_time"],
        }
        # pd.isna is True for missing values (request with no response) -> show "" instead of <NA>.
        for key, value in details.items():
            if pd.isna(value):
                details[key] = ""
            elif key == "Response time (http.time)":
                details[key] = f"{value:.6f} s"
        # Show the details as a 2-column table (Field, Value). Values are converted to text.
        st.table(pd.DataFrame({"Field": list(details.keys()),
                               "Value": [str(v) for v in details.values()]}))

        # A display filter the user can paste into Wireshark to see the same two packets.
        wireshark_filter = f"frame.number == {row['request_frame']}"
        if not pd.isna(row["response_frame"]):
            wireshark_filter += f" || frame.number == {row['response_frame']}"
        st.code(wireshark_filter, language=None)
        st.caption("Paste this filter into Wireshark to see the same packets.")
        if pd.isna(row["response_frame"]):
            st.warning("No response was captured for this request.")

    # ---------------------------------------------------------------------------
    # Creativity feature, part 2: response time per transaction.
    # One bar per transaction, labeled by the request frame number; 4xx/5xx in red.
    # ---------------------------------------------------------------------------
    st.subheader("HTTP response time per transaction")
    # Requests without a response have no response time, so they cannot be drawn.
    chart_data = table.dropna(subset=["Response time (s)"]).copy()
    if len(chart_data) == 0:
        st.info("None of the selected requests received a response, so there is nothing to plot.")
    else:
        # Status codes 400 and above are client (4xx) or server (5xx) errors.
        chart_data["Result"] = "OK (1xx-3xx)"
        chart_data.loc[chart_data["Status code"] >= 400, "Result"] = "Error (4xx/5xx)"
        # The frame number as text, so Plotly treats it as a label and not as a number on an axis.
        chart_data["Request"] = "Frame " + chart_data["Request frame"].astype(str)

        fig = px.bar(
            chart_data,
            x="Request",
            y="Response time (s)",
            color="Result",
            color_discrete_map={"OK (1xx-3xx)": "#3b6fb6", "Error (4xx/5xx)": "#d64545"},
            hover_data=["Method", "Host", "URI", "Status code", "Response frame"],
        )
        fig.update_xaxes(type="category", title="Request frame")  # keep bars in table order
        st.plotly_chart(fig, width="stretch")


show_http_section(http)

# ---------------------------------------------------------------------------
# 30-32. Ask the AI about this capture
# The AI gets only data we already extracted (see ai_context.py), never the PCAP file.
# ---------------------------------------------------------------------------
st.header("Ask about this capture (AI)")
st.caption("The AI receives only the extracted tables and pre-computed facts shown under "
           "'Context sent to the AI', not the capture file.")

# type="password" hides the key while typing. It is kept only in this browser session,
# never written to disk or to the log.
typed_key = st.text_input("Gemini API key", type="password",
                          help="Get a free key at https://aistudio.google.com/apikey. "
                               "If left empty, GEMINI_API_KEY from the .env file is used.")
# Model dropdown: the .env model (or the default) is selected first.
# If Google answers "503 high demand", choose another model here.
choices = ai.MODEL_CHOICES if ai.get_model() in ai.MODEL_CHOICES else [ai.get_model()] + ai.MODEL_CHOICES
model = st.selectbox("Gemini model", choices, index=choices.index(ai.get_model()),
                     help="If you get error 503 (model overloaded), try another model.")
if not ai.get_api_key(typed_key):
    st.info("Enter a Gemini API key above to use the AI questions. The rest of the dashboard works without it.")

# Optional TCP stream: the stream numbers that appear in the HTTP table.
# Plain strings ("58"), not numpy numbers: the browser sends the choice back as text,
# and numpy values may not match it, which made the choice jump back to "none".
stream_numbers = sorted(int(n) for n in http["tcp_stream"].dropna().astype(int).unique()) if len(http) else []
stream_options = ["none"] + [str(n) for n in stream_numbers]
stream_choice = st.selectbox("TCP stream to include (optional)", stream_options, key="stream_choice",
                             help="Adds every frame of this stream (tcp.stream == N) to the AI context.")
stream_number = None if stream_choice == "none" else int(stream_choice)
stream = get_stream(uploaded.getvalue(), uploaded.name, stream_number) if stream_number is not None else None

# Build the context from the data we already have (cheap, so we do it on every rerun).
context = ai_context.build_context(packets, http, stream, stream_number)

question = st.text_input("Your question",
                         placeholder="e.g. Which request was the slowest? / What happened in this TCP stream?")
if st.button("Ask", disabled=not ai.get_api_key(typed_key)):
    if question.strip() == "":
        st.warning("Type a question first.")
    else:
        with st.spinner("Asking Gemini... (usually 5-20 seconds; up to ~2 minutes if Google is busy)"):
            result = ai.ask(question, context, typed_key, model)
        # session_state keeps the answer when the page reruns (e.g. after clicking a table row).
        st.session_state["ai_result"] = result
        st.session_state["ai_question"] = question
        st.session_state["ai_context_text"] = context["text"]
        st.session_state["ai_file"] = uploaded.name

# Show the last answer, but only if it belongs to the file that is loaded now.
result = st.session_state.get("ai_result")
if result is not None and st.session_state.get("ai_file") == uploaded.name:
    st.subheader("Answer")
    st.markdown(f"**Question:** {st.session_state['ai_question']}")
    if result["error"]:
        st.error(result["error"])
    if result["answer"]:
        st.write(result["answer"])
        st.markdown(f"**Confidence:** {result['confidence']}")

    # 32. Evidence: frame numbers and timestamps, checked against the extracted data.
    if result["evidence"]:
        st.markdown("**Evidence** (time = seconds since the first packet; "
                    "'real time' is the value from our extracted data)")
        evidence = pd.DataFrame(result["evidence"]).rename(columns={
            "frame": "Frame", "timestamp": "Time (AI)", "real_timestamp": "Real time",
            "detail": "Detail", "status": "Check"})

        def highlight(row):
            """Red background for every evidence row that did not pass the check."""
            color = "" if row["Check"] == "ok" else "background-color: #f8d7da; color: #721c24"
            return [color] * len(row)   # one style per cell in the row

        st.dataframe(evidence.style.apply(highlight, axis=1), hide_index=True, width="stretch")
        bad = (evidence["Check"] != "ok").sum()
        if bad:
            st.warning(f"{bad} evidence row(s) failed the check - do not trust those parts of the answer.")
    elif result["answer"]:
        st.info("The AI gave no frame evidence for this answer.")

    with st.expander("Raw model response"):
        st.code(result["raw_response"] or "(empty)", language="json")

with st.expander("Context sent to the AI"):
    # After a question: exactly what was sent. Before: what will be sent.
    shown_context = st.session_state.get("ai_context_text") if result is not None else None
    st.code(shown_context or context["text"], language=None)
    if context["truncated"]:
        st.warning("Truncated: " + "; ".join(context["truncated"]))
