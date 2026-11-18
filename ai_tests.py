"""
ai_tests.py - run a list of questions against the AI and print each answer next to
the answer we found manually in Wireshark (requirement 33).

Usage:
    .venv/bin/python ai_tests.py capture.pcapng [ai_test_questions.json]

The questions file is a JSON list of {"question": ..., "stream": N or null, "expected": ...}.
"stream" is the TCP stream to include in the context (like the dashboard's stream selector).
The Gemini key is read from GEMINI_API_KEY (.env file or environment); if it is missing,
the script asks for it without showing it on screen.
Every call is also logged to logs/ai_log.jsonl by ai.ask().
"""

import getpass
import json
import sys

import ai
import ai_context
import pcap_parser


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    capture_path = sys.argv[1]
    questions_path = sys.argv[2] if len(sys.argv) > 2 else "ai_test_questions.json"

    api_key = ai.get_api_key()
    if not api_key:
        # getpass reads a line without echoing it, so the key is not shown or saved in shell history.
        api_key = getpass.getpass("Gemini API key: ")

    with open(questions_path, encoding="utf-8") as f:
        questions = json.load(f)

    # Extract the data once; it is the same for every question.
    packets, _ = pcap_parser.load_packets(capture_path)
    http = pcap_parser.load_http_transactions(capture_path)
    streams = {}   # stream number -> DataFrame, so each stream is loaded only once

    print(f"Capture: {capture_path} | model: {ai.get_model()} | prompt: {ai.PROMPT_VERSION}")
    failed_evidence = 0
    for number, item in enumerate(questions, start=1):
        stream_number = item.get("stream")
        stream = None
        if stream_number is not None:
            if stream_number not in streams:
                streams[stream_number] = pcap_parser.load_tcp_stream(capture_path, stream_number)
            stream = streams[stream_number]
        context = ai_context.build_context(packets, http, stream, stream_number)

        result = ai.ask(item["question"], context, api_key)

        print("\n" + "=" * 80)
        print(f"Q{number}: {item['question']}")
        if stream_number is not None:
            print(f"TCP stream: {stream_number}")
        if result["error"]:
            print(f"ERROR: {result['error']}")
        print(f"AI answer:  {result['answer']}")
        print(f"Confidence: {result['confidence']}")
        print("Evidence:")
        if not result["evidence"]:
            print("  (none)")
        for row in result["evidence"]:
            mark = "OK " if row["status"] == "ok" else "BAD"
            if row["status"] != "ok":
                failed_evidence += 1
            print(f"  [{mark}] frame {row['frame']}, time {row['timestamp']} "
                  f"(real: {row['real_timestamp'] or '-'}) - {row['detail']} [{row['status']}]")
        print(f"EXPECTED:   {item.get('expected', '')}")

    print("\n" + "=" * 80)
    print(f"{len(questions)} question(s) asked. Evidence rows that failed the check: {failed_evidence}.")
    print("Compare each AI answer with EXPECTED. Full details of every call: logs/ai_log.jsonl")


if __name__ == "__main__":
    main()
