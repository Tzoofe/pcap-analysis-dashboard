"""
ai.py - sends a question plus the extracted capture data to Google's Gemini model,
parses the JSON answer, checks the evidence, and logs every call to logs/ai_log.jsonl.

Main function: ask(question, context, api_key) -> dict
(context is the dict returned by ai_context.build_context)
"""

import json
import os
from datetime import datetime

from dotenv import load_dotenv
from google import genai                 # official Google Gen AI SDK (package "google-genai")
from google.genai import errors, types

from prompts import PROMPT_VERSION, SYSTEM_PROMPT

# Read GEMINI_API_KEY and GEMINI_MODEL from the .env file (if it exists) into the environment.
load_dotenv()

DEFAULT_MODEL = "gemini-3.8-flash"

# Log file next to this script: logs/ai_log.jsonl (one JSON object per line).
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "ai_log.jsonl")


def get_model():
    """Model name from .env (GEMINI_MODEL), or the default."""
    return os.getenv("GEMINI_MODEL") or DEFAULT_MODEL


def get_api_key(typed_key=""):
    """
    The key typed in the dashboard wins; otherwise GEMINI_API_KEY from .env / the environment.
    Returns "" if there is no key at all.
    """
    return typed_key.strip() or os.getenv("GEMINI_API_KEY", "")


def build_user_message(question, context_text):
    """The message sent to the model: the extracted data in tags, then the question."""
    return f"<capture_data>\n{context_text}\n</capture_data>\n\nQuestion: {question}"


# ---------------------------------------------------------------------------
# Calling the model
# ---------------------------------------------------------------------------

def call_model(user_message, model, api_key):
    """
    Send one request to Gemini. Returns (raw_text, info), where info holds
    the finish reason and token usage, for the log.
    """
    client = genai.Client(
        api_key=api_key,
        # If Google is busy (503), rate-limited (429) or has another temporary server error,
        # the SDK retries by itself: up to 4 attempts, waiting about 2s, 4s, 8s in between.
        http_options=types.HttpOptions(
            retry_options=types.HttpRetryOptions(attempts=4, initial_delay=2, max_delay=20),
        ),
    )
    response = client.models.generate_content(
        model=model,
        contents=user_message,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,           # the rules from prompts.py
            response_mime_type="application/json",      # ask Gemini to reply with JSON only
        ),
    )
    # response.text is None when Gemini returned no text (e.g. blocked by a safety filter).
    raw_text = response.text or ""
    # finish_reason says why the model stopped: STOP = finished normally.
    finish = response.candidates[0].finish_reason if response.candidates else None
    usage = response.usage_metadata
    info = {
        "finish_reason": finish.name if finish else "NO_CANDIDATES",
        "model_version": response.model_version,
        "input_tokens": usage.prompt_token_count if usage else None,
        "output_tokens": usage.candidates_token_count if usage else None,
    }
    return raw_text, info


# ---------------------------------------------------------------------------
# Parsing and validating the answer
# ---------------------------------------------------------------------------

def parse_response(raw_text):
    """
    Turn the model's text into a dict. Returns (parsed_dict, error_message).
    If the text is not valid JSON, parsed_dict is None and error_message explains why.
    """
    text = raw_text.strip()
    # Some models wrap JSON in ```json ... ``` despite the instructions: keep only
    # the part from the first "{" to the last "}".
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        return None, "The response contains no JSON object."
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError as error:
        return None, f"The response is not valid JSON: {error}"
    if not isinstance(data, dict):
        return None, "The JSON is not an object."

    # Fill in missing keys so the rest of the code can rely on them.
    parsed = {
        "answer": str(data.get("answer", "")),
        "evidence": data.get("evidence") if isinstance(data.get("evidence"), list) else [],
        "confidence": data.get("confidence") if data.get("confidence") in ("high", "medium", "low") else "unknown",
    }
    return parsed, None


def parse_time(value):
    """Turn a timestamp the model wrote ("79.711470" or "79.711470 s") into a float, or None."""
    try:
        return float(str(value).replace("s", "").strip())
    except ValueError:
        return None


def validate_evidence(evidence, context):
    """
    Check every frame the model cited, against the data we extracted.
    Returns a list of rows: frame, timestamp (model), real_timestamp, detail, status.

    status is one of:
      "ok"                                - the frame was in the data given to the model
      "ok, but the timestamp is wrong"    - frame exists, but the model wrote a different time
      "in capture, but not given to the AI" - a real frame the model could not have seen
      "not found in capture"              - the frame number does not exist (hallucinated)
      "invalid frame number"              - not a number at all
    """
    rows = []
    for item in evidence:
        if not isinstance(item, dict):
            item = {"frame": item}
        model_time = item.get("timestamp", "")
        row = {"frame": item.get("frame"), "timestamp": model_time, "real_timestamp": "",
               "detail": item.get("detail", ""), "status": ""}
        try:
            frame = int(item.get("frame"))
        except (TypeError, ValueError):
            row["status"] = "invalid frame number"
            rows.append(row)
            continue

        if frame in context["frames"]:
            real_time = context["frames"][frame]
            row["real_timestamp"] = f"{real_time:.6f}"
            given_time = parse_time(model_time)
            # Allow a difference of up to 1 microsecond (Wireshark shows 6 decimals).
            if given_time is not None and abs(given_time - real_time) > 0.000001:
                row["status"] = "ok, but the timestamp is wrong"
            else:
                row["status"] = "ok"
        elif 1 <= frame <= context["packet_count"]:
            # Frame numbers in a capture always go from 1 to the packet count.
            row["status"] = "in capture, but not given to the AI"
        else:
            row["status"] = "not found in capture"
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def write_log(entry):
    """Append one JSON object as one line to logs/ai_log.jsonl."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)   # create logs/ if needed
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        # ensure_ascii=False keeps characters like "·" and "→" readable in the file.
        log.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def ask(question, context, api_key=""):
    """
    Ask the model a question about the capture.
    api_key: the key typed in the dashboard; if empty, GEMINI_API_KEY from .env is used.
    Returns a dict: answer, confidence, evidence (validated rows), error, raw_response, model.
    The key itself is never logged.
    """
    model = get_model()
    result = {"answer": "", "confidence": "", "evidence": [], "error": "",
              "raw_response": "", "model": model, "prompt_version": PROMPT_VERSION}
    info = {}

    key = get_api_key(api_key)
    if not key:
        result["error"] = "No Gemini API key. Enter one in the key field (or set GEMINI_API_KEY in .env)."
        return result   # nothing was sent, so nothing to log

    user_message = build_user_message(question, context["text"])
    try:
        raw_text, info = call_model(user_message, model, key)
        result["raw_response"] = raw_text
        if info["finish_reason"] == "MAX_TOKENS":
            result["error"] = "The answer was cut off (maximum output length reached)."
        elif info["finish_reason"] not in ("STOP", "MAX_TOKENS"):
            # SAFETY, RECITATION, OTHER, ...: Gemini stopped without a normal answer.
            result["error"] = f"Gemini did not finish normally (finish reason: {info['finish_reason']})."
        parsed, parse_error = parse_response(raw_text)
        if parsed is None:
            result["error"] = result["error"] or parse_error
        else:
            result["answer"] = parsed["answer"]
            result["confidence"] = parsed["confidence"]
            result["evidence"] = validate_evidence(parsed["evidence"], context)
    # ClientError = 4xx (bad key, unknown model, quota); ServerError = 5xx (Google's side).
    except errors.ClientError as error:
        if error.code in (400, 401, 403) and "API key" in str(error.message):
            result["error"] = "The Gemini API key was rejected. Check the key and try again."
        elif error.code == 404:
            result["error"] = f"Model '{model}' was not found. Set GEMINI_MODEL in .env to a model your key can use."
        elif error.code == 429:
            result["error"] = "Gemini quota / rate limit reached. Wait a minute and try again."
        else:
            result["error"] = f"Gemini API error {error.code}: {error.message}"
    except errors.ServerError as error:
        # 503 = the model is overloaded on Google's side (we already retried 4 times).
        result["error"] = (f"Gemini server error {error.code}: {error.message} "
                           "Google's servers are busy - try again in a minute, or set "
                           "GEMINI_MODEL in .env to another model (e.g. gemini-3.5-flash).")
    except Exception as error:
        # Anything else, mostly network problems (no internet, timeout): show it instead of crashing.
        result["error"] = f"Could not get an answer from Gemini: {type(error).__name__}: {error}"

    # Log everything needed to reproduce and review this call (requirement 34).
    write_log({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "prompt_version": PROMPT_VERSION,
        "model": model,
        "question": question,
        "selected_stream": context["stream_number"],
        "context": context["text"],
        "truncated": context["truncated"],
        "raw_response": result["raw_response"],
        "parsed": {"answer": result["answer"], "confidence": result["confidence"]},
        "validation": result["evidence"],
        "error": result["error"],
        "api_info": info,
    })
    return result


# Command-line test (key from .env):
#   .venv/bin/python ai.py capture.pcapng "Which request was the slowest?" [stream]
if __name__ == "__main__":
    import sys

    import ai_context
    import pcap_parser

    path, question = sys.argv[1], sys.argv[2]
    number = int(sys.argv[3]) if len(sys.argv) > 3 else None
    packets, _ = pcap_parser.load_packets(path)
    http = pcap_parser.load_http_transactions(path)
    stream = pcap_parser.load_tcp_stream(path, number) if number is not None else None
    context = ai_context.build_context(packets, http, stream, number)

    result = ask(question, context)
    print("Model:", result["model"], "| prompt", result["prompt_version"])
    if result["error"]:
        print("ERROR:", result["error"])
    print("Answer:", result["answer"])
    print("Confidence:", result["confidence"])
    for row in result["evidence"]:
        print(f"  frame {row['frame']} @ {row['timestamp']} (real: {row['real_timestamp']}) "
              f"[{row['status']}] {row['detail']}")
