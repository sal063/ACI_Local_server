"""
Build a redacted local debug report for the Ace Combat Infinity mock server.

The listener intentionally captures very detailed runtime telemetry. This helper
summarizes that data without copying private identifiers into the report.
"""

import argparse
import collections
import datetime as _dt
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TELEMETRY_DIR = HERE / "telemetry"
HTTP_JSONL_PATH = TELEMETRY_DIR / "http_events.jsonl"
SUMMARY_PATH = TELEMETRY_DIR / "summary.json"
SAVE_PATH = HERE / "save_state.json"
EVENTS_DIR = TELEMETRY_DIR / "events"
NPSTORAGE_ANALYSIS_PATH = TELEMETRY_DIR / "npstorage_analysis_latest.json"

SENSITIVE_KEYS = {
    "uid",
    "open_psid",
    "open_psid_enc",
    "mac_address",
    "mac_address_enc",
    "authorization",
    "oauth_signature",
    "oauth_token",
    "token",
    "session",
    "user_id",
    "username",
    "ticket",
    "ticketjid",
    "psid",
    "jid",
    "sign",
}


def _now():
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _load_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def _read_jsonl(path):
    path = Path(path)
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _redact(value):
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                out[key] = "<redacted>"
            else:
                out[key] = _redact(child)
        return out
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


def _redact_string(value):
    replacements = {
        str(ROOT): "<repo>",
        ROOT.as_posix(): "<repo>",
        str(HERE): "<repo>\\listener\\Myserver",
        HERE.as_posix(): "<repo>/listener/Myserver",
    }
    result = value
    for needle, repl in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        if needle:
            result = result.replace(needle, repl)
    return result


def _save_summary(state):
    if not isinstance(state, dict):
        return {"type": type(state).__name__}
    return {
        "player_rank": state.get("player_rank"),
        "credit": state.get("credit"),
        "aircraft_count": len(state.get("aircraft", [])),
        "mission_count": len(state.get("mission", [])),
        "mission_ids": [
            item.get("mission_id")
            for item in state.get("mission", [])
            if isinstance(item, dict) and "mission_id" in item
        ],
        "keys": sorted(str(k) for k in state.keys()),
    }


def _event_name(parsed):
    if not isinstance(parsed, dict):
        return None
    if "accum_data" in parsed:
        return "accum_data"
    for key in parsed:
        if str(key).startswith("ev_"):
            return str(key)
    return None


def summarize_http():
    records = _read_jsonl(HTTP_JSONL_PATH)
    paths = collections.Counter()
    routes = collections.Counter()
    events = collections.Counter()
    statuses = collections.Counter()
    hosts = collections.Counter()
    methods = collections.Counter()
    raw_uids = collections.Counter()
    last_requests = []

    for record in records:
        req = record.get("request", {})
        resp = record.get("response", {})
        parsed = record.get("parsed_json")
        paths[req.get("path_only")] += 1
        routes[resp.get("route")] += 1
        statuses[str(resp.get("status"))] += 1
        hosts[req.get("host")] += 1
        methods[req.get("method")] += 1
        event = _event_name(parsed)
        if event:
            events[event] += 1
        if isinstance(parsed, dict) and parsed.get("uid"):
            raw_uids[parsed.get("uid")] += 1
        last_requests.append(
            {
                "request_id": req.get("request_id"),
                "method": req.get("method"),
                "path": req.get("path_only"),
                "route": resp.get("route"),
                "event": event,
                "status": resp.get("status"),
                "body_bytes": req.get("body", {}).get("bytes"),
            }
        )

    return {
        "records_total": len(records),
        "paths": dict(paths.most_common()),
        "routes": dict(routes.most_common()),
        "events": dict(events.most_common()),
        "statuses": dict(statuses.most_common()),
        "hosts": dict(hosts.most_common()),
        "methods": dict(methods.most_common()),
        "redacted_uid_values_seen": len(raw_uids),
        "last_requests": last_requests[-40:],
    }


def summarize_event_files():
    result = {}
    if not EVENTS_DIR.exists():
        return result
    for path in sorted(EVENTS_DIR.glob("*.jsonl")):
        rows = _read_jsonl(path)
        latest = rows[-1] if rows else None
        payload = latest.get("payload") if isinstance(latest, dict) else None
        result[path.name] = {
            "records": len(rows),
            "latest_request_id": latest.get("request_id") if isinstance(latest, dict) else None,
            "latest_payload_redacted": _redact(payload) if payload else None,
        }
    return result


def write_report():
    summary = _load_json(SUMMARY_PATH, {})
    state = _load_json(SAVE_PATH, {})
    report = {
        "generated": _now(),
        "local_paths": "redacted",
        "private_values": "redacted",
        "listener_summary": _redact(summary),
        "http": summarize_http(),
        "events": summarize_event_files(),
        "save_summary": _save_summary(state),
        "npstorage": _redact(_load_json(NPSTORAGE_ANALYSIS_PATH, {})),
    }

    TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)
    json_path = TELEMETRY_DIR / "debug_report_latest.json"
    md_path = TELEMETRY_DIR / "debug_report_latest.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# ACI Mock Debug Report",
        "",
        f"Generated: {report['generated']}",
        "",
        "Private identifiers are redacted in this report.",
        "",
        "## HTTP",
        "",
        f"Total records: {report['http']['records_total']}",
        "",
        "Events:",
    ]
    for key, value in report["http"]["events"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "Paths:"])
    for key, value in report["http"]["paths"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Save Summary", ""])
    for key, value in report["save_summary"].items():
        lines.append(f"- {key}: {value}")
    if report["npstorage"]:
        fmt = report["npstorage"].get("format_guess", {})
        xml = report["npstorage"].get("xml", {})
        lines.extend(
            [
                "",
                "## NP Storage Sample",
                "",
                f"- container: {fmt.get('container')}",
                f"- declared_data_size: {fmt.get('declared_data_size')}",
                f"- tail_payload_bytes: {fmt.get('tail_payload_bytes')}",
                f"- npcommid: {xml.get('npcommid', {}).get('value') if isinstance(xml, dict) else None}",
            ]
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path, report


def main():
    parser = argparse.ArgumentParser(description="Create a redacted debug report from local mock telemetry.")
    parser.parse_args()
    json_path, md_path, report = write_report()
    print(json.dumps({"json": str(json_path), "markdown": str(md_path), "save_summary": report["save_summary"]}, indent=2))


if __name__ == "__main__":
    main()
