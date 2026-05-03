"""
Ace Combat Infinity local mock server with exhaustive local telemetry.

Listens on:
  - 0.0.0.0:80   (HTTP)
  - 0.0.0.0:443  (HTTPS, self-signed cert auto-generated on first run)

Everything this process can observe is written locally:
  - requests.log                         human-readable stream
  - telemetry/http_events.jsonl          structured per-request records
  - telemetry/raw/<date>/<request>/      raw request/response bytes + metadata
  - telemetry/events/<event>.jsonl       one stream per Wind telemetry event
  - telemetry/rpcs3_hle_events.jsonl     parsed RPCS3 HLE save/TSS calls
  - saves/                               save snapshots and binary upload bodies

Important save finding:
  Current RPCS3 logs show the game saving through sceNpTusSetDataAsync
  (slotId=3, totalSize=93672), not through /Wind/load/test. The HTTP mock
  still replays captured /Wind/save/accum_data to every known Wind load route,
  but the RPCS3 TUS path is only visible in the emulator log unless RPCS3 or
  the game is patched to route TUS payload bytes through this server.
"""

import argparse
import base64
import collections
import datetime as _dt
import gzip
import hashlib
import http.client
import http.server
import json
import math
import mimetypes
import os
import platform
import re
import socket
import ssl
import sys
import threading
import time
import traceback
import uuid
import warnings
import zlib
import xml.etree.ElementTree as ET
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qsl, unquote, urlsplit


HERE = Path(__file__).resolve().parent
CERT_PATH = HERE / "cert.pem"
KEY_PATH = HERE / "key.pem"
LOG_PATH = HERE / "requests.log"
SAVE_PATH = HERE / "save_state.json"
SAVE_ENVELOPE_PATH = HERE / "save_state_envelope.json"
TSS_DIR = HERE / "tss"
SAVES_DIR = HERE / "saves"
TELEMETRY_DIR = HERE / "telemetry"
RAW_DIR = TELEMETRY_DIR / "raw"
EVENTS_DIR = TELEMETRY_DIR / "events"
HTTP_JSONL_PATH = TELEMETRY_DIR / "http_events.jsonl"
SOCKET_JSONL_PATH = TELEMETRY_DIR / "socket_events.jsonl"
RPCS3_JSONL_PATH = TELEMETRY_DIR / "rpcs3_hle_events.jsonl"
TSS_JSONL_PATH = TELEMETRY_DIR / "tss_events.jsonl"
TSS_ANALYSIS_DIR = TELEMETRY_DIR / "tss_analysis"
NPSTORAGE_JSONL_PATH = TELEMETRY_DIR / "npstorage_samples.jsonl"
SUMMARY_PATH = TELEMETRY_DIR / "summary.json"
RPCS3_LOG_DEFAULT = (
    HERE.parent.parent
    / "rpcs3-v0.0.40-19253-7028e85f_win64_msvc"
    / "log"
    / "RPCS3.log"
)
RPCS3_ROOT_DEFAULT = RPCS3_LOG_DEFAULT.parents[1]
RPCS3_USER_SAVEDATA_DIR = (
    RPCS3_ROOT_DEFAULT
    / "dev_hdd0"
    / "home"
    / "00000001"
    / "savedata"
)
RPCS3_PLAYDATA_DIR = RPCS3_USER_SAVEDATA_DIR / "BLUS30613-PLAYDATA"

SERVER_RUN_ID = f"{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
BODY_TEXT_LIMIT = int(os.environ.get("ACI_BODY_TEXT_LIMIT", "200000"))


_log_lock = threading.Lock()
_jsonl_lock = threading.Lock()
_seq_lock = threading.Lock()
_stats_lock = threading.Lock()
_save_lock = threading.Lock()
_request_seq = 0
_save_state = {}
_stats = {
    "server_run_id": SERVER_RUN_ID,
    "started_local": None,
    "started_utc": None,
    "requests": 0,
    "by_path": {},
    "by_route": {},
    "by_method": {},
    "by_host": {},
    "by_status": {},
    "events": {},
    "body_bytes_in": 0,
    "body_bytes_out": 0,
    "raw_capture_dirs": 0,
    "tss_requests": 0,
    "last_request": None,
    "last_save": None,
    "last_tss": None,
    "last_save_rebuild": None,
    "last_rpcs3_scan": None,
}


def _ensure_dirs():
    for path in (TELEMETRY_DIR, RAW_DIR, EVENTS_DIR, SAVES_DIR, TSS_DIR, TSS_ANALYSIS_DIR):
        path.mkdir(parents=True, exist_ok=True)


def _now():
    local = _dt.datetime.now().astimezone()
    utc = _dt.datetime.now(_dt.timezone.utc)
    return {
        "local": local.isoformat(timespec="milliseconds"),
        "utc": utc.isoformat(timespec="milliseconds"),
        "epoch": time.time(),
        "monotonic": time.monotonic(),
    }


def _json_default(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return repr(value)


def _atomic_json_write(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, default=_json_default)
        f.write("\n")
    os.replace(tmp, path)


def _write_jsonl(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(obj, ensure_ascii=False, sort_keys=True, default=_json_default)
    with _jsonl_lock:
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def log(msg):
    line = f"[{_dt.datetime.now().isoformat(timespec='milliseconds')}] {msg}"
    console_encoding = sys.stdout.encoding or "utf-8"
    console_line = line.encode(console_encoding, errors="backslashreplace").decode(
        console_encoding, errors="replace"
    )
    with _log_lock:
        print(console_line, flush=True)
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def telemetry(kind, **fields):
    obj = {"kind": kind, "server_run_id": SERVER_RUN_ID, **_now(), **fields}
    path = SOCKET_JSONL_PATH if kind.startswith(("tcp.", "tls.", "server.")) else HTTP_JSONL_PATH
    _write_jsonl(path, obj)
    return obj


def _next_request_id():
    global _request_seq
    with _seq_lock:
        _request_seq += 1
        return _request_seq


def _inc_stat(bucket, key, amount=1):
    key = str(key)
    with _stats_lock:
        _stats[bucket][key] = _stats[bucket].get(key, 0) + amount


def _write_summary():
    with _stats_lock:
        snapshot = json.loads(json.dumps(_stats, default=_json_default))
    snapshot["updated"] = _now()
    _atomic_json_write(SUMMARY_PATH, snapshot)


def _safe_name(text, fallback="item", limit=120):
    text = (text or fallback).strip().replace("\\", "/")
    text = text.replace(":", "_").replace("/", "_").replace("?", "_")
    text = re.sub(r"[^A-Za-z0-9._=-]+", "_", text).strip("._")
    if not text:
        text = fallback
    return text[:limit]


def _hash_bytes(data):
    data = data or b""
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "first16_hex": data[:16].hex(),
        "last16_hex": data[-16:].hex() if data else "",
    }


def _byte_entropy(data):
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _printable_ascii(data):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def _extract_ascii_spans(data, min_len=4, limit=250):
    spans = []
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data or b""):
        text = match.group(0).decode("ascii", errors="replace")
        spans.append({"offset": match.start(), "length": len(text), "text": text[:240]})
        if len(spans) >= limit:
            break
    return spans


def _u32_preview(data, endian, limit=16):
    out = []
    usable = min(len(data or b""), limit * 4)
    for i in range(0, usable - (usable % 4), 4):
        out.append(int.from_bytes(data[i : i + 4], endian))
    return out


def _compression_probe(data):
    probes = {}
    if not data:
        return probes
    if data.startswith(b"\x1f\x8b"):
        try:
            decoded = gzip.decompress(data)
            probes["gzip"] = {"ok": True, **_hash_bytes(decoded)}
        except Exception as exc:
            probes["gzip"] = {"ok": False, "error": repr(exc)}
    for label, wbits in (("zlib", zlib.MAX_WBITS), ("raw_deflate", -zlib.MAX_WBITS)):
        try:
            decoded = zlib.decompress(data, wbits=wbits)
            probes[label] = {"ok": True, **_hash_bytes(decoded)}
        except Exception as exc:
            probes[label] = {"ok": False, "error": type(exc).__name__}
    return probes


def _block_repetition(data, block_size):
    if not data or len(data) < block_size:
        return {"block_size": block_size, "blocks": 0, "unique": 0, "top_repeated": []}
    block_count = len(data) // block_size
    counter = collections.Counter(
        hashlib.sha1(data[i * block_size : (i + 1) * block_size]).hexdigest()
        for i in range(block_count)
    )
    return {
        "block_size": block_size,
        "blocks": block_count,
        "unique": len(counter),
        "top_repeated": [
            {"sha1": digest, "count": count}
            for digest, count in counter.most_common(5)
            if count > 1
        ],
    }


def _tss_slot_from_name(filename):
    match = re.search(r"-(\d+)\.tss$", filename or "", re.I)
    return int(match.group(1)) if match else None


def _parse_dpl_structure(data, entry_limit=80):
    data = data or b""
    dpl_offset = data.find(b"DPL")
    if dpl_offset < 0 or dpl_offset + 20 > len(data):
        return None

    def u16(offset):
        return int.from_bytes(data[offset : offset + 2], "big")

    def u32(offset):
        return int.from_bytes(data[offset : offset + 4], "big")

    def u64(offset):
        return int.from_bytes(data[offset : offset + 8], "big")

    base = dpl_offset
    header = {
        "offset": dpl_offset,
        "sign": data[base : base + 4].decode("latin-1", errors="replace"),
        "byte_order_marker": u32(base + 4),
        "timestamp": u32(base + 8),
        "entry_count": u32(base + 12),
        "info_table_size": u32(base + 16),
    }
    if header["byte_order_marker"] != 20101010:
        header["warning"] = "unexpected byte-order marker"
    archived = header["timestamp"] != 2011082201
    cursor = base + 20
    entries = []
    errors = []
    for index in range(header["entry_count"]):
        if cursor + 72 > len(data):
            errors.append(f"entry {index}: table ended early at 0x{cursor:x}")
            break
        fhm = {
            "sign": data[cursor : cursor + 4].decode("latin-1", errors="replace"),
            "byte_order_marker": u32(cursor + 4),
            "timestamp": u32(cursor + 8),
            "unknown_struct_count": u32(cursor + 12),
            "unknown": u32(cursor + 16),
            "size": u32(cursor + 20),
            "unknown3": u32(cursor + 24),
            "unknown4": u32(cursor + 28),
            "unknown5": u32(cursor + 32),
            "unknown_16": u32(cursor + 36),
            "unknown_pot": u32(cursor + 40),
            "unknown_pot2": u32(cursor + 44),
        }
        cursor += 48
        entry = {
            "index": index,
            "offset": u64(cursor),
            "packed_size": u32(cursor + 8),
            "idx": u32(cursor + 12),
            "unknown": u32(cursor + 16),
            "key": u16(cursor + 20),
            "unpacked_size_estimate": fhm["size"] + 48 if archived else u32(cursor + 8),
            "fhm": fhm,
        }
        cursor += 24
        cursor += fhm["unknown_struct_count"] * 12
        if len(entries) < entry_limit:
            entries.append(entry)
    return {
        "header": header,
        "archived": archived,
        "table_end_offset": cursor - base,
        "entries_reported": len(entries),
        "entries": entries,
        "entry_errors": errors,
        "packed_size_total": sum(entry["packed_size"] for entry in entries),
        "unpacked_size_estimate_total_reported": sum(entry["unpacked_size_estimate"] for entry in entries),
    }


def _analyze_tss_bytes(filename, data, include_strings=True):
    data = data or b""
    first_lines = []
    for raw in data[:4096].splitlines()[:16]:
        first_lines.append(raw[:240].decode("latin-1", errors="replace"))

    markers = []
    for marker in (b"GST", b"DPL", b"FHM", b"NTP3", b"RIFF", b"CRILAYLA"):
        pos = data.find(marker)
        if pos >= 0:
            markers.append({"marker": marker.decode("ascii", errors="replace"), "offset": pos})

    analysis = {
        "filename": filename,
        "slot": _tss_slot_from_name(filename),
        "hash": _hash_bytes(data),
        "entropy": round(_byte_entropy(data), 5),
        "first64_hex": data[:64].hex(),
        "first64_ascii": _printable_ascii(data[:64]),
        "last64_hex": data[-64:].hex() if data else "",
        "last64_ascii": _printable_ascii(data[-64:]) if data else "",
        "line_preview": first_lines,
        "markers": markers,
        "u32_be_first": _u32_preview(data, "big"),
        "u32_le_first": _u32_preview(data, "little"),
        "whole_file_compression": _compression_probe(data),
        "dpl": _parse_dpl_structure(data),
        "block_repetition": [
            _block_repetition(data, size)
            for size in (16, 32, 64, 128, 2048)
        ],
    }
    if data.startswith(b"GST"):
        analysis["format_guess"] = {
            "container": "GST/DPL-like TSS payload",
            "basis": "file begins with GST and contains DPL near the header",
            "dpl_offset": data.find(b"DPL"),
        }
    elif markers:
        analysis["format_guess"] = {
            "container": "unknown binary with recognizable embedded markers",
            "basis": markers[:8],
        }
    else:
        analysis["format_guess"] = {"container": "opaque binary", "basis": "no known whole-file magic"}
    if include_strings:
        analysis["ascii_strings"] = _extract_ascii_spans(data)
    return analysis


def analyze_tss_cache(write=True):
    files = []
    groups = collections.defaultdict(list)
    size_groups = collections.defaultdict(list)
    for path in sorted(TSS_DIR.glob("*.tss")):
        data = path.read_bytes()
        analysis = _analyze_tss_bytes(path.name, data, include_strings=True)
        summary = {
            "name": path.name,
            "slot": analysis["slot"],
            "bytes": analysis["hash"]["bytes"],
            "sha256": analysis["hash"]["sha256"],
            "entropy": analysis["entropy"],
            "first16_hex": analysis["hash"]["first16_hex"],
            "format_guess": analysis["format_guess"],
            "markers": analysis["markers"],
            "dpl": {
                "offset": analysis["dpl"]["header"]["offset"],
                "entries": analysis["dpl"]["header"]["entry_count"],
                "archived": analysis["dpl"]["archived"],
                "table_end_offset": analysis["dpl"]["table_end_offset"],
            }
            if analysis.get("dpl")
            else None,
        }
        files.append(summary)
        groups[analysis["hash"]["sha256"]].append(path.name)
        size_groups[str(analysis["hash"]["bytes"])].append(path.name)
        if write:
            _atomic_json_write(TSS_ANALYSIS_DIR / f"{path.stem}.analysis.json", analysis)

    inventory = {
        "generated": _now(),
        "directory": str(TSS_DIR),
        "files": files,
        "duplicate_sha256_groups": [
            {"sha256": sha, "files": names, "count": len(names)}
            for sha, names in sorted(groups.items())
            if len(names) > 1
        ],
        "size_groups": [
            {"bytes": int(size), "files": names, "count": len(names)}
            for size, names in sorted(size_groups.items(), key=lambda item: int(item[0]))
        ],
    }
    if write:
        _atomic_json_write(TELEMETRY_DIR / "tss_inventory_latest.json", inventory)
    return inventory


def _secret_summary(text):
    if text is None:
        return {"present": False, "length": 0}
    raw = str(text).encode("utf-8", errors="replace")
    return {
        "present": True,
        "length": len(str(text)),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _redact_jid(text):
    if not text:
        return None
    value = str(text).strip()
    if "@" not in value:
        return "<redacted>"
    _, domain = value.split("@", 1)
    return f"<redacted>@{domain}"


def _parse_npstorage_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "redacted_preview": re.sub(
                r"(<(?:ticket|sign|psid)[^>]*>).*?(</(?:ticket|sign|psid)>)",
                r"\1<redacted>\2",
                xml_text[:2000],
                flags=re.IGNORECASE | re.DOTALL,
            ),
        }

    def child_text(name):
        node = root.find(name)
        return node.text.strip() if node is not None and node.text else None

    data_nodes = []
    for node in root.findall("data"):
        size_text = None
        size_node = node.find("size")
        if size_node is not None and size_node.text:
            size_text = size_node.text.strip()
        try:
            declared_size = int(size_text) if size_text is not None else None
        except ValueError:
            declared_size = size_text
        info_node = node.find("info")
        info_text = info_node.text if info_node is not None and info_node.text else ""
        data_nodes.append(
            {
                "slot": node.attrib.get("slot"),
                "declared_size": declared_size,
                "info_present": bool(info_text),
                "info_length": len(info_text),
            }
        )

    user = root.find("user")
    npcommid = root.find("npcommid")
    sign = root.find("sign")
    return {
        "ok": True,
        "root": root.tag,
        "platform": root.attrib.get("platform"),
        "system_version": root.attrib.get("sv"),
        "ticket": _secret_summary(child_text("ticket")),
        "ticketjid": _redact_jid(child_text("ticketjid")),
        "psid": _secret_summary(child_text("psid")),
        "npcommid": {
            "value": npcommid.text.strip() if npcommid is not None and npcommid.text else None,
            "version": npcommid.attrib.get("version") if npcommid is not None else None,
        },
        "sign": {
            **_secret_summary(sign.text.strip() if sign is not None and sign.text else None),
            "pf": sign.attrib.get("pf") if sign is not None else None,
        },
        "user": {
            "mode": user.attrib.get("mode") if user is not None else None,
            "jid": _redact_jid(user.findtext("jid") if user is not None else None),
        },
        "data": data_nodes,
    }


def analyze_npstorage_blob(label, data):
    data = data or b""
    close_tag = b"</npstorage>"
    close_pos = data.find(close_tag)
    xml_end = close_pos + len(close_tag) if close_pos >= 0 else None
    xml_bytes = data[:xml_end] if xml_end is not None else b""
    tail = data[xml_end:] if xml_end is not None else data
    tail_stripped = tail.lstrip(b" \r\n\t")
    xml_text = xml_bytes.decode("utf-8", errors="replace") if xml_bytes else ""
    xml = _parse_npstorage_xml(xml_text) if xml_text else {"ok": False, "error": "npstorage XML not found"}
    declared_sizes = [
        node.get("declared_size")
        for node in xml.get("data", [])
        if isinstance(node.get("declared_size"), int)
    ]
    first_declared = declared_sizes[0] if declared_sizes else None
    tail_payload_bytes = len(tail_stripped)
    notes = []
    if xml_end is None:
        notes.append("No closing npstorage XML tag was found.")
    if first_declared is not None and tail_payload_bytes != first_declared:
        notes.append(
            "Binary tail length does not match the first declared data size; this is likely a partial capture or envelope fragment."
        )
    if tail_stripped.startswith(b"SAVE"):
        notes.append("Binary tail begins with SAVE magic.")

    analysis = {
        "generated": _now(),
        "source": {
            "label": str(label),
            "label_sha256": hashlib.sha256(str(label).encode("utf-8", errors="replace")).hexdigest(),
        },
        "hash": _hash_bytes(data),
        "entropy": round(_byte_entropy(data), 5),
        "first64_hex": data[:64].hex(),
        "first64_ascii": _printable_ascii(data[:64]),
        "last64_hex": data[-64:].hex() if data else "",
        "last64_ascii": _printable_ascii(data[-64:]) if data else "",
        "xml": xml,
        "xml_bytes": len(xml_bytes),
        "binary_tail_offset": xml_end,
        "binary_tail_bytes": len(tail),
        "binary_tail_payload_bytes": tail_payload_bytes,
        "binary_tail_hash": _hash_bytes(tail_stripped),
        "binary_tail_first32_hex": tail_stripped[:32].hex(),
        "binary_tail_first32_ascii": _printable_ascii(tail_stripped[:32]),
        "binary_tail_compression": _compression_probe(tail_stripped),
        "binary_tail_ascii_strings": _extract_ascii_spans(tail_stripped, min_len=4, limit=50),
        "format_guess": {
            "container": "npstorage XML envelope with binary tail"
            if xml.get("root") == "npstorage" and tail_stripped
            else "unknown or partial npstorage capture",
            "declared_data_size": first_declared,
            "tail_payload_bytes": tail_payload_bytes,
        },
        "notes": notes,
    }
    return analysis


def analyze_npstorage_file(path, write=True):
    source = Path(path)
    data = source.read_bytes()
    analysis = analyze_npstorage_blob("<local-npstorage-sample>", data)
    analysis["source"]["suffix"] = source.suffix
    analysis["source"]["path_sha256"] = hashlib.sha256(str(source).encode("utf-8", errors="replace")).hexdigest()
    if write:
        _write_jsonl(NPSTORAGE_JSONL_PATH, analysis)
        _atomic_json_write(TELEMETRY_DIR / "npstorage_analysis_latest.json", analysis)
    return analysis


def _load_json_file(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def _tail_jsonl(path, limit=100):
    path = Path(path)
    if not path.exists():
        return []
    rows = collections.deque(maxlen=limit)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(rows)


def _decode_text(data):
    if not data:
        return None
    for enc in ("utf-8", "utf-8-sig", "shift_jis", "latin-1"):
        try:
            return enc, data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def _schema(value, depth=0, max_depth=6):
    if depth > max_depth:
        return "..."
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        item_schema = _schema(value[0], depth + 1, max_depth) if value else "empty"
        return {"list": item_schema, "len": len(value)}
    if isinstance(value, dict):
        return {
            str(k): _schema(v, depth + 1, max_depth)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))[:200]
        }
    return type(value).__name__


def _json_paths(value, prefix="$", out=None, depth=0, max_depth=8):
    if out is None:
        out = []
    if depth > max_depth:
        out.append({"path": prefix, "type": "..."})
        return out
    if isinstance(value, dict):
        out.append({"path": prefix, "type": "object", "keys": len(value)})
        for key, child in sorted(value.items(), key=lambda item: str(item[0]))[:500]:
            _json_paths(child, f"{prefix}.{key}", out, depth + 1, max_depth)
    elif isinstance(value, list):
        out.append({"path": prefix, "type": "array", "len": len(value)})
        if value:
            _json_paths(value[0], f"{prefix}[0]", out, depth + 1, max_depth)
    else:
        out.append({"path": prefix, "type": type(value).__name__})
    return out


def _parse_oauth_header(header):
    if not header or not header.startswith("OAuth "):
        return None
    result = {"scheme": "OAuth", "raw": header}
    for key, value in re.findall(r'([A-Za-z0-9_]+)="([^"]*)"', header):
        result[key] = unquote(value)
    if "oauth_signature" in result:
        sig = result["oauth_signature"].encode("utf-8", errors="replace")
        result["oauth_signature_sha256"] = hashlib.sha256(sig).hexdigest()
        result["oauth_signature_length"] = len(result["oauth_signature"])
    return result


def _body_observations(headers, body):
    headers_l = {str(k).lower(): str(v) for k, v in headers.items()}
    info = {
        **_hash_bytes(body),
        "entropy": round(_byte_entropy(body), 5),
        "content_type": headers_l.get("content-type", ""),
        "content_encoding": headers_l.get("content-encoding", ""),
        "transfer_encoding": headers_l.get("transfer-encoding", ""),
    }

    decoded_bytes = body
    content_encoding = info["content_encoding"].lower()
    if body and content_encoding == "gzip":
        try:
            decoded_bytes = gzip.decompress(body)
            info["gzip_decoded"] = _hash_bytes(decoded_bytes)
        except Exception as exc:
            info["gzip_error"] = repr(exc)
    elif body and content_encoding == "deflate":
        try:
            decoded_bytes = zlib.decompress(body)
            info["deflate_decoded"] = _hash_bytes(decoded_bytes)
        except Exception as exc:
            info["deflate_error"] = repr(exc)

    decoded = _decode_text(decoded_bytes)
    if decoded:
        enc, text = decoded
        info["text_encoding"] = enc
        info["text_bytes"] = len(decoded_bytes)
        info["text_preview"] = text[:BODY_TEXT_LIMIT]
        info["text_truncated"] = len(text) > BODY_TEXT_LIMIT
        printable = sum(1 for ch in text[:4096] if ch.isprintable() or ch in "\r\n\t")
        info["printable_ratio"] = round(printable / max(1, min(len(text), 4096)), 5)
        try:
            parsed = json.loads(text)
            info["json"] = {
                "type": type(parsed).__name__,
                "schema": _schema(parsed),
                "paths": _json_paths(parsed),
            }
            if isinstance(parsed, dict):
                info["json"]["top_keys"] = sorted(str(k) for k in parsed.keys())
                info["json"]["wind_event_keys"] = sorted(
                    k for k in parsed.keys() if str(k).startswith("ev_") or k == "accum_data"
                )
            info["parsed_json"] = parsed
        except json.JSONDecodeError:
            if "=" in text and "&" in text:
                pairs = parse_qsl(text, keep_blank_values=True)
                info["form"] = {
                    "pairs": pairs,
                    "dict": {k: v for k, v in pairs},
                    "keys": sorted({k for k, _v in pairs}),
                }
            if "multipart/form-data" in info["content_type"].lower():
                boundary_match = re.search(r"boundary=([^;]+)", info["content_type"], re.I)
                boundary = boundary_match.group(1).strip("\"") if boundary_match else None
                info["multipart"] = {"boundary": boundary}
                if boundary:
                    marker = ("--" + boundary).encode("utf-8", errors="replace")
                    info["multipart"]["part_count_estimate"] = max(0, decoded_bytes.count(marker) - 1)
    else:
        info["base64_preview"] = base64.b64encode(decoded_bytes[:4096]).decode("ascii")
        info["base64_truncated"] = len(decoded_bytes) > 4096
    return info


def _extract_wind_event(parsed):
    if not isinstance(parsed, dict):
        return None
    if "accum_data" in parsed:
        return "accum_data"
    for key in sorted(parsed.keys()):
        if str(key).startswith("ev_"):
            return str(key)
    return None


def _request_common(req, body, request_id):
    split = urlsplit(req.path)
    headers = {k: v for k, v in req.headers.items()}
    local = req.connection.getsockname() if hasattr(req.connection, "getsockname") else None
    peer = req.connection.getpeername() if hasattr(req.connection, "getpeername") else None
    tls = None
    if isinstance(req.connection, ssl.SSLSocket):
        tls = {
            "cipher": req.connection.cipher(),
            "version": req.connection.version(),
            "selected_alpn": req.connection.selected_alpn_protocol(),
            "server_hostname": getattr(req.connection, "_aci_sni", None),
            "compression": req.connection.compression(),
        }
    body_info = _body_observations(headers, body)
    parsed = body_info.pop("parsed_json", None)
    query_pairs = parse_qsl(split.query, keep_blank_values=True)
    return {
        "request_id": request_id,
        "method": req.command,
        "requestline": req.requestline,
        "request_version": req.request_version,
        "protocol_version": req.protocol_version,
        "path": req.path,
        "path_only": split.path,
        "query": split.query,
        "query_pairs": query_pairs,
        "query_dict": {k: v for k, v in query_pairs},
        "client": {"ip": req.client_address[0], "port": req.client_address[1]},
        "peer_sockname": peer,
        "local_sockname": local,
        "scheme": "https" if isinstance(req.connection, ssl.SSLSocket) else "http",
        "host": headers.get("Host", ""),
        "headers": headers,
        "headers_order": list(headers.keys()),
        "oauth": _parse_oauth_header(headers.get("Authorization", "")),
        "tls": tls,
        "chunked_read": getattr(req, "_chunked_read", None),
        "chunked_read_error": getattr(req, "_chunked_read_error", None),
        "body": body_info,
        "parsed_json": parsed,
        "thread": {
            "id": threading.get_ident(),
            "name": threading.current_thread().name,
        },
    }


def _capture_files(meta, request_body, response_headers, response_body):
    date_dir = _dt.datetime.now().strftime("%Y%m%d")
    req_name = f"{meta['request_id']:06d}_{meta['method']}_{_safe_name(meta['path_only'], 'root')}"
    out_dir = RAW_DIR / date_dir / req_name
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "request_body.bin").write_bytes(request_body or b"")
    (out_dir / "response_body.bin").write_bytes(response_body or b"")
    _atomic_json_write(out_dir / "request_meta.json", meta)
    _atomic_json_write(out_dir / "response_meta.json", response_headers)

    with _stats_lock:
        _stats["raw_capture_dirs"] += 1
    return out_dir


def _record_event_payload(event_name, meta):
    if not event_name or meta.get("parsed_json") is None:
        return
    event_record = {
        "event_name": event_name,
        "request_id": meta["request_id"],
        "server_run_id": SERVER_RUN_ID,
        "local": _now()["local"],
        "host": meta.get("host"),
        "path": meta.get("path"),
        "uid": meta["parsed_json"].get("uid") if isinstance(meta["parsed_json"], dict) else None,
        "log_no": meta["parsed_json"].get("log_no") if isinstance(meta["parsed_json"], dict) else None,
        "payload": meta["parsed_json"],
    }
    _write_jsonl(EVENTS_DIR / f"{_safe_name(event_name)}.jsonl", event_record)
    _inc_stat("events", event_name)


def _persist_save_to_disk(state):
    _atomic_json_write(SAVE_PATH, state)
    envelope = {
        "server_run_id": SERVER_RUN_ID,
        "updated": _now(),
        "state_hash": _hash_bytes(json.dumps(state, sort_keys=True, ensure_ascii=False).encode("utf-8")),
        "state": state,
    }
    _atomic_json_write(SAVE_ENVELOPE_PATH, envelope)


def _load_save_from_disk():
    global _save_state
    if SAVE_PATH.exists():
        try:
            with SAVE_PATH.open("r", encoding="utf-8") as f:
                _save_state = json.load(f)
            log(f"[save] loaded persisted state from {SAVE_PATH} ({len(_save_state)} top-level keys)")
        except Exception as exc:
            log(f"[save] WARNING: could not load {SAVE_PATH}: {exc}")


def _save_history_name(kind, request_id):
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return SAVES_DIR / f"{stamp}_{kind}_req{request_id}.json"


def _record_save(kind, state, meta):
    global _save_state
    with _save_lock:
        previous = json.loads(json.dumps(_save_state, default=_json_default))
        merged_state = _merge_save_states(previous, state)
        _save_state = merged_state
        _persist_save_to_disk(merged_state)
        summary = {
            "kind": kind,
            "request_id": meta["request_id"],
            "updated": _now(),
            "source_path": meta["path"],
            "merge_policy": "union keyed lists, keep richer numeric progress, preserve non-empty captured fields",
            "previous_summary": _summarize_save(previous),
            "incoming_summary": _summarize_save(state),
            "state_summary": _summarize_save(merged_state),
            "previous_score": _state_score(previous),
            "incoming_score": _state_score(state),
            "merged_score": _state_score(merged_state),
            "incoming_state": state,
            "state": merged_state,
        }
        _atomic_json_write(_save_history_name(kind, meta["request_id"]), summary)
        with _stats_lock:
            _stats["last_save"] = summary["state_summary"]
    log(
        "[save] captured %s; merged credit=%s aircraft=%d missions=%d keys=%d"
        % (
            kind,
            merged_state.get("credit") if isinstance(merged_state, dict) else None,
            len(merged_state.get("aircraft", [])) if isinstance(merged_state, dict) else 0,
            len(merged_state.get("mission", [])) if isinstance(merged_state, dict) else 0,
            len(merged_state) if isinstance(merged_state, dict) else 0,
        )
    )


def _summarize_save(state):
    if not isinstance(state, dict):
        return {"type": type(state).__name__}
    return {
        "player_rank": state.get("player_rank"),
        "credit": state.get("credit"),
        "aircraft_count": len(state.get("aircraft", [])),
        "mission_count": len(state.get("mission", [])),
        "mission_ids": [
            m.get("mission_id")
            for m in state.get("mission", [])
            if isinstance(m, dict) and "mission_id" in m
        ][:100],
        "keys": sorted(str(k) for k in state.keys()),
    }


_LIST_ID_KEYS = {
    "mission": ("mission_id", "id", "name"),
    "aircraft": ("aircraft_id", "id"),
    "arms": ("arms_id", "id"),
    "parts": ("parts_id", "id"),
    "development": ("id", "aircraft_id", "arms_id", "parts_id"),
    "challenges": ("challenge_id", "id"),
    "messages": ("message_id", "id"),
    "presents": ("message_id", "item_id", "id"),
    "drop_items": ("item_id", "id"),
}
_RANK_ORDER = {"": -1, "E": 0, "D": 1, "C": 2, "B": 3, "A": 4, "S": 5, "SS": 6, "SSS": 7}


def _is_empty_for_merge(value):
    return value is None or value == "" or value == [] or value == {}


def _json_key(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=_json_default)


def _list_item_identity(list_key, item):
    if isinstance(item, dict):
        for key in _LIST_ID_KEYS.get(list_key, ("id",)):
            if key in item:
                return f"{key}:{item[key]}"
    return _json_key(item)


def _merge_lists(list_key, previous, incoming):
    previous = previous if isinstance(previous, list) else []
    incoming = incoming if isinstance(incoming, list) else []
    if not previous:
        return json.loads(json.dumps(incoming, default=_json_default))
    if not incoming:
        return json.loads(json.dumps(previous, default=_json_default))

    merged = []
    index = {}
    for item in previous:
        key = _list_item_identity(list_key, item)
        index[key] = len(merged)
        merged.append(json.loads(json.dumps(item, default=_json_default)))

    for item in incoming:
        key = _list_item_identity(list_key, item)
        if key in index:
            merged[index[key]] = _merge_values(merged[index[key]], item, list_key)
        else:
            index[key] = len(merged)
            merged.append(json.loads(json.dumps(item, default=_json_default)))
    return merged


def _merge_values(previous, incoming, key_hint=""):
    if _is_empty_for_merge(previous):
        return json.loads(json.dumps(incoming, default=_json_default))
    if _is_empty_for_merge(incoming):
        return json.loads(json.dumps(previous, default=_json_default))

    if isinstance(previous, dict) and isinstance(incoming, dict):
        merged = json.loads(json.dumps(previous, default=_json_default))
        for key, value in incoming.items():
            merged[key] = _merge_values(merged.get(key), value, str(key))
        return merged

    if isinstance(previous, list) and isinstance(incoming, list):
        return _merge_lists(key_hint, previous, incoming)

    if isinstance(previous, (int, float)) and isinstance(incoming, (int, float)):
        return incoming if incoming >= previous else previous

    if key_hint == "clear_rank":
        prev_score = _RANK_ORDER.get(str(previous).upper(), -1)
        incoming_score = _RANK_ORDER.get(str(incoming).upper(), -1)
        return incoming if incoming_score >= prev_score else previous

    return incoming


def _merge_save_states(previous, incoming):
    if not isinstance(previous, dict) or not previous:
        return json.loads(json.dumps(incoming, default=_json_default))
    if not isinstance(incoming, dict) or not incoming:
        return json.loads(json.dumps(previous, default=_json_default))
    return _merge_values(previous, incoming, "accum_data")


def _state_score(state):
    if not isinstance(state, dict):
        return 0
    score = len(state) * 10
    score += len(state.get("mission", [])) * 100
    score += len(state.get("aircraft", [])) * 100
    credit = state.get("credit")
    if isinstance(credit, dict):
        score += int(credit.get("gain", 0) or 0)
        score += int(credit.get("paid", 0) or 0)
    score += int(state.get("player_rank", 0) or 0) * 1000
    return score


def _save_snapshot():
    with _save_lock:
        state = json.loads(json.dumps(_save_state))
    if state:
        return state
    return {
        "player_rank": 1,
        "matching_rates": {
            "coop_war": 1500,
            "fleet_assault": 1500,
            "team_deathmatch": 1500,
            "ring_domination": 1500,
        },
        "penalty_rank": 0,
        "credit": {"gain": 80000, "paid": 0},
        "rreport": {"aircraft": 0, "arms": 0, "parts": 0},
        "fuel": {"free": 0, "paid": 0, "present": 0},
        "fuel_consumption": {"free": 0, "paid": 0, "present": 0},
        "sortie": {"free": 0, "paid_present": 0},
        "total_login_time": 0,
        "mileage": 0,
        "nb_kill": {"air": 0, "ground": 0},
        "development": {"aircraft": 1, "parts": 1},
        "lv_up": {"aircraft": 0, "arms": 0},
        "coop_war_record": {"nb_win": 0, "nb_lost": 0},
        "mission": [
            {
                "mission_id": 100,
                "nb_sortie": 0,
                "nb_accomplished": 0,
                "nb_failed": 0,
                "clear_rank": "E",
                "best_score": 0,
                "nb_death": 0,
            },
            {
                "mission_id": 101,
                "nb_sortie": 0,
                "nb_accomplished": 0,
                "nb_failed": 0,
                "clear_rank": "E",
                "best_score": 0,
                "nb_death": 0,
            },
            {
                "mission_id": 102,
                "nb_sortie": 0,
                "nb_accomplished": 0,
                "nb_failed": 0,
                "clear_rank": "E",
                "best_score": 0,
                "nb_death": 0,
            },
        ],
        "aircraft": [],
    }


def ensure_cert():
    if CERT_PATH.exists() and KEY_PATH.exists():
        return
    print("[setup] generating self-signed cert for dev-wind.siliconstudio.co.jp ...")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        sys.exit(
            "[setup] missing 'cryptography' package.\n"
            "        run: pip install cryptography\n"
            "        then re-run this script."
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "dev-wind.siliconstudio.co.jp"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACI Mock"),
        ]
    )
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("dev-wind.siliconstudio.co.jp"),
            x509.DNSName("a0.ww.np.dl.playstation.net"),
            x509.DNSName("localhost"),
        ]
    )
    now = _dt.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=365 * 10))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"[setup] wrote {CERT_PATH} / {KEY_PATH}")


def _looks_like_tls_client_hello(sock):
    try:
        first = sock.recv(1, socket.MSG_PEEK)
    except (BlockingIOError, InterruptedError):
        return True
    except OSError:
        return False
    return bool(first and first[0] == 0x16)


def _response_json(obj, status=200):
    return status, "application/json; charset=utf-8", json.dumps(obj, ensure_ascii=False).encode("utf-8")


def _stub_authorize(req, meta):
    return _response_json(
        {
            "result": 0,
            "status": "ok",
            "session": "00000000000000000000000000000000",
            "playerId": 1,
            "serverTime": int(time.time()),
            "server_run_id": SERVER_RUN_ID,
        }
    )


def _stub_player(req, meta):
    state = _save_snapshot()
    return _response_json(
        {
            "result": 0,
            "player": {
                "id": 1,
                "name": meta.get("parsed_json", {}).get("uid", "Pilot") if isinstance(meta.get("parsed_json"), dict) else "Pilot",
                "rank": state.get("player_rank", 1),
                "credits": state.get("credit", {}).get("gain", 80000),
            },
            "accum_data": state,
        }
    )


def _stub_accum_data(req, meta):
    parsed = meta.get("parsed_json")
    if isinstance(parsed, dict) and isinstance(parsed.get("accum_data"), dict):
        _record_save("accum_data", parsed["accum_data"], meta)
    else:
        log("[save] accum_data POST had no JSON accum_data object; raw body was still captured")
    return _response_json({"result": 0})


def _stub_upload_save(req, meta):
    raw = getattr(req, "_cached_body", b"")
    out = SAVES_DIR / f"{_dt.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_uploadSaveData_req{meta['request_id']}.bin"
    out.write_bytes(raw)
    record = {
        "kind": "uploadSaveData",
        "request_id": meta["request_id"],
        "path": str(out),
        "hash": _hash_bytes(raw),
        "parsed_json": meta.get("parsed_json"),
    }
    _atomic_json_write(out.with_suffix(".json"), record)
    log(f"[save] captured uploadSaveData raw body {len(raw)} bytes -> {out}")
    return _response_json({"result": 0, "stored": True, "bytes": len(raw)})


def _stub_load(req, meta):
    state = _save_snapshot()
    log(
        "[save] replaying save state to %s credit=%s aircraft=%d missions=%d"
        % (
            meta["path"],
            state.get("credit"),
            len(state.get("aircraft", [])),
            len(state.get("mission", [])),
        )
    )
    return _response_json(
        {
            "result": 0,
            "status": "ok",
            "serverTime": int(time.time()),
            "slot": 3,
            "save_slot": 3,
            "accum_data": state,
            "save_data": state,
            "save": state,
            "load": {"result": 0, "slot": 3, "accum_data": state},
            "data": {"accum_data": state, "slot": 3},
            "slots": [{"slot": 3, "accum_data": state, "summary": _summarize_save(state)}],
        }
    )


def _stub_recovery(req, meta):
    state = _save_snapshot()
    return _response_json(
        {
            "result": 0,
            "status": "ok",
            "recovery_id": 0,
            "recovery_mode": "AllDone",
            "phase": "Saved",
            "slot": 3,
            "actions": [],
            "data": {"accum_data": state, "slot": 3},
            "accum_data": state,
            "save_data": state,
            "save_summary": _summarize_save(state),
        }
    )


def _stub_save_event(req, meta):
    parsed = meta.get("parsed_json")
    event_name = _extract_wind_event(parsed)
    if event_name == "accum_data" and isinstance(parsed, dict) and isinstance(parsed.get("accum_data"), dict):
        _record_save("accum_data_generic", parsed["accum_data"], meta)
    if event_name:
        log(f"[event] {event_name} uid={parsed.get('uid') if isinstance(parsed, dict) else None} log_no={parsed.get('log_no') if isinstance(parsed, dict) else None}")
    return _response_json({"result": 0})


def _stub_test(req, meta):
    return _response_json(
        {
            "result": 0,
            "status": "ok",
            "server_run_id": SERVER_RUN_ID,
            "time": _now(),
            "save_summary": _summarize_save(_save_snapshot()),
        }
    )


def _record_tss_request(filename, meta, status, payload=None, error=None):
    payload = payload or b""
    event = {
        "event_name": "tss_request",
        "server_run_id": SERVER_RUN_ID,
        "observed": _now(),
        "request_id": meta.get("request_id"),
        "method": meta.get("method"),
        "host": meta.get("host"),
        "path": meta.get("path"),
        "path_only": meta.get("path_only"),
        "query": meta.get("query_dict"),
        "client": meta.get("client"),
        "filename": filename,
        "slot": _tss_slot_from_name(filename),
        "status": status,
        "error": error,
        "file": _analyze_tss_bytes(filename, payload, include_strings=False) if payload else None,
    }
    _write_jsonl(TSS_JSONL_PATH, event)
    with _stats_lock:
        _stats["tss_requests"] += 1
        _stats["last_tss"] = {
            "filename": filename,
            "slot": event["slot"],
            "status": status,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
            "time": event["observed"]["local"],
        }
    return event


def _serve_tss(req, meta):
    split = urlsplit(req.path)
    filename = Path(unquote(split.path)).name
    if not filename.endswith(".tss"):
        _record_tss_request(filename, meta, 404, error="not a tss path")
        return _response_json({"result": 1, "error": "not a tss path", "path": split.path}, status=404)

    file_path = TSS_DIR / filename
    if not file_path.exists():
        log(f"[tss] MISSING {filename}; local TSS dir={TSS_DIR}")
        _record_tss_request(filename, meta, 404, error="missing tss file")
        return _response_json(
            {
                "result": 1,
                "error": "missing tss file",
                "requested": filename,
                "available": sorted(p.name for p in TSS_DIR.glob("*.tss")),
            },
            status=404,
        )

    payload = file_path.read_bytes()
    event = _record_tss_request(filename, meta, 200, payload=payload)
    log(
        "[tss] serving %s slot=%s bytes=%d sha256=%s entropy=%.5f"
        % (
            filename,
            event["slot"],
            len(payload),
            hashlib.sha256(payload).hexdigest(),
            event["file"]["entropy"],
        )
    )
    return 200, "application/octet-stream", payload


def _debug_endpoint(req, meta):
    path = meta["path_only"].rstrip("/") or "/__debug"
    query = meta.get("query_dict") or {}
    if path in ("/__debug", "/__debug/summary"):
        payload = {
            "result": 0,
            "server_run_id": SERVER_RUN_ID,
            "now": _now(),
            "summary": _load_json_file(SUMMARY_PATH, {}),
            "save_summary": _summarize_save(_save_snapshot()),
            "rpcs3_latest": _load_json_file(TELEMETRY_DIR / "rpcs3_hle_scan_latest.json", {}),
            "tss_inventory": _load_json_file(TELEMETRY_DIR / "tss_inventory_latest.json", {}),
            "npstorage_latest": _load_json_file(TELEMETRY_DIR / "npstorage_analysis_latest.json", {}),
            "recent_tss": _tail_jsonl(TSS_JSONL_PATH, 25),
        }
        return _response_json(payload)
    if path == "/__debug/tss":
        refresh = str(query.get("refresh", "")).lower() in ("1", "true", "yes")
        inventory = _load_json_file(TELEMETRY_DIR / "tss_inventory_latest.json", {})
        if refresh or not inventory:
            inventory = analyze_tss_cache(write=True)
        return _response_json({"result": 0, "inventory": inventory, "recent": _tail_jsonl(TSS_JSONL_PATH, 100)})
    if path == "/__debug/rpcs3":
        return _response_json(
            {
                "result": 0,
                "latest_scan": _load_json_file(TELEMETRY_DIR / "rpcs3_hle_scan_latest.json", {}),
                "recent_events": _tail_jsonl(RPCS3_JSONL_PATH, 100),
            }
        )
    if path == "/__debug/npstorage":
        return _response_json(
            {
                "result": 0,
                "latest_analysis": _load_json_file(TELEMETRY_DIR / "npstorage_analysis_latest.json", {}),
                "recent_samples": _tail_jsonl(NPSTORAGE_JSONL_PATH, 25),
            }
        )
    if path == "/__debug/events":
        events = {}
        if EVENTS_DIR.exists():
            for event_path in sorted(EVENTS_DIR.glob("*.jsonl")):
                events[event_path.name] = _tail_jsonl(event_path, 25)
        return _response_json({"result": 0, "events": events})
    if path == "/__debug/save":
        state = _save_snapshot()
        return _response_json({"result": 0, "summary": _summarize_save(state), "state": state})
    if path == "/__debug/report":
        from aci_debug_report import write_report

        json_path, md_path, report = write_report()
        return _response_json(
            {
                "result": 0,
                "json": str(json_path),
                "markdown": str(md_path),
                "save_summary": report["save_summary"],
            }
        )
    return _response_json({"result": 1, "error": "unknown debug endpoint", "path": meta["path_only"]}, status=404)


def _stub_unknown_wind(req, meta):
    log(f"!!! UNRECOGNIZED /Wind/ ENDPOINT: {meta['path']} -- captured and returned generic ok")
    return _response_json({"result": 0, "unrecognized": True, "path": meta["path"]})


def _stub_unknown(req, meta):
    log(f"!!! NON-WIND REQUEST host={meta.get('host')} path={meta['path']} -- captured and returned empty body")
    return 200, "application/octet-stream", b""


def _route(req, meta):
    path = meta["path_only"]
    if path.startswith("/__debug"):
        return "__debug", _debug_endpoint
    if path.startswith("/tss/") or path.endswith(".tss"):
        return "tss", _serve_tss

    routes = [
        ("/Wind/authorize", _stub_authorize),
        ("/Wind/player", _stub_player),
        ("/Wind/uploadSaveData", _stub_upload_save),
        ("/Wind/recovery", _stub_recovery),
        ("/Wind/load/test", _stub_load),
        ("/Wind/load", _stub_load),
        ("/Wind/save/accum_data", _stub_accum_data),
        ("/Wind/save/test", _stub_save_event),
        ("/Wind/save/", _stub_save_event),
        ("/Wind/save", _stub_save_event),
        ("/Wind/test", _stub_test),
    ]
    for prefix, handler in sorted(routes, key=lambda item: len(item[0]), reverse=True):
        if path.startswith(prefix):
            return prefix, handler
    if path.startswith("/Wind/"):
        return "/Wind/*", _stub_unknown_wind
    return "(unknown)", _stub_unknown


class ACIHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ACIMock/2.0"

    def log_message(self, fmt, *args):
        return

    def _read_body(self):
        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in transfer_encoding:
            chunks = []
            total = 0
            while True:
                size_line = self.rfile.readline(65536)
                if not size_line:
                    break
                size_text = size_line.split(b";", 1)[0].strip()
                try:
                    size = int(size_text, 16)
                except ValueError:
                    self._chunked_read_error = f"invalid chunk size line: {size_line!r}"
                    break
                if size == 0:
                    while True:
                        trailer = self.rfile.readline(65536)
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    break
                data = self.rfile.read(size)
                chunks.append(data)
                total += len(data)
                self.rfile.read(2)
            self._chunked_read = {"chunks": len(chunks), "decoded_bytes": total}
            return b"".join(chunks)

        length_header = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(length_header)
        except ValueError:
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def send_error(self, code, message=None, explain=None):
        telemetry(
            "http.send_error",
            code=code,
            message=message,
            explain=explain,
            path=getattr(self, "path", None),
            client=getattr(self, "client_address", None),
        )
        super().send_error(code, message, explain)

    def _serve(self, method):
        request_id = _next_request_id()
        start = time.perf_counter()
        body = self._read_body()
        self._cached_body = body
        meta = _request_common(self, body, request_id)
        route_name = "(no route)"
        status = 500
        ctype = "application/json; charset=utf-8"
        payload = b""
        error = None

        log("=" * 80)
        log(f">>> #{request_id:06d} {method} {meta['scheme']}://{meta['host']}{self.path} client={self.client_address[0]}:{self.client_address[1]}")
        log(f"    requestline: {self.requestline}")
        for h, v in self.headers.items():
            log(f"    h: {h}: {v}")
        log(
            "    body: bytes=%d sha256=%s entropy=%.5f"
            % (meta["body"]["bytes"], meta["body"]["sha256"], meta["body"]["entropy"])
        )
        if meta["body"].get("text_preview"):
            log("    body[text]:\n" + meta["body"]["text_preview"])
        elif body:
            log("    body[hex]: " + body[:4096].hex() + (" ...[truncated]" if len(body) > 4096 else ""))
        else:
            log("    body: (empty)")

        try:
            event_name = _extract_wind_event(meta.get("parsed_json"))
            _record_event_payload(event_name, meta)
            route_name, handler = _route(self, meta)
            status, ctype, payload = handler(self, meta)
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
        except Exception as exc:
            error = {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            }
            log("[error] request handler failed:\n" + error["traceback"])
            status, ctype, payload = _response_json({"result": 1, "error": error}, status=500)

        if method == "HEAD":
            send_payload = b""
        else:
            send_payload = payload or b""

        response_headers = {
            "status": status,
            "content_type": ctype,
            "content_length": len(payload or b""),
            "connection": "close",
            "route": route_name,
            "duration_ms": round((time.perf_counter() - start) * 1000, 3),
            "payload_hash": _hash_bytes(payload or b""),
        }

        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload or b"")))
            self.send_header("Connection", "close")
            self.send_header("X-ACI-Request-Id", str(request_id))
            self.send_header("X-ACI-Server-Run", SERVER_RUN_ID)
            self.end_headers()
            if send_payload:
                self.wfile.write(send_payload)
        finally:
            capture_dir = _capture_files(meta, body, response_headers, payload or b"")
            event_record = {
                "request": {k: v for k, v in meta.items() if k != "parsed_json"},
                "parsed_json": meta.get("parsed_json"),
                "response": response_headers,
                "error": error,
                "capture_dir": str(capture_dir),
            }
            _write_jsonl(HTTP_JSONL_PATH, event_record)
            _inc_stat("by_path", meta["path_only"])
            _inc_stat("by_route", route_name)
            _inc_stat("by_method", method)
            _inc_stat("by_host", meta.get("host", ""))
            _inc_stat("by_status", status)
            with _stats_lock:
                _stats["requests"] += 1
                _stats["body_bytes_in"] += len(body)
                _stats["body_bytes_out"] += len(payload or b"")
                _stats["last_request"] = {
                    "id": request_id,
                    "path": meta["path"],
                    "route": route_name,
                    "status": status,
                    "time": _now()["local"],
                }
            _write_summary()

        payload_bytes = payload or b""
        if ctype.startswith("application/json") or ctype.startswith("text/"):
            preview = payload_bytes.decode("utf-8", errors="replace")[:2000]
            if len(payload_bytes) > 2000:
                preview += f"\n    ...[{len(payload_bytes)} bytes total]"
        else:
            digest = _hash_bytes(payload_bytes)
            preview = (
                f"[binary body bytes={digest['bytes']} sha256={digest['sha256']} "
                f"first16={digest['first16_hex']} last16={digest['last16_hex']}]"
            )
        log(f"<<< #{request_id:06d} {status} {ctype} matched={route_name} duration_ms={response_headers['duration_ms']}")
        log(f"    resp: {preview}")
        log(f"    raw_capture: {capture_dir}")

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")

    def do_PUT(self):
        self._serve("PUT")

    def do_DELETE(self):
        self._serve("DELETE")

    def do_HEAD(self):
        self._serve("HEAD")

    def do_PATCH(self):
        self._serve("PATCH")

    def do_OPTIONS(self):
        self._serve("OPTIONS")


class ThreadingHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        err = traceback.format_exc()
        log(f"[server] unhandled error for {client_address}:\n{err}")
        telemetry("server.handle_error", client=client_address, traceback=err)


class LoggingHTTPServer(ThreadingHTTPServer):
    def get_request(self):
        sock, addr = self.socket.accept()
        telemetry("tcp.accept", port=self.server_port, client={"ip": addr[0], "port": addr[1]})
        log(f"[tcp:{self.server_port}] accept from {addr[0]}:{addr[1]}")
        return sock, addr


class LoggingPort443Server(ThreadingHTTPServer):
    """Port 443 accepts TLS or plaintext HTTP."""

    def __init__(self, addr, handler, ctx):
        super().__init__(addr, handler)
        self._ctx = ctx

    def get_request(self):
        sock, addr = self.socket.accept()
        telemetry("tcp.accept", port=self.server_port, client={"ip": addr[0], "port": addr[1]})
        log(f"[tcp:{self.server_port}] accept from {addr[0]}:{addr[1]}")
        if not _looks_like_tls_client_hello(sock):
            telemetry("tls.plaintext_fallback", port=self.server_port, client={"ip": addr[0], "port": addr[1]})
            log(f"[http:{self.server_port}] plaintext HTTP from {addr[0]}:{addr[1]}")
            return sock, addr
        try:
            tls = self._ctx.wrap_socket(sock, server_side=True)
        except Exception as exc:
            telemetry(
                "tls.handshake_failed",
                port=self.server_port,
                client={"ip": addr[0], "port": addr[1]},
                error={"type": type(exc).__name__, "message": str(exc)},
            )
            log(f"[tls:{self.server_port}] handshake FAILED from {addr[0]}:{addr[1]}: {type(exc).__name__}: {exc}")
            try:
                sock.close()
            except Exception:
                pass
            raise
        telemetry(
            "tls.handshake_ok",
            port=self.server_port,
            client={"ip": addr[0], "port": addr[1]},
            cipher=tls.cipher(),
            version=tls.version(),
            sni=getattr(tls, "_aci_sni", None),
            alpn=tls.selected_alpn_protocol(),
        )
        log(f"[tls:{self.server_port}] handshake OK from {addr[0]}:{addr[1]} cipher={tls.cipher()} ver={tls.version()} sni={getattr(tls, '_aci_sni', None)}")
        return tls, addr


RPCS3_PATTERNS = {
    "sceNpTusSetDataAsync": re.compile(r"sceNpTusSetDataAsync\((?P<args>[^)]*)\)"),
    "sceNpTusSetData": re.compile(r"sceNpTusSetData\((?P<args>[^)]*)\)"),
    "sceNpTusGetData": re.compile(r"sceNpTusGetData(?:Async)?\((?P<args>[^)]*)\)"),
    "sceNpTssGetData": re.compile(r"sceNpTssGetData\((?P<args>[^)]*)\)"),
    "sceNpTusPollAsync": re.compile(r"sceNpTusPollAsync\((?P<args>[^)]*)\)"),
    "sceNpTusCreateTitleCtx": re.compile(r"sceNpTusCreateTitleCtx\((?P<args>[^)]*)\)"),
    "sceNpTusCreateTransactionCtx": re.compile(r"sceNpTusCreateTransactionCtx\((?P<args>[^)]*)\)"),
    "sceNpTusDestroyTransactionCtx": re.compile(r"sceNpTusDestroyTransactionCtx\((?P<args>[^)]*)\)"),
    "cellSaveDataAutoLoad2": re.compile(r"cellSaveDataAutoLoad2\((?P<args>[^)]*)\)"),
    "cellSaveDataAutoSave2": re.compile(r"cellSaveDataAutoSave2\((?P<args>[^)]*)\)"),
    "savedata_cb_result": re.compile(r"savedata_op\(\): funcStat returned result=(?P<result>-?\d+)"),
}


def _parse_rpcs3_context(line):
    context = {}
    elapsed = re.search(r"\s(?P<elapsed>\d+:\d+:\d+\.\d+)\s", line)
    if elapsed:
        context["elapsed"] = elapsed.group("elapsed")
    if len(line) >= 2 and line[0] == "·":
        context["severity"] = line[1]
    thread = re.search(r"\{(?P<thread>[^}]*)\}", line)
    if thread:
        context["thread"] = thread.group("thread")
    hle = re.search(r"\[(?P<callee>(?:HLE|liblv2):\s*0x[0-9A-Fa-f]+|0x[0-9A-Fa-f]+),\s*LR:(?P<lr>0x[0-9A-Fa-f]+)\]", line)
    if hle:
        context["callee"] = hle.group("callee").replace(" ", "")
        context["lr"] = hle.group("lr")
    module = re.search(r"\]\s+(?P<module>[A-Za-z0-9_]+):\s", line)
    if module:
        context["module"] = module.group("module")
    return context


def _parse_args_blob(blob):
    result = {}
    parts = [p.strip() for p in blob.split(",")]
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        value = value.replace("“", "").replace("”", "")
        result[key] = value
        if re.fullmatch(r"-?\d+", value):
            result[key + "_int"] = int(value)
        elif re.fullmatch(r"0x[0-9A-Fa-f]+", value):
            result[key + "_int"] = int(value, 16)
    return result


def parse_rpcs3_line(line, line_no=None):
    interesting = ("sceNpTus", "sceNpTss", "cellSaveData", "savedata_op")
    if not any(token in line for token in interesting):
        return None
    for name, pattern in RPCS3_PATTERNS.items():
        match = pattern.search(line)
        if match:
            args = _parse_args_blob(match.groupdict().get("args", ""))
            record = {
                "source": "RPCS3.log",
                "line_no": line_no,
                "function": name,
                "args": args,
                "context": _parse_rpcs3_context(line),
                "raw": line.rstrip("\n"),
                "server_run_id": SERVER_RUN_ID,
                "observed": _now(),
            }
            if name == "sceNpTusSetDataAsync":
                size = args.get("totalSize_int") or args.get("sendSize_int")
                slot = args.get("slotId_int")
                record["save_candidate"] = {
                    "slot": slot,
                    "size": size,
                    "data_pointer": args.get("data"),
                    "note": "RPCS3 logs the TUS metadata but not the payload bytes.",
                }
            if name.startswith("cellSaveData"):
                record["savedata"] = {
                    "dirName": args.get("dirName"),
                    "playdata_dir": str(RPCS3_PLAYDATA_DIR),
                    "playdata_dir_exists": RPCS3_PLAYDATA_DIR.exists(),
                }
            if name == "savedata_cb_result":
                result_int = args.get("result_int")
                if result_int is None:
                    result_int = int(match.groupdict().get("result", "0"))
                record["savedata"] = {
                    "callback_result": result_int,
                    "meaning": "negative callback result from the game's save-data stat callback",
                    "playdata_dir": str(RPCS3_PLAYDATA_DIR),
                    "playdata_dir_exists": RPCS3_PLAYDATA_DIR.exists(),
                }
            return record
    return None


def scan_rpcs3_log(path=RPCS3_LOG_DEFAULT, append=True):
    path = Path(path)
    summary = {
        "path": str(path),
        "exists": path.exists(),
        "events": {},
        "save_candidates": [],
        "tss_slots": [],
        "savedata": {
            "user_savedata_dir": str(RPCS3_USER_SAVEDATA_DIR),
            "playdata_dir": str(RPCS3_PLAYDATA_DIR),
            "playdata_dir_exists": RPCS3_PLAYDATA_DIR.exists(),
        },
    }
    if not path.exists():
        return summary
    line_no = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            record = parse_rpcs3_line(line, line_no)
            if not record:
                continue
            fn = record["function"]
            summary["events"][fn] = summary["events"].get(fn, 0) + 1
            if record.get("save_candidate"):
                summary["save_candidates"].append(record["save_candidate"] | {"line_no": line_no})
            if fn == "sceNpTssGetData":
                summary["tss_slots"].append(
                    {
                        "slot": record["args"].get("slotId_int"),
                        "recvSize": record["args"].get("recvSize_int"),
                        "data": record["args"].get("data"),
                        "line_no": line_no,
                    }
                )
            if record.get("savedata"):
                summary["savedata"].setdefault("events", []).append(
                    {
                        "function": fn,
                        "args": record.get("args", {}),
                        "context": record.get("context", {}),
                        "savedata": record.get("savedata", {}),
                        "line_no": line_no,
                    }
                )
            if append:
                _write_jsonl(RPCS3_JSONL_PATH, record)
    summary["lines"] = line_no
    summary["scanned"] = _now()
    with _stats_lock:
        _stats["last_rpcs3_scan"] = summary
    _atomic_json_write(TELEMETRY_DIR / "rpcs3_hle_scan_latest.json", summary)
    return summary


def _extract_json_objects_from_text(text):
    objects = []
    i = 0
    n = len(text)
    while True:
        start = text.find("{", i)
        if start < 0:
            break
        depth = 0
        in_string = False
        escaped = False
        for j in range(start, n):
            ch = text[j]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : j + 1]
                    try:
                        objects.append(json.loads(candidate))
                        i = j + 1
                    except json.JSONDecodeError:
                        i = start + 1
                    break
        else:
            break
    return objects


def _iter_accum_data_from_log(path):
    path = Path(path)
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    for obj in _extract_json_objects_from_text(text):
        if not isinstance(obj, dict):
            continue
        uid = obj.get("uid")
        if uid == "self_test":
            continue
        state = obj.get("accum_data")
        if isinstance(state, dict):
            yield {
                "source": str(path),
                "uid": uid,
                "log_no": obj.get("log_no"),
                "state": state,
                "summary": _summarize_save(state),
            }


def _iter_accum_data_from_event_jsonl(path):
    path = Path(path)
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            payload = obj.get("payload") if isinstance(obj, dict) else None
            if not isinstance(payload, dict) or payload.get("uid") == "self_test":
                continue
            state = payload.get("accum_data")
            if isinstance(state, dict):
                yield {
                    "source": str(path),
                    "line_no": line_no,
                    "uid": payload.get("uid"),
                    "log_no": payload.get("log_no"),
                    "state": state,
                    "summary": _summarize_save(state),
                }


def rebuild_save_from_logs(extra_logs=None):
    global _save_state
    log_paths = [
        HERE.parent.parent / "First_session_requests.log",
        HERE / "second_requests.log",
    ]
    if extra_logs:
        log_paths.extend(Path(p) for p in extra_logs)

    candidates = []
    for path in log_paths:
        candidates.extend(_iter_accum_data_from_log(path) or [])
    candidates.extend(_iter_accum_data_from_event_jsonl(EVENTS_DIR / "accum_data.jsonl") or [])

    with _save_lock:
        merged = json.loads(json.dumps(_save_state, default=_json_default))
        initial_summary = _summarize_save(merged)
        for candidate in candidates:
            merged = _merge_save_states(merged, candidate["state"])
        _save_state = merged
        _persist_save_to_disk(merged)

    result = {
        "rebuilt": _now(),
        "candidate_count": len(candidates),
        "initial_summary": initial_summary,
        "final_summary": _summarize_save(merged),
        "sources": [
            {k: v for k, v in candidate.items() if k != "state"}
            for candidate in candidates
        ],
        "save_path": str(SAVE_PATH),
    }
    _atomic_json_write(TELEMETRY_DIR / "save_rebuild_latest.json", result)
    _atomic_json_write(_save_history_name("rebuild_from_logs", 0), {"kind": "rebuild_from_logs", **result, "state": merged})
    with _stats_lock:
        _stats["last_save_rebuild"] = result
        _stats["last_save"] = result["final_summary"]
    _write_summary()
    log(
        "[save] rebuilt merged save from logs candidates=%d missions=%s aircraft=%d credit=%s"
        % (
            len(candidates),
            result["final_summary"].get("mission_ids"),
            result["final_summary"].get("aircraft_count"),
            result["final_summary"].get("credit"),
        )
    )
    return result


class Rpcs3LogWatcher(threading.Thread):
    def __init__(self, path):
        super().__init__(daemon=True, name="rpcs3-log-watch")
        self.path = Path(path)
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        if not self.path.exists():
            log(f"[rpcs3] log watcher disabled; missing {self.path}")
            return
        log(f"[rpcs3] tailing HLE save/TSS calls from {self.path}")
        with self.path.open("r", encoding="utf-8", errors="replace") as f:
            line_no = sum(1 for _ in f)
            f.seek(0, os.SEEK_END)
            while not self._stop.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.25)
                    continue
                line_no += 1
                record = parse_rpcs3_line(line, None)
                if record:
                    _write_jsonl(RPCS3_JSONL_PATH, record)
                    if record.get("save_candidate"):
                        log(f"[rpcs3] TUS save candidate {record['save_candidate']}")
                    if record.get("savedata"):
                        log(f"[rpcs3] savedata event {record['function']} {record['savedata']}")


def serve_http(port):
    httpd = LoggingHTTPServer(("0.0.0.0", port), ACIHandler)
    log(f"[http] listening on 0.0.0.0:{port}")
    httpd.serve_forever()


def _make_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_PATH, KEY_PATH)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0:!aNULL:!eNULL")
    except ssl.SSLError:
        pass

    def _sni(sock, server_name, context):
        setattr(sock, "_aci_sni", server_name)
        telemetry("tls.sni", server_name=server_name)

    ctx.set_servername_callback(_sni)
    return ctx


def serve_https(port):
    ctx = _make_ssl_context()
    httpd = LoggingPort443Server(("0.0.0.0", port), ACIHandler, ctx)
    log(f"[https] listening on 0.0.0.0:{port} (TLS + plaintext fallback, cert={CERT_PATH})")
    httpd.serve_forever()


def _startup_inventory():
    tss_inventory = analyze_tss_cache(write=True)
    tss = tss_inventory["files"]
    playdata_files = []
    if RPCS3_PLAYDATA_DIR.exists():
        for path in sorted(RPCS3_PLAYDATA_DIR.rglob("*")):
            if path.is_file():
                rel = path.relative_to(RPCS3_PLAYDATA_DIR)
                playdata_files.append({"path": str(rel), "bytes": path.stat().st_size, "mtime": path.stat().st_mtime})
    inv = {
        "server_run_id": SERVER_RUN_ID,
        "cwd": str(Path.cwd()),
        "here": str(HERE),
        "python": sys.version,
        "platform": platform.platform(),
        "pid": os.getpid(),
        "tss_files": tss,
        "tss_inventory": tss_inventory,
        "save_summary": _summarize_save(_save_snapshot()),
        "paths": {
            "requests_log": str(LOG_PATH),
            "telemetry_dir": str(TELEMETRY_DIR),
            "save_path": str(SAVE_PATH),
            "rpcs3_log_default": str(RPCS3_LOG_DEFAULT),
            "rpcs3_user_savedata_dir": str(RPCS3_USER_SAVEDATA_DIR),
            "rpcs3_playdata_dir": str(RPCS3_PLAYDATA_DIR),
        },
        "rpcs3_savedata": {
            "user_savedata_dir_exists": RPCS3_USER_SAVEDATA_DIR.exists(),
            "playdata_dir_exists": RPCS3_PLAYDATA_DIR.exists(),
            "playdata_files": playdata_files,
        },
    }
    _atomic_json_write(TELEMETRY_DIR / "startup_inventory.json", inv)
    telemetry("server.startup_inventory", inventory=inv)
    log(f"[startup] TSS inventory: {len(tss)} files")
    for item in tss:
        log(
            "[startup]   %s slot=%s bytes=%s sha256=%s guess=%s"
            % (
                item["name"],
                item.get("slot"),
                item["bytes"],
                item["sha256"],
                item.get("format_guess", {}).get("container"),
            )
        )
    if not RPCS3_PLAYDATA_DIR.exists():
        log(f"[startup] RPCS3 playdata dir is missing: {RPCS3_PLAYDATA_DIR}")


def run_self_test():
    _ensure_dirs()
    ensure_cert()
    _load_save_from_disk()
    _startup_inventory()
    global _save_state
    with _save_lock:
        original_state = json.loads(json.dumps(_save_state))
        original_had_state = bool(_save_state)

    httpd = LoggingHTTPServer(("127.0.0.1", 0), ACIHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    httpsd = LoggingPort443Server(("127.0.0.1", 0), ACIHandler, _make_ssl_context())
    https_port = httpsd.server_address[1]
    https_thread = threading.Thread(target=httpsd.serve_forever, daemon=True)
    https_thread.start()

    sample = {
        "log_ver": 1014,
        "_id": 0,
        "uid": "self_test",
        "log_no": 1,
        "accum_data": {
            "player_rank": 7,
            "credit": {"gain": 123456, "paid": 0},
            "mission": [{"mission_id": 101, "clear_rank": "S"}],
            "aircraft": [{"aircraft_id": 5, "lv": 2}],
        },
    }

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps(sample).encode("utf-8")
    conn.request("POST", "/Wind/save/accum_data", body=body, headers={"Host": "dev-wind.siliconstudio.co.jp:443", "Content-Type": "application/json;charset=utf-8"})
    resp = conn.getresponse()
    save_resp = resp.status, resp.read()
    conn.close()

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/Wind/load/test", headers={"Host": "dev-wind.siliconstudio.co.jp:443"})
    resp = conn.getresponse()
    load_body = resp.read()
    load_resp = resp.status, load_body
    conn.close()

    tss_status = None
    tss_sample = next(iter(sorted(TSS_DIR.glob("NPWR04428_00-0.tss"))), None)
    if tss_sample:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", f"/tss/np/NPWR04428_00/{tss_sample.name}", headers={"Host": "a0.ww.np.dl.playstation.net"})
        resp = conn.getresponse()
        tss_status = (resp.status, len(resp.read()))
        conn.close()

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/__debug/tss", headers={"Host": "127.0.0.1"})
    resp = conn.getresponse()
    debug_tss_status = (resp.status, len(resp.read()))
    conn.close()

    tls_status = None
    tls_context = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection("127.0.0.1", https_port, timeout=5, context=tls_context)
    conn.request("GET", "/Wind/test", headers={"Host": "dev-wind.siliconstudio.co.jp"})
    resp = conn.getresponse()
    tls_status = (resp.status, len(resp.read()))
    conn.close()

    httpd.shutdown()
    httpsd.shutdown()
    thread.join(timeout=5)
    https_thread.join(timeout=5)
    with _save_lock:
        _save_state = original_state
        if original_had_state:
            _persist_save_to_disk(original_state)
    scan = scan_rpcs3_log(RPCS3_LOG_DEFAULT, append=False)
    result = {
        "save_response": {"status": save_resp[0], "body": save_resp[1].decode("utf-8", errors="replace")},
        "load_response": {"status": load_resp[0], "body": load_resp[1].decode("utf-8", errors="replace")[:2000]},
        "tss_response": tss_status,
        "debug_tss_response": debug_tss_status,
        "tls_response": tls_status,
        "rpcs3_scan": scan,
        "summary_path": str(SUMMARY_PATH),
    }
    _atomic_json_write(TELEMETRY_DIR / "self_test_latest.json", result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if (
        save_resp[0] != 200
        or load_resp[0] != 200
        or debug_tss_status[0] != 200
        or tls_status[0] != 200
        or (tss_sample and tss_status[0] != 200)
    ):
        return 1
    if b"123456" not in load_body:
        return 2
    return 0


def main():
    parser = argparse.ArgumentParser(description="Ace Combat Infinity local mock server")
    parser.add_argument("--http-port", type=int, default=int(os.environ.get("ACI_HTTP_PORT", "80")))
    parser.add_argument("--https-port", type=int, default=int(os.environ.get("ACI_HTTPS_PORT", "443")))
    parser.add_argument("--no-https", action="store_true")
    parser.add_argument("--no-rpcs3-log-watch", action="store_true")
    parser.add_argument("--rpcs3-log", default=str(RPCS3_LOG_DEFAULT))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--rebuild-save-from-logs", action="store_true")
    parser.add_argument("--extra-save-log", action="append", default=[])
    parser.add_argument("--analyze-tss", action="store_true", help="Analyze cached TSS files and exit.")
    parser.add_argument(
        "--analyze-npstorage",
        action="append",
        default=[],
        metavar="PATH",
        help="Analyze a scraped NP storage/TUS envelope sample with private fields redacted.",
    )
    parser.add_argument("--debug-report", action="store_true", help="Write a redacted telemetry/debug report and exit.")
    args = parser.parse_args()

    _ensure_dirs()
    ensure_cert()
    LOG_PATH.touch(exist_ok=True)
    _load_save_from_disk()

    with _stats_lock:
        started = _now()
        _stats["started_local"] = started["local"]
        _stats["started_utc"] = started["utc"]
    _startup_inventory()

    if args.analyze_tss:
        result = analyze_tss_cache(write=True)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=_json_default))
        sys.exit(0)

    if args.analyze_npstorage:
        result = [analyze_npstorage_file(path, write=True) for path in args.analyze_npstorage]
        print(json.dumps(result, indent=2, ensure_ascii=False, default=_json_default))
        sys.exit(0)

    if args.rebuild_save_from_logs:
        result = rebuild_save_from_logs(args.extra_save_log)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=_json_default))
        sys.exit(0)

    if args.debug_report:
        from aci_debug_report import write_report

        json_path, md_path, report = write_report()
        print(
            json.dumps(
                {"json": str(json_path), "markdown": str(md_path), "save_summary": report["save_summary"]},
                indent=2,
                ensure_ascii=False,
            )
        )
        sys.exit(0)

    scan_summary = scan_rpcs3_log(Path(args.rpcs3_log), append=False)
    log(f"[rpcs3] scanned {scan_summary.get('lines', 0)} lines; events={scan_summary.get('events', {})}")
    _write_summary()

    if args.self_test:
        sys.exit(run_self_test())

    log("=" * 80)
    log("ACI mock listener starting")
    log(f"server_run_id={SERVER_RUN_ID}")
    log("=" * 80)

    watcher = None
    if not args.no_rpcs3_log_watch:
        watcher = Rpcs3LogWatcher(args.rpcs3_log)
        watcher.start()

    threads = [threading.Thread(target=serve_http, args=(args.http_port,), daemon=True)]
    if not args.no_https:
        threads.append(threading.Thread(target=serve_https, args=(args.https_port,), daemon=True))
    for thread in threads:
        thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("shutting down")
        if watcher:
            watcher.stop()


if __name__ == "__main__":
    main()
