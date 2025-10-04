# app.py
from flask import Flask, render_template, request, jsonify, Response
from concurrent.futures import ThreadPoolExecutor, Future
import uuid
import time
import logging
import datetime

# <-- Update import to your scanner file -->
from port_scanner import run_scan_sync, analyze_results

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

jobs = {}
executor = ThreadPoolExecutor(max_workers=4)

MAX_PORT_RANGE = 2000
MAX_CONCURRENCY = 2000

# ---------------- Helper functions ----------------
def validate_params(target: str, start: int, end: int, concurrency: int):
    if not target:
        raise ValueError("target required")
    if start < 1 or end > 65535 or start > end:
        raise ValueError("invalid port range")
    if (end - start + 1) > MAX_PORT_RANGE:
        raise ValueError(f"port range too large (limit {MAX_PORT_RANGE})")
    if concurrency < 1 or concurrency > MAX_CONCURRENCY:
        raise ValueError("invalid concurrency")


def format_scan_results(results_json):
    """
    Turn the scan JSON dict into a human-readable terminal-style report (plain text).
    """
    lines = []
    lines.append("=" * 60)
    lines.append(f"Scan report for {results_json.get('target')} ({results_json.get('resolved_ip')})")
    lines.append(f"Port range: {results_json.get('start')}-{results_json.get('end')}")
    ts = results_json.get("scanned_at")
    try:
        ts_str = datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts_str = str(ts)
    lines.append(f"Scanned at: {ts_str}")
    lines.append(f"Found {len(results_json.get('results', []))} open ports\n")

    for r in results_json.get("results", []):
        port = r.get("port")
        service = r.get("detected_service") or "unknown"
        rtt = r.get("rtt_ms", 0.0)
        lines.append(f"- Port {port:5d} | Service: {service:12} | RTT: {rtt:.1f} ms")
        if r.get("insecure_note"):
            lines.append(f"    ⚠ {r['insecure_note']}")
        if r.get("banner"):
            banner_lines = [ln.strip() for ln in r["banner"].splitlines() if ln.strip()]
            snippet = " | ".join(banner_lines[:3])
            if snippet:
                lines.append(f"    Banner: {snippet}")
    lines.append("=" * 60)
    return "\n".join(lines)


def run_scan_task(target, start, end, concurrency, connect_timeout, read_timeout, rate_delay, jitter, no_banner):
    try:
        ip, raw = run_scan_sync(target, start, end, concurrency, connect_timeout, (0.01 if no_banner else read_timeout), rate_delay, jitter)
        enriched = analyze_results(raw)
        result_obj = {
            "status": "done",
            "target": target,
            "resolved_ip": ip,
            "start": start,
            "end": end,
            "results": enriched,
            "scanned_at": time.time()
        }
        result_obj["_formatted"] = format_scan_results(result_obj)
        return result_obj
    except Exception as e:
        logging.exception("Scan failed for %s", target)
        return {"status": "error", "error": str(e)}

# ---------------- Routes ----------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan-blocking", methods=["POST"])
def scan_blocking():
    data = request.get_json() or request.form
    try:
        target = data.get("target")
        start = int(data.get("start", 1))
        end = int(data.get("end", 1024))
        concurrency = int(data.get("concurrency", 200))
        connect_timeout = float(data.get("connect_timeout", 3.0))
        read_timeout = float(data.get("read_timeout", 2.0))
        rate_delay = float(data.get("rate_delay", 0.0))
        jitter = float(data.get("jitter", 0.02))
        no_banner = bool(data.get("no_banner", False))
        validate_params(target, start, end, concurrency)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400

    try:
        # Run the scan synchronously
        result_obj = run_scan_task(target, start, end, concurrency, connect_timeout, read_timeout, rate_delay, jitter, no_banner)
        
        # Ensure _formatted exists
        formatted = result_obj.get("_formatted") or format_scan_results(result_obj)
        
        return Response(formatted, mimetype="text/plain")
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500



@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or request.form
    try:
        target = data.get("target")
        start = int(data.get("start", 1))
        end = int(data.get("end", 1024))
        concurrency = int(data.get("concurrency", 200))
        connect_timeout = float(data.get("connect_timeout", 3.0))
        read_timeout = float(data.get("read_timeout", 2.0))
        rate_delay = float(data.get("rate_delay", 0.0))
        jitter = float(data.get("jitter", 0.02))
        no_banner = bool(data.get("no_banner", False))
        validate_params(target, start, end, concurrency)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400

    job_id = str(uuid.uuid4())
    future: Future = executor.submit(run_scan_task, target, start, end, concurrency, connect_timeout, read_timeout, rate_delay, jitter, no_banner)
    jobs[job_id] = {"future": future, "created": time.time(), "params": {"target": target, "start": start, "end": end}}
    return jsonify({"status": "submitted", "job_id": job_id})


@app.route("/scan-status/<job_id>", methods=["GET"])
def scan_status(job_id):
    meta = jobs.get(job_id)
    if not meta:
        return jsonify({"status": "error", "error": "job not found"}), 404
    future: Future = meta["future"]
    want_text = request.args.get("format", "").lower() in ("txt", "text", "plain")
    if future.done():
        result = future.result()
        if want_text:
            formatted = result.get("_formatted") or format_scan_results(result)
            return Response(formatted, mimetype="text/plain")
        else:
            return jsonify({"status": result.get("status", "done"), "result": result})
    else:
        return jsonify({"status": "running", "created": meta["created"], "params": meta["params"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
