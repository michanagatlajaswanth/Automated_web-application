
from flask import Blueprint, request, jsonify
from urllib.parse import urlparse
from threading import Thread

from scanner.zap_scanner import (
    check_zap_connection,
    connect_to_zap,
    start_spider,
    wait_for_passive_scan,
    start_active_scan,
    get_alerts
)

from database.db import (
    create_scan as db_create_scan,
    update_scan,
    get_all_scans,
    get_scan_by_id
)

scan_bp = Blueprint("scan", __name__)


def is_valid_url(url):
    try:
        parsed_url = urlparse(url)

        return (
            parsed_url.scheme in ["http", "https"]
            and parsed_url.hostname is not None
        )
    except Exception:
        return False


def run_scan(scan):
    """Execute ZAP scanning and save progress and findings."""

    try:
        zap = connect_to_zap()

        target_url = scan["target_url"]
        scan_mode = scan.get("scan_mode", "thorough")

        # Step 1: Spider scanning
        scan["status"] = "spider_scanning"
        update_scan(scan)

        spider_result = start_spider(
            zap,
            target_url,
            scan_mode
        )

        scan["spider"] = spider_result
        update_scan(scan)

        # Do not continue if spidering was stopped
        if spider_result.get("status") != "completed":
            raise RuntimeError(
                "Spider scanning did not complete. "
                "Active scanning was not started."
            )

        # Step 2: Passive scanning
        scan["status"] = "passive_scanning"
        update_scan(scan)

        wait_for_passive_scan(zap)

        # Step 3: Active scanning
        scan["status"] = "active_scanning"
        update_scan(scan)

        active_result = start_active_scan(
            zap,
            target_url,
            scan_mode
        )

        scan["active_scan"] = active_result
        update_scan(scan)

        # Step 4: Collect vulnerability findings
        scan["status"] = "collecting_findings"
        update_scan(scan)

        findings = get_alerts(zap, target_url)

        scan["findings"] = findings
        scan["total_findings"] = len(findings)
        scan["status"] = "completed"

        update_scan(scan)

    except Exception as e:
        scan["status"] = "failed"
        scan["error"] = str(e)

        update_scan(scan)


# Create a new scan
@scan_bp.route("/api/scans", methods=["POST"])
def create_scan():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Request body is required"
        }), 400

    target_url = data.get("target_url")

    if not isinstance(target_url, str):
        return jsonify({
            "error": "target_url must be a string"
        }), 400

    target_url = target_url.strip()

    if not target_url:
        return jsonify({
            "error": "target_url cannot be empty"
        }), 400

    if not is_valid_url(target_url):
        return jsonify({
            "error": "Invalid target URL. Use http:// or https://"
        }), 400

    # Require authorization confirmation
    if data.get("authorized") is not True:
        return jsonify({
            "error": "Confirm that you are authorized to scan this target"
        }), 403

    # Validate scan mode
    scan_mode = data.get("scan_mode", "thorough")

    if scan_mode not in ("quick", "thorough"):
        return jsonify({
            "error": "Invalid scan mode. Choose quick or thorough."
        }), 400

    # Create scan record
    scan = {
        "target_url": target_url,
        "scan_mode": scan_mode,
        "status": "queued",
        "findings": [],
        "total_findings": 0,
        "spider": None,
        "active_scan": None,
        "error": None
    }

    # Save scan to SQLite
    scan["id"] = db_create_scan(scan)

    # Start scanning in background
    thread = Thread(
        target=run_scan,
        args=(scan,),
        daemon=True
    )

    thread.start()

    return jsonify({
        "message": "Scan started successfully",
        "scan": scan
    }), 202


# Get all scans
@scan_bp.route("/api/scans", methods=["GET"])
def get_scans():

    scans = get_all_scans()

    return jsonify({
        "count": len(scans),
        "scans": scans
    }), 200


# Get a particular scan
@scan_bp.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):

    scan = get_scan_by_id(scan_id)

    if scan:
        return jsonify({
            "scan": scan
        }), 200

    return jsonify({
        "error": "Scan not found"
    }), 404


# Get scan status
@scan_bp.route("/api/scans/<int:scan_id>/status", methods=["GET"])
def get_scan_status(scan_id):

    scan = get_scan_by_id(scan_id)

    if scan:
        return jsonify({
            "scan_id": scan_id,
            "status": scan["status"],
            "error": scan.get("error")
        }), 200

    return jsonify({
        "error": "Scan not found"
    }), 404


# Get scan findings
@scan_bp.route("/api/scans/<int:scan_id>/findings", methods=["GET"])
def get_scan_findings(scan_id):

    scan = get_scan_by_id(scan_id)

    if scan:
        return jsonify({
            "scan_id": scan_id,
            "total_findings": scan["total_findings"],
            "findings": scan["findings"]
        }), 200

    return jsonify({
        "error": "Scan not found"
    }), 404


# Check OWASP ZAP connection
@scan_bp.route("/api/zap/status", methods=["GET"])
def zap_status():

    result = check_zap_connection()

    if result["connected"]:
        return jsonify({
            "message": "OWASP ZAP connected successfully",
            "zap": result
        }), 200

    return jsonify({
        "message": "Unable to connect to OWASP ZAP",
        "zap": result
    }), 500
