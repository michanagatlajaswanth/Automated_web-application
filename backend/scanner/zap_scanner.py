
import os
import time
from zapv2 import ZAPv2

ZAP_ADDRESS = "127.0.0.1"
ZAP_PORT = 8080


def connect_to_zap():
    api_key = os.getenv("ZAP_API_KEY")

    if not api_key:
        raise RuntimeError("ZAP_API_KEY environment variable is not set")

    proxies = {
        "http": f"http://{ZAP_ADDRESS}:{ZAP_PORT}",
        "https": f"http://{ZAP_ADDRESS}:{ZAP_PORT}"
    }

    return ZAPv2(
        apikey=api_key,
        proxies=proxies,
        validate_status_code=True
    )


def check_zap_connection():
    try:
        zap = connect_to_zap()
        version = zap.core.version

        return {
            "connected": True,
            "version": version
        }

    except Exception as e:
        return {
            "connected": False,
            "error": str(e)
        }


def start_spider(zap, target_url, scan_mode="thorough"):

    if scan_mode == "quick":
        max_depth = 2
        max_children = 5
        max_duration = 60
    else:
        max_depth = 5
        max_children = 10
        max_duration = 120

    zap.spider.set_option_max_depth(max_depth)
    zap.spider.set_option_max_children(max_children)

    scan_id = zap.spider.scan(
        url=target_url,
        maxchildren=max_children,
        recurse=True
    )

    start_time = time.time()

    while int(zap.spider.status(scan_id)) < 100:

        if time.time() - start_time >= max_duration:
            zap.spider.stop(scan_id)

            return {
                "spider_scan_id": scan_id,
                "status": "stopped",
                "message": f"Spider stopped after {max_duration} seconds"
            }

        time.sleep(2)

    return {
        "spider_scan_id": scan_id,
        "status": "completed"
    }

def wait_for_passive_scan(zap):
    while int(zap.pscan.records_to_scan) > 0:
        time.sleep(2)

    return "completed"

def start_active_scan(zap, target_url, scan_mode="thorough"):

    if scan_mode == "quick":
        threads = 4
        delay = 50
        max_duration = 120
        recurse = False
    else:
        threads = 4
        delay = 50
        max_duration = 300
        recurse = True

    zap.ascan.set_option_thread_per_host(threads)
    zap.ascan.set_option_delay_in_ms(delay)

    scan_id = zap.ascan.scan(
        url=target_url,
        recurse=recurse
    )

    start_time = time.time()

    while int(zap.ascan.status(scan_id)) < 100:

        if time.time() - start_time >= max_duration:
            zap.ascan.stop(scan_id)

            return {
                "active_scan_id": scan_id,
                "status": "stopped",
                "message": f"Active scan stopped after {max_duration} seconds"
            }

        time.sleep(3)

    return {
        "active_scan_id": scan_id,
        "status": "completed"
    }
def get_alerts(zap, target_url):
    alerts = zap.core.alerts(baseurl=target_url)

    findings = []

    for alert in alerts:
        findings.append({
            "name": alert.get("name"),
            "risk": alert.get("risk"),
            "confidence": alert.get("confidence"),
            "url": alert.get("url"),
            "description": alert.get("description"),
            "solution": alert.get("solution"),
            "reference": alert.get("reference")
        })

    return findings
