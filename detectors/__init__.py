
from collections import defaultdict
from datetime import datetime, timedelta, timezone


def detect_brute_force(logs, threshold=5, window_minutes=5):
    """
    Detect repeated failed login attempts from the same IP
    within a rolling time window.
    
    Each log must contain:
    timestamp, ip_address, status
    """
    failed_by_ip = defaultdict(list)
    alerts = []

    for log in logs:
        if log.get("status", "").lower() != "failed":
            continue

        ip = log.get("ip_address")
        timestamp = datetime.fromisoformat(
            log["timestamp"].replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        failed_by_ip[ip].append(timestamp)

    for ip, timestamps in failed_by_ip.items():
        timestamps.sort()

        left = 0
        for right, current_time in enumerate(timestamps):
            while (
                current_time - timestamps[left]
                > timedelta(minutes=window_minutes)
            ):
                left += 1

            count = right - left + 1

            if count == threshold:
                alerts.append({
                    "type": "Repeated Failed Logins",
                    "severity": "High",
                    "ip_address": ip,
                    "failed_attempts": count,
                    "window_minutes": window_minutes,
                    "timestamp": current_time.isoformat(),
                    "message": (
                        f"{count} failed login attempts from {ip} "
                        f"within {window_minutes} minutes."
                    )
                })

    return alerts
