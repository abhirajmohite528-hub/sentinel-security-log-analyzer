
from collections import defaultdict
from datetime import datetime, timedelta, timezone


def parse_timestamp(value):
    timestamp = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp


def detect_brute_force(logs, threshold=5, window_minutes=5):
    """Detect repeated failed logins from the same IP."""

    failed_by_ip = defaultdict(list)
    alerts = []

    for log in logs:
        if log.get("status", "").lower() != "failed":
            continue

        ip = log.get("ip_address")
        if not ip:
            continue

        timestamp = parse_timestamp(log["timestamp"])
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
                    ),
                })

    return alerts


def detect_multiple_account_targeting(
    logs, threshold=5, window_minutes=5
):
    """Detect failed logins targeting multiple usernames from one IP."""

    failed_by_ip = defaultdict(list)
    alerts = []

    for log in logs:
        if log.get("status", "").lower() != "failed":
            continue

        ip = log.get("ip_address")
        username = log.get("username")

        if not ip or not username or username == "unknown":
            continue

        timestamp = parse_timestamp(log["timestamp"])
        failed_by_ip[ip].append((timestamp, username))

    for ip, attempts in failed_by_ip.items():
        attempts.sort(key=lambda item: item[0])
        left = 0

        for right, (current_time, _) in enumerate(attempts):
            while (
                current_time - attempts[left][0]
                > timedelta(minutes=window_minutes)
            ):
                left += 1

            usernames = {
                username
                for _, username in attempts[left:right + 1]
            }

            if len(usernames) >= threshold:
                alerts.append({
                    "type": "Multiple Account Targeting",
                    "severity": "High",
                    "ip_address": ip,
                    "failed_attempts": right - left + 1,
                    "window_minutes": window_minutes,
                    "timestamp": current_time.isoformat(),
                    "message": (
                        f"Failed login attempts targeted "
                        f"{len(usernames)} different usernames "
                        f"from {ip} within {window_minutes} minutes."
                    ),
                })
                break

    return alerts
