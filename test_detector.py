
from detectors.login_detector import detect_brute_force


def test_detects_repeated_failed_logins():
    logs = [
        {
            "timestamp": f"2026-10-18T10:0{i}:00Z",
            "ip_address": "192.0.2.10",
            "status": "failed"
        }
        for i in range(5)
    ]

    alerts = detect_brute_force(logs)

    assert len(alerts) == 1
    assert alerts[0]["ip_address"] == "192.0.2.10"
    assert alerts[0]["failed_attempts"] == 5


def test_successful_logins_do_not_trigger_alert():
    logs = [
        {
            "timestamp": f"2026-10-18T10:0{i}:00Z",
            "ip_address": "192.0.2.20",
            "status": "success"
        }
        for i in range(5)
    ]

    alerts = detect_brute_force(logs)

    assert len(alerts) == 0


def test_failures_from_different_ips_are_not_combined():
    logs = [
        {
            "timestamp": f"2026-10-18T10:0{i}:00Z",
            "ip_address": f"192.0.2.{i + 1}",
            "status": "failed"
        }
        for i in range(5)
    ]

    alerts = detect_brute_force(logs)

    assert len(alerts) == 0


if __name__ == "__main__":
    test_detects_repeated_failed_logins()
    test_successful_logins_do_not_trigger_alert()
    test_failures_from_different_ips_are_not_combined()

    print("PASS: All 3 Sentinel detection tests passed!")
