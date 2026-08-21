"""Alert identity for the deduplicating router."""


def alert_key(alert):
    return f"{alert.service}:{alert.severity}:{alert.check_id}"
