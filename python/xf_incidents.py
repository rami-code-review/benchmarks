"""Alert identity for incident tracking."""


def incident_key(alert):
    return f"{alert.service}:{alert.severity}:{alert.check_id}"
