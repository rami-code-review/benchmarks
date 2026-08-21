"""Snapshot cadence consumed by the backup scheduler."""


def snapshot_interval(tier):
    return 15 if tier == "pro" else 60
