"""Prune cadence consumed by the backup pruner."""


def prune_interval(tier):
    return 30 if tier == "pro" else 120
