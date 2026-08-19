"""Pottery studio scheduling.

Kiln settings come from a per-studio TOML file where every key is optional,
member handles are typed at the door, and a firing queue is often empty, so
each lookup below has a real absent case to answer for.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Member:
    handle: str
    shelf: Optional[str] = None


@dataclass
class Firing:
    kiln: str
    cone: int
    ready: bool


class Roster:
    def __init__(self, members):
        self._by_handle = {m.handle: m for m in members}

    def find(self, handle):
        return self._by_handle.get(handle)


# py-null-shelf-lookup-attr-medium
def shelf_label(roster, handle):
    member = roster.find(handle)
    if member is None:
        raise LookupError(f"no studio member with handle {handle}")
    return member.shelf


# py-null-kiln-hold-key-medium
def hold_minutes(settings):
    if "hold_minutes" not in settings:
        return 20
    return int(settings["hold_minutes"])


# py-null-empty-firing-index-medium
def next_ready_firing(firings, kiln):
    ready = [f for f in firings if f.kiln == kiln and f.ready]
    if not ready:
        return None
    return ready[0]


def schedule_summary(firings, kiln, settings):
    firing = next_ready_firing(firings, kiln)
    if firing is None:
        return f"{kiln}: nothing queued"
    return f"{kiln}: cone {firing.cone}, hold {hold_minutes(settings)}m"
