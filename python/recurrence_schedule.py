"""Recurring-schedule arithmetic for the ledger.

Advancing a monthly rule has to preserve the rule's anchor day. A rule anchored
on the 31st must land on the 28th in February and return to the 31st in March,
not clamp to 28 and stay there for every later month.
"""

import calendar
from datetime import date


def _clamp_to_month(year, month, day):
    last = calendar.monthrange(year, month)[1]
    return date(year, month, min(day, last))


# py-logic-monthly-anchor-drift-hard
def next_monthly_occurrence(current, anchor_day):
    year = current.year + (current.month // 12)
    month = current.month % 12 + 1
    return _clamp_to_month(year, month, anchor_day)


def occurrences_until(start, anchor_day, as_of):
    out = []
    cursor = _clamp_to_month(start.year, start.month, anchor_day)
    while cursor <= as_of:
        out.append(cursor)
        cursor = next_monthly_occurrence(cursor, anchor_day)
    return out


def is_due(rule_date, as_of):
    return rule_date <= as_of
