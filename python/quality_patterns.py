"""Logic, error-handling and maintainability fixtures."""

import logging
from datetime import date

from .catalog import VALID_CATEGORIES, VALID_TYPES, Database, Order, Receipt, Result, User
from .catalog import default_value, gateway, handle, parse, run_stage

logger = logging.getLogger(__name__)


def append_item(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items


def add_item(item: str, items: list[str] | None = None) -> list[str]:
    if items is None:
        items = []
    items.append(item)
    return items


def build_multipliers():
    multipliers = [lambda x, i=i: x * i for i in range(5)]
    return multipliers


def transactions_since(txns, start: str):
    start_date = date.fromisoformat(start)
    return [t for t in txns if date.fromisoformat(t["date"]) >= start_date]


def transactions_in_category(txns, category: str):
    if category not in VALID_CATEGORIES:
        raise ValueError("invalid category")
    return [t for t in txns if t["category"] == category]


def parse_amount(raw: str) -> int:
    try:
        return int(raw)
    except ValueError as e:
        logger.error(f"Invalid value: {e}")
        raise


def handle_request(payload):
    try:
        return run_stage(payload)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return {"error": "An unexpected error occurred"}


def commit_batch(batch):
    try:
        return batch.commit()
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        raise


def parse_with_default(data):
    try:
        result = parse(data)
    except ValueError:
        result = default_value
    return result


def get_users(db: Database, active_only: bool = True) -> list[User]:
    query = "SELECT * FROM users"
    if active_only:
        query += " WHERE active = true"
    return db.execute(query)


def process(data: dict) -> Result:
    if not data:
        return Result.error("no data")
    if "type" not in data:
        return Result.error("missing type")
    if data["type"] not in VALID_TYPES:
        return Result.error("invalid type")
    return handle(data)


def process_payment(order: Order) -> Receipt:
    logger.info("Processing payment for order %s", order.id)
    return gateway.charge(order)


def display_name(user):
    if user is not None:
        return user.name
    return ""


def process_allowed(items, allowed_items, process):
    allowed_set = set(allowed_items)
    for item in items:
        if item in allowed_set:
            process(item)


def join_items(items) -> str:
    result = "".join(items)
    return result
