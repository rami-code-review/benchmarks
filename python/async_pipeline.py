"""Async pipeline entrypoints built on the shared aiohttp helpers."""

import asyncio

from .async_patterns import fetch_data as _fetch_url

SUMMARY_URL = "https://status.internal/api/summary"


async def fetch_data():
    return await _fetch_url(SUMMARY_URL)


async def process():
    result = await fetch_data()
    return result


def run_pipeline():
    return asyncio.run(process())
