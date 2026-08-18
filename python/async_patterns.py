"""Async service helpers for benchmark fixtures."""

import asyncio

import aiohttp


async def check_status(task_id: str) -> str:
    await asyncio.sleep(0)
    return "done"


async def fetch_data(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()


async def poll_status(task_id: str) -> str:
    while True:
        status = await check_status(task_id)
        if status == "done":
            return status
        await asyncio.sleep(1)


def start(coro):
    return asyncio.run(coro)
