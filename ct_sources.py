from __future__ import annotations

import asyncio
import json
import logging
import os
from abc import ABC, abstractmethod

import aiohttp

from utils import exponential_backoff

logger = logging.getLogger(__name__)


class CTProvider(ABC):
    @abstractmethod
    async def fetch(self, domain: str, session: aiohttp.ClientSession) -> list[dict]:
        ...


class CrtShProvider(CTProvider):
    BASE_URL = "https://crt.sh"
    MAX_RETRIES = 4

    async def fetch(self, domain: str, session: aiohttp.ClientSession) -> list[dict]:
        url = f"{self.BASE_URL}/"
        params = {"q": f"%.{domain}", "output": "json"}
        logger.debug("crt.sh: querying: %s with params %s", url, params)

        for attempt in range(self.MAX_RETRIES):
            try:
                async with session.get(url, params=params) as response:
                    logger.debug("crt.sh: HTTP %d on attempt %d", response.status, attempt + 1)

                    if response.status == 429:
                        wait = exponential_backoff(attempt)
                        logger.warning("crt.sh rate limited — waiting %.1fs", wait)
                        await asyncio.sleep(wait)
                        continue

                    if response.status != 200:
                        body_preview = (await response.text())[:200]
                        logger.error(
                            "crt.sh unexpected status %d: %s",
                            response.status, body_preview
                        )
                        wait = exponential_backoff(attempt)
                        await asyncio.sleep(wait)
                        continue

                    raw_text = await response.text()
                    logger.debug("crt.sh: received %d bytes", len(raw_text))

                    if not raw_text.strip():
                        logger.warning("crt.sh returned empty body")
                        return []

                    try:
                        data = json.loads(raw_text)
                    except Exception as exc:
                        logger.error("crt.sh invalid JSON (%s) — preview: %s", exc, raw_text[:200])
                        return []

                    if not isinstance(data, list):
                        logger.error("crt.sh unexpected response shape: %s", type(data))
                        return []

                    logger.debug("crt.sh: %d raw certificate entries", len(data))
                    return data

            except asyncio.TimeoutError:
                wait = exponential_backoff(attempt)
                logger.warning(
                    "crt.sh timed out on attempt %d, retrying in %.1fs", attempt + 1, wait
                )
                await asyncio.sleep(wait)
            except aiohttp.ClientError as exc:
                wait = exponential_backoff(attempt)
                logger.warning(
                    "crt.sh client error (%s) on attempt %d, retrying in %.1fs",
                    exc, attempt + 1, wait
                )
                await asyncio.sleep(wait)

        logger.error("crt.sh exhausted all %d retries for %s", self.MAX_RETRIES, domain)
        return []


class CensysProvider(CTProvider):
    BASE_URL = "https://search.censys.io/api/v2/certificates/search"
    MAX_RETRIES = 4

    def _credentials(self) -> tuple[str, str] | None:
        api_id = os.getenv("CENSYS_API_ID")
        api_secret = os.getenv("CENSYS_API_SECRET")
        if api_id and api_secret:
            return api_id, api_secret
        return None

    async def fetch(self, domain: str, session: aiohttp.ClientSession) -> list[dict]:
        creds = self._credentials()
        if creds is None:
            logger.debug("Censys credentials not set — skipping")
            return []

        auth = aiohttp.BasicAuth(creds[0], creds[1])
        query = f"parsed.names: {domain}"
        per_page = 100
        cursor: str | None = None
        results: list[dict] = []

        for attempt in range(self.MAX_RETRIES):
            try:
                while True:
                    payload: dict = {"q": query, "per_page": per_page}
                    if cursor:
                        payload["cursor"] = cursor
                    async with session.post(self.BASE_URL, json=payload, auth=auth) as resp:
                        if resp.status == 429:
                            wait = exponential_backoff(attempt)
                            logger.warning("Censys rate limited — waiting %.1fs", wait)
                            await asyncio.sleep(wait)
                            break
                        resp.raise_for_status()
                        try:
                            body = await resp.json(content_type=None)
                        except Exception as exc:
                            logger.error("Censys invalid JSON: %s", exc)
                            return results
                        hits = body.get("result", {}).get("hits", [])
                        results.extend(hits)
                        logger.debug("Censys → page fetched, %d total so far", len(results))
                        cursor = body.get("result", {}).get("links", {}).get("next")
                        if not cursor:
                            return results
                return results
            except aiohttp.ClientError as exc:
                wait = exponential_backoff(attempt)
                logger.warning("Censys error (%s) — retrying in %.1fs", exc, wait)
                await asyncio.sleep(wait)

        logger.error("Censys exhausted retries for %s", domain)
        return results


def get_providers() -> list[CTProvider]:
    return [CrtShProvider(), CensysProvider()]
