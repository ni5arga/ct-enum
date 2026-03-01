from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

import aiohttp

from ct_sources import CTProvider, CrtShProvider, CensysProvider, get_providers
from parser import extract_names_crtsh, extract_names_censys, filter_subdomains
from utils import validate_domain, aligned_table

logger = logging.getLogger(__name__)


def build_session(timeout: float) -> aiohttp.ClientSession:
    connector = aiohttp.TCPConnector(limit=10, ssl=True)
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    headers = {"User-Agent": "https://github.com/ni5arga/ct-enum - s1.0"}
    return aiohttp.ClientSession(
        connector=connector,
        timeout=client_timeout,
        headers=headers,
    )


async def collect(domain: str, providers: list[CTProvider], timeout: float) -> set[str]:
    async with build_session(timeout) as session:
        tasks = [p.fetch(domain, session) for p in providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    all_names: set[str] = set()
    for provider, result in zip(providers, results):
        name = type(provider).__name__
        if isinstance(result, BaseException):
            logger.error("Provider %s raised an exception: %s", name, result)
            continue
        logger.debug("Provider %s returned %d raw entries", name, len(result))
        if isinstance(provider, CrtShProvider):
            all_names.update(extract_names_crtsh(result))
        elif isinstance(provider, CensysProvider):
            all_names.update(extract_names_censys(result))
        else:
            all_names.update(extract_names_crtsh(result))

    logger.debug("Total unique names across all providers: %d", len(all_names))
    return all_names


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
        stream=sys.stderr,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ct-enum",
        description="Passive subdomain enumeration via Certificate Transparency logs",
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output as JSON"
    )
    parser.add_argument("--output", metavar="FILE", help="Write results to file")
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        metavar="SECS",
        help="Request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose/debug logging"
    )
    return parser.parse_args()


async def run(args: argparse.Namespace) -> None:
    try:
        domain = validate_domain(args.domain)
    except ValueError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        sys.exit(1)

    providers = get_providers()
    logger.debug("Loaded %d provider(s): %s", len(providers), [type(p).__name__ for p in providers])

    raw_names = await collect(domain, providers, args.timeout)
    subdomains = filter_subdomains(raw_names, domain)

    if args.json_output:
        payload = {
            "domain": domain,
            "count": len(subdomains),
            "subdomains": subdomains,
        }
        output = json.dumps(payload, indent=2)
    else:
        separator = "─" * 50
        header = f"\nSubdomains of {domain} ({len(subdomains)} found)\n{separator}"
        body = aligned_table(subdomains)
        output = f"{header}\n{body}\n"

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output + "\n")
            print(f"[+] Results written to {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"[error] Cannot write to {args.output}: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output, flush=True)


def main() -> None:
    args = parse_args()
    configure_logging(args.verbose)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()