from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys

import aiohttp

from ct_sources import CTProvider, CrtShProvider, CensysProvider, get_providers
from extractor import extract_names_crtsh, extract_names_censys, filter_subdomains
from utils import validate_domain, aligned_table

logger = logging.getLogger(__name__)

_RESET   = "\033[0m"
_BOLD    = "\033[1m"
_DIM     = "\033[2m"
_GREEN   = "\033[32m"
_BGREEN  = "\033[92m"
_CYAN    = "\033[36m"
_BCYAN   = "\033[96m"
_YELLOW  = "\033[33m"
_BYELLOW = "\033[93m"
_RED     = "\033[31m"
_BRED    = "\033[91m"
_MAGENTA = "\033[35m"
_DIM_GREEN = "\033[2;32m"


def _supports_color() -> bool:
    return sys.stderr.isatty() and "--no-color" not in sys.argv


def _c(text: str, *codes: str) -> str:
    """Wrap *text* with ANSI codes if colour is supported."""
    if not _supports_color():
        return text
    return "".join(codes) + str(text) + _RESET


_BANNER = r"""
  ██████╗████████╗      ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
 ██╔════╝╚══██╔══╝      ██╔════╝████╗  ██║██║   ██║████╗ ████║
 ██║        ██║   █████╗█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
 ██║        ██║   ╚════╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
 ╚██████╗   ██║         ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
  ╚═════╝   ╚═╝         ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝"""

_TAGLINE = "  Certificate Transparency  //  Passive Subdomain Enumeration"
_VERSION = "v1.0"


def print_banner() -> None:
    if _supports_color():
        print(_c(_BANNER, _BGREEN, _BOLD), file=sys.stderr)
        print(_c(_TAGLINE, _DIM_GREEN), file=sys.stderr)
        print(_c(f"  {_VERSION}\n", _DIM, _GREEN), file=sys.stderr)
    else:
        print(_BANNER, file=sys.stderr)
        print(_TAGLINE, file=sys.stderr)
        print(f"  {_VERSION}\n", file=sys.stderr)


def _info(msg: str) -> None:
    label = _c("[*]", _BCYAN, _BOLD)
    print(f"{label} {_c(msg, _CYAN)}", file=sys.stderr)


def _ok(msg: str) -> None:
    label = _c("[+]", _BGREEN, _BOLD)
    print(f"{label} {_c(msg, _GREEN)}", file=sys.stderr)


def _warn(msg: str) -> None:
    label = _c("[!]", _BYELLOW, _BOLD)
    print(f"{label} {_c(msg, _YELLOW)}", file=sys.stderr)


def _err(msg: str) -> None:
    label = _c("[✗]", _BRED, _BOLD)
    print(f"{label} {_c(msg, _RED)}", file=sys.stderr)


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
    print_banner()

    try:
        domain = validate_domain(args.domain)
    except ValueError as exc:
        _err(str(exc))
        sys.exit(1)

    providers = get_providers()
    provider_names = ", ".join(type(p).__name__ for p in providers)
    _info(f"Target   : {_c(domain, _BYELLOW, _BOLD)}")
    _info(f"Providers: {_c(provider_names, _MAGENTA)}")
    _info(f"Timeout  : {_c(str(args.timeout) + 's', _MAGENTA)}")
    print(_c("  " + "─" * 52, _DIM_GREEN), file=sys.stderr)
    logger.debug("Loaded %d provider(s): %s", len(providers), [type(p).__name__ for p in providers])

    _info("Querying Certificate Transparency logs...")
    raw_names = await collect(domain, providers, args.timeout)
    subdomains = filter_subdomains(raw_names, domain)
    _ok(f"Done — {_c(str(len(subdomains)), _BYELLOW, _BOLD)} unique subdomains found")
    print(_c("  " + "─" * 52, _DIM_GREEN), file=sys.stderr)

    if args.json_output:
        payload = {
            "domain": domain,
            "count": len(subdomains),
            "subdomains": subdomains,
        }
        output = json.dumps(payload, indent=2)
    else:
        if _supports_color():
            sep   = _c("  " + "═" * 52, _GREEN)
            title = (
                f"\n{sep}\n"
                f"  {_c('TARGET', _DIM, _GREEN)}  {_c(domain, _BYELLOW, _BOLD)}"
                f"   {_c('FOUND', _DIM, _GREEN)}  {_c(str(len(subdomains)), _BGREEN, _BOLD)}\n"
                f"{sep}"
            )
            lines = [
                f"  {_c('▸', _BGREEN)}  {_c(s, _BGREEN)}"
                for s in subdomains
            ] if subdomains else [f"  {_c('(none found)', _DIM)}"]
            output = f"{title}\n" + "\n".join(lines) + f"\n{sep}\n"
        else:
            separator = "═" * 54
            header = f"\n{separator}\n  TARGET  {domain}   FOUND  {len(subdomains)}\n{separator}"
            body = aligned_table(subdomains)
            output = f"{header}\n{body}\n{separator}\n"

    if args.output:
        clean = re.sub(r"\033\[[0-9;]*m", "", output)
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(clean + "\n")
            _ok(f"Results written to {_c(args.output, _BCYAN, _BOLD)}")
        except OSError as exc:
            _err(f"Cannot write to {args.output}: {exc}")
            sys.exit(1)
    else:
        print(output, flush=True)


def main() -> None:
    args = parse_args()
    configure_logging(args.verbose)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        _warn("Interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
