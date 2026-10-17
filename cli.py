import argparse
import asyncio
import sys
from pathlib import Path

from icescan import __version__, __author__, __description__
from icescan.config import Config


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="icescan",
        description=f"{__description__} - crafted by {__author__}",
        add_help=True,
    )

    p.add_argument("target", nargs="?", help="target url (http:// or https://)")
    p.add_argument("-V", "--version", action="store_true", help="print version and exit")
    p.add_argument("-c", "--config", type=Path, help="load config file (yaml/json)")
    p.add_argument("-o", "--output", type=Path, default=Path("report"), help="output dir (default: ./report)")
    p.add_argument("--format", default="json,html", help="report formats: json,html,sarif,txt (comma list)")

    p.add_argument("--level", type=int, choices=[1, 2, 3], default=1, help="scan level 1-3 (default 1)")
    p.add_argument("--tests", default="all", help="include checks by category or name (comma list)")
    p.add_argument("--exclude", default="", help="exclude checks by category or name (comma list)")

    p.add_argument("--crawl", action="store_true", help="enable crawler")
    p.add_argument("--depth", type=int, default=2, help="crawl depth (default 2)")
    p.add_argument("--max-urls", type=int, default=500, help="max urls to crawl (default 500)")
    p.add_argument("--subdomains", action="store_true", help="include subdomains in crawl scope")
    p.add_argument("--respect-robots", action="store_true", help="respect robots.txt")

    p.add_argument("--threads", type=int, default=20, help="concurrency (default 20)")
    p.add_argument("--rate", type=float, default=10.0, help="requests per second per host (default 10)")
    p.add_argument("--timeout", type=float, default=15.0, help="request timeout seconds (default 15)")
    p.add_argument("--retries", type=int, default=2, help="retries on failure (default 2)")
    p.add_argument("--proxy", help="http/socks proxy url")

    p.add_argument("--cookie", help="raw cookie string")
    p.add_argument("--header", action="append", default=[], help="extra header (repeatable)")
    p.add_argument("--basic-auth", help="user:pass for basic auth")
    p.add_argument("--bearer", help="bearer token")

    p.add_argument("--waf-evade", action="store_true", help="enable waf evasion encoders")
    p.add_argument("--stacked", action="store_true", help="enable stacked query probes (level 3)")

    p.add_argument("--oob-listen", action="store_true", help="spin up built-in oob callback listener")
    p.add_argument("--oob-host", help="external oob callback host")
    p.add_argument("--oob-port", type=int, default=8443, help="oob listener port (default 8443)")

    p.add_argument("--second-order-url", help="trigger endpoint for stored/second-order checks")
    p.add_argument("--baseline", type=Path, help="previous findings.json for diff mode")
    p.add_argument("--record", type=Path, help="dump every request/response to this dir")
    p.add_argument("--checkpoint", type=Path, help="resume file")

    p.add_argument("--quiet", action="store_true", help="findings only")
    p.add_argument("--no-color", action="store_true", help="disable ansi color")
    p.add_argument("--json-stream", action="store_true", help="one json per line to stdout")
    p.add_argument("--plain", action="store_true", help="no rich ui, plain output")

    return p


def _parse_version_and_exit(args, parser):
    if args.version:
        print(f"icescan v{__version__}")
        print(__description__)
        print(f"crafted by {__author__}")
        return 0
    return None


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    rc = _parse_version_and_exit(args, parser)
    if rc is not None:
        return rc

    if not args.target and not args.config:
        parser.print_help()
        return 2

    try:
        cfg = Config.from_sources(args)
    except Exception as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    from icescan.ui.banner import print_banner
    from icescan.ui.log import get_console
    from icescan.core.engine import run_scan

    console = get_console(quiet=cfg.quiet, no_color=cfg.no_color, plain=cfg.plain)
    print_banner(console, quiet=cfg.quiet, no_color=cfg.no_color)

    try:
        return asyncio.run(run_scan(cfg, console))
    except KeyboardInterrupt:
        console.print("\n[dim]interrupted[/dim]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
