"""Command-line interface for tuya_scanner."""

import argparse
import json
import logging
import sys

from . import TuyaScanner, __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tuya-scanner",
        description="Discover Tuya smart devices on your local network.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"tuya-scanner {__version__}",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="How long to listen for UDP broadcasts (default: 5).",
    )
    parser.add_argument(
        "--network",
        metavar="CIDR",
        default=None,
        help=(
            "Also probe every host in this CIDR range on TCP port 6668, "
            "e.g. 192.168.1.0/24."
        ),
    )
    parser.add_argument(
        "--bind",
        metavar="ADDRESS",
        default="",
        help=(
            "Local IP address to bind the UDP listener to "
            "(default: all interfaces). Example: 192.168.1.5."
        ),
    )
    parser.add_argument(
        "--json",
        dest="output_json",
        action="store_true",
        default=False,
        help="Output results as a JSON array.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase verbosity (use -vv for debug output).",
    )
    return parser


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Configure logging
    log_level = logging.WARNING
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    print(f"Scanning for Tuya devices (timeout={args.timeout}s)...", flush=True)

    discovered = []

    def on_device(device):
        if not args.output_json:
            print(f"  Found: {device}", flush=True)
        discovered.append(device)

    scanner = TuyaScanner(
        timeout=args.timeout,
        network=args.network,
        bind_address=args.bind,
        on_device=on_device,
    )
    devices = scanner.scan()

    if args.output_json:
        print(json.dumps([d.to_dict() for d in devices], indent=2))
    else:
        print(f"\n{len(devices)} device(s) found.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
