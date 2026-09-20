import argparse
import asyncio
import logging
import pathlib
import platform

try:
    import uvloop

    event_loop = "uvloop"
except ImportError:
    try:
        import winloop

        event_loop = "winloop"
    except ImportError:
        event_loop = "asyncio"

import wisp
from wisp.server import http


def run_async(func, *args, **kwargs):
    try:
        if event_loop == "uvloop":
            uvloop.run(func(*args, **kwargs))
        elif event_loop == "winloop":
            winloop.run(func(*args, **kwargs))
        else:
            asyncio.run(func(*args, **kwargs))
    except KeyboardInterrupt:
        pass


def run_http(args):
    run_async(http.main, args)


def main():
    parser = argparse.ArgumentParser(
        prog="wisp-server-python",
        description=(
            "A Wisp server implementation, written in Python "
            f"(v{wisp.version})"
        ),
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="The hostname the server will listen on.",
    )

    parser.add_argument(
        "--port",
        default=6001,
        type=int,
        help="The TCP port the server will listen on.",
    )

    parser.add_argument(
        "--static",
        help="Where static files are served from.",
    )

    parser.add_argument(
        "--limits",
        action="store_true",
        help="Enable rate limits.",
    )

    parser.add_argument(
        "--bandwidth",
        default=1000,
        type=float,
        help="Bandwidth limit per IP, in kilobytes per second.",
    )

    parser.add_argument(
        "--connections",
        default=30,
        type=int,
        help="New connections limit per IP.",
    )

    parser.add_argument(
        "--window",
        default=60,
        type=float,
        help="Fixed window length for rate limits, in seconds.",
    )

    parser.add_argument(
        "--allow-loopback",
        action="store_true",
        help="Allow connections to loopback IP addresses.",
    )

    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow connections to private IP addresses.",
    )

    parser.add_argument(
        "--log-level",
        default="info",
        help=(
            "The log level "
            "(debug, info, warning, error, critical)."
        ),
    )

    parser.add_argument(
        "--proxy",
        default=None,
        help="Proxy URL for the local Python server.",
    )

    parser.add_argument(
        "--block-udp",
        action="store_true",
        help="Block UDP streams.",
    )

    parser.add_argument(
        "--block-tcp",
        action="store_true",
        help="Block TCP streams.",
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="[%(asctime)s] %(levelname)-8s %(message)s",
        level=getattr(
            logging,
            args.log_level.upper(),
        ),
        datefmt="%Y/%m/%d - %H:%M:%S",
    )

    logging.info(
        "running wisp-server-python v%s (async)",
        wisp.version,
    )

    if args.static:
        static_path = pathlib.Path(
            args.static
        ).resolve()

        logging.info(
            "serving static files from %s",
            static_path,
        )

    if args.limits:
        logging.info("enabled rate limits")

    if args.proxy:
        logging.info(
            "proxy enabled: %s",
            args.proxy,
        )

    logging.info(
        "running on %s %s",
        platform.python_implementation(),
        platform.python_version(),
    )

    logging.info(
        "listening on %s:%s",
        args.host,
        args.port,
    )

    if event_loop == "asyncio":
        logging.warning(
            "uvloop or winloop unavailable; "
            "using asyncio."
        )

    run_http(args)
