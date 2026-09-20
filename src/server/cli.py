import asyncio
import argparse
import pathlib
import sys
import logging

import wisp
from wisp.server import http 
from wisp.server import net


def run_async(func, *args, **kwargs):
  """Run async function using standard asyncio (Cloudflare Workers compatible)"""
  try:
    asyncio.run(func(*args, **kwargs))
  except KeyboardInterrupt:
    pass


def main():
  parser = argparse.ArgumentParser(
    prog="wisp-server-python",
    description=f"A Wisp server implementation, written in Python (v{wisp.version})"
  )

  parser.add_argument("--host", default="127.0.0.1", help="The hostname the server will listen on.")
  parser.add_argument("--port", default=6001, help="The TCP port the server will listen on.")
  parser.add_argument("--static", help="Where static files are served from.")
  parser.add_argument("--limits", action="store_true", help="Enable rate limits.")
  parser.add_argument("--bandwidth", default=1000, help="Bandwidth limit per IP, in kilobytes per second.")
  parser.add_argument("--connections", default=30, help="New connections limit per IP.")
  parser.add_argument("--window", default=60, help="Fixed window length for rate limits, in seconds.")
  parser.add_argument("--allow-loopback", action="store_true", help="Allow connections to loopback IP addresses.")
  parser.add_argument("--allow-private", action="store_true", help="Allow connections to private IP addresses.")
  parser.add_argument("--log-level", default="info", help="The log level (either debug, info, warning, error, or critical).")
  parser.add_argument("--proxy", default=None, help="The url of the socks5h, socks5, sock4a, socks4 or http proxy to use.")
  parser.add_argument("--block-udp", action="store_true", help="Block UDP streams.")
  parser.add_argument("--block-tcp", action="store_true", help="Block TCP streams.")
  args = parser.parse_args()

  logging.basicConfig(
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    level=getattr(logging, args.log_level.upper()),
    datefmt="%Y/%m/%d - %H:%M:%S"
  )

  logging.info(f"running wisp-server-python v{wisp.version} (async)")
  if args.static:
    static_path = pathlib.Path(args.static).resolve()
    logging.info(f"serving static files from {static_path}")
  if args.limits:
    logging.info("enabled rate limits")
  if args.proxy:
    logging.info(f"proxy enabled: {args.proxy}")
  logging.info(f"listening on {args.host}:{args.port}")

  # Run single-threaded async handler (Cloudflare Workers compatible)
  run_async(http.main, args)