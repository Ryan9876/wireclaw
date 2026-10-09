"""Developer launcher; single worker and validated loopback binding."""

import argparse
import logging
from pathlib import Path

import uvicorn

from .app import create_app
from .config import Policy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    policy = Policy(host=args.host, port=args.port)
    # No request/access/exception logs: these can include sensitive URLs/bodies.
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("uvicorn.error").disabled = True
    uvicorn.run(
        create_app(args.data_root, policy),
        host=policy.host,
        port=policy.port,
        workers=1,
        access_log=False,
        limit_concurrency=32,
        log_config=None,
    )


if __name__ == "__main__":
    main()
