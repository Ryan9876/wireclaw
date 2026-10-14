"""Developer launcher; single worker and validated loopback binding."""

import argparse
import logging
import os
from pathlib import Path

import uvicorn

from .app import create_app
from .config import Policy


def policy_for_listener(*, host: str, listen_port: int, container_network: bool) -> Policy:
    public_port = os.environ.get("WIRECLAW_PUBLIC_PORT")
    return Policy.from_environment(
        host=host,
        port=int(public_port) if public_port is not None else listen_port,
        container_network=container_network,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--container-network",
        action="store_true",
        help="allow 0.0.0.0 only inside an isolated Docker network namespace",
    )
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    policy = policy_for_listener(
        host=args.host, listen_port=args.port, container_network=args.container_network
    )
    # No request/access/exception logs: these can include sensitive URLs/bodies.
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("uvicorn.error").disabled = True
    uvicorn.run(
        create_app(args.data_root, policy),
        host=policy.host,
        port=args.port,
        workers=1,
        access_log=False,
        limit_concurrency=32,
        log_config=None,
    )


if __name__ == "__main__":
    main()
