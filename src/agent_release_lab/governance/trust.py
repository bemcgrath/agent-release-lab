"""Offline trust administration for the local governance database."""

import argparse
import json
from os import environ
from pathlib import Path

from ..registry import Registry
from .models import LocalTrust
from .service import Governance


def main() -> None:
    parser = argparse.ArgumentParser(description="Activate the operator's local governance trust configuration")
    parser.add_argument("action", choices=["activate"])
    parser.parse_args()
    trust_path = environ.get("AGENT_RELEASE_LAB_TRUST")
    if not trust_path:
        parser.error("Set AGENT_RELEASE_LAB_TRUST to the local trust configuration file")
    database = environ.get("AGENT_RELEASE_LAB_DB", "agent-release-lab.sqlite3")
    try:
        trust = LocalTrust.from_json(Path(trust_path).read_bytes())
    except (OSError, ValueError, RecursionError):
        parser.error("The local trust configuration file could not be read or validated")
    revision = Governance(Registry(database), trust).activate_trust()
    print(json.dumps(revision))


if __name__ == "__main__":
    main()
