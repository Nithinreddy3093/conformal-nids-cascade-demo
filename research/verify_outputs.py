#!/usr/bin/env python3
"""Verify output files against research/pipeline.py's artifact_manifest.json."""
from __future__ import annotations

import argparse
import json

from pipeline import verify_artifact_manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", default="results/run-001/artifact_manifest.json")
    args = parser.parse_args()
    result = verify_artifact_manifest(args.manifest)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
